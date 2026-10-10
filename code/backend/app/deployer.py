"""
Exécution d'un plan de déploiement avec le SDK Docker.

  switch          → réseau Docker (bridge) dont la plage est déduite des interfaces
  pc / serveur    → container attaché à ses réseaux, route par défaut = sa passerelle
  routeur         → container multi-réseaux avec ip_forward=1 et sa table de routage
  sonde IDS       → container attaché au segment surveillé, mis en mode « hub »

Les messages de progression sont destinés à l'utilisateur : ils parlent
d'équipements et de réseaux, jamais de Docker.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import shlex
from pathlib import Path
from typing import Callable, Dict, List, Optional

import docker
from docker.errors import APIError, BuildError, DockerException, ImageNotFound
from docker.types import IPAMConfig, IPAMPool

from .planner import DevicePlan, NetworkPlan, Plan
from .settings import DeviceRuntime, Settings

log = logging.getLogger(__name__)

# Docker ≥ 28 : nom de l'interface dans le container (eth0, eth1…)
IFNAME_OPT = "com.docker.network.endpoint.ifname"
LISTENER_SOURCE = (Path(__file__).parent / "service_listener.py").read_text(encoding="utf-8")


class EngineUnavailable(Exception):
    """Le moteur de virtualisation ne répond pas."""


class DeploymentError(Exception):
    """Échec d'une étape ; le message est affichable tel quel."""


class Reporter:
    """Interface de suivi utilisée par LabManager.deploy (implémentée par jobs.Job)."""

    def begin(self, total: int) -> None: ...
    def step(self, label: str) -> None: ...
    def warn(self, message: str) -> None: ...


class LabManager:
    def __init__(self, settings: Settings, client_factory: Callable[[], docker.DockerClient] = docker.from_env):
        self.settings = settings
        self._client_factory = client_factory
        self._client: Optional[docker.DockerClient] = None

    # ------------------------------------------------------------------ outils

    @property
    def client(self) -> docker.DockerClient:
        try:
            if self._client is None:
                self._client = self._client_factory()
            self._client.ping()
        except (DockerException, OSError) as exc:
            self._client = None
            log.warning("Moteur Docker indisponible : %s", exc)
            raise EngineUnavailable() from exc
        return self._client

    @property
    def label(self) -> str:
        return f"{self.settings.prefix}.managed"

    def _labels(self, **extra: str) -> Dict[str, str]:
        return {self.label: "true", **{f"{self.settings.prefix}.{k}": v for k, v in extra.items()}}

    def _resource_name(self, item_id: str) -> str:
        return f"{self.settings.prefix}-{item_id}"

    def _exec(self, container, script: str, what: str) -> str:
        result = container.exec_run(["sh", "-c", script])
        output = result.output.decode(errors="replace").strip()
        if result.exit_code != 0:
            log.error("%s : échec de « %s » : %s", container.name, script, output)
            raise DeploymentError(f"{what} : la configuration a échoué ({output.splitlines()[-1] if output else 'erreur inconnue'}).")
        return output

    def start_capture_helper(self, device):
        """
        Conteneur d'analyse partageant la pile réseau d'un équipement (mêmes
        interfaces) : on y lance tcpdump sans rien installer dans l'équipement.
        Il porte le label du lab : l'arrêt du réseau le supprime aussi.
        """
        client = self.client
        runtime = self.settings.capture
        image = self._image_name(runtime)
        self._ensure_image(client, image, runtime)
        return client.containers.run(
            image,
            runtime.command,
            network_mode=f"container:{device.id}",
            cap_add=runtime.cap_add,
            labels=self._labels(role="capture"),
            init=True,
            detach=True,
        )

    def remove_capture_helpers(self, keep) -> None:
        """Supprime les conteneurs de capture orphelins (ceux dont l'id n'est pas dans `keep`)."""
        role = f"{self.settings.prefix}.role=capture"
        for c in self.client.containers.list(all=True, filters={"label": [self.label, role]}):
            if c.id not in keep:
                log.warning("Outil de capture orphelin supprimé : %s", c.short_id)
                try:
                    c.remove(force=True)
                except DockerException:
                    pass

    def _image_name(self, runtime: DeviceRuntime) -> str:
        """Image à instancier : celle de devices.toml, ou sa variante enrichie de `packages`."""
        if not runtime.packages:
            return runtime.image
        digest = hashlib.sha256(" ".join([runtime.image, *sorted(runtime.packages)]).encode()).hexdigest()[:12]
        return f"{self.settings.prefix}/device:{digest}"

    # ------------------------------------------------------------------ état

    def find_device(self, node_id: str):
        """Machine instanciée pour un équipement de la topologie (None si absente)."""
        found = self.client.containers.list(
            all=True, filters={"label": [self.label, f"{self.settings.prefix}.node={node_id}"]}
        )
        return found[0] if found else None

    def status(self) -> dict:
        client = self.client
        devices = []
        for c in client.containers.list(all=True, filters={"label": self.label}):
            labels = c.labels
            if f"{self.settings.prefix}.node" not in labels:
                continue  # conteneur auxiliaire (capture…), pas un équipement
            devices.append(
                {
                    "id": labels.get(f"{self.settings.prefix}.node"),
                    "name": labels.get(f"{self.settings.prefix}.name"),
                    "running": c.status == "running",
                }
            )
        networks = [n.attrs["Labels"].get(f"{self.settings.prefix}.node") for n in client.networks.list(filters={"label": self.label})]
        return {"running": bool(devices or networks), "devices": devices, "networks": networks}

    def teardown(self) -> None:
        client = self.client
        for c in client.containers.list(all=True, filters={"label": self.label}):
            c.remove(force=True)
        for n in client.networks.list(filters={"label": self.label}):
            n.remove()

    # ------------------------------------------------------------------ déploiement

    def deploy(self, plan: Plan, reporter: Reporter) -> None:
        client = self.client
        runtimes = self.settings.devices
        images: Dict[str, List[str]] = {}
        sources: Dict[str, DeviceRuntime] = {}
        for device in plan.devices:
            image = self._image_name(runtimes[device.type])
            sources[image] = runtimes[device.type]
            labels = images.setdefault(image, [])
            if device.label not in labels:
                labels.append(device.label)
        monitored = [d for d in plan.devices if d.monitored_network]
        if monitored:
            images.setdefault(self.settings.helper_image, [])
        # Outil de capture préparé d'avance : ouvrir une capture sera instantané
        capture_image = self._image_name(self.settings.capture)
        sources[capture_image] = self.settings.capture
        images.setdefault(capture_image, [])
        tools = {self.settings.helper_image: "des outils de surveillance", capture_image: "des outils d'analyse du trafic"}

        reporter.begin(1 + len(images) + len(plan.networks) + 2 * len(plan.devices) + len(monitored))

        reporter.step("Nettoyage de la simulation précédente")
        self.teardown()

        try:
            for image, labels in images.items():
                what = f"des équipements {', '.join(labels)}" if labels else tools[image]
                reporter.step(f"Préparation {what} (plus long au premier lancement)")
                self._ensure_image(client, image, sources.get(image))

            for net in plan.networks:
                desc = f" ({net.subnet})" if net.subnet else ""
                reporter.step(f"Création du réseau {net.name}{desc}")
                self._create_network(client, net)

            containers = {}
            for device in plan.devices:
                reporter.step(f"Mise sous tension de {device.name}")
                containers[device.id] = self._create_device(client, plan, device)

            for device in plan.devices:
                reporter.step(self._configure_label(device))
                self._configure_device(plan, device, containers[device.id])

            for device in monitored:
                net = plan.network(device.monitored_network)
                reporter.step(f"Recopie du trafic de {net.name} vers {device.name}")
                try:
                    self._enable_hub_mode(client, net)
                except DockerException as exc:
                    log.warning("Mode hub impossible sur %s : %s", net.name, exc)
                    reporter.warn(
                        f"{device.name} ne verra que le trafic qui lui est destiné sur {net.name} "
                        "(la recopie de trafic n'a pas pu être activée)."
                    )
        except BaseException:
            # On ne laisse jamais un réseau à moitié construit
            try:
                self.teardown()
            except DockerException:
                log.exception("Nettoyage après échec impossible")
            raise

    def _ensure_image(self, client, image: str, runtime: Optional[DeviceRuntime] = None) -> None:
        try:
            client.images.get(image)
            return
        except ImageNotFound:
            pass
        try:
            if runtime is not None and runtime.packages:
                # Image dérivée construite une seule fois puis réutilisée (cache local)
                packages = " ".join(shlex.quote(p) for p in runtime.packages)
                dockerfile = f"FROM {runtime.image}\nRUN apk add --no-cache {packages}\n"
                client.images.build(fileobj=io.BytesIO(dockerfile.encode()), tag=image, rm=True)
            else:
                client.images.pull(image)
        except (APIError, BuildError) as exc:
            log.error("Préparation de l'image %s impossible : %s", image, exc)
            raise DeploymentError(
                "Impossible de préparer les équipements : vérifiez la connexion Internet de la machine hôte."
            ) from exc

    def _create_network(self, client, net: NetworkPlan) -> None:
        kwargs = dict(
            name=self._resource_name(net.id),
            driver="bridge",
            labels=self._labels(node=net.id, name=net.name, vlan=str(net.vlan or "")),
            options={"com.docker.network.bridge.name": self._bridge_name(net)},
        )
        if net.subnet is not None:
            kwargs["ipam"] = IPAMConfig(pool_configs=[IPAMPool(subnet=str(net.subnet), gateway=net.reserved_address)])
        try:
            client.networks.create(**kwargs)
        except APIError as exc:
            log.error("Création du réseau %s : %s", net.name, exc)
            if "overlap" in str(exc).lower():
                raise DeploymentError(
                    f"Le sous-réseau {net.subnet} de {net.name} est déjà utilisé sur la machine hôte : choisissez une autre plage."
                ) from exc
            raise DeploymentError(f"Impossible de créer le réseau {net.name}.") from exc

    def _bridge_name(self, net: NetworkPlan) -> str:
        # Nom d'interface Linux : 15 caractères maximum
        return f"br-{net.id}"[:15]

    def _endpoint_config(self, device: DevicePlan, index: int) -> dict:
        ep = device.endpoints[index]
        return dict(
            ipv4_address=str(ep.address.ip) if ep.address else None,
            driver_opt={IFNAME_OPT: ep.interface},
        )

    def _create_device(self, client, plan: Plan, device: DevicePlan):
        runtime = self.settings.devices[device.type]
        command = runtime.command
        if device.type == "server":
            services = [s.model_dump() for s in device.services]
            command = ["python3", "-u", "-c", LISTENER_SOURCE, json.dumps(services)]

        kwargs = dict(
            image=self._image_name(runtime),
            command=command,
            name=self._resource_name(device.id),
            hostname=device.hostname,
            labels=self._labels(node=device.id, name=device.name, type=device.type),
            cap_add=runtime.cap_add,
            sysctls={"net.ipv4.ip_forward": "1" if device.type == "router" else "0"},
            init=True,
            detach=True,
        )
        if device.endpoints:
            first = self._resource_name(device.endpoints[0].network_id)
            kwargs["network"] = first
            kwargs["networking_config"] = {first: client.api.create_endpoint_config(**self._endpoint_config(device, 0))}
        else:
            kwargs["network_mode"] = "none"

        try:
            container = client.containers.create(**kwargs)
            for i, ep in enumerate(device.endpoints[1:], start=1):
                client.api.connect_container_to_network(
                    container.id, self._resource_name(ep.network_id), **self._endpoint_config(device, i)
                )
            container.start()
        except APIError as exc:
            log.error("Création de %s : %s", device.name, exc)
            raise DeploymentError(f"Impossible de mettre {device.name} sous tension.") from exc
        container.reload()
        return container

    def _configure_label(self, device: DevicePlan) -> str:
        details = ["interfaces"]
        if device.type == "router":
            details.append("table de routage")
        elif device.routes:
            details.append("passerelle")
        if device.services:
            details.append("services " + ", ".join(s.name or str(s.port) for s in device.services))
        return f"Configuration de {device.name} ({', '.join(details)})"

    def _configure_device(self, plan: Plan, device: DevicePlan, container) -> None:
        if not device.endpoints:
            return
        self._ensure_interface_names(plan, device, container)

        # Seules les routes définies par l'utilisateur subsistent : la route par
        # défaut posée automatiquement est retirée (pas d'accès hors de la topologie).
        lines = ["set -e", "ip route del default 2>/dev/null || true"]
        lines += [route.command() for route in device.routes]
        if device.monitored_network:
            iface = next(ep.interface for ep in device.endpoints if ep.network_id == device.monitored_network)
            lines.append(f"ip link set dev {shlex.quote(iface)} promisc on")
        self._exec(container, "\n".join(lines), device.name)

    def _ensure_interface_names(self, plan: Plan, device: DevicePlan, container) -> None:
        """
        Vérifie que chaque interface porte le nom choisi par l'utilisateur.
        Docker ≥ 28 l'applique via IFNAME_OPT ; sur une version plus ancienne,
        on renomme à la main (identification par adresse MAC).
        """
        attached = container.attrs["NetworkSettings"]["Networks"]
        expected = {}  # mac → nom voulu
        for ep in device.endpoints:
            mac = attached.get(self._resource_name(ep.network_id), {}).get("MacAddress", "").lower()
            if mac:
                expected[mac] = ep.interface

        listing = self._exec(
            container, 'for i in /sys/class/net/*; do echo "${i##*/} $(cat $i/address)"; done', device.name
        )
        current = {}  # mac → nom actuel
        for line in listing.splitlines():
            name, _, mac = line.partition(" ")
            current[mac.lower()] = name

        renames = [(current[mac], want) for mac, want in expected.items() if mac in current and current[mac] != want]
        if not renames:
            return
        log.info("%s : renommage des interfaces %s", device.name, renames)
        # Deux passes (via des noms temporaires) pour permettre les échanges eth0 ↔ eth1
        script = ["set -e"]
        for i, (old, _) in enumerate(renames):
            script += [f"ip link set dev {old} down", f"ip link set dev {old} name tmpif{i}"]
        for i, (_, new) in enumerate(renames):
            script += [f"ip link set dev tmpif{i} name {new}", f"ip link set dev {new} up"]
        self._exec(container, "\n".join(script), device.name)

    def _enable_hub_mode(self, client, net: NetworkPlan) -> None:
        """
        Un bridge Linux se comporte comme un switch : il n'envoie à chaque port
        que le trafic qui lui est destiné. Avec ageing_time = 0 il n'apprend
        plus aucune adresse MAC et diffuse tout, comme un hub : la sonde voit
        alors l'ensemble du trafic du segment (équivalent d'un port miroir).
        """
        bridge = self._bridge_name(net)
        client.containers.run(
            self.settings.helper_image,
            ["sh", "-c", f"echo 0 > /sys/class/net/{bridge}/bridge/ageing_time"],
            privileged=True,
            network_mode="host",
            remove=True,
            labels=self._labels(),
        )
