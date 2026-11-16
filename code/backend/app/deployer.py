"""
Exécution d'un plan de déploiement avec le SDK Docker.

  switch          → réseau Docker (bridge) dont la plage est déduite des interfaces
  pc / serveur    → container attaché à ses réseaux, route par défaut = sa passerelle
  routeur         → container multi-réseaux avec ip_forward=1 et sa table de routage
  sonde IDS       → container attaché au segment surveillé, mis en mode « hub »

Chaque rôle (pc, server, router, ids, et la boîte à outils « toolbox ») a son
image, construite depuis code/docker/<rôle>/Dockerfile. Elles sont reconstruites
à chaque déploiement : grâce au cache de Docker, c'est instantané tant qu'un
Dockerfile n'a pas changé.

Les messages de progression sont destinés à l'utilisateur : ils parlent
d'équipements et de réseaux, jamais de Docker.
"""

from __future__ import annotations

import json
import logging
import shlex
from pathlib import Path
from typing import Callable, Dict, Optional

import docker
from docker.errors import APIError, BuildError, DockerException
from docker.types import IPAMConfig, IPAMPool

from .errors import EngineUnavailable, UserError
from .models import dns_name
from .planner import DevicePlan, NetworkPlan, Plan
from .settings import DOCKER_DIR, PREFIX

log = logging.getLogger(__name__)

# Nom de l'interface dans le container (eth0, eth1…) : option reconnue par Docker ≥ 28
IFNAME_OPT = "com.docker.network.endpoint.ifname"
LISTENER_SOURCE = (Path(__file__).parent / "service_listener.py").read_text(encoding="utf-8")

# NET_ADMIN : configurer routes et interfaces ; NET_RAW : ping, capture, scans SYN.
CAP_ADD = ["NET_ADMIN", "NET_RAW"]
KEEP_ALIVE = ["sleep", "infinity"]  # processus qui maintient un équipement allumé


def image(role: str) -> str:
    """Nom de l'image d'un rôle : « idslab/pc », « idslab/toolbox »…"""
    return f"{PREFIX}/{role}"


class LabManager:
    def __init__(self, client_factory: Callable[[], docker.DockerClient] = docker.from_env):
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
        return f"{PREFIX}.managed"

    def _labels(self, **extra: str) -> Dict[str, str]:
        return {self.label: "true", **{f"{PREFIX}.{k}": v for k, v in extra.items()}}

    def _resource_name(self, item_id: str) -> str:
        return f"{PREFIX}-{item_id}"

    def _exec(self, container, script: str, what: str) -> str:
        result = container.exec_run(["sh", "-c", script])
        output = result.output.decode(errors="replace").strip()
        if result.exit_code != 0:
            log.error("%s : échec de « %s » : %s", container.name, script, output)
            raise UserError(f"{what} : la configuration a échoué ({output.splitlines()[-1] if output else 'erreur inconnue'}).")
        return output

    def start_netns_helper(self, device, command, role: str, **extra_labels):
        """
        Conteneur éphémère partageant la pile réseau d'un équipement (même IP,
        mêmes interfaces) : tout ce qu'il émet semble provenir de l'équipement,
        et il voit tout le trafic de ses interfaces. Sert à la génération de
        trafic (agent bénin, attaques) et à la capture (tcpdump), sans rien
        installer dans l'équipement (image « toolbox », construite au déploiement).
        Il porte le label du lab : l'arrêt du réseau le supprime aussi. `role` et
        `extra_labels` permettent de le retrouver.
        """
        return self.client.containers.run(
            image("toolbox"),
            command,
            network_mode=f"container:{device.id}",
            cap_add=CAP_ADD,
            labels=self._labels(role=role, **extra_labels),
            init=True,
            detach=True,
        )

    def helpers(self, role: str):
        """Conteneurs auxiliaires d'un rôle donné (capture, traffic, scenario…)."""
        selector = f"{PREFIX}.role={role}"
        return self.client.containers.list(all=True, filters={"label": [self.label, selector]})

    # ------------------------------------------------------------------ état

    def find_device(self, node_id: str):
        """Machine instanciée pour un équipement de la topologie (None si absente)."""
        found = self.client.containers.list(
            all=True, filters={"label": [self.label, f"{PREFIX}.node={node_id}"]}
        )
        return found[0] if found else None

    def status(self) -> dict:
        client = self.client
        devices = []
        for c in client.containers.list(all=True, filters={"label": self.label}):
            labels = c.labels
            if f"{PREFIX}.node" not in labels:
                continue  # conteneur auxiliaire (capture…), pas un équipement
            devices.append(
                {
                    "id": labels.get(f"{PREFIX}.node"),
                    "name": labels.get(f"{PREFIX}.name"),
                    "running": c.status == "running",
                }
            )
        networks = [n.attrs["Labels"].get(f"{PREFIX}.node") for n in client.networks.list(filters={"label": self.label})]
        return {"running": bool(devices or networks), "devices": devices, "networks": networks}

    def teardown(self) -> None:
        client = self.client
        for c in client.containers.list(all=True, filters={"label": self.label}):
            try:
                c.remove(force=True)
            except DockerException as exc:  # déjà en cours de suppression (fin d'un scénario, par exemple)
                log.info("Conteneur %s déjà supprimé : %s", c.short_id, exc)
        for n in client.networks.list(filters={"label": self.label}):
            n.remove()

    # ------------------------------------------------------------------ déploiement

    def deploy(self, plan: Plan, reporter) -> None:
        """`reporter` (une tâche de fond, voir jobs.Job) affiche la progression : begin, step, warn."""
        client = self.client
        # Images à préparer : celle de chaque type d'équipement présent (rôle → libellé),
        # et la boîte à outils (trafic, attaques, captures, mode hub).
        roles: Dict[str, str] = {d.type: d.label for d in plan.devices}
        roles["toolbox"] = "des outils (trafic, attaques, capture)"
        monitored = [d for d in plan.devices if d.monitored_network]

        reporter.begin(1 + len(roles) + len(plan.networks) + 2 * len(plan.devices) + len(monitored))

        reporter.step("Nettoyage de la simulation précédente")
        self.teardown()

        try:
            for role, label in roles.items():
                what = label if role == "toolbox" else f"des équipements {label}"
                reporter.step(f"Préparation {what} (plus long au premier lancement)")
                self._build_image(client, role)

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
                self._configure_device(device, containers[device.id])

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

    def _build_image(self, client, role: str) -> None:
        """Construit l'image d'un rôle depuis code/docker/<rôle>/ (cache de Docker : rapide si inchangée)."""
        try:
            client.images.build(path=str(DOCKER_DIR / role), tag=image(role), rm=True)
        except (APIError, BuildError) as exc:
            log.error("Construction de l'image %s impossible : %s", image(role), exc)
            raise UserError(
                "Impossible de préparer les équipements : vérifiez la connexion Internet de la machine hôte."
            ) from exc

    def _create_network(self, client, net: NetworkPlan) -> None:
        kwargs = dict(
            name=self._resource_name(net.id),
            driver="bridge",
            labels=self._labels(node=net.id, name=net.name),
            options={"com.docker.network.bridge.name": self._bridge_name(net)},
        )
        if net.subnet is not None:
            kwargs["ipam"] = IPAMConfig(pool_configs=[IPAMPool(subnet=str(net.subnet), gateway=net.reserved_address)])
        try:
            client.networks.create(**kwargs)
        except APIError as exc:
            log.error("Création du réseau %s : %s", net.name, exc)
            if "overlap" in str(exc).lower():
                raise UserError(
                    f"Le sous-réseau {net.subnet} de {net.name} est déjà utilisé sur la machine hôte : choisissez une autre plage."
                ) from exc
            raise UserError(f"Impossible de créer le réseau {net.name}.") from exc

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
        command = KEEP_ALIVE
        if device.type == "server":
            services = [s.model_dump() for s in device.services]
            # Annuaire de la topologie (nom DNS → IP) : sert au serveur DNS s'il y en a un.
            hosts = {
                dns_name(d.name): str(ep.address.ip)
                for d in plan.devices
                for ep in d.endpoints[:1]
                if ep.address is not None
            }
            command = ["python3", "-u", "-c", LISTENER_SOURCE, json.dumps(services), json.dumps(hosts)]

        kwargs = dict(
            image=image(device.type),
            command=command,
            name=self._resource_name(device.id),
            hostname=device.hostname,
            labels=self._labels(node=device.id, name=device.name, type=device.type),
            cap_add=CAP_ADD,
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
            raise UserError(f"Impossible de mettre {device.name} sous tension.") from exc
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

    def _configure_device(self, device: DevicePlan, container) -> None:
        if not device.endpoints:
            return

        # Seules les routes définies par l'utilisateur subsistent : la route par
        # défaut posée automatiquement est retirée (pas d'accès hors de la topologie).
        lines = ["set -e", "ip route del default 2>/dev/null || true"]
        lines += [route.command() for route in device.routes]
        if device.monitored_network:
            iface = next(ep.interface for ep in device.endpoints if ep.network_id == device.monitored_network)
            lines.append(f"ip link set dev {shlex.quote(iface)} promisc on")
        self._exec(container, "\n".join(lines), device.name)

    def _enable_hub_mode(self, client, net: NetworkPlan) -> None:
        """
        Un bridge Linux se comporte comme un switch : il n'envoie à chaque port
        que le trafic qui lui est destiné. Avec ageing_time = 0 il n'apprend
        plus aucune adresse MAC et diffuse tout, comme un hub : la sonde voit
        alors l'ensemble du trafic du segment (équivalent d'un port miroir).
        """
        bridge = self._bridge_name(net)
        client.containers.run(
            image("toolbox"),
            ["sh", "-c", f"echo 0 > /sys/class/net/{bridge}/bridge/ageing_time"],
            privileged=True,
            network_mode="host",
            remove=True,
            labels=self._labels(),
        )
