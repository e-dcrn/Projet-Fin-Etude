"""
Crée dans Docker le réseau décrit par un plan (voir planner.py).

  switch        → réseau Docker (bridge)
  pc / serveur  → conteneur branché sur ses réseaux, avec sa route par défaut
  routeur       → conteneur branché sur plusieurs réseaux, qui fait suivre les paquets
  sonde IDS     → conteneur branché sur le switch surveillé, qui reçoit tout son trafic

Chaque type d'équipement a son image Docker, construite depuis
code/docker/<type>/Dockerfile. Docker garde les images en cache : la
reconstruction est instantanée tant qu'un Dockerfile n'a pas changé.

Toutes les ressources créées portent le label « idslab.managed » : c'est
comme ça qu'on les retrouve, et qu'on les supprime à l'arrêt.
"""

import json
from pathlib import Path

import docker
from docker.types import IPAMConfig, IPAMPool

from .errors import UserError
from .models import dns_name
from .settings import DOCKER_DIR, PREFIX

# Programme lancé dans chaque serveur : il démarre ses services (HTTP, SSH, FTP…)
LISTENER_SOURCE = (Path(__file__).parent / "service_listener.py").read_text(encoding="utf-8")

# Droits réseau donnés aux conteneurs : NET_ADMIN pour configurer routes et
# interfaces, NET_RAW pour ping, capture et scans.
CAP_ADD = ["NET_ADMIN", "NET_RAW"]


def image(role):
    """Nom de l'image d'un type d'équipement : « idslab/pc », « idslab/toolbox »…"""
    return f"{PREFIX}/{role}"


def labels(**extra):
    """Labels Docker d'une ressource du lab : { "idslab.managed": "true", "idslab.node": "pc-1", … }"""
    result = {LabManager.label: "true"}
    for key, value in extra.items():
        result[f"{PREFIX}.{key}"] = value
    return result


class LabManager:
    label = f"{PREFIX}.managed"

    def __init__(self):
        self._client = None

    @property
    def client(self):
        """Connexion à Docker, ouverte à la première utilisation."""
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------------ retrouver les conteneurs

    def find_device(self, node_id):
        """Conteneur d'un équipement de la topologie (None s'il n'existe pas)."""
        found = self.client.containers.list(all=True, filters={"label": [self.label, f"{PREFIX}.node={node_id}"]})
        return found[0] if found else None

    def helpers(self, role):
        """Conteneurs auxiliaires d'un rôle (« traffic », « scenario », « capture »…)."""
        return self.client.containers.list(all=True, filters={"label": [self.label, f"{PREFIX}.role={role}"]})

    def start_netns_helper(self, device, command, role, **extra_labels):
        """
        Lance un conteneur auxiliaire (image « toolbox ») qui partage le réseau
        d'un équipement : même IP, mêmes interfaces. Tout ce qu'il envoie semble
        venir de l'équipement. Sert au trafic bénin, aux attaques et aux captures.
        """
        return self.client.containers.run(
            image("toolbox"),
            command,
            network_mode=f"container:{device.id}",
            cap_add=CAP_ADD,
            labels=labels(role=role, **extra_labels),
            init=True,
            detach=True,
        )

    # ------------------------------------------------------------------ état et arrêt

    def status(self):
        """Équipements et réseaux du lab, pour l'interface."""
        devices = []
        for c in self.client.containers.list(all=True, filters={"label": self.label}):
            if f"{PREFIX}.node" in c.labels:  # sinon, c'est un conteneur auxiliaire
                devices.append({
                    "id": c.labels[f"{PREFIX}.node"],
                    "name": c.labels[f"{PREFIX}.name"],
                    "running": c.status == "running",
                })
        networks = []
        for n in self.client.networks.list(filters={"label": self.label}):
            networks.append(n.attrs["Labels"][f"{PREFIX}.node"])
        return {"running": bool(devices or networks), "devices": devices, "networks": networks}

    def teardown(self):
        """Supprime tous les conteneurs, puis tous les réseaux du lab."""
        for c in self.client.containers.list(all=True, filters={"label": self.label}):
            try:
                c.remove(force=True)
            except docker.errors.APIError:
                pass  # déjà en train de disparaître (fin d'un scénario, par exemple)
        for n in self.client.networks.list(filters={"label": self.label}):
            n.remove()

    # ------------------------------------------------------------------ déploiement

    def deploy(self, plan, job):
        """Crée le réseau du plan. `job` (voir jobs.py) affiche la progression dans l'interface."""
        roles = {d.type for d in plan.devices} | {"toolbox"}
        probes = [d for d in plan.devices if d.monitored_network]
        job.begin(1 + len(roles) + len(plan.networks) + 2 * len(plan.devices) + len(probes))

        job.step("Nettoyage de la simulation précédente")
        self.teardown()

        for role in roles:
            job.step(f"Préparation de l'image {role} (plus long au premier lancement)")
            self.client.images.build(path=str(DOCKER_DIR / role), tag=image(role), rm=True)

        for net in plan.networks:
            job.step(f"Création du réseau {net.name}")
            self.create_network(net)

        containers = {}
        for device in plan.devices:
            job.step(f"Mise sous tension de {device.name}")
            containers[device.id] = self.create_device(plan, device)

        for device in plan.devices:
            job.step(f"Configuration de {device.name}")
            self.configure_device(device, containers[device.id])

        for device in probes:
            net = plan.network(device.monitored_network)
            job.step(f"Recopie du trafic de {net.name} vers {device.name}")
            self.enable_hub_mode(net)

    def create_network(self, net):
        options = {"com.docker.network.bridge.name": f"br-{net.id}"[:15]}  # nom Linux : 15 caractères max
        ipam = None
        if net.subnet is not None:
            ipam = IPAMConfig(pool_configs=[IPAMPool(subnet=str(net.subnet), gateway=net.reserved_address)])
        self.client.networks.create(
            f"{PREFIX}-{net.id}",
            driver="bridge",
            ipam=ipam,
            options=options,
            labels=labels(node=net.id, name=net.name),
        )

    def create_device(self, plan, device):
        # Un serveur lance ses services ; les autres équipements attendent sans rien faire.
        command = ["sleep", "infinity"]
        if device.type == "server":
            services = [s.model_dump() for s in device.services]
            # Annuaire de la topologie (nom DNS → IP), utilisé si le serveur fait aussi DNS
            hosts = {}
            for d in plan.devices:
                if d.endpoints and d.endpoints[0].address is not None:
                    hosts[dns_name(d.name)] = str(d.endpoints[0].address.ip)
            command = ["python3", "-u", "-c", LISTENER_SOURCE, json.dumps(services), json.dumps(hosts)]

        # Docker ne branche qu'un réseau à la création : on branche le premier
        # câble ici, les suivants juste après avec connect_container_to_network.
        network_options = {"network_mode": "none"}
        if device.endpoints:
            first = device.endpoints[0]
            name = f"{PREFIX}-{first.network_id}"
            network_options = {
                "network": name,
                "networking_config": {name: self.client.api.create_endpoint_config(**endpoint_config(first))},
            }

        container = self.client.containers.create(
            image(device.type),
            command,
            name=f"{PREFIX}-{device.id}",
            hostname=device.hostname,
            labels=labels(node=device.id, name=device.name, type=device.type),
            cap_add=CAP_ADD,
            sysctls={"net.ipv4.ip_forward": "1" if device.type == "router" else "0"},  # seul le routeur relaie
            init=True,  # petit processus init : le conteneur s'arrête tout de suite quand on le supprime
            detach=True,
            **network_options,
        )
        for ep in device.endpoints[1:]:
            self.client.api.connect_container_to_network(container.id, f"{PREFIX}-{ep.network_id}", **endpoint_config(ep))
        container.start()
        return container

    def configure_device(self, device, container):
        """Pose les routes (et le mode promiscuité d'une sonde) dans le conteneur."""
        if not device.endpoints:
            return
        # Docker ajoute une route par défaut vers lui-même : on la retire, seules
        # les routes de la topologie comptent.
        lines = ["ip route del default 2>/dev/null || true"]
        for route in device.routes:
            lines.append(route.command())
        if device.monitored_network:
            for ep in device.endpoints:
                if ep.network_id == device.monitored_network:
                    lines.append(f"ip link set dev {ep.interface} promisc on")  # accepte les paquets des autres
        result = container.exec_run(["sh", "-c", "set -e\n" + "\n".join(lines)])
        if result.exit_code != 0:
            raise UserError(f"Configuration de {device.name} impossible : {result.output.decode().strip()}")

    def enable_hub_mode(self, net):
        """
        Un bridge Linux se comporte comme un switch : chaque port ne reçoit que
        le trafic qui lui est destiné. Avec ageing_time = 0, il n'apprend plus
        aucune adresse MAC et envoie tout partout, comme un hub : la sonde voit
        alors tout le trafic du switch (équivalent d'un port miroir).
        """
        bridge = f"br-{net.id}"[:15]
        self.client.containers.run(
            image("toolbox"),
            ["sh", "-c", f"echo 0 > /sys/class/net/{bridge}/bridge/ageing_time"],
            privileged=True,
            network_mode="host",
            remove=True,
            labels=labels(),
        )


def endpoint_config(ep):
    """Adresse IP et nom d'interface (eth0…) d'un câble, au format attendu par Docker."""
    return {
        "ipv4_address": str(ep.address.ip) if ep.address else None,
        "driver_opt": {"com.docker.network.endpoint.ifname": ep.interface},  # Docker ≥ 28
    }
