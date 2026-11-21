"""
Topologie dessinée dans l'interface → plan de déploiement.

On ne vérifie rien ici : l'interface (src/utils/validators.js) refuse déjà une
topologie incohérente avant de l'envoyer. Ce fichier se contente de traduire
les données reçues en objets simples, que deployer.py crée ensuite dans Docker :

  - un switch       → un NetworkPlan  (un réseau Docker)
  - un équipement   → un DevicePlan   (un conteneur Docker)
  - un câble        → un EndpointPlan (une interface du conteneur, branchée sur un réseau)
"""

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv4Network
from typing import List, Optional

from .models import Service, Topology

TYPE_LABELS = {"pc": "PC", "server": "Serveur", "router": "Routeur", "ids": "Sonde IDS"}


@dataclass
class NetworkPlan:
    id: str                                  # « switch-1 »
    name: str                                # « Switch-1 »
    subnet: Optional[IPv4Network] = None     # 10.0.1.0/24 (None : Docker en choisit un)
    reserved_address: Optional[str] = None   # adresse gardée par Docker pour le réseau lui-même


@dataclass
class EndpointPlan:
    network_id: str                          # switch sur lequel le câble est branché
    interface: str                           # « eth0 »
    address: Optional[IPv4Interface]         # 10.0.1.11/24 (None : sonde IDS, adresse automatique)


@dataclass
class RoutePlan:
    destination: IPv4Network                 # 0.0.0.0/0 pour la route par défaut
    via: Optional[str] = None                # passerelle
    interface: Optional[str] = None          # interface de sortie

    def command(self):
        """Commande Linux qui ajoute cette route dans le conteneur."""
        dest = "default" if self.destination.prefixlen == 0 else str(self.destination)
        cmd = f"ip route replace {dest}"
        if self.via:
            cmd += f" via {self.via}"
        if self.interface:
            cmd += f" dev {self.interface}"
        return cmd


@dataclass
class DevicePlan:
    id: str                                  # « pc-1 »
    name: str                                # « PC-1 »
    type: str                                # pc, server, router ou ids
    hostname: str                            # nom de la machine dans le conteneur
    endpoints: List[EndpointPlan] = field(default_factory=list)
    routes: List[RoutePlan] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)   # serveurs uniquement
    monitored_network: Optional[str] = None                  # sondes IDS uniquement

    @property
    def label(self):
        return TYPE_LABELS[self.type]


@dataclass
class Plan:
    networks: List[NetworkPlan]
    devices: List[DevicePlan]

    def network(self, network_id):
        for net in self.networks:
            if net.id == network_id:
                return net


def build_plan(topology: Topology) -> Plan:
    # 1. Un réseau par switch
    networks = {}
    for n in topology.networks:
        subnet = IPv4Network(n.subnet) if n.subnet else None
        networks[n.id] = NetworkPlan(id=n.id, name=n.name, subnet=subnet)

    # 2. Un conteneur par équipement
    devices = {}
    for n in topology.nodes:
        devices[n.id] = DevicePlan(
            id=n.id,
            name=n.name,
            type=n.type,
            hostname=re.sub(r"[^A-Za-z0-9-]+", "-", n.name).strip("-") or n.id,  # « PC 1 » → « PC-1 »
        )
        if n.type == "server":
            devices[n.id].services = n.config.services
        if n.type == "ids":
            devices[n.id].monitored_network = n.config.monitoredSegment or None

    # 3. Chaque câble devient une interface de l'équipement
    for link in topology.links:
        address = None
        if link.ip:
            mask = link.mask.lstrip("/")      # « 255.255.255.0 », « 24 » ou « /24 »
            address = IPv4Interface(f"{link.ip}/{mask}")
        devices[link.node].endpoints.append(EndpointPlan(link.network, link.interface, address))

        # Switch sans réseau déclaré : il prend celui de la première adresse branchée dessus
        net = networks[link.network]
        if net.subnet is None and address is not None:
            net.subnet = address.network

    # 4. Les routes
    for n in topology.nodes:
        device = devices[n.id]
        if n.type in ("pc", "server") and n.config.gateway:
            device.routes.append(RoutePlan(IPv4Network("0.0.0.0/0"), via=n.config.gateway))
        if n.type == "router":
            for r in n.config.routes:
                destination = IPv4Network(r.destination, strict=False)
                device.routes.append(RoutePlan(destination, via=r.gateway or None, interface=r.interface or None))

    # 5. Docker garde une adresse de chaque réseau pour lui-même. Par défaut c'est
    #    la première (10.0.1.1), souvent celle d'un routeur : on lui donne plutôt
    #    la plus haute adresse libre (10.0.1.254).
    for net in networks.values():
        if net.subnet is None:
            continue
        used = set()
        for device in devices.values():
            for ep in device.endpoints:
                if ep.network_id == net.id and ep.address is not None:
                    used.add(ep.address.ip)
        candidate = net.subnet.broadcast_address - 1
        while candidate in used:
            candidate -= 1
        net.reserved_address = str(candidate)

    # 6. L'ordre de création compte :
    #    - les interfaces dans l'ordre eth0, eth1… ;
    #    - les sondes IDS en dernier, car leur adresse est automatique : elle ne
    #      doit pas prendre une adresse qu'un autre équipement a demandée ;
    #    - les réseaux à plage connue d'abord, pour que Docker évite ces plages
    #      quand il en choisit une lui-même.
    for device in devices.values():
        device.endpoints.sort(key=lambda ep: ep.interface)
    device_list = sorted(devices.values(), key=lambda d: d.type == "ids")
    network_list = sorted(networks.values(), key=lambda n: n.subnet is None)
    return Plan(networks=network_list, devices=device_list)
