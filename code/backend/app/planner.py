"""
Topologie (models.Topology) → plan de déploiement.

Le plan est indépendant de Docker : il décrit des réseaux (avec un
sous-réseau déduit des adresses des interfaces) et des équipements (avec
leurs interfaces, routes et services). deployer.py se charge de l'exécuter.

Toutes les erreurs sont collectées puis levées ensemble (TopologyError),
avec des messages destinés à l'utilisateur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List, Optional

from .models import Service, Topology

TYPE_LABELS = {"pc": "PC", "server": "Serveur", "router": "Routeur", "ids": "Sonde IDS"}
INTERFACE_PATTERN = re.compile(r"^[a-z][a-z0-9]{0,14}$")
MAX_PREFIX = 30  # au-delà, plus d'adresse libre pour le segment lui-même


class TopologyError(Exception):
    def __init__(self, errors: List[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass
class NetworkPlan:
    id: str
    name: str
    vlan: Optional[int]
    subnet: Optional[IPv4Network] = None
    # Adresse réservée au segment lui-même (pont côté hôte), choisie libre
    reserved_address: Optional[str] = None


@dataclass
class EndpointPlan:
    network_id: str
    interface: str
    address: Optional[IPv4Interface]  # None : attribuée automatiquement (sonde IDS)


@dataclass
class RoutePlan:
    destination: IPv4Network
    via: Optional[str] = None
    interface: Optional[str] = None

    def command(self) -> str:
        dest = "default" if self.destination.prefixlen == 0 else str(self.destination)
        cmd = f"ip route replace {dest}"
        if self.via:
            cmd += f" via {self.via}"
        if self.interface:
            cmd += f" dev {self.interface}"
        return cmd


@dataclass
class DevicePlan:
    id: str
    name: str
    type: str
    hostname: str
    endpoints: List[EndpointPlan] = field(default_factory=list)
    routes: List[RoutePlan] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    monitored_network: Optional[str] = None

    @property
    def label(self) -> str:
        return TYPE_LABELS[self.type]


@dataclass
class Plan:
    networks: List[NetworkPlan]
    devices: List[DevicePlan]

    def network(self, network_id: str) -> NetworkPlan:
        return next(n for n in self.networks if n.id == network_id)


# ---------------------------------------------------------------------------
# Utilitaires d'adressage
# ---------------------------------------------------------------------------


def parse_prefix(mask: str) -> Optional[int]:
    """« 255.255.255.0 », « /24 » ou « 24 » → 24 ; None si invalide."""
    mask = mask.strip().lstrip("/")
    if re.fullmatch(r"\d{1,2}", mask):
        prefix = int(mask)
        return prefix if prefix <= 32 else None
    try:
        return IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def parse_address(value: str) -> Optional[IPv4Address]:
    try:
        return IPv4Address(value.strip())
    except ValueError:
        return None


def interface_sort_key(name: str):
    """eth2 < eth10 : tri naturel des noms d'interface."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", name)]


def sanitize_hostname(name: str, fallback: str) -> str:
    host = re.sub(r"[^A-Za-z0-9-]+", "-", name).strip("-")[:63]
    return host or fallback


# ---------------------------------------------------------------------------
# Construction du plan
# ---------------------------------------------------------------------------


def build_plan(topology: Topology) -> Plan:
    errors: List[str] = []
    nodes = {n.id: n for n in topology.nodes}
    networks = {n.id: n for n in topology.networks}

    # --- Noms et identifiants ------------------------------------------------
    seen_ids, seen_names = set(), {}
    for item in [*topology.nodes, *topology.networks]:
        if item.id in seen_ids:
            errors.append(f"Identifiant « {item.id} » en double.")
        seen_ids.add(item.id)
        name = item.name.strip()
        if not name:
            errors.append(f"L'équipement {item.id} n'a pas de nom.")
        elif name in seen_names:
            errors.append(f"Nom « {name} » utilisé par plusieurs équipements.")
        seen_names[name] = item.id

    network_plans = {n.id: NetworkPlan(id=n.id, name=n.name.strip(), vlan=n.vlan) for n in topology.networks}
    declared: Dict[str, IPv4Network] = {}  # réseaux déclarés sur les switches
    for n in topology.networks:
        if not n.subnet.strip():
            continue
        try:
            subnet = IPv4Network(n.subnet.strip(), strict=True)
        except ValueError:
            errors.append(f"{n.name.strip()} : réseau invalide « {n.subnet} » (ex. 10.0.1.0/24).")
            continue
        if subnet.prefixlen > MAX_PREFIX:
            errors.append(f"{n.name.strip()} : réseau {subnet} trop petit (/{MAX_PREFIX} maximum).")
            continue
        declared[n.id] = network_plans[n.id].subnet = subnet
    device_plans = {
        n.id: DevicePlan(
            id=n.id,
            name=n.name.strip(),
            type=n.type,
            hostname=sanitize_hostname(n.name, n.id),
            services=list(n.config.services) if n.type == "server" else [],
        )
        for n in topology.nodes
    }

    # --- Liens / interfaces --------------------------------------------------
    used_addresses: Dict[IPv4Address, str] = {}  # adresse → nom de l'équipement
    linked_pairs = set()
    for link in topology.links:
        node, net = nodes.get(link.node), networks.get(link.network)
        if node is None or net is None:
            errors.append(f"Le câble {link.id} doit relier un équipement à un switch existant.")
            continue
        device = device_plans[node.id]
        where = f"{device.name} ({link.interface or '?'})"

        if (node.id, net.id) in linked_pairs:
            errors.append(f"{device.name} est relié plusieurs fois à {net.name}.")
        linked_pairs.add((node.id, net.id))

        if not INTERFACE_PATTERN.match(link.interface):
            errors.append(f"{device.name} : nom d'interface invalide « {link.interface} » (ex. eth0).")
        elif any(ep.interface == link.interface for ep in device.endpoints):
            errors.append(f"{device.name} : l'interface {link.interface} est utilisée deux fois.")

        address = None
        if link.ip.strip():
            ip = parse_address(link.ip)
            prefix = parse_prefix(link.mask) if link.mask.strip() else None
            if ip is None:
                errors.append(f"{where} : adresse IP invalide « {link.ip} ».")
            elif prefix is None:
                errors.append(f"{where} : masque de sous-réseau invalide ou manquant.")
            elif prefix > MAX_PREFIX:
                errors.append(f"{where} : masque /{prefix} trop restrictif (/{MAX_PREFIX} maximum).")
            else:
                address = IPv4Interface(f"{ip}/{prefix}")
                if ip in (address.network.network_address, address.network.broadcast_address):
                    errors.append(f"{where} : {ip} est l'adresse de réseau ou de diffusion de {address.network}.")
                elif ip in used_addresses:
                    errors.append(f"Adresse {ip} attribuée à la fois à {used_addresses[ip]} et à {device.name}.")
                used_addresses.setdefault(ip, device.name)
        elif node.type != "ids":
            errors.append(f"{where} : adresse IP manquante.")

        device.endpoints.append(EndpointPlan(network_id=net.id, interface=link.interface, address=address))

    # --- Sous-réseau de chaque switch -----------------------------------------
    for net in network_plans.values():
        members = [
            (d, ep) for d in device_plans.values() for ep in d.endpoints if ep.network_id == net.id and ep.address
        ]
        for device, ep in members:
            if net.id in declared:
                if ep.address.network != net.subnet:
                    errors.append(
                        f"{device.name} ({ep.address.with_prefixlen}) n'appartient pas au réseau "
                        f"de {net.name} ({net.subnet})."
                    )
            elif net.subnet is None:
                net.subnet = ep.address.network
                first = f"{device.name} ({ep.address.with_prefixlen})"
            elif ep.address.network != net.subnet:
                errors.append(
                    f"{net.name} : {device.name} ({ep.address.with_prefixlen}) n'est pas dans le même "
                    f"sous-réseau que {first}."
                )
        if net.subnet is not None:
            taken = {ep.address.ip for _, ep in members}
            candidate = net.subnet.broadcast_address - 1
            while candidate in taken and candidate > net.subnet.network_address:
                candidate -= 1
            if candidate <= net.subnet.network_address:
                errors.append(f"{net.name} : le sous-réseau {net.subnet} est plein, élargissez le masque.")
            else:
                net.reserved_address = str(candidate)

    subnets = [n for n in network_plans.values() if n.subnet is not None]
    for i, a in enumerate(subnets):
        for b in subnets[i + 1 :]:
            if a.subnet.overlaps(b.subnet):
                errors.append(f"{a.name} ({a.subnet}) et {b.name} ({b.subnet}) utilisent des plages qui se chevauchent.")

    # --- Configuration propre à chaque type -----------------------------------
    for node in topology.nodes:
        device = device_plans[node.id]
        connected = [network_plans[ep.network_id].subnet for ep in device.endpoints]
        own_ips = {ep.address.ip for ep in device.endpoints if ep.address}

        def reachable(ip: IPv4Address) -> bool:
            return any(s is not None and ip in s for s in connected)

        if node.type in ("pc", "server") and node.config.gateway.strip():
            gw = parse_address(node.config.gateway)
            if gw is None:
                errors.append(f"{device.name} : passerelle invalide « {node.config.gateway} ».")
            elif gw in own_ips:
                errors.append(f"{device.name} : la passerelle ne peut pas être sa propre adresse.")
            elif not reachable(gw):
                errors.append(f"{device.name} : la passerelle {gw} n'appartient à aucun réseau auquel il est relié.")
            else:
                device.routes.append(RoutePlan(destination=IPv4Network("0.0.0.0/0"), via=str(gw)))

        if node.type == "router":
            interfaces = {ep.interface for ep in device.endpoints}
            for i, route in enumerate(node.config.routes, start=1):
                where = f"{device.name}, route n°{i}"
                try:
                    destination = IPv4Network(route.destination.strip(), strict=False)
                except ValueError:
                    errors.append(f"{where} : réseau de destination invalide « {route.destination} » (ex. 10.0.2.0/24).")
                    continue
                via = route.gateway.strip() or None
                dev = route.interface.strip() or None
                if not via and not dev:
                    errors.append(f"{where} : indiquez une passerelle ou une interface de sortie.")
                    continue
                if via:
                    gw = parse_address(via)
                    if gw is None:
                        errors.append(f"{where} : passerelle invalide « {via} ».")
                        continue
                    if not reachable(gw):
                        errors.append(f"{where} : la passerelle {gw} n'est joignable par aucune interface.")
                        continue
                if dev and dev not in interfaces:
                    errors.append(f"{where} : l'interface {dev} n'existe pas (relier le routeur avec un câble).")
                    continue
                device.routes.append(RoutePlan(destination=destination, via=via, interface=dev))

        if node.type == "server":
            seen = set()
            for svc in node.config.services:
                if (svc.port, svc.protocol) in seen:
                    errors.append(f"{device.name} : port {svc.port}/{svc.protocol} déclaré deux fois.")
                seen.add((svc.port, svc.protocol))

        if node.type == "ids" and node.config.monitoredSegment:
            segment = node.config.monitoredSegment
            if segment not in network_plans:
                errors.append(f"{device.name} : le segment surveillé n'existe plus.")
            elif not any(ep.network_id == segment for ep in device.endpoints):
                errors.append(
                    f"{device.name} doit être relié par un câble au switch qu'il surveille "
                    f"({network_plans[segment].name})."
                )
            else:
                device.monitored_network = segment

    if errors:
        raise TopologyError(errors)

    for device in device_plans.values():
        device.endpoints.sort(key=lambda ep: interface_sort_key(ep.interface))

    # Les sondes en dernier : leurs adresses automatiques ne doivent pas
    # prendre la place d'une adresse fixe demandée par un autre équipement.
    devices = sorted(device_plans.values(), key=lambda d: d.type == "ids")
    # Réseaux à plage explicite d'abord, pour que les plages automatiques les évitent.
    nets = sorted(network_plans.values(), key=lambda n: n.subnet is None)
    return Plan(networks=nets, devices=devices)
