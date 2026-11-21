"""
Schéma de la topologie envoyée par l'interface (format version 2).

{
  "version": 2,
  "nodes":    [{ "id", "type", "name", "position", "config": {...} }],
  "networks": [{ "id", "name", "position", "subnet" }],  # les switches
  "links":    [{ "id", "node", "network", "interface", "port", "ip", "mask" }]
}

`version` et `position` servent à l'interface (recharger un fichier) : le
serveur les ignore. Ce module ne vérifie que la forme ; la cohérence réseau (sous-réseaux,
passerelles, routes…) est vérifiée par planner.py.
"""

from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel, Field, computed_field
from typing_extensions import Literal

# Identifiants techniques générés par l'interface (pc-1, switch-2…)
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"


class Route(BaseModel):
    destination: str = ""
    gateway: str = ""
    interface: str = ""


# Services réellement exécutés par les serveurs (voir service_listener.py). Le type
# d'un service est son nom ; un autre nom donne un port simplement ouvert (simulé).
SERVICE_KINDS = ("http", "https", "ssh", "ftp", "telnet", "smtp", "dns", "mysql")


def dns_name(name: str) -> str:
    """Nom DNS d'un équipement dans le domaine « lab » : « Serveur Web » → « serveur-web »."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


class Service(BaseModel):
    port: int  # 1–65535, vérifié par l'interface (validators.js)
    protocol: Literal["tcp", "udp"] = "tcp"
    name: str = ""

    @computed_field
    @property
    def kind(self) -> Optional[str]:
        """Service réel correspondant (« http »…), ou None pour un port simulé."""
        name = self.name.strip().lower()
        return name if name in SERVICE_KINDS else None


class NodeConfig(BaseModel):
    gateway: str = ""  # pc, server
    services: List[Service] = []  # server
    routes: List[Route] = []  # router
    monitoredSegment: str = ""  # ids : id du réseau surveillé


class Node(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    type: Literal["pc", "server", "router", "ids"]
    name: str
    config: NodeConfig = NodeConfig()


class Network(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    name: str
    # Réseau du switch (« 10.0.1.0/24 »), attribué par l'IPAM de l'interface.
    # Vide : déduit des adresses des interfaces reliées.
    subnet: str = ""


class Link(BaseModel):
    id: str
    node: str
    network: str
    interface: str  # interface de l'équipement (eth0…)
    port: str = ""  # port du switch (Fa0/1…), informatif
    ip: str = ""
    mask: str = ""


class Topology(BaseModel):
    nodes: List[Node] = []
    networks: List[Network] = []
    links: List[Link] = []
