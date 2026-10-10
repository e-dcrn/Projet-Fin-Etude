"""
Schéma de la topologie envoyée par l'interface (format version 2).

{
  "version": 2,
  "nodes":    [{ "id", "type", "name", "position", "config": {...} }],
  "networks": [{ "id", "name", "position", "vlan", "subnet" }],  # les switches
  "links":    [{ "id", "node", "network", "interface", "port", "ip", "mask" }]
}

Ce module ne vérifie que la forme ; la cohérence réseau (sous-réseaux,
passerelles, routes…) est vérifiée par planner.py.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field
from typing_extensions import Literal

# Identifiants techniques générés par l'interface (pc-1, switch-2…)
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"


class Position(BaseModel):
    x: float = 0
    y: float = 0


class Route(BaseModel):
    destination: str = ""
    gateway: str = ""
    interface: str = ""


class Service(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    name: str = ""


class NodeConfig(BaseModel):
    gateway: str = ""  # pc, server
    services: List[Service] = []  # server
    routes: List[Route] = []  # router
    monitoredSegment: str = ""  # ids : id du réseau surveillé


class Node(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    type: Literal["pc", "server", "router", "ids"]
    name: str
    position: Optional[Position] = None
    config: NodeConfig = NodeConfig()


class Network(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    name: str
    position: Optional[Position] = None
    vlan: Optional[int] = Field(default=None, ge=1, le=4094)
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
    version: int = 2
    nodes: List[Node] = []
    networks: List[Network] = []
    links: List[Link] = []
