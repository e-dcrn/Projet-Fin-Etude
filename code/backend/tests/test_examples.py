"""
Topologies d'exemple (examples/topologies/*.json) : chacune doit être acceptée
par le planificateur et, une fois instanciée, permettre à toute machine
adressée d'en joindre toute autre (aller ET retour, comme un ping).

Le routage est simulé à partir du plan : réseaux directement connectés, puis
routes (plus long préfixe d'abord), seuls les routeurs relayant les paquets.
"""

import json
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from app.models import Topology
from app.planner import build_plan

EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples" / "topologies"
EXAMPLES = sorted(EXAMPLES_DIR.glob("*.json"))
MAX_HOPS = 16


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_examples_exist():
    assert EXAMPLES, f"aucune topologie d'exemple dans {EXAMPLES_DIR}"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_example_metadata(path):
    meta = load(path)["example"]
    assert meta["name"] and meta["description"]
    assert meta["difficulty"] in ("débutant", "intermédiaire", "avancé")


class Router:
    """Acheminement d'un paquet IP à travers les équipements d'un plan."""

    def __init__(self, plan):
        self.devices = {d.id: d for d in plan.devices}
        self.subnets = {n.id: n.subnet for n in plan.networks}
        # adresse → (équipement, réseau) : à qui le switch remet une trame
        self.owner = {
            ep.address.ip: (d.id, ep.network_id) for d in plan.devices for ep in d.endpoints if ep.address
        }

    def next_hop(self, device_id, dst):
        """(équipement suivant, ou None si le paquet est perdu) depuis device_id vers dst."""
        device = self.devices[device_id]
        for ep in device.endpoints:
            if ep.address and dst in ep.address.network:  # réseau directement connecté
                owner = self.owner.get(dst)
                return owner[0] if owner and owner[1] == ep.network_id else None
        routes = sorted(device.routes, key=lambda r: r.destination.prefixlen, reverse=True)
        route = next((r for r in routes if dst in r.destination), None)
        if route is None or route.via is None:
            return None
        owner = self.owner.get(IPv4Address(route.via))
        on_link = any(ep.address and owner and ep.network_id == owner[1] for ep in device.endpoints)
        return owner[0] if on_link else None

    def path(self, src_id, dst):
        """Équipements traversés de src_id jusqu'au propriétaire de dst (AssertionError sinon)."""
        hops, current = [src_id], src_id
        while self.owner[dst][0] != current:
            nxt = self.next_hop(current, dst)
            assert nxt is not None, f"{' → '.join(hops)} : pas de route vers {dst}"
            assert len(hops) < MAX_HOPS, f"boucle de routage vers {dst} : {' → '.join(hops)}"
            if nxt != self.owner[dst][0]:
                assert self.devices[nxt].type == "router", f"{nxt} ne relaie pas les paquets (vers {dst})"
            hops.append(nxt)
            current = nxt
        return hops


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_example_full_reachability(path):
    plan = build_plan(Topology.model_validate(load(path)))  # lève TopologyError si incohérent
    router = Router(plan)
    hosts = [d for d in plan.devices if d.type in ("pc", "server")]

    for src in hosts:
        src_ip = next(ep.address.ip for ep in src.endpoints if ep.address)
        for dst_ip, (dst_id, _) in router.owner.items():
            if dst_id == src.id:
                continue
            router.path(src.id, dst_ip)  # aller
            router.path(dst_id, src_ip)  # retour (la réponse au ping)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_example_ids_watches_a_linked_segment(path):
    plan = build_plan(Topology.model_validate(load(path)))
    for ids in (d for d in plan.devices if d.type == "ids"):
        assert ids.monitored_network in {ep.network_id for ep in ids.endpoints}
