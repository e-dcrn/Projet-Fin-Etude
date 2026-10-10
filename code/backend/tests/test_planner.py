import pytest

from app.models import Topology
from app.planner import TopologyError, build_plan


def topo(nodes=(), networks=(), links=()):
    return Topology.model_validate({"version": 2, "nodes": list(nodes), "networks": list(networks), "links": list(links)})


def node(id, type, name=None, **config):
    return {"id": id, "type": type, "name": name or id.upper(), "config": config}


def net(id, name=None, vlan=None):
    return {"id": id, "name": name or id.upper(), "vlan": vlan}


def link(node_id, net_id, iface, ip="", mask="255.255.255.0"):
    return {"id": f"{node_id}-{net_id}", "node": node_id, "network": net_id, "interface": iface, "ip": ip, "mask": mask}


def two_lans():
    return topo(
        nodes=[
            node("pc-1", "pc", gateway="10.0.1.1"),
            node("server-1", "server", gateway="10.0.2.1", services=[{"port": 80, "name": "http"}]),
            node("router-1", "router", routes=[{"destination": "10.0.3.0/24", "gateway": "10.0.2.254", "interface": "eth1"}]),
            node("ids-1", "ids", monitoredSegment="switch-1"),
        ],
        networks=[net("switch-1"), net("switch-2")],
        links=[
            link("pc-1", "switch-1", "eth0", "10.0.1.10"),
            link("router-1", "switch-2", "eth1", "10.0.2.1", "/24"),
            link("router-1", "switch-1", "eth0", "10.0.1.1", "24"),
            link("server-1", "switch-2", "eth0", "10.0.2.20"),
            link("ids-1", "switch-1", "eth0"),
        ],
    )


def test_valid_plan():
    plan = build_plan(two_lans())
    nets = {n.id: n for n in plan.networks}
    assert str(nets["switch-1"].subnet) == "10.0.1.0/24"
    assert nets["switch-1"].reserved_address == "10.0.1.254"
    devices = {d.id: d for d in plan.devices}
    assert [ep.interface for ep in devices["router-1"].endpoints] == ["eth0", "eth1"]
    assert devices["router-1"].routes[0].command() == "ip route replace 10.0.3.0/24 via 10.0.2.254 dev eth1"
    assert devices["pc-1"].routes[0].command() == "ip route replace default via 10.0.1.1"
    assert devices["ids-1"].monitored_network == "switch-1"
    assert plan.devices[-1].type == "ids"


def test_reserved_address_skips_used():
    t = two_lans()
    t.links[0].ip = "10.0.1.254"
    plan = build_plan(t)
    assert next(n for n in plan.networks if n.id == "switch-1").reserved_address == "10.0.1.253"


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda t: setattr(t.links[0], "ip", "10.0.9.10"), "même sous-réseau"),
        (lambda t: setattr(t.links[0], "ip", "10.0.1.1"), "à la fois"),
        (lambda t: setattr(t.links[0], "ip", ""), "IP manquante"),
        (lambda t: setattr(t.links[0], "mask", "255.0.255.0"), "masque"),
        (lambda t: setattr(t.links[0], "ip", "10.0.1.255"), "diffusion"),
        (lambda t: setattr(t.nodes[0].config, "gateway", "10.0.2.1"), "n'appartient à aucun réseau"),
        (lambda t: setattr(t.nodes[2].config.routes[0], "interface", "eth7"), "n'existe pas"),
        (lambda t: setattr(t.nodes[2].config.routes[0], "gateway", "192.168.0.1"), "joignable"),
        (lambda t: setattr(t.nodes[0], "name", "ROUTER-1"), "plusieurs équipements"),
        (lambda t: setattr(t.links[1], "interface", "eth0"), "deux fois"),
        (lambda t: setattr(t.nodes[3].config, "monitoredSegment", "switch-2"), "relié par un câble"),
    ],
)
def test_errors(mutate, expected):
    t = two_lans()
    mutate(t)
    with pytest.raises(TopologyError) as exc:
        build_plan(t)
    assert any(expected in e for e in exc.value.errors), exc.value.errors


def test_overlapping_networks():
    t = two_lans()
    t.links[1].ip, t.links[1].mask = "10.0.0.1", "255.255.0.0"
    t.links[3].ip, t.links[3].mask = "10.0.0.20", "255.255.0.0"
    t.nodes[1].config.gateway = "10.0.0.1"
    t.nodes[2].config.routes = []
    with pytest.raises(TopologyError) as exc:
        build_plan(t)
    assert any("chevauchent" in e for e in exc.value.errors)


def test_full_subnet():
    t = topo(
        nodes=[node("router-1", "router"), node("router-2", "router")],
        networks=[net("switch-1")],
        links=[link("router-1", "switch-1", "eth0", "10.9.0.1", "/30"), link("router-2", "switch-1", "eth0", "10.9.0.2", "/30")],
    )
    with pytest.raises(TopologyError) as exc:
        build_plan(t)
    assert any("plein" in e for e in exc.value.errors)


def declared(t, **subnets):
    for n in t.networks:
        n.subnet = subnets.get(n.id.replace("-", "_"), n.subnet)
    return t


def test_declared_subnet():
    t = declared(two_lans(), switch_1="10.0.1.0/24", switch_2="10.0.2.0/24")
    nets = {n.id: n for n in build_plan(t).networks}
    assert str(nets["switch-1"].subnet) == "10.0.1.0/24"
    assert nets["switch-1"].reserved_address == "10.0.1.254"


def test_declared_subnet_without_addresses():
    t = topo(nodes=[node("ids-1", "ids", monitoredSegment="switch-1")], networks=[net("switch-1")], links=[link("ids-1", "switch-1", "eth0")])
    t.networks[0].subnet = "10.0.7.0/24"
    nets = {n.id: n for n in build_plan(t).networks}
    assert str(nets["switch-1"].subnet) == "10.0.7.0/24"


@pytest.mark.parametrize(
    "subnet, expected",
    [("10.0.1.5/24", "réseau invalide"), ("bad", "réseau invalide"), ("10.0.1.0/31", "trop petit"), ("10.0.0.0/16", "n'appartient pas")],
)
def test_declared_subnet_errors(subnet, expected):
    t = declared(two_lans(), switch_1=subnet)
    if expected == "n'appartient pas":
        t.links[0].mask = "255.255.255.0"
    with pytest.raises(TopologyError) as exc:
        build_plan(t)
    assert any(expected in e for e in exc.value.errors), exc.value.errors
