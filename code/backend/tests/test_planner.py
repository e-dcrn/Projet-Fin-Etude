from app.models import Topology
from app.planner import build_plan


def topo(nodes=(), networks=(), links=()):
    return Topology.model_validate({"version": 2, "nodes": list(nodes), "networks": list(networks), "links": list(links)})


def node(id, type, name=None, **config):
    return {"id": id, "type": type, "name": name or id.upper(), "config": config}


def net(id, name=None):
    return {"id": id, "name": name or id.upper()}


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


def test_declared_subnet():
    t = two_lans()
    t.networks[0].subnet = "10.0.1.0/24"
    nets = {n.id: n for n in build_plan(t).networks}
    assert str(nets["switch-1"].subnet) == "10.0.1.0/24"
    assert nets["switch-1"].reserved_address == "10.0.1.254"


def test_declared_subnet_without_addresses():
    t = topo(nodes=[node("ids-1", "ids", monitoredSegment="switch-1")], networks=[net("switch-1")], links=[link("ids-1", "switch-1", "eth0")])
    t.networks[0].subnet = "10.0.7.0/24"
    nets = {n.id: n for n in build_plan(t).networks}
    assert str(nets["switch-1"].subnet) == "10.0.7.0/24"


def test_hostname_and_masks():
    devices = {d.id: d for d in build_plan(two_lans()).devices}
    router = devices["router-1"]
    assert [str(ep.address) for ep in router.endpoints] == ["10.0.1.1/24", "10.0.2.1/24"]  # masques « 24 » et « /24 »
    t = two_lans()
    t.nodes[0].name = "Poste de Paul"
    assert build_plan(t).devices[0].hostname == "Poste-de-Paul"
