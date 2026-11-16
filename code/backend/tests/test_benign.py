"""
Trafic bénin et services des serveurs : type d'un service, nom DNS,
construction des sessions possibles de l'agent, requête DNS.

Les sessions elles-mêmes (vrais clients contre vrais démons) ont besoin de
Docker : elles se vérifient dans le lab, pas ici.
"""

import socket
import struct
import threading

import pytest

from app import service_listener as listener
from app import traffic_agent as agent
from app.models import SERVICE_KINDS, Service, dns_name


@pytest.mark.parametrize("name,expected", [
    ("http", "http"), ("HTTP", "http"), (" ssh ", "ssh"), ("mysql", "mysql"), ("dns", "dns"),
    ("pop3", None), ("", None),  # nom inconnu ou absent : port simulé
])
def test_service_kind_is_its_name(name, expected):
    assert Service(port=1234, name=name).kind == expected


def test_every_service_kind_has_a_real_implementation():
    assert set(listener.REAL_SERVICES) == set(SERVICE_KINDS)


def test_dns_name():
    assert dns_name("Serveur Web (DMZ)") == "serveur-web-dmz"
    assert dns_name("PC_1") == "pc-1"


TARGETS = [
    {"ip": "10.0.20.10", "host": "serveur-web", "services": [
        {"port": 80, "protocol": "tcp", "kind": "http"},
        {"port": 443, "protocol": "tcp", "kind": "https"},
        {"port": 3306, "protocol": "tcp", "kind": "mysql"},
    ]},
    {"ip": "10.0.20.11", "host": "serveur-fichiers", "services": [
        {"port": 22, "protocol": "tcp", "kind": "ssh"},
        {"port": 53, "protocol": "udp", "kind": "dns"},
    ]},
    {"ip": "10.0.10.11", "host": "pc-2", "services": []},
]


def labels(actions):
    return sorted(label for _, label, _, _, _ in actions)


def test_actions_follow_the_checked_kinds():
    assert labels(agent.build_actions(TARGETS, {"http", "https"}, "pc-1")) == [
        "http 10.0.20.10:80", "https 10.0.20.10:443"]
    assert labels(agent.build_actions(TARGETS, {"ssh", "mysql", "dns"}, "pc-1")) == [
        "mysql 10.0.20.10:3306", "ssh 10.0.20.11:22"]  # le DNS n'est pas une session à part
    assert labels(agent.build_actions(TARGETS, {"icmp"}, "pc-1")) == [
        "ping 10.0.10.11", "ping 10.0.20.10", "ping 10.0.20.11"]


def test_one_kind_per_service_only_reaches_that_service():
    assert labels(agent.build_actions(TARGETS, {"http"}, "pc-1")) == ["http 10.0.20.10:80"]
    assert labels(agent.build_actions(TARGETS, {"ssh", "mysql"}, "pc-1")) == [
        "mysql 10.0.20.10:3306", "ssh 10.0.20.11:22"]
    # un type coché sans service ouvert correspondant ne produit rien
    assert agent.build_actions(TARGETS, {"ftp"}, "pc-1") == []


def test_unknown_tcp_ports_are_the_tcp_kind():
    targets = [{"ip": "10.0.0.5", "host": "s", "services": [{"port": 110, "protocol": "tcp", "kind": None}]}]
    assert labels(agent.build_actions(targets, {"tcp"}, "pc")) == ["tcp 10.0.0.5:110"]
    assert agent.build_actions(targets, {"http"}, "pc") == []


def test_web_weighs_more_than_other_sessions():
    weights = {label.split()[0]: w for w, label, _, _, _ in agent.build_actions(TARGETS, {"http", "https", "ssh", "mysql"}, "pc")}
    assert weights["http"] > weights["ssh"] and weights["https"] > weights["mysql"]


def test_dns_servers_are_found_among_targets():
    assert agent.dns_servers(TARGETS) == [("10.0.20.11", 53)]


def test_dns_query_sends_a_valid_question_and_reads_the_rcode():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    received = {}

    def answer():
        data, addr = srv.recvfrom(512)
        received["data"] = data
        qid, flags = struct.unpack(">HH", data[:4])
        srv.sendto(struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0) + data[12:], addr)  # NXDOMAIN

    t = threading.Thread(target=answer)
    t.start()
    rcode = agent.dns_query("127.0.0.1", port, "inconnu.lab")
    t.join()
    srv.close()
    assert rcode == 3
    assert b"\x07inconnu\x03lab\x00" in received["data"]
