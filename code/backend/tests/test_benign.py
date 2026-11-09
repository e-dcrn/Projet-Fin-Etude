"""
Trafic bénin et services des serveurs : correspondance nom/port → service réel,
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


@pytest.mark.parametrize("name,port,expected", [
    ("http", 80, "http"), ("https", 443, "https"), ("HTTP", 8000, "http"), ("http-alt", 8080, "http"),
    ("ssh", 2222, "ssh"), ("ftp", 21, "ftp"), ("telnet", 23, "telnet"), ("smtp", 25, "smtp"),
    ("dns", 53, "dns"), ("mysql", 3306, "mysql"),
    ("", 22, "ssh"), ("", 443, "https"),   # sans nom : port usuel
    ("pop3", 110, None),                    # nom inconnu : simulateur
])
def test_service_kind_is_shared_by_server_and_client(name, port, expected):
    assert listener.service_kind(name, port, "tcp") == expected
    assert agent.service_kind({"name": name, "port": port}) == expected


def test_every_known_service_has_a_real_implementation():
    assert set(listener.REAL_SERVICES) == {"http", "https", "ssh", "ftp", "telnet", "smtp", "dns", "mysql"}


def test_host_slug_matches_between_dns_server_and_client():
    for name in ("Serveur-Web", "PC 1", "Serveur_Fichiers", "IDS-1"):
        assert listener.host_slug(name) == agent.host_slug(name)
    assert agent.host_slug("Serveur Web (DMZ)") == "serveur-web-dmz"


TARGETS = [
    {"ip": "10.0.20.10", "name": "Serveur-Web", "services": [
        {"port": 80, "protocol": "tcp", "name": "http"},
        {"port": 443, "protocol": "tcp", "name": "https"},
        {"port": 3306, "protocol": "tcp", "name": "mysql"},
    ]},
    {"ip": "10.0.20.11", "name": "Serveur-Fichiers", "services": [
        {"port": 22, "protocol": "tcp", "name": "ssh"},
        {"port": 53, "protocol": "udp", "name": "dns"},
    ]},
    {"ip": "10.0.10.11", "name": "PC-2", "services": []},
]


def labels(actions):
    return sorted(label for _, label, _, _, _ in actions)


def test_actions_follow_the_checked_kinds():
    assert labels(agent.build_actions(TARGETS, {"web"}, "pc-1")) == [
        "http 10.0.20.10:80", "https 10.0.20.10:443"]
    assert labels(agent.build_actions(TARGETS, {"service"}, "pc-1")) == [
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
    targets = [{"ip": "10.0.0.5", "name": "S", "services": [{"port": 110, "protocol": "tcp", "name": "pop3"}]}]
    assert labels(agent.build_actions(targets, {"tcp"}, "pc")) == ["tcp 10.0.0.5:110"]
    assert agent.build_actions(targets, {"http"}, "pc") == []


def test_web_weighs_more_than_other_sessions():
    weights = {label.split()[0]: w for w, label, _, _, _ in agent.build_actions(TARGETS, {"web", "service"}, "pc")}
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
