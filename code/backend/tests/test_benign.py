"""
Trafic bénin : construction des sessions possibles de l'agent.

Les sessions elles-mêmes (vrais clients contre vrais services) ont besoin de
Docker : elles se vérifient dans le lab, pas ici.
"""

from app import traffic_agent as agent

TARGETS = [
    {"ip": "10.0.1.10", "server": True},
    {"ip": "10.0.1.12", "server": False},
]


def test_a_server_offers_http_ssh_ftp_and_every_machine_answers_ping():
    assert sorted(agent.build_actions(TARGETS, ["icmp", "http", "ssh", "ftp"])) == [
        ("ftp", "10.0.1.10"), ("http", "10.0.1.10"), ("icmp", "10.0.1.10"), ("icmp", "10.0.1.12"),
        ("ssh", "10.0.1.10")]


def test_only_the_checked_kinds_are_played():
    assert agent.build_actions(TARGETS, ["ssh"]) == [("ssh", "10.0.1.10")]
    assert agent.build_actions(TARGETS, []) == []


def test_web_weighs_more_than_other_sessions():
    assert agent.WEIGHTS["http"] == max(agent.WEIGHTS.values())
