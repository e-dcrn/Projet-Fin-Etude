"""Tests de l'exporteur de flux étiquetés (app/flows.py)."""

import struct

from app.flows import build_flows, flows_to_csv, label_flows, parse_pcap


def _tcp_packet(ts, src, dst, sport, dport, flags, payload=b""):
    """Construit une trame Ethernet/IPv4/TCP minimale pour un enregistrement pcap."""
    def ip_bytes(ip):
        return bytes(int(p) for p in ip.split("."))

    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 0, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + ip_bytes(src) + ip_bytes(dst)
    frame = b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def _pcap(records):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # lien Ethernet
    return header + b"".join(records)


def _scan_pcap():
    # Un scan : 10.0.0.2 -> 10.0.0.9 sur 5 ports (SYN/RST) + un flux bénin vers un autre hôte.
    records = []
    t = 1000.0
    for i, port in enumerate(range(20, 25)):
        records.append(_tcp_packet(t + i * 0.01, "10.0.0.2", "10.0.0.9", 40000 + i, port, 0x02))
        records.append(_tcp_packet(t + i * 0.01 + 0.001, "10.0.0.9", "10.0.0.2", port, 40000 + i, 0x14))
    records.append(_tcp_packet(t + 1, "10.0.0.2", "10.0.0.50", 55000, 80, 0x02, b"GET /"))
    records.append(_tcp_packet(t + 1.01, "10.0.0.50", "10.0.0.2", 80, 55000, 0x12))
    return _pcap(records)


def test_parse_and_build_flows():
    packets = parse_pcap(_scan_pcap())
    assert len(packets) == 12
    flows = build_flows(packets)
    # 5 flux de scan (un par port) + 1 flux bénin
    assert len(flows) == 6
    # Chaque flux a bien deux sens agrégés
    scan = [f for f in flows if f.dst == "10.0.0.9"]
    assert len(scan) == 5
    assert all(len(f.fwd) == 1 and len(f.bwd) == 1 for f in scan)


def test_label_flows_separates_attack_from_benign():
    flows = build_flows(parse_pcap(_scan_pcap()))
    counts = label_flows(flows, attack_src="10.0.0.2", target="10.0.0.9", needs="ip", subcategory="port-scan")
    assert counts == {"port-scan": 5, "BENIGN": 1}
    # Le trafic vers une autre IP reste bénin
    benign = [f for f in flows if f.dst == "10.0.0.50"]
    assert benign and benign[0].label == "BENIGN"


def test_label_flows_subnet_scope():
    flows = build_flows(parse_pcap(_scan_pcap()))
    counts = label_flows(flows, attack_src="10.0.0.2", target="10.0.0.0/24", needs="subnet", subcategory="ping-sweep")
    # En mode sous-réseau, tout le trafic de la source dans la plage est l'attaque
    assert counts.get("ping-sweep") == 6


def test_csv_has_cic_columns_and_labels():
    flows = build_flows(parse_pcap(_scan_pcap()))
    label_flows(flows, attack_src="10.0.0.2", target="10.0.0.9", needs="ip", subcategory="port-scan")
    csv_text = flows_to_csv(flows)
    header = csv_text.splitlines()[0]
    for column in ("Src IP", "Dst Port", "Flow Duration", "SYN Flag Count", "Label"):
        assert column in header
    assert "port-scan" in csv_text and "BENIGN" in csv_text


def test_parse_pcap_rejects_invalid():
    import pytest

    with pytest.raises(ValueError):
        parse_pcap(b"not a pcap")
