"""Tests du découpage en fenêtres et de l'étiquetage des flux (app/cicflowmeter.py)."""

import struct

import pytest

from app.cicflowmeter import label_cic_csv, split_pcap


def _pcap(timestamps):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = b""
    for ts in timestamps:
        frame = b"\x00" * 60
        records += struct.pack("<IIII", int(ts), int((ts - int(ts)) * 1e6), len(frame), len(frame)) + frame
    return header + records


def _count(pcap):
    return (len(pcap) - 24) // (16 + 60)


def test_split_pcap_in_time_windows():
    pcap = _pcap([1000.0, 1000.02, 1000.04, 1001.0, 1001.01])
    windows = split_pcap(pcap, 0.5)
    assert [_count(w) for w in windows] == [3, 2]  # aucun paquet perdu
    assert len(split_pcap(pcap, 5)) == 1


def test_split_pcap_rejects_invalid():
    with pytest.raises(ValueError):
        split_pcap(b"pas un pcap", 5)


def test_label_only_flows_from_source_to_target():
    csv_text = "Src IP,Dst IP,Timestamp,Label\n10.0.0.2,10.0.0.9,t,x\n10.0.0.2,10.0.0.50,t,x\n10.0.0.9,10.0.0.2,t,x\n"
    _, counts, total = label_cic_csv(csv_text, "10.0.0.2", "10.0.0.9", "ip", "port-scan")
    assert counts == {"port-scan": 1, "BENIGN": 2} and total == 3
