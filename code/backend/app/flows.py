"""
Export de flux étiquetés à partir d'un pcap (étape « CICFlowMeter » du projet).

Un pcap capturé pendant un scénario est découpé en flux bidirectionnels
(5-uplet : protocole + les deux couples IP:port), et chaque flux reçoit des
caractéristiques au format CICFlowMeter (durée, nombre et taille des paquets
dans chaque sens, débits, inter-arrivées, drapeaux TCP…). Chaque flux est
ensuite étiqueté « attaque » ou « BENIGN » selon qu'il a été produit par le
scénario (voir label_flows), afin d'obtenir un jeu de données d'entraînement
pour la sonde IDS, comme les jeux CIC-IDS.

Autonome : seulement la bibliothèque standard (parseur pcap maison). Le choix
d'un exporteur interne, plutôt que du paquet externe CICFlowMeter (Java, ou un
portage Python fragile), garantit un résultat reproductible et testable.
"""

from __future__ import annotations

import csv
import io
import struct
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Dict, List, Tuple

# Boutisme + horodatage selon le nombre magique pcap (voir capture.py).
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
_LINKTYPE_ETHERNET = 1

# Drapeaux TCP (octet 13 de l'en-tête TCP)
_FIN, _SYN, _RST, _PSH, _ACK, _URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@dataclass
class Packet:
    ts: float          # horodatage (secondes)
    src: str           # IP source
    dst: str           # IP destination
    sport: int
    dport: int
    proto: int         # 6 = TCP, 17 = UDP
    length: int        # longueur IP (octets)
    flags: int         # drapeaux TCP (0 pour UDP)


def parse_pcap(data: bytes) -> List[Packet]:
    """Découpe un pcap (lien Ethernet) en paquets IPv4/TCP-UDP. Ignore le reste."""
    if len(data) < 24 or data[:4] not in _PCAP_MAGIC:
        raise ValueError("flux pcap invalide ou vide")
    endian, nanoseconds = _PCAP_MAGIC[data[:4]]
    (linktype,) = struct.unpack_from(endian + "I", data, 20)
    packets: List[Packet] = []
    offset = 24
    while offset + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + incl]
        offset += incl
        if len(frame) < incl:
            break
        ts = sec + (frac / 1e9 if nanoseconds else frac / 1e6)
        pkt = _parse_frame(frame, linktype, ts)
        if pkt is not None:
            packets.append(pkt)
    return packets


def _parse_frame(frame: bytes, linktype: int, ts: float):
    if linktype != _LINKTYPE_ETHERNET or len(frame) < 14:
        return None
    if frame[12:14] != b"\x08\x00":  # EtherType IPv4
        return None
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total_length = struct.unpack_from(">H", ip, 2)[0]
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    sport = dport = flags = 0
    l4 = ip[ihl:]
    if proto == 6 and len(l4) >= 14:       # TCP
        sport, dport = struct.unpack_from(">HH", l4, 0)
        flags = l4[13]
    elif proto == 17 and len(l4) >= 8:     # UDP
        sport, dport = struct.unpack_from(">HH", l4, 0)
    else:
        return None
    return Packet(ts, src, dst, sport, dport, proto, total_length, flags)


@dataclass
class Flow:
    src: str
    sport: int
    dst: str
    dport: int
    proto: int
    fwd: List[Packet] = field(default_factory=list)  # sens initiateur → cible
    bwd: List[Packet] = field(default_factory=list)  # sens retour
    first_ts: float = 0.0
    last_ts: float = 0.0
    label: str = "BENIGN"


def _flow_key(pkt: Packet):
    """Clé canonique d'un flux (indépendante du sens)."""
    a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
    lo, hi = sorted((a, b))
    return (pkt.proto, lo, hi)


def build_flows(packets: List[Packet]) -> List[Flow]:
    """Agrège les paquets en flux bidirectionnels, triés par horodatage de départ."""
    flows: Dict[Tuple, Flow] = {}
    for pkt in sorted(packets, key=lambda p: p.ts):
        key = _flow_key(pkt)
        flow = flows.get(key)
        if flow is None:
            # Le premier paquet donne le sens « aller » (src = initiateur).
            flow = Flow(pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto, first_ts=pkt.ts)
            flows[key] = flow
        forward = (pkt.src, pkt.sport) == (flow.src, flow.sport)
        (flow.fwd if forward else flow.bwd).append(pkt)
        flow.last_ts = pkt.ts
    return sorted(flows.values(), key=lambda f: f.first_ts)


# --------------------------------------------------------------------------- étiquetage

def label_flows(flows: List[Flow], attack_src: str, target: str, needs: str, subcategory: str) -> Dict[str, int]:
    """
    Étiquette chaque flux et renvoie le décompte par étiquette.

    Un flux est « attaque » (sous-catégorie du scénario) s'il a été initié par
    la source du scénario vers la cible : pour un scan de sous-réseau, tout le
    trafic de la source ; pour une cible unique, les flux vers cette IP. Le
    reste (trafic de fond éventuel) est « BENIGN » — même logique que ConCap.
    """
    try:
        net = ip_network(target, strict=False) if needs == "subnet" else None
        target_ip = None if needs == "subnet" else ip_address(target)
    except ValueError:
        net = target_ip = None

    counts: Dict[str, int] = {}
    for flow in flows:
        attack = False
        if flow.src == attack_src:
            if needs == "subnet":
                attack = net is None or ip_address(flow.dst) in net
            else:
                attack = target_ip is not None and ip_address(flow.dst) == target_ip
        flow.label = subcategory if attack else "BENIGN"
        counts[flow.label] = counts.get(flow.label, 0) + 1
    return counts


# --------------------------------------------------------------------------- CSV (format CICFlowMeter)

# Colonnes au nom des caractéristiques CICFlowMeter (sous-ensemble le plus utilisé).
_COLUMNS = [
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "SYN Flag Count", "ACK Flag Count", "RST Flag Count", "FIN Flag Count",
    "PSH Flag Count", "URG Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Label",
]


def _stats(values: List[int]):
    return (max(values), min(values), sum(values) / len(values)) if values else (0, 0, 0.0)


def _iat_mean(packets: List[Packet]) -> float:
    ts = sorted(p.ts for p in packets)
    if len(ts) < 2:
        return 0.0
    gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    return sum(gaps) / len(gaps) * 1e6  # microsecondes, comme CICFlowMeter


def _flow_row(flow: Flow) -> dict:
    proto_name = {6: "TCP", 17: "UDP"}.get(flow.proto, str(flow.proto))
    all_pkts = flow.fwd + flow.bwd
    duration = max(0.0, flow.last_ts - flow.first_ts) * 1e6  # µs
    fwd_lengths = [p.length for p in flow.fwd]
    bwd_lengths = [p.length for p in flow.bwd]
    total_bytes = sum(fwd_lengths) + sum(bwd_lengths)
    n = len(all_pkts)
    count = lambda bit: sum(1 for p in all_pkts if p.flags & bit)
    fwd_max, fwd_min, fwd_mean = _stats(fwd_lengths)
    bwd_max, bwd_min, bwd_mean = _stats(bwd_lengths)
    secs = duration / 1e6 or 1e-6  # évite la division par zéro pour les débits
    return {
        "Flow ID": f"{flow.src}-{flow.dst}-{flow.sport}-{flow.dport}-{flow.proto}",
        "Src IP": flow.src, "Src Port": flow.sport,
        "Dst IP": flow.dst, "Dst Port": flow.dport, "Protocol": proto_name,
        "Timestamp": round(flow.first_ts, 6),
        "Flow Duration": round(duration),
        "Total Fwd Packets": len(flow.fwd), "Total Backward Packets": len(flow.bwd),
        "Total Length of Fwd Packets": sum(fwd_lengths),
        "Total Length of Bwd Packets": sum(bwd_lengths),
        "Fwd Packet Length Max": fwd_max, "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": round(fwd_mean, 2),
        "Bwd Packet Length Max": bwd_max, "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": round(bwd_mean, 2),
        "Flow Bytes/s": round(total_bytes / secs, 2),
        "Flow Packets/s": round(n / secs, 2),
        "Flow IAT Mean": round(_iat_mean(all_pkts), 2),
        "SYN Flag Count": count(_SYN), "ACK Flag Count": count(_ACK),
        "RST Flag Count": count(_RST), "FIN Flag Count": count(_FIN),
        "PSH Flag Count": count(_PSH), "URG Flag Count": count(_URG),
        "Down/Up Ratio": round(len(flow.bwd) / len(flow.fwd), 2) if flow.fwd else 0,
        "Average Packet Size": round(total_bytes / n, 2) if n else 0,
        "Label": flow.label,
    }


def flows_to_csv(flows: List[Flow]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS)
    writer.writeheader()
    for flow in flows:
        writer.writerow(_flow_row(flow))
    return buffer.getvalue()
