"""
Extraction des flux : les mêmes colonnes que les jeux CIC-IDS (CIC-IDS2017/2018),
grâce à l'image CICFlowMeter conteneurisée de ConCap
(ghcr.io/idlab-discover/concap/cicflowmeter). Un pcap est découpé en fenêtres de
FLOW_WINDOW_SEC secondes, comme le fait la détection en direct, et chaque fenêtre
est convertie en flux.

Détails d'exécution (validés) :
  - le pcap est injecté dans /tmp du conteneur (put_archive), pas monté : un
    volume monté fait échouer le contrôle « out folder » de CICFlowMeter sous
    émulation ;
  - CICFlowMeter écrit dans un dossier INTERNE au conteneur, puis on récupère le
    CSV sur la sortie standard (cat) ;
  - le dossier de sortie ne doit PAS avoir de slash final (bug de l'outil).
"""

from __future__ import annotations

import csv
import io
import logging
import os
import struct
import tarfile
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Callable, Dict, List, Optional, Tuple

from docker.errors import DockerException

log = logging.getLogger(__name__)

# Image CICFlowMeter de ConCap (surchargeable). Contient l'outil `cfm`.
CFM_IMAGE = os.environ.get(
    "IDSLAB_CICFLOWMETER_IMAGE",
    "ghcr.io/idlab-discover/concap/cicflowmeter:tools-1.0.0",
)

# Durée des fenêtres d'analyse (secondes) : la détection en direct classe le trafic
# fenêtre par fenêtre, et les datasets sont découpés de la même façon (voir
# windowed_flows_csv). Un flux plus long qu'une fenêtre est vu en morceaux.
FLOW_WINDOW_SEC = 5

# Boutisme + horodatage selon le nombre magique pcap (voir capture.py).
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}

# pcap injecté dans /tmp/dump.pcap ; sortie vers un dossier interne ; CSV sur stdout.
_CMD = "mkdir -p /out && /CICFlowMeter/bin/cfm /tmp/dump.pcap /out >/dev/null 2>&1 && cat /out/*_Flow.csv"


def _tar_bytes(name: str, data: bytes) -> bytes:
    """Archive tar à un seul fichier (pour put_archive)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FlowMeterWorker:
    """
    Conteneur CICFlowMeter permanent, pour convertir une suite de petits pcap
    (détection en direct, voir detection.py) sans payer à chaque fois le
    démarrage d'un conteneur : ~1,5 s par fenêtre au lieu de plusieurs secondes.
    Il porte le label du lab : l'arrêt du réseau le supprime aussi.
    """

    def __init__(self, lab, role: str = "flowmeter"):
        client = lab.client
        try:
            client.images.get(CFM_IMAGE)
        except DockerException:
            log.info("Téléchargement de l'image CICFlowMeter %s…", CFM_IMAGE)
            client.images.pull(CFM_IMAGE)
        prefix = lab.settings.prefix
        self.container = client.containers.run(
            CFM_IMAGE, entrypoint=["sh", "-c"], command=["sleep infinity"], detach=True,
            labels={lab.label: "true", f"{prefix}.role": role},
        )

    def convert(self, pcap_bytes: bytes) -> str:
        """pcap → CSV de flux CICFlowMeter (brut, colonne Label vide) ; "" si aucun flux."""
        self.container.put_archive("/tmp", _tar_bytes("dump.pcap", pcap_bytes))
        result = self.container.exec_run(["sh", "-c", "rm -rf /out && " + _CMD])
        text = result.output.decode(errors="replace")
        lines = text.splitlines()
        # Fenêtre sans flux exploitable (que de l'ARP…) : CICFlowMeter n'écrit pas de CSV.
        return text if lines and "Src IP" in lines[0] else ""

    def close(self) -> None:
        try:
            self.container.remove(force=True)
        except DockerException:
            pass


def split_pcap(data: bytes, window: float) -> List[bytes]:
    """
    Découpe un pcap en pcap successifs de `window` secondes (fenêtres consécutives,
    à partir du premier paquet ; une fenêtre sans paquet est omise). C'est le
    découpage que subit le trafic en détection en direct : appliqué aussi aux
    datasets, il garantit que le modèle apprend sur des flux préparés exactement
    comme ceux qu'il classera.
    """
    if len(data) < 24 or data[:4] not in _PCAP_MAGIC:
        raise ValueError("flux pcap invalide ou vide")
    endian, nanoseconds = _PCAP_MAGIC[data[:4]]
    header = data[:24]
    windows: Dict[int, List[bytes]] = {}
    first = None
    offset = 24
    while offset + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", data, offset)
        record = data[offset:offset + 16 + incl]
        offset += 16 + incl
        if len(record) < 16 + incl:
            break
        ts = sec + (frac / 1e9 if nanoseconds else frac / 1e6)
        first = ts if first is None else first
        windows.setdefault(int((ts - first) // window), []).append(record)
    return [header + b"".join(windows[k]) for k in sorted(windows)]


def windowed_flows_csv(lab, pcap_bytes: bytes, window: float = FLOW_WINDOW_SEC) -> str:
    """
    pcap → CSV CICFlowMeter, fenêtre par fenêtre (comme en détection en direct) :
    les CSV des fenêtres sont mis bout à bout sous un seul en-tête.
    """
    worker = FlowMeterWorker(lab, role="dflowmeter")
    header, rows = None, []
    try:
        for chunk in split_pcap(pcap_bytes, window):
            lines = worker.convert(chunk).splitlines()
            if not lines:
                continue
            header = header or lines[0]
            rows.extend(line for line in lines[1:] if line.strip())
    finally:
        worker.close()
    if header is None:
        raise RuntimeError("CICFlowMeter n'a produit aucun flux")
    return "\n".join([header, *rows]) + "\n"


def _is_attack(src: str, dst: str, attack_src: str, target: str, needs: str, net, target_ip) -> bool:
    """Le flux va-t-il de la source de l'attaque vers sa cible ?"""
    if src != attack_src:
        return False
    try:
        if needs == "subnet":
            return net is None or ip_address(dst) in net
        return target_ip is not None and ip_address(dst) == target_ip
    except ValueError:
        return False


def relabel_csv(csv_text: str, label_of: Callable[[str, str, str], str]) -> Tuple[str, Dict[str, int], int]:
    """
    Remplit la colonne Label de chaque flux et renvoie (CSV, décompte, total).
    `label_of(src, dst, timestamp)` donne l'étiquette d'un flux (Timestamp brut
    de CICFlowMeter, voir parse_timestamp).
    """
    rows = list(csv.reader(io.StringIO(csv_text)))
    header = rows[0]
    index = {name: i for i, name in enumerate(header)}
    src_i, dst_i, ts_i = index.get("Src IP"), index.get("Dst IP"), index.get("Timestamp")
    label_i = index.get("Label")

    def cell(row, i):
        return row[i] if i is not None and i < len(row) else ""

    counts: Dict[str, int] = {}
    out = [header]
    for row in rows[1:]:
        if not row:
            continue
        label = label_of(cell(row, src_i), cell(row, dst_i), cell(row, ts_i))
        if label_i is not None and label_i < len(row):
            row[label_i] = label
        else:
            row.append(label)
        counts[label] = counts.get(label, 0) + 1
        out.append(row)

    buffer = io.StringIO()
    csv.writer(buffer).writerows(out)
    return buffer.getvalue(), counts, len(out) - 1


def parse_timestamp(value: str) -> Optional[float]:
    """Timestamp CICFlowMeter (« 2026-10-30 09:42:50.291252 », en UTC) → secondes epoch."""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def label_cic_csv(csv_text: str, attack_src: str, target: str, needs: str, subcategory: str) -> Tuple[str, Dict[str, int], int]:
    """Étiquette un CSV de scénario : attaque = de la source vers la cible, le reste BENIGN."""
    try:
        net = ip_network(target, strict=False) if needs == "subnet" else None
        target_ip = None if needs == "subnet" else ip_address(target)
    except ValueError:
        net = target_ip = None

    def label_of(src: str, dst: str, _ts: str) -> str:
        return subcategory if _is_attack(src, dst, attack_src, target, needs, net, target_ip) else "BENIGN"

    return relabel_csv(csv_text, label_of)


def pcap_to_labeled_csv(lab, pcap_bytes: bytes, attack_src: str, target: str, needs: str, subcategory: str) -> Tuple[str, Dict[str, int], int]:
    """pcap → CSV CICFlowMeter étiqueté. Lève si l'outil n'est pas disponible."""
    return label_cic_csv(windowed_flows_csv(lab, pcap_bytes), attack_src, target, needs, subcategory)
