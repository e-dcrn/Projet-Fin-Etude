"""
Export de flux au format CICFlowMeter RÉEL — les mêmes ~90 colonnes que les jeux
CIC-IDS (CIC-IDS2017/2018). On réutilise l'image conteneurisée de ConCap
(ghcr.io/idlab-discover/concap/cicflowmeter) : un pcap capturé pendant un
scénario est converti en CSV de flux, puis chaque flux est étiqueté « attaque »
ou « BENIGN » selon le scénario (même règle que flows.label_flows).

Pourquoi en plus de flows.py ? flows.py reste un exporteur interne, autonome et
testable (repli si Docker/l'image manquent) ; CICFlowMeter donne, lui, des
features STRICTEMENT identiques aux datasets publics, pour entraîner/évaluer un
ML-IDS de façon comparable (voir docs/ARCHITECTURE.md, « le pont »).

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
import tarfile
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Callable, Dict, Optional, Tuple

from docker.errors import DockerException

from .flows import split_pcap

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


def run_cicflowmeter(lab, pcap_bytes: bytes, timeout: int = 180) -> str:
    """Convertit un pcap en CSV de flux CICFlowMeter (brut, colonne Label vide)."""
    client = lab.client
    try:
        client.images.get(CFM_IMAGE)
    except DockerException:
        log.info("Téléchargement de l'image CICFlowMeter %s…", CFM_IMAGE)
        client.images.pull(CFM_IMAGE)

    container = client.containers.create(CFM_IMAGE, entrypoint=["sh", "-c"], command=[_CMD])
    try:
        container.put_archive("/tmp", _tar_bytes("dump.pcap", pcap_bytes))
        container.start()
        container.wait(timeout=timeout)
        output = container.logs(stdout=True, stderr=False)
    finally:
        try:
            container.remove(force=True)
        except DockerException:
            pass

    text = output.decode(errors="replace")
    lines = text.splitlines()
    if not lines or "Src IP" not in lines[0]:
        raise RuntimeError("CICFlowMeter n'a pas produit de CSV exploitable")
    return text


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
    """Même règle d'étiquetage que flows.label_flows."""
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
    return label_cic_csv(run_cicflowmeter(lab, pcap_bytes), attack_src, target, needs, subcategory)
