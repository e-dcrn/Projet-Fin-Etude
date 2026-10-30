"""
Génération et observation du trafic du réseau instancié.

Deux usages, construits sur le même mécanisme que la capture (un conteneur
éphémère qui partage la pile réseau d'un équipement, voir
LabManager.start_netns_helper) :

  - trafic « bénin » de fond : un agent imite un utilisateur sur un PC
    (navigation web, connexions aux services ouverts…). Il sert de trafic
    « normal » de référence pour la sonde IDS.
  - scénarios d'audit : une activité malveillante typique (reconnaissance
    réseau avec nmap) lancée au nom d'un équipement vers une cible, étiquetée
    pour servir d'exemple « attaque ».

Tout ce que ce module crée porte le label du lab et un `role` (« traffic » ou
« scenario ») : l'arrêt du réseau le supprime, et on peut l'arrêter seul.
"""

from __future__ import annotations

import io
import json
import logging
import re
import tarfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from docker.errors import DockerException, NotFound

from .cicflowmeter import pcap_to_labeled_csv
from .deployer import LabManager
from .flows import build_flows, flows_to_csv, label_flows, parse_pcap

log = logging.getLogger(__name__)

AGENT_SOURCE = (Path(__file__).parent / "traffic_agent.py").read_text(encoding="utf-8")

# Compte de démonstration des serveurs (doit correspondre à service_listener.py) :
# cible des scénarios de force brute sur un réseau isolé.
LAB_USER = "labuser"
LAB_PASSWORD = "password123"

# Petite liste de mots de passe (faux, puis le vrai en dernier) : la force brute
# essaie d'abord des échecs réalistes, puis « réussit », ce qui illustre l'attaque.
WORDLIST = ["admin", "123456", "root", "toor", "qwerty", "password", "letmein", LAB_PASSWORD]

# Cibles acceptées : une adresse IPv4 ou un sous-réseau. Restreindre à cette forme
# évite toute injection quand la cible est insérée dans une commande shell.
TARGET_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")


def _bruteforce_cmd(service: str, target: str) -> list:
    """Commande hydra : écrit la liste de mots de passe puis tente l'authentification."""
    passwords = " ".join(WORDLIST)
    return [
        "sh", "-c",
        f"printf '%s\\n' {passwords} > /tmp/pw.txt && "
        f"hydra -l {LAB_USER} -P /tmp/pw.txt -t 4 -f -I {service}://{target}",
    ]

# Profils de trafic bénin proposés à l'utilisateur (le détail du rythme est dans traffic_agent.py).
# Fréquence du trafic (le libellé indique le débit ; les intervalles sont dans
# traffic_agent.PROFILES). Ce ne sont que des cadences, pas des « personas ».
BENIGN_PROFILES = {
    "slow": "Lente (~1 requête / 10 s)",
    "moderate": "Modérée (~1 requête / 3 s)",
    "steady": "Soutenue (~1 requête / s)",
    "intense": "Intense (~3 requêtes / s)",
}

# Catalogue de scénarios d'audit. Tous sont de la RECONNAISSANCE réseau (nmap),
# la famille « port scan » des jeux de données de référence (CIC-IDS…), et ne
# visent que des équipements de la topologie isolée.
#   needs   : "ip" (une cible) ou "subnet" (un sous-réseau entier)
#   label   : (catégorie, sous-catégorie) attachée au trafic produit
#   command : construit la commande à partir de la cible
ATTACKS = {
    "ping-sweep": {
        "name": "Balayage de découverte",
        "description": "Repère les machines actives d'un sous-réseau (nmap -sn).",
        "needs": "subnet",
        "label": ("reconnaissance", "ping-sweep"),
        "command": lambda t: ["nmap", "-sn", "-T4", t],
    },
    "tcp-connect-scan": {
        "name": "Scan de ports (connect)",
        "description": "Teste les 200 ports les plus courants d'une machine (nmap -sT).",
        "needs": "ip",
        "label": ("reconnaissance", "port-scan"),
        "command": lambda t: ["nmap", "-sT", "-T4", "--top-ports", "200", t],
    },
    "syn-scan": {
        "name": "Scan de ports furtif (SYN)",
        "description": "Scan SYN de tous les ports, sans ouvrir de connexion complète (nmap -sS).",
        "needs": "ip",
        "label": ("reconnaissance", "syn-scan"),
        "command": lambda t: ["nmap", "-sS", "-T4", "-p-", t],
    },
    "service-scan": {
        "name": "Identification des services",
        "description": "Identifie les logiciels et versions derrière les ports ouverts (nmap -sV).",
        "needs": "ip",
        "label": ("reconnaissance", "service-detection"),
        "command": lambda t: ["nmap", "-sV", "-T4", "--top-ports", "100", t],
    },
    "aggressive-scan": {
        "name": "Scan approfondi",
        "description": "Scan complet : services, système, scripts par défaut (nmap -A).",
        "needs": "ip",
        "label": ("reconnaissance", "aggressive-scan"),
        "command": lambda t: ["nmap", "-A", "-T4", t],
    },
    "ssh-bruteforce": {
        "name": "Force brute SSH",
        "description": f"Essaie plusieurs mots de passe sur le compte « {LAB_USER} » en SSH (hydra).",
        "needs": "ip",
        "label": ("force-brute", "ssh-patator"),
        "command": lambda t: _bruteforce_cmd("ssh", t),
    },
    "ftp-bruteforce": {
        "name": "Force brute FTP",
        "description": f"Essaie plusieurs mots de passe sur le compte « {LAB_USER} » en FTP (hydra).",
        "needs": "ip",
        "label": ("force-brute", "ftp-patator"),
        "command": lambda t: _bruteforce_cmd("ftp", t),
    },
}

class TrafficError(Exception):
    """Opération impossible ; le message est affichable tel quel."""


def attack_catalog() -> List[dict]:
    """Description des scénarios pour l'interface (sans les fonctions internes)."""
    return [
        {"id": key, "name": a["name"], "description": a["description"],
         "needs": a["needs"], "category": a["label"][0], "subcategory": a["label"][1]}
        for key, a in ATTACKS.items()
    ]


class TrafficManager:
    def __init__(self, lab: LabManager):
        self.lab = lab
        # Flux étiquetés produits par chaque scénario : id → { status, counts, csv, total }
        self._flows: Dict[str, dict] = {}
        self._flows_lock = threading.Lock()

    # ------------------------------------------------------------------ outils

    @property
    def _prefix(self) -> str:
        return self.lab.settings.prefix

    def _require_device(self, node_id: str, what: str):
        device = self.lab.find_device(node_id)
        if device is None or device.status != "running":
            raise TrafficError(f"{what} : l'équipement est éteint (validez la topologie pour démarrer le réseau).")
        return device

    def _name_of(self, container) -> str:
        return container.labels.get(f"{self._prefix}.name", "?")

    # ------------------------------------------------------------------ trafic bénin

    def start_benign(self, node_id: str, profile: str, targets: List[dict], dest: str = "all", kinds: Optional[List[str]] = None) -> dict:
        """(Re)lance l'agent de trafic bénin sur un PC. Un seul agent par équipement.
        `dest` est un libellé conservé pour l'affichage (vers qui animer le trafic) ;
        `kinds` liste les types de trafic à générer (« icmp », « http », « service »)."""
        if profile not in BENIGN_PROFILES:
            raise TrafficError(f"Profil de trafic inconnu « {profile} ».")
        device = self._require_device(node_id, "Trafic de fond")
        self.stop_benign(node_id)  # un seul agent par équipement

        config = {"profile": profile, "targets": targets, "kinds": kinds or ["icmp"]}
        command = ["python3", "-u", "-c", AGENT_SOURCE, json.dumps(config)]
        try:
            self.lab.start_netns_helper(
                device, self.lab.settings.traffic, command,
                role="traffic", attached=node_id, profile=profile, dest=dest or "all",
            )
        except DockerException as exc:
            log.error("Agent de trafic sur %s : %s", node_id, exc)
            raise TrafficError("Impossible de démarrer le trafic de fond sur cet équipement.") from exc
        log.info("Trafic bénin « %s » démarré sur %s → %s", profile, self._name_of(device), dest)
        return {"node": node_id, "profile": profile, "dest": dest or "all", "running": True}

    def stop_benign(self, node_id: Optional[str] = None) -> int:
        """Arrête l'agent d'un équipement, ou tous les agents si node_id est None."""
        removed = 0
        for helper in self.lab.helpers("traffic"):
            if node_id and helper.labels.get(f"{self._prefix}.attached") != node_id:
                continue
            try:
                helper.remove(force=True)
                removed += 1
            except NotFound:
                pass
            except DockerException as exc:
                log.warning("Arrêt d'un agent de trafic impossible : %s", exc)
        return removed

    # ------------------------------------------------------------------ scénarios d'audit

    def run_scenario(self, source_id: str, attack_id: str, target: str) -> dict:
        """Lance un scénario d'audit depuis `source_id` vers `target` (IP ou sous-réseau)."""
        attack = ATTACKS.get(attack_id)
        if attack is None:
            raise TrafficError(f"Scénario inconnu « {attack_id} ».")
        target = (target or "").strip()
        if not target:
            raise TrafficError("Indiquez une cible pour le scénario.")
        if not TARGET_RE.match(target):
            raise TrafficError("Cible invalide : attendez une adresse IP ou un sous-réseau (ex. 10.0.20.10).")
        device = self._require_device(source_id, "Scénario")
        source_ip = self._device_ip(device)

        command = attack["command"](target)
        category, subcategory = attack["label"]
        try:
            # Capture lancée AVANT l'attaque : elle enregistre tout le trafic du
            # scénario dans un pcap, converti ensuite en flux étiquetés.
            interface = self._primary_interface(device)
            capture = self.lab.start_netns_helper(
                device, self.lab.settings.capture,
                ["tcpdump", "-i", interface, "-p", "-U", "-w", "/tmp/scan.pcap"],
                role="scapture", attached=source_id,
            )
            helper = self.lab.start_netns_helper(
                device, self.lab.settings.traffic, command,
                role="scenario", attached=source_id, attack=attack_id,
                target=target, category=category, subcategory=subcategory,
                started=str(int(time.time())),
            )
        except DockerException as exc:
            log.error("Scénario %s depuis %s : %s", attack_id, source_id, exc)
            raise TrafficError("Impossible de lancer le scénario d'audit.") from exc

        scenario_id = helper.id[:12]
        with self._flows_lock:
            self._flows[scenario_id] = {"status": "pending", "counts": {}, "csv": None, "total": 0}
        threading.Thread(
            target=self._finalize,
            args=(scenario_id, helper, capture, source_ip, target, attack["needs"], subcategory),
            daemon=True, name=f"flows-{scenario_id}",
        ).start()

        log.info("Scénario « %s » lancé depuis %s vers %s", attack_id, self._name_of(device), target)
        return self._scenario_info(helper)

    # ------------------------------------------------------------------ flux étiquetés

    def _device_ip(self, container) -> str:
        """Première adresse IP du conteneur (pour étiqueter les flux du scénario)."""
        try:
            container.reload()
            nets = container.attrs["NetworkSettings"]["Networks"]
            return next((n["IPAddress"] for n in nets.values() if n.get("IPAddress")), "")
        except (DockerException, KeyError, StopIteration):
            return ""

    def _primary_interface(self, container) -> str:
        """Première interface « up » de l'équipement (eth0…), où capturer le trafic."""
        script = (
            'for d in /sys/class/net/*; do n=${d##*/}; [ "$n" = lo ] && continue; '
            '[ "$(cat "$d/operstate" 2>/dev/null)" = up ] && { echo "$n"; break; }; done'
        )
        try:
            result = container.exec_run(["sh", "-c", script])
            name = result.output.decode(errors="replace").strip()
            return name or "eth0"
        except DockerException:
            return "eth0"

    def _extract_file(self, container, path: str) -> bytes:
        """Récupère un fichier du conteneur (archive tar renvoyée par l'API Docker)."""
        stream, _ = container.get_archive(path)
        buffer = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=buffer) as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            if member is None:
                raise ValueError("pcap introuvable dans la capture")
            return tar.extractfile(member).read()

    def _finalize(self, scenario_id, attack_helper, capture, source_ip, target, needs, subcategory):
        """Attend la fin de l'attaque, arrête la capture, en tire des flux étiquetés."""
        result = {"status": "error", "counts": {}, "csv": None, "total": 0}
        try:
            for _ in range(360):  # fin de l'attaque (90 s maximum)
                attack_helper.reload()
                if attack_helper.status != "running":
                    break
                time.sleep(0.25)
            time.sleep(1.5)  # laisse les derniers paquets arriver
            try:
                capture.stop(timeout=3)  # tcpdump vide son tampon et écrit le pcap
            except DockerException:
                pass
            data = self._extract_file(capture, "/tmp/scan.pcap")
            try:
                # Features identiques aux jeux CIC-IDS (voir cicflowmeter.py).
                csv_text, counts, total = pcap_to_labeled_csv(self.lab, data, source_ip, target, needs, subcategory)
                engine = "CICFlowMeter"
            except Exception as exc:  # noqa: BLE001 - Docker/image absents : repli sur l'exporteur interne
                log.warning("CICFlowMeter indisponible (%s) : repli sur l'exporteur interne", exc)
                flows = build_flows(parse_pcap(data))
                counts = label_flows(flows, source_ip, target, needs, subcategory)
                csv_text, total = flows_to_csv(flows), len(flows)
                engine = "interne"
            result = {"status": "ready", "counts": counts, "csv": csv_text, "total": total}
            log.info("Scénario %s : %d flux étiquetés %s (%s)", scenario_id, total, counts, engine)
        except Exception as exc:  # noqa: BLE001 - l'échec de l'export ne doit pas remonter
            log.warning("Export de flux du scénario %s : %s", scenario_id, exc)
            result = {"status": "error", "counts": {}, "csv": None, "total": 0, "error": str(exc)}
        finally:
            try:
                capture.remove(force=True)
            except DockerException:
                pass
            with self._flows_lock:
                # Le scénario a pu être supprimé entre-temps : on n'écrit que s'il existe encore.
                if scenario_id in self._flows:
                    self._flows[scenario_id] = result

    def scenario_flows_csv(self, scenario_id: str) -> str:
        """CSV des flux étiquetés d'un scénario (lève TrafficError si indisponible)."""
        with self._flows_lock:
            entry = next((v for k, v in self._flows.items() if k.startswith(scenario_id)), None)
        if entry is None:
            raise TrafficError("Scénario introuvable (le réseau a peut-être été arrêté).")
        if entry["status"] == "pending":
            raise TrafficError("Les flux sont encore en préparation : réessayez dans un instant.")
        if entry["status"] != "ready" or not entry["csv"]:
            raise TrafficError("L'export des flux a échoué pour ce scénario.")
        return entry["csv"]

    def _scenario_info(self, helper) -> dict:
        labels = helper.labels
        attack_id = labels.get(f"{self._prefix}.attack", "")
        attack = ATTACKS.get(attack_id, {})
        try:
            helper.reload()
            exit_code = helper.attrs.get("State", {}).get("ExitCode")
        except DockerException:
            exit_code = None
        scenario_id = helper.id[:12]
        with self._flows_lock:
            flow = self._flows.get(scenario_id, {"status": "none", "counts": {}, "total": 0})
        return {
            "id": scenario_id,
            "attack": attack_id,
            "name": attack.get("name", attack_id),
            "source": labels.get(f"{self._prefix}.attached", ""),
            "target": labels.get(f"{self._prefix}.target", ""),
            "category": labels.get(f"{self._prefix}.category", ""),
            "subcategory": labels.get(f"{self._prefix}.subcategory", ""),
            "started": int(labels.get(f"{self._prefix}.started", "0") or 0),
            "status": helper.status,  # running | exited
            "exitCode": exit_code,
            "flows": {"status": flow["status"], "counts": flow.get("counts", {}), "total": flow.get("total", 0)},
        }

    def scenario_logs(self, scenario_id: str) -> str:
        """Sortie (résultat du scan) d'un scénario, pour l'afficher dans l'interface."""
        for helper in self.lab.helpers("scenario"):
            if helper.id.startswith(scenario_id):
                try:
                    return helper.logs().decode(errors="replace")
                except DockerException:
                    return ""
        raise TrafficError("Scénario introuvable (le réseau a peut-être été arrêté).")

    def list_scenarios(self) -> List[dict]:
        scenarios = [self._scenario_info(h) for h in self.lab.helpers("scenario")]
        scenarios.sort(key=lambda s: s["started"], reverse=True)
        return scenarios

    def clear_scenarios(self) -> int:
        """Supprime les scénarios terminés (garde ceux encore en cours)."""
        removed = 0
        for helper in self.lab.helpers("scenario"):
            try:
                helper.reload()
                if helper.status == "running":
                    continue
                scenario_id = helper.id[:12]
                helper.remove(force=True)
                with self._flows_lock:
                    self._flows.pop(scenario_id, None)
                removed += 1
            except NotFound:
                pass
            except DockerException as exc:
                log.warning("Nettoyage d'un scénario impossible : %s", exc)
        return removed

    # ------------------------------------------------------------------ état global

    def overview(self) -> dict:
        """Résumé de l'activité : agents bénins en cours et scénarios."""
        benign = [
            {"node": h.labels.get(f"{self._prefix}.attached"),
             "profile": h.labels.get(f"{self._prefix}.profile"),
             "dest": h.labels.get(f"{self._prefix}.dest", "all")}
            for h in self.lab.helpers("traffic") if h.status == "running"
        ]
        return {"benign": benign, "scenarios": self.list_scenarios()}
