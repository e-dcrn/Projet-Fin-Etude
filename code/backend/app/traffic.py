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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from docker.errors import DockerException, NotFound

from .deployer import LabManager
from .errors import NotFoundError, UserError
from .models import dns_name
# Compte de démonstration créé sur les serveurs : cible des forces brutes, utilisé par l'agent bénin.
from .service_listener import DOMAIN, LAB_PASSWORD, LAB_USER
from .settings import PREFIX

log = logging.getLogger(__name__)

AGENT_SOURCE = (Path(__file__).parent / "traffic_agent.py").read_text(encoding="utf-8")


# Liste de mots de passe (faux, puis le vrai en dernier) : la force brute essaie d'abord
# des échecs réalistes, puis « réussit », ce qui illustre l'attaque. Assez longue pour
# produire des dizaines de flux : avec 8 essais, le modèle n'en voyait qu'une poignée.
_COMMON_PASSWORDS = ["admin", "123456", "root", "toor", "qwerty", "password", "letmein", "welcome", "dragon", "monkey"]
WORDLIST = [*_COMMON_PASSWORDS, *(f"{word}{n}" for word in _COMMON_PASSWORDS for n in (1, 12, 2026, 99, 7)), LAB_PASSWORD]

# Cibles acceptées : une adresse IPv4 ou un sous-réseau. Restreindre à cette forme
# évite toute injection quand la cible est insérée dans une commande shell.
TARGET_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")


# Vitesses d'attaque : faire varier le rythme diversifie les flux d'un dataset
# (un scan lent n'a pas les mêmes durées / inter-arrivées qu'un scan rapide).
#   nmap  : options de temporisation (modèle -T, éventuellement --scan-delay / --max-rate) ;
#   hydra : options de cadence (nombre de connexions parallèles -t, attente -W).
# Les valeurs peuvent contenir plusieurs options séparées par des espaces : elles sont
# découpées en arguments à la construction de la commande.
#
# « Évasion » est une vitesse à part : c'est l'attaque de temporisation de l'état de l'art
# (Han/TrafficManipulator, Sharon/TANTRA). Le modèle n'a appris que des scans et des forces
# brutes denses (-T2 à -T5, -t≥1 en rafale). En étalant fortement les paquets, le trafic
# malveillant prend un rythme proche du bénin : ses features de temps (Fwd/Flow IAT) et de
# volume sortent de la zone « attaque » apprise, et le modèle peut le classer BENIGN. À ne
# pas utiliser pour entraîner : c'est la variante à lancer *contre* un modèle déjà entraîné.
SPEEDS = {
    "slow": {"label": "Lente", "nmap": "-T2", "hydra": "-t 1"},
    "normal": {"label": "Normale", "nmap": "-T3", "hydra": "-t 2"},
    "fast": {"label": "Rapide", "nmap": "-T4", "hydra": "-t 4"},
    "insane": {"label": "Très rapide", "nmap": "-T5", "hydra": "-t 16"},
    "evasion": {"label": "Évasion (furtif, temporisé)",
                "nmap": "-T2 --scan-delay 250ms --max-rate 8",
                "hydra": "-t 1 -W 1"},
}
DEFAULT_SPEED = "fast"


def _bruteforce_cmd(service: str, target: str, speed: str) -> list:
    """Commande hydra : écrit la liste de mots de passe puis tente l'authentification."""
    passwords = " ".join(WORDLIST)
    flags = SPEEDS[speed]["hydra"]
    return [
        "sh", "-c",
        f"printf '%s\\n' {passwords} > /tmp/pw.txt && "
        f"hydra -l {LAB_USER} -P /tmp/pw.txt {flags} -f -I {service}://{target}",
    ]


def _nmap_cmd(*args: str):
    """Commande nmap (cible et vitesse ajoutées au lancement ; la vitesse peut tenir plusieurs options)."""
    return lambda t, speed: ["nmap", *args, *SPEEDS[speed]["nmap"].split(), t]


# --------------------------------------------------------------------------- évasion Okada
#
# Force brute FTP « furtive » : évasion par mimétisme du trafic bénin (inspirée d'Okada et al.,
# « XAI-driven black-box adversarial attacks », voir l'état de l'art). Le modèle décide PAR FLUX
# (features CICFlowMeter) : la temporisation seule ne l'évade pas (cf. rapport d'évasion), car elle
# ne change pas la forme d'un flux. Ici on change la forme : au lieu de hydra (dont la micro-structure
# des logins ratés a été apprise comme « ftp-patator »), on utilise le MÊME client que l'agent de
# trafic bénin — ftplib — avec la MÊME cadence humaine. Chaque essai raté produit alors un flux
# quasi identique au « login raté » que l'agent bénin génère déjà (traffic_agent.HumanUser.ftp).
# Objectif : que le modèle ne sache plus distinguer ces flux du bénin.
_FTP_STEALTH_TEMPLATE = r'''
import ftplib, random, sys, time
TARGET = sys.argv[1]
USER = %USER%
WORDLIST = %WORDLIST%
REMOTE = ["notes.txt", "data/ventes.csv", "data/rapport.pdf", "backup/archive.tar.gz"]
rng = random.Random()
def think(a, b): time.sleep(rng.uniform(a, b))
def attempt(pw):
    ftp = ftplib.FTP()
    try:
        ftp.connect(TARGET, 21, timeout=10)
        try:
            ftp.login(USER, pw)
        except ftplib.error_perm:
            return False  # login raté : flux identique au "typo" de l'agent benin
        # succes : on se comporte comme un client legitime (LIST + telechargements)
        try:
            ftp.retrlines("LIST", lambda _l: None)
            for _ in range(rng.randint(1, 3)):
                think(0.5, 2.5)
                ftp.retrbinary("RETR " + rng.choice(REMOTE), lambda _c: None)
        except Exception:
            pass
        try: ftp.quit()
        except Exception: pass
        return True
    except Exception:
        return False
    finally:
        try: ftp.close()
        except Exception: pass
found = False
for pw in WORDLIST:
    if attempt(pw):
        found = True
        break
    think(1.0, 4.0)  # cadence humaine, comme l'agent benin (pas une rafale hydra)
print("ftp-stealth done found=%r" % found)
'''


def _ftp_stealth_cmd(target: str) -> list:
    """Force brute FTP mimant le client bénin (ftplib). La vitesse est ignorée : la cadence
    est volontairement « humaine » pour ressembler au trafic de fond."""
    script = (_FTP_STEALTH_TEMPLATE
              .replace("%USER%", repr(LAB_USER))
              .replace("%WORDLIST%", repr(list(WORDLIST))))
    return ["python3", "-c", script, target]

# Profils de trafic bénin proposés à l'utilisateur (le détail du rythme est dans traffic_agent.py).
# Fréquence du trafic (le libellé indique le débit ; les intervalles sont dans
# traffic_agent.PROFILES). Ce ne sont que des cadences, pas des « personas ».
BENIGN_PROFILES = {
    "slow": "Lente (~1 session / 10 s)",
    "moderate": "Modérée (~1 session / 3 s)",
    "steady": "Soutenue (~1 session / s, 2 en parallèle)",
    "intense": "Intense (~3 sessions / s, 3 en parallèle)",
}

# Catalogue des attaques : reconnaissance réseau (nmap, famille « port scan » des
# jeux CIC-IDS) et force brute (hydra, famille « Patator »). Elles ne visent que
# des équipements de la topologie isolée.
#   needs   : "ip" (une cible) ou "subnet" (un sous-réseau entier)
#   label   : (catégorie, sous-catégorie) attachée au trafic produit
#   command : construit la commande à partir de la cible et de la vitesse (SPEEDS)
ATTACKS = {
    "ping-sweep": {
        "name": "Balayage de découverte",
        "description": "Repère les machines actives d'un sous-réseau (nmap -sn).",
        "needs": "subnet",
        "tool": "nmap",
        "label": ("reconnaissance", "ping-sweep"),
        "command": _nmap_cmd("-sn"),
    },
    "tcp-connect-scan": {
        "name": "Scan de ports (connect)",
        "description": "Teste les 200 ports les plus courants d'une machine (nmap -sT).",
        "needs": "ip",
        "tool": "nmap",
        "label": ("reconnaissance", "port-scan"),
        "command": _nmap_cmd("-sT", "--top-ports", "200"),
    },
    "syn-scan": {
        "name": "Scan de ports furtif (SYN)",
        "description": "Scan SYN de tous les ports, sans ouvrir de connexion complète (nmap -sS).",
        "needs": "ip",
        "tool": "nmap",
        "label": ("reconnaissance", "syn-scan"),
        "command": _nmap_cmd("-sS", "-p-"),
    },
    "service-scan": {
        "name": "Identification des services",
        "description": "Identifie les logiciels et versions derrière les ports ouverts (nmap -sV).",
        "needs": "ip",
        "tool": "nmap",
        "label": ("reconnaissance", "service-detection"),
        "command": _nmap_cmd("-sV", "--top-ports", "100"),
    },
    "aggressive-scan": {
        "name": "Scan approfondi",
        "description": "Scan complet : services, système, scripts par défaut (nmap -A).",
        "needs": "ip",
        "tool": "nmap",
        "label": ("reconnaissance", "aggressive-scan"),
        "command": _nmap_cmd("-A"),
    },
    "ssh-bruteforce": {
        "name": "Force brute SSH",
        "description": f"Essaie plusieurs mots de passe sur le compte « {LAB_USER} » en SSH (hydra).",
        "needs": "ip",
        "tool": "hydra",
        "service": "ssh",
        "label": ("force-brute", "ssh-patator"),
        "command": lambda t, speed: _bruteforce_cmd("ssh", t, speed),
    },
    "ftp-bruteforce": {
        "name": "Force brute FTP",
        "description": f"Essaie plusieurs mots de passe sur le compte « {LAB_USER} » en FTP (hydra).",
        "needs": "ip",
        "tool": "hydra",
        "service": "ftp",
        "label": ("force-brute", "ftp-patator"),
        "command": lambda t, speed: _bruteforce_cmd("ftp", t, speed),
    },
    "ftp-bruteforce-stealth": {
        "name": "Force brute FTP (furtive, évasion)",
        "description": ("Force brute FTP qui imite le client bénin (ftplib) et sa cadence humaine : "
                        "chaque essai ressemble à un login raté légitime. Évasion inspirée d'Okada "
                        "(on change la forme des flux, pas seulement le rythme)."),
        "needs": "ip",
        "tool": "python-ftp",
        "service": "ftp",
        "label": ("force-brute", "ftp-patator-stealth"),
        "command": lambda t, speed: _ftp_stealth_cmd(t),
    },
}


def command_preview(attack_id: str, speed: str, target: str = "<cible>") -> str:
    """Commande lancée par une attaque, lisible (la liste de mots de passe est résumée)."""
    attack = ATTACKS[attack_id]
    if attack["tool"] == "hydra":
        return (f"hydra -l {LAB_USER} -P <{len(WORDLIST)} mots de passe> {SPEEDS[speed]['hydra']} "
                f"-f {attack['service']}://{target}")
    if attack["tool"] == "python-ftp":
        return (f"python3 ftp_stealth.py {target}  # imite ftplib (client bénin) : "
                f"{len(WORDLIST)} essais à cadence humaine, session LIST/RETR après succès")
    return " ".join(attack["command"](target, speed))


def attack_catalog() -> List[dict]:
    """Description des scénarios pour l'interface (sans les fonctions internes)."""
    return [
        {"id": key, "name": a["name"], "description": a["description"],
         "needs": a["needs"], "category": a["label"][0], "subcategory": a["label"][1]}
        for key, a in ATTACKS.items()
    ]


def speed_catalog() -> List[dict]:
    """Vitesses proposées à l'interface."""
    return [{"id": k, "label": v["label"]} for k, v in SPEEDS.items()]


def docker_time(value: str) -> Optional[float]:
    """Horodatage Docker (« 2026-10-30T10:49:59.123456789Z ») → secondes epoch ; None si absent."""
    if not value or value.startswith("0001-"):
        return None
    main, _, frac = value.rstrip("Z").partition(".")
    try:
        moment = datetime.fromisoformat(f"{main}.{(frac or '0')[:6].ljust(6, '0')}")
    except ValueError:
        return None
    return moment.replace(tzinfo=timezone.utc).timestamp()


class TrafficManager:
    def __init__(self, lab: LabManager):
        self.lab = lab
        # Scénarios interrompus depuis l'interface (id court), pour les distinguer des terminés
        self._stopped: set = set()
        # Agents bénins mis en pause le temps d'une attaque : équipement → commande de l'agent et libellés
        self._paused: Dict[str, dict] = {}

    # ------------------------------------------------------------------ outils

    def require_device(self, node_id: str, what: str):
        device = self.lab.find_device(node_id)
        if device is None or device.status != "running":
            raise UserError(f"{what} : l'équipement est éteint (validez la topologie pour démarrer le réseau).")
        return device

    def name_of(self, container) -> str:
        return container.labels.get(f"{PREFIX}.name", "?")

    # ------------------------------------------------------------------ trafic bénin

    def start_benign(self, node_id: str, profile: str, targets: List[dict], dest: str = "all", kinds: Optional[List[str]] = None) -> dict:
        """(Re)lance l'agent de trafic bénin sur un PC. Un seul agent par équipement.
        `dest` est un libellé conservé pour l'affichage (vers qui animer le trafic) ;
        `kinds` liste les types de trafic à générer (voir traffic_agent.build_actions)."""
        if profile not in BENIGN_PROFILES:
            raise UserError(f"Profil de trafic inconnu « {profile} ».")
        device = self.require_device(node_id, "Trafic de fond")
        self.stop_benign(node_id)  # un seul agent par équipement
        self._paused.pop(node_id, None)

        config = {
            "profile": profile,
            "kinds": kinds or ["icmp"],
            "targets": [{**t, "host": dns_name(t["name"])} for t in targets],
            "account": {"user": LAB_USER, "password": LAB_PASSWORD},
            "domain": DOMAIN,
        }
        command = ["python3", "-u", "-c", AGENT_SOURCE, json.dumps(config)]
        try:
            self.lab.start_netns_helper(
                device, command,
                role="traffic", attached=node_id, profile=profile, dest=dest or "all",
            )
        except DockerException as exc:
            log.error("Agent de trafic sur %s : %s", node_id, exc)
            raise UserError("Impossible de démarrer le trafic de fond sur cet équipement.") from exc
        log.info("Trafic bénin « %s » démarré sur %s → %s", profile, self.name_of(device), dest)
        return {"node": node_id, "profile": profile, "dest": dest or "all", "running": True}

    def stop_benign(self, node_id: Optional[str] = None) -> int:
        """Arrête l'agent d'un équipement, ou tous les agents si node_id est None."""
        removed = 0
        for helper in self.lab.helpers("traffic"):
            if node_id and helper.labels.get(f"{PREFIX}.attached") != node_id:
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

    def run_scenario(self, source_id: str, attack_id: str, target: str, speed: str = DEFAULT_SPEED) -> dict:
        """Lance un scénario d'audit depuis `source_id` vers `target` (IP ou sous-réseau), une fois."""
        attack = ATTACKS.get(attack_id)
        if attack is None:
            raise UserError(f"Scénario inconnu « {attack_id} ».")
        if speed not in SPEEDS:
            raise UserError(f"Vitesse inconnue « {speed} ».")
        target = (target or "").strip()
        if not target:
            raise UserError("Indiquez une cible pour le scénario.")
        if not TARGET_RE.match(target):
            raise UserError("Cible invalide : attendez une adresse IP ou un sous-réseau (ex. 10.0.20.10).")
        device = self.require_device(source_id, "Scénario")

        command = attack["command"](target, speed)
        category, subcategory = attack["label"]
        self._pause_benign(source_id)
        try:
            helper = self.lab.start_netns_helper(
                device, command,
                role="scenario", attached=source_id, attack=attack_id,
                target=target, category=category, subcategory=subcategory, speed=speed,
                started=str(int(time.time())),
            )
        except DockerException as exc:
            log.error("Scénario %s depuis %s : %s", attack_id, source_id, exc)
            self._resume_benign(source_id)
            raise UserError("Impossible de lancer le scénario d'audit.") from exc

        threading.Thread(
            target=self._resume_after, args=(helper, source_id), daemon=True, name=f"scenario-{helper.id[:12]}",
        ).start()

        log.info("Scénario « %s » lancé depuis %s vers %s", attack_id, self.name_of(device), target)
        return self._scenario_info(helper)

    # ------------------------------------------------------------------ flux étiquetés

    def device_ip(self, container) -> str:
        """Première adresse IP du conteneur (pour étiqueter les flux du scénario)."""
        try:
            container.reload()
            nets = container.attrs["NetworkSettings"]["Networks"]
            return next((n["IPAddress"] for n in nets.values() if n.get("IPAddress")), "")
        except (DockerException, KeyError, StopIteration):
            return ""

    def primary_interface(self, container) -> str:
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

    def extract_file(self, container, path: str) -> bytes:
        """Récupère un fichier du conteneur (archive tar renvoyée par l'API Docker)."""
        stream, _ = container.get_archive(path)
        buffer = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=buffer) as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            if member is None:
                raise ValueError("pcap introuvable dans la capture")
            return tar.extractfile(member).read()

    def _pause_benign(self, node_id: str) -> None:
        """
        Suspend l'agent bénin de la source pendant son attaque, comme pendant un dataset :
        tout flux de la source vers la cible est alors bien de l'attaque, et la vérité
        terrain de la détection ne compte pas le trafic de l'agent comme des attaques manquées.
        """
        for helper in self.lab.helpers("traffic"):
            if helper.labels.get(f"{PREFIX}.attached") == node_id and helper.status == "running":
                self._paused[node_id] = {
                    "command": helper.attrs["Config"]["Cmd"],
                    "profile": helper.labels.get(f"{PREFIX}.profile", ""),
                    "dest": helper.labels.get(f"{PREFIX}.dest", "all"),
                }
                self.stop_benign(node_id)

    @staticmethod
    def _wait_until_finished(helper) -> None:
        """Attend la fin réelle d'une attaque (ou la disparition de son conteneur)."""
        try:
            helper.reload()
            while helper.status == "running":
                time.sleep(0.5)
                helper.reload()
        except DockerException:
            pass

    def _resume_benign(self, node_id: str) -> None:
        """Relance l'agent suspendu, une fois la dernière attaque de cet équipement terminée."""
        if node_id not in self._paused or any(
            h.status == "running" and h.labels.get(f"{PREFIX}.attached") == node_id
            for h in self.lab.helpers("scenario")
        ):
            return
        saved = self._paused.pop(node_id)
        device = self.lab.find_device(node_id)
        if device is None or device.status != "running":
            return  # réseau arrêté pendant l'attaque
        try:
            self.lab.start_netns_helper(
                device, saved["command"], role="traffic",
                attached=node_id, profile=saved["profile"], dest=saved["dest"],
            )
        except DockerException as exc:
            log.warning("Reprise du trafic bénin sur %s impossible : %s", node_id, exc)

    def _resume_after(self, attack_helper, source_id: str) -> None:
        """Attend la fin de l'attaque, puis relance le trafic bénin suspendu de la source."""
        self._wait_until_finished(attack_helper)
        time.sleep(1.0)  # l'agent reprend après la marge de fin d'attaque de la vérité terrain
        self._resume_benign(source_id)

    def _scenario_info(self, helper) -> dict:
        labels = helper.labels
        attack_id = labels.get(f"{PREFIX}.attack", "")
        attack = ATTACKS.get(attack_id, {})
        try:
            helper.reload()
            state = helper.attrs.get("State", {})
            exit_code = state.get("ExitCode")
            began = docker_time(state.get("StartedAt", ""))
            ended = docker_time(state.get("FinishedAt", "")) if helper.status != "running" else time.time()
        except DockerException:
            exit_code = began = ended = None
        speed = labels.get(f"{PREFIX}.speed", DEFAULT_SPEED)
        target = labels.get(f"{PREFIX}.target", "")
        scenario_id = helper.id[:12]
        return {
            "id": scenario_id,
            "attack": attack_id,
            "name": attack.get("name", attack_id),
            "source": labels.get(f"{PREFIX}.attached", ""),
            "target": target,
            "speed": SPEEDS.get(speed, {}).get("label", speed),
            "command": command_preview(attack_id, speed, target) if attack else "",
            "durationSec": round(ended - began, 1) if began and ended else None,
            "category": labels.get(f"{PREFIX}.category", ""),
            "subcategory": labels.get(f"{PREFIX}.subcategory", ""),
            "started": int(labels.get(f"{PREFIX}.started", "0") or 0),
            # running | exited | stopped (interrompu depuis l'interface)
            "status": "stopped" if helper.status != "running" and scenario_id in self._stopped else helper.status,
            "exitCode": exit_code,
        }

    def scenario_logs(self, scenario_id: str) -> str:
        """Sortie (résultat du scan) d'un scénario, pour l'afficher dans l'interface."""
        for helper in self.lab.helpers("scenario"):
            if helper.id.startswith(scenario_id):
                try:
                    return helper.logs().decode(errors="replace")
                except DockerException:
                    return ""
        raise NotFoundError("Scénario introuvable (le réseau a peut-être été arrêté).")

    def list_scenarios(self) -> List[dict]:
        scenarios = [self._scenario_info(h) for h in self.lab.helpers("scenario")]
        scenarios.sort(key=lambda s: s["started"], reverse=True)
        return scenarios

    def stop_scenarios(self, scenario_id: Optional[str] = None) -> int:
        """Interrompt un scénario en cours, ou tous si scenario_id est None.

        Le conteneur est arrêté, pas supprimé : la détection garde la vraie fenêtre
        de temps de l'attaque (de son début jusqu'à l'arrêt).
        """
        stopped = 0
        for helper in self.lab.helpers("scenario"):
            if scenario_id and not helper.id.startswith(scenario_id):
                continue
            try:
                helper.reload()
                if helper.status != "running":
                    continue
                helper.stop(timeout=1)
                self._stopped.add(helper.id[:12])
                stopped += 1
            except NotFound:
                pass
            except DockerException as exc:
                log.warning("Arrêt d'un scénario impossible : %s", exc)
        return stopped

    def clear_scenarios(self) -> int:
        """Supprime les scénarios terminés (garde ceux encore en cours)."""
        removed = 0
        for helper in self.lab.helpers("scenario"):
            try:
                helper.reload()
                if helper.status == "running":
                    continue
                helper.remove(force=True)
                self._stopped.discard(helper.id[:12])
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
            {"node": h.labels.get(f"{PREFIX}.attached"),
             "profile": h.labels.get(f"{PREFIX}.profile"),
             "dest": h.labels.get(f"{PREFIX}.dest", "all")}
            for h in self.lab.helpers("traffic") if h.status == "running"
        ]
        return {"benign": benign, "scenarios": self.list_scenarios()}
