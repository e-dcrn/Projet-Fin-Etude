"""
Agent de trafic « bénin », exécuté DANS un conteneur éphémère qui partage la
pile réseau d'un équipement (python3 -u -c <ce fichier> '<profil JSON>').

Il imite un utilisateur ordinaire : il consulte les services ouverts des
serveurs de la topologie (pages web, connexions SSH/FTP qui s'ouvrent puis se
ferment, requêtes répétées…) en espaçant ses actions de pauses aléatoires.
Le but n'est pas de faire du débit mais de produire des flux réalistes et
variés, qui serviront de trafic « normal » de référence pour la sonde IDS.

Le profil décrit le rythme et les cibles :
{
  "profile": "slow" | "moderate" | "steady" | "intense",  # fréquence (voir PROFILES)
  "kinds": ["icmp", "http", "service"],  # types de trafic à générer (au moins un)
  "targets": [ { "ip": "10.0.20.10", "name": "Serveur-Web",
                 "services": [ { "port": 80, "protocol": "tcp", "name": "http" } ] } ],
  "seed": 1234            # optionnel : rend le trafic reproductible
}

Autonome : uniquement la bibliothèque standard + les commandes busybox/curl
présentes dans l'image (ping, wget…). Rien n'est installé sur l'équipement.
"""

import json
import random
import socket
import subprocess
import sys
import time

# Fréquence du trafic : (pause mini, pause maxi) en secondes entre deux actions.
# Le débit ≈ 1 / pause moyenne (voir BENIGN_PROFILES pour les libellés).
PROFILES = {
    "slow": (8.0, 12.0),      # ~1 requête / 10 s
    "moderate": (2.0, 4.0),   # ~1 requête / 3 s
    "steady": (0.6, 1.4),     # ~1 requête / s
    "intense": (0.2, 0.45),   # ~3 requêtes / s
}
DEFAULT_PROFILE = "moderate"


def log(message):
    print(message, flush=True)


def http_get(ip, port):
    """Une requête HTTP complète via curl (déjà présent dans l'image)."""
    url = f"http://{ip}:{port}/"
    subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "--max-time", "5", url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def tcp_touch(ip, port):
    """Ouvre une connexion TCP, lit l'éventuelle bannière, puis referme :
    reproduit une prise de contact SSH/FTP/SMTP vue par la sonde."""
    try:
        with socket.create_connection((ip, port), timeout=4) as sock:
            sock.settimeout(2)
            try:
                sock.recv(256)          # bannière de service, s'il en envoie une
                sock.sendall(b"\r\n")   # un échange minimal, puis on raccroche
            except OSError:
                pass
    except OSError:
        pass


def ping(ip):
    subprocess.run(
        ["ping", "-c", "1", "-W", "2", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def build_actions(targets, kinds):
    """Construit la liste des actions possibles à partir des cibles et des TYPES
    de trafic demandés (`kinds`, un sous-ensemble de {"icmp", "http", "service"}).
    Chaque action est un couple (libellé, fonction sans argument).

    - "icmp"    : un ping vers chaque cible ;
    - "http"    : une requête HTTP vers chaque service web (port 80/8080 ou nom http*) ;
    - "service" : une prise de contact TCP vers chaque autre service (SSH, FTP, SMTP…).

    Rien n'est implicite : si « http » n'est pas coché, aucune requête web ; si une
    cible n'a pas le type de service demandé, elle ne reçoit rien pour ce type."""
    actions = []
    for target in targets:
        ip = target.get("ip")
        if not ip:
            continue
        for svc in target.get("services", []):
            port = int(svc.get("port", 0) or 0)
            if not port or svc.get("protocol", "tcp") != "tcp":
                continue
            is_http = (svc.get("name") or "").lower().startswith("http") or port in (80, 8080)
            if is_http and "http" in kinds:
                actions.append((f"http {ip}:{port}", lambda ip=ip, p=port: http_get(ip, p)))
            elif not is_http and "service" in kinds:
                actions.append((f"tcp {ip}:{port}", lambda ip=ip, p=port: tcp_touch(ip, p)))
        if "icmp" in kinds:
            actions.append((f"ping {ip}", lambda ip=ip: ping(ip)))
    return actions


def main():
    config = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    profile = config.get("profile", DEFAULT_PROFILE)
    low, high = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])
    rng = random.Random(config.get("seed"))

    kinds = set(config.get("kinds") or ["icmp"])
    actions = build_actions(config.get("targets", []), kinds)
    if not actions:
        log("aucune action à générer : agent de trafic inactif")
        # On reste en vie : l'équipement peut recevoir d'autres flux, et l'arrêt
        # se fait en supprimant le conteneur (pas en terminant ce processus).
        while True:
            time.sleep(3600)

    log(f"agent de trafic « {profile} » démarré ({len(actions)} action(s), types : {','.join(sorted(kinds))})")
    while True:
        label, action = rng.choice(actions)
        try:
            action()
        except Exception as exc:  # noqa: BLE001 - une action ratée ne doit pas tuer l'agent
            log(f"action {label} : {exc}")
        time.sleep(rng.uniform(low, high))


if __name__ == "__main__":
    main()
