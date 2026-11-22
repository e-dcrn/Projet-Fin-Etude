"""
Agent de trafic « bénin », exécuté DANS un conteneur éphémère qui partage la
pile réseau d'un équipement (python3 -u -c <ce fichier> '<configuration JSON>').

Il imite un utilisateur ordinaire. Chaque action est une SESSION complète, avec
les vrais clients des protocoles, contre les vrais services des serveurs
(docker/server/services.py) :

  - web (HTTP) : navigation — une page, puis son style, son script et ses images
    sur la même connexion (comme un navigateur), plusieurs pages avec des temps
    de lecture, parfois un téléchargement, un appel d'API ou une connexion ;
  - SSH        : quelques commandes espacées de pauses, ou copie d'un fichier (SFTP) ;
  - FTP        : connexion, listing, téléchargement ou dépôt de fichiers ;
  - ICMP       : ping (1 à 4 paquets, tailles variables).

Un vrai utilisateur se trompe parfois de mot de passe : de temps en temps, une
connexion échoue une fois avant de réussir. Ce n'est PAS une force brute (une
seule erreur, puis le bon mot de passe), et c'est ce qu'un IDS doit savoir distinguer.

Configuration, préparée par le moteur (traffic.py) :
{
  "profile": "slow" | "moderate" | "steady" | "intense",   # fréquence (voir PROFILES)
  "kinds": ["icmp", "http", "ssh", "ftp"],                 # types de trafic cochés
  "targets": [{ "ip": "10.0.1.10", "server": true }],      # un serveur offre HTTP, SSH et FTP
  "account": { "user": "labuser", "password": "…" }
}
"""

import ftplib
import http.client
import io
import json
import os
import random
import re
import subprocess
import sys
import threading
import time

# Fréquence : (pause mini, pause maxi) en secondes entre deux sessions,
# facteur appliqué aux temps de lecture À L'INTÉRIEUR d'une session,
# nombre de sessions menées en parallèle.
PROFILES = {
    "slow": ((8.0, 12.0), 1.0, 1),      # ~1 action / 10 s
    "moderate": ((2.0, 4.0), 0.6, 1),   # ~1 action / 3 s
    "steady": ((0.6, 1.4), 0.35, 2),    # ~1 action / s
    "intense": ((0.2, 0.45), 0.15, 3),  # ~3 actions / s
}

# Poids : la navigation web domine le trafic d'un vrai réseau.
WEIGHTS = {"http": 5, "ssh": 2, "ftp": 1.5, "icmp": 1.5}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "curl/8.10.1",
]
SHELL_COMMANDS = [
    "ls -la", "cat notes.txt", "uptime", "df -h", "ps", "head -n 40 data/ventes.csv", "wc -l data/ventes.csv",
    "ls -la photos", "du -sh .", "id", "date", "free", "tail -n 20 notes.txt", "grep produit-7 data/ventes.csv | head",
]
REMOTE_FILES = ["notes.txt", "data/ventes.csv", "data/rapport.pdf", "photos/photo-1.jpg", "photos/photo-3.jpg",
                "backup/archive.tar.gz"]
SSH_OPTIONS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR"]


def quiet(cmd, timeout):
    """Lance une commande sans afficher sa sortie (et l'abandonne après `timeout` secondes)."""
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


class User:
    """Un utilisateur : choisit des sessions et les joue avec ses temps de lecture."""

    def __init__(self, rng, think, account):
        self.rng = rng
        self.think_factor = think
        self.user = account["user"]
        self.password = account["password"]

    def think(self, low=0.5, high=4.0):
        time.sleep(self.rng.uniform(low, high) * self.think_factor)

    def typo(self, rate=0.05):
        """Vrai si l'utilisateur se trompe de mot de passe cette fois-ci."""
        return self.rng.random() < rate

    # ---------------------------------------------------------------- web

    def web(self, ip):
        rng = self.rng
        headers = {"User-Agent": rng.choice(USER_AGENTS), "Accept": "*/*", "Connection": "keep-alive"}
        conn = http.client.HTTPConnection(ip, 80, timeout=10)

        def get(path, method="GET", body=None):
            extra = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
            conn.request(method, path, body=body, headers={**headers, **extra})
            resp = conn.getresponse()
            return resp.status, resp.read()

        try:
            choice = rng.random()
            if choice < 0.12:  # appli qui interroge une API
                for _ in range(rng.randint(2, 8)):
                    get(rng.choice(["/api/status", f"/api/produits?page={rng.randint(1, 10)}"]))
                    self.think(0.3, 2.0)
                return
            if choice < 0.20:  # connexion à l'intranet par formulaire
                get("/contact.html")
                self.think(1, 4)
                password = "pasword123" if self.typo(0.15) else self.password
                status, _ = get("/login", "POST", f"user={self.user}&password={password}")
                if status != 302:
                    self.think(1, 3)
                    get("/login", "POST", f"user={self.user}&password={self.password}")
            # navigation : l'accueil puis quelques pages en suivant leurs liens, chacune avec ses ressources
            page = "/index.html"
            for _ in range(rng.randint(1, 4)):
                _, html = get(page)
                for asset in dict.fromkeys(re.findall(rb'(?:src|href)="(/static/[^"]+)"', html)):
                    get(asset.decode())
                downloads = re.findall(rb'href="(/downloads/[^"]+)"', html)
                if downloads and rng.random() < 0.10:  # téléchargement d'un fichier proposé sur la page
                    get(rng.choice(downloads).decode())
                self.think(1.5, 8.0)  # lecture de la page
                page = rng.choice(re.findall(rb'href="(/[\w-]+\.html)"', html)).decode()
        finally:
            conn.close()

    # ---------------------------------------------------------------- SSH

    def ssh(self, ip):
        rng = self.rng
        if self.typo():
            quiet(["sshpass", "-p", "Password123", "ssh", *SSH_OPTIONS, f"{self.user}@{ip}", "true"], 15)
            self.think(1, 3)
        if rng.random() < 0.3:  # copie de fichier (SFTP), dans un sens ou dans l'autre
            if rng.random() < 0.7:
                src, dst = f"{self.user}@{ip}:{rng.choice(REMOTE_FILES)}", "/tmp/recu"
            else:
                with open("/tmp/envoi", "wb") as f:
                    f.write(os.urandom(rng.randint(5_000, 1_500_000)))
                src, dst = "/tmp/envoi", f"{self.user}@{ip}:upload/fichier-{rng.randint(1, 999)}.bin"
            quiet(["sshpass", "-p", self.password, "scp", *SSH_OPTIONS, src, dst], 60)
            return
        # session : quelques commandes, avec des pauses comme un humain au clavier
        steps = []
        for _ in range(rng.randint(1, 5)):
            steps.append(rng.choice(SHELL_COMMANDS))
            steps.append(f"sleep {rng.uniform(0.5, 6.0) * self.think_factor:.1f}")
        quiet(["sshpass", "-p", self.password, "ssh", *SSH_OPTIONS, f"{self.user}@{ip}", "; ".join(steps)], 90)

    # ---------------------------------------------------------------- FTP

    def ftp(self, ip):
        rng = self.rng
        if self.typo():  # un login raté, puis le bon mot de passe
            ftp = ftplib.FTP(ip, timeout=10)
            try:
                ftp.login(self.user, "password12")
            except ftplib.error_perm:
                pass
            ftp.close()
            self.think(1, 3)
        ftp = ftplib.FTP(ip, timeout=10)
        try:
            ftp.login(self.user, self.password)
            ftp.retrlines("LIST", lambda _line: None)
            for _ in range(rng.randint(1, 3)):
                self.think(0.5, 3)
                if rng.random() < 0.25:
                    data = io.BytesIO(os.urandom(rng.randint(2_000, 800_000)))
                    ftp.storbinary(f"STOR upload/depot-{rng.randint(1, 999)}.bin", data)
                else:
                    ftp.retrbinary("RETR " + rng.choice(REMOTE_FILES), lambda _chunk: None)
            ftp.quit()
        finally:
            ftp.close()

    # ---------------------------------------------------------------- ICMP

    def ping(self, ip):
        size = self.rng.choice([56, 56, 56, 100, 500, 1000])
        quiet(["ping", "-c", str(self.rng.randint(1, 4)), "-s", str(size), "-W", "2", ip], 15)


def build_actions(targets, kinds):
    """Sessions possibles : (type, ip). Un serveur offre HTTP, SSH et FTP ; toute machine répond au ping."""
    actions = []
    for target in targets:
        offered = ["icmp", "http", "ssh", "ftp"] if target.get("server") else ["icmp"]
        actions += [(kind, target["ip"]) for kind in offered if kind in kinds]
    return actions


def worker(config, actions):
    """Un utilisateur qui enchaîne les sessions, sans fin (l'arrêt se fait en supprimant le conteneur)."""
    (low, high), think, _ = PROFILES[config["profile"]]
    rng = random.Random()
    user = User(rng, think, config["account"])
    sessions = {"http": user.web, "ssh": user.ssh, "ftp": user.ftp, "icmp": user.ping}
    while True:
        kind, ip = rng.choices(actions, [WEIGHTS[k] for k, _ in actions])[0]
        try:
            sessions[kind](ip)
        except Exception as exc:  # une session ratée ne doit pas arrêter l'agent
            print(f"session {kind} {ip} : {exc}", flush=True)
        time.sleep(rng.uniform(low, high))


def main():
    config = json.loads(sys.argv[1])
    actions = build_actions(config["targets"], config["kinds"])
    if not actions:
        print("aucune action à générer : agent de trafic inactif", flush=True)
        threading.Event().wait()  # on reste en vie : l'arrêt se fait en supprimant le conteneur

    _, _, parallel = PROFILES[config["profile"]]
    print(f"agent de trafic « {config['profile']} » démarré : {len(actions)} session(s) possible(s), "
          f"{parallel} en parallèle", flush=True)
    threads = [threading.Thread(target=worker, args=(config, actions)) for _ in range(parallel)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
