"""
Agent de trafic « bénin », exécuté DANS un conteneur éphémère qui partage la
pile réseau d'un équipement (python3 -u -c <ce fichier> '<profil JSON>').

Il imite un utilisateur ordinaire qui travaille avec les serveurs de la
topologie. Chaque action est une SESSION complète, avec les vrais clients
des protocoles, contre les vrais services des serveurs (service_listener.py) :

  - web (HTTP, HTTPS)  : navigation — une page, puis son style, son script et
    ses images sur la même connexion (comme un navigateur), plusieurs pages
    avec des temps de lecture, parfois un téléchargement, un appel d'API ou
    une connexion par formulaire ;
  - SSH                : connexion réussie, quelques commandes espacées de
    pauses, ou copie d'un fichier (SFTP) dans un sens ou dans l'autre ;
  - FTP                : connexion, listing, téléchargement ou dépôt de fichiers ;
  - SMTP               : envoi d'un courriel, parfois avec une pièce jointe ;
  - MySQL              : connexion et quelques requêtes (lecture, commande) ;
  - Telnet             : connexion, une ou deux commandes ;
  - DNS                : résolution du nom d'un équipement (souvent juste avant
    d'aller dessus), parfois un nom inexistant ;
  - ICMP               : ping (1 à 4 paquets, tailles variables).

Un vrai utilisateur se trompe parfois de mot de passe : de temps en temps, une
connexion échoue une fois avant de réussir. Ce n'est PAS une force brute (une
seule erreur, puis le bon mot de passe), et c'est ce qu'un IDS doit savoir
distinguer.

La configuration, préparée par le moteur (traffic.py), décrit le rythme et les cibles :
{
  "profile": "slow" | "moderate" | "steady" | "intense",  # fréquence (voir PROFILES)
  "kinds": ["icmp", "http", "ssh", "tcp"…],  # types de trafic cochés : ping, un par service, autres ports TCP
  "targets": [ { "ip": "10.0.20.10", "host": "serveur-web",       # host : nom DNS (domaine « domain »)
                 "services": [ { "port": 80, "protocol": "tcp", "kind": "http" } ] } ],
  "account": { "user": "labuser", "password": "…" },  # compte de démonstration des serveurs
  "domain": "lab",
  "seed": 1234            # optionnel : rend le choix des actions reproductible
}

Autonome : bibliothèque standard + clients présents dans l'image
(curl, ssh/sshpass, mariadb). Rien n'est installé sur l'équipement.
"""

import ftplib
import http.client
import io
import json
import os
import random
import re
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import warnings
from email.message import EmailMessage

warnings.filterwarnings("ignore", category=DeprecationWarning)
import telnetlib  # noqa: E402 - déprécié mais présent en Python 3.12 (image de la boîte à outils)

# Fréquence : (pause mini, pause maxi) en secondes entre deux sessions,
# facteur appliqué aux temps de lecture À L'INTÉRIEUR d'une session,
# nombre de sessions menées en parallèle (plusieurs onglets, plusieurs outils).
PROFILES = {
    "slow": ((8.0, 12.0), 1.0, 1),      # ~1 action / 10 s
    "moderate": ((2.0, 4.0), 0.6, 1),   # ~1 action / 3 s
    "steady": ((0.6, 1.4), 0.35, 2),    # ~1 action / s
    "intense": ((0.2, 0.45), 0.15, 3),  # ~3 actions / s
}
DEFAULT_PROFILE = "moderate"

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
SQL_QUERIES = [
    "SELECT * FROM produits WHERE id = {i};",
    "SELECT nom, prix FROM produits WHERE prix < {p} ORDER BY prix LIMIT 20;",
    "SELECT COUNT(*) FROM commandes;",
    "INSERT INTO commandes (produit, quantite, client) VALUES ({i}, {q}, 'client-{c}');",
    "SELECT * FROM commandes ORDER BY cree DESC LIMIT 10;",
    "UPDATE produits SET stock = stock - 1 WHERE id = {i} AND stock > 0;",
    "SELECT * FROM produits;",
]


def log(message):
    print(message, flush=True)


def quiet(cmd, timeout, **kwargs):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        pass


class User:
    """Un utilisateur : choisit des sessions et les joue avec ses temps de lecture."""

    def __init__(self, rng, think, account, domain):
        self.rng = rng
        self.think_factor = think
        self.user = account["user"]
        self.password = account["password"]
        self.domain = domain

    def think(self, low=0.5, high=4.0):
        time.sleep(self.rng.uniform(low, high) * self.think_factor)

    def typo(self, rate=0.05):
        """Vrai si l'utilisateur se trompe de mot de passe cette fois-ci."""
        return self.rng.random() < rate

    # ---------------------------------------------------------------- web

    def web(self, ip, port, tls):
        rng = self.rng
        ua = rng.choice(USER_AGENTS)

        def connect():
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                return http.client.HTTPSConnection(ip, port, timeout=10, context=ctx)
            return http.client.HTTPConnection(ip, port, timeout=10)

        def get(conn, path, method="GET", body=None, headers=None):
            hdrs = {"User-Agent": ua, "Accept": "*/*", "Connection": "keep-alive", **(headers or {})}
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data

        conn = connect()
        try:
            choice = rng.random()
            if choice < 0.12:  # appli qui interroge une API
                for _ in range(rng.randint(2, 8)):
                    get(conn, rng.choice(["/api/status", f"/api/produits?page={rng.randint(1, 10)}"]))
                    self.think(0.3, 2.0)
                return
            if choice < 0.20:  # connexion à l'intranet par formulaire
                get(conn, "/contact.html")
                self.think(1, 4)
                password = "pasword123" if self.typo(0.15) else self.password
                form = f"user={self.user}&password={password}"
                status, _ = get(conn, "/login", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"})
                if status != 302:
                    self.think(1, 3)
                    get(conn, "/login", "POST", f"user={self.user}&password={self.password}",
                        {"Content-Type": "application/x-www-form-urlencoded"})
            # navigation : l'accueil puis quelques pages en suivant leurs liens, chacune avec ses ressources
            page = "/index.html"
            for _ in range(rng.randint(1, 4)):
                _, html = get(conn, page)
                for asset in dict.fromkeys(re.findall(rb'(?:src|href)="(/static/[^"]+)"', html)):
                    get(conn, asset.decode())
                downloads = re.findall(rb'href="(/downloads/[^"]+)"', html)
                if downloads and rng.random() < 0.10:  # téléchargement d'un fichier proposé sur la page
                    get(conn, rng.choice(downloads).decode())
                self.think(1.5, 8.0)  # lecture de la page
                links = re.findall(rb'href="(/[\w-]+\.html)"', html)
                if not links:
                    break
                page = rng.choice(links).decode()
        finally:
            conn.close()

    # ---------------------------------------------------------------- SSH

    def ssh(self, ip, port):
        rng = self.rng
        base = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR"]
        if self.typo():
            quiet(["sshpass", "-p", "Password123", "ssh", *base, "-p", str(port), f"{self.user}@{ip}", "true"], 15)
            self.think(1, 3)
        if rng.random() < 0.3:  # copie de fichier (SFTP)
            if rng.random() < 0.7:
                src, dst = f"{self.user}@{ip}:{rng.choice(REMOTE_FILES)}", "/tmp/recu"
            else:
                with open("/tmp/envoi", "wb") as f:
                    f.write(os.urandom(rng.randint(5_000, 1_500_000)))
                src, dst = "/tmp/envoi", f"{self.user}@{ip}:upload/fichier-{rng.randint(1, 999)}.bin"
            quiet(["sshpass", "-p", self.password, "scp", *base, "-P", str(port), src, dst], 60)
            return
        # session : quelques commandes, avec des pauses comme un humain au clavier
        steps = []
        for _ in range(rng.randint(1, 5)):
            steps.append(rng.choice(SHELL_COMMANDS))
            steps.append(f"sleep {rng.uniform(0.5, 6.0) * self.think_factor:.1f}")
        quiet(["sshpass", "-p", self.password, "ssh", *base, "-p", str(port), f"{self.user}@{ip}", "; ".join(steps)], 90)

    # ---------------------------------------------------------------- FTP

    def ftp(self, ip, port):
        rng = self.rng
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=10)
        try:
            if self.typo():
                try:
                    ftp.login(self.user, "password12")
                except ftplib.error_perm:
                    pass
                ftp.close()
                self.think(1, 3)
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=10)
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

    # ---------------------------------------------------------------- SMTP

    def smtp(self, ip, port, sender):
        rng = self.rng
        msg = EmailMessage()
        msg["From"] = f"{sender}@{self.domain}"
        msg["To"] = f"{rng.choice(['equipe', 'support', 'direction', self.user, 'compta'])}@{self.domain}"
        msg["Subject"] = rng.choice(["Compte rendu", "Réunion de demain", "Facture", "Question", "Rapport mensuel"])
        msg.set_content("\n".join(f"Ligne {i} du message." for i in range(rng.randint(3, 400))))
        if rng.random() < 0.3:
            msg.add_attachment(os.urandom(rng.randint(20_000, 600_000)), maintype="application",
                               subtype="octet-stream", filename="piece-jointe.bin")
        with smtplib.SMTP(ip, port, timeout=15) as s:
            s.ehlo(f"{sender}.{self.domain}")
            s.send_message(msg)

    # ---------------------------------------------------------------- MySQL

    def mysql(self, ip, port):
        rng = self.rng
        queries = []
        for _ in range(rng.randint(1, 6)):
            q = rng.choice(SQL_QUERIES).format(i=rng.randint(1, 200), p=rng.randint(10, 300),
                                               q=rng.randint(1, 5), c=rng.randint(1, 99))
            queries.append(q)
            if rng.random() < 0.4:
                queries.append(f"SELECT SLEEP({rng.uniform(0.2, 3.0) * self.think_factor:.1f});")
        password = "password1234" if self.typo() else self.password
        cmd = ["mariadb", "-h", ip, "-P", str(port), "-u", self.user, f"-p{password}", "--skip-ssl",
               "--connect-timeout=5", "boutique", "-e", " ".join(queries)]
        quiet(cmd, 60)
        if password != self.password:
            self.think(1, 3)
            cmd[cmd.index(f"-p{password}")] = f"-p{self.password}"
            quiet(cmd, 60)

    # ---------------------------------------------------------------- Telnet

    def telnet(self, ip, port):
        rng = self.rng
        with telnetlib.Telnet(ip, port, timeout=10) as t:
            t.read_until(b"login: ", 10)
            t.write(self.user.encode() + b"\n")
            t.read_until(b"Password: ", 10)
            t.write(self.password.encode() + b"\n")
            t.read_until(b"$ ", 10)
            for _ in range(rng.randint(1, 3)):
                self.think(0.5, 3)
                t.write(rng.choice(SHELL_COMMANDS).encode() + b"\n")
                t.read_until(b"$ ", 10)
            t.write(b"exit\n")
            t.read_all()

    # ---------------------------------------------------------------- ICMP

    def ping(self, ip):
        rng = self.rng
        quiet(["ping", "-c", str(rng.randint(1, 4)), "-s", str(rng.choice([56, 56, 56, 100, 500, 1000])),
               "-W", "2", ip], 15)


# ---------------------------------------------------------------------- DNS

def dns_query(server, port, name, qtype=1, timeout=3.0):
    """Une vraie requête DNS (UDP), construite à la main : renvoie le code de réponse."""
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # récursion demandée, 1 question
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"
    packet = header + qname + struct.pack(">HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            return None
    return data[3] & 0x0F if len(data) >= 4 else None


def tcp_touch(ip, port):
    """Service inconnu : ouvre une connexion, lit la bannière, referme."""
    try:
        with socket.create_connection((ip, port), timeout=4) as sock:
            sock.settimeout(2)
            try:
                sock.recv(256)
                sock.sendall(b"\r\n")
            except OSError:
                pass
    except OSError:
        pass


# ---------------------------------------------------------------------- choix des actions

# Poids : la navigation web domine le trafic d'un vrai réseau.
WEIGHTS = {"http": 5, "https": 5, "ssh": 2, "ftp": 1.5, "smtp": 1.5, "mysql": 2, "telnet": 0.5,
           "dns": 1, "ping": 1.5, "other": 0.5}


def build_actions(targets, kinds, me):
    """Liste pondérée des sessions possibles : (poids, libellé, ip, nom DNS de la cible, fonction(user)).

    `kinds` : types cochés (« icmp », « http », « ssh »…, « tcp » pour les ports sans
    service connu). Seuls les services ouverts de chaque cible sont contactés, et rien
    n'est implicite : un type non coché ne produit aucun trafic. Le DNS n'est pas une
    session à part (voir worker)."""
    actions = []
    for target in targets:
        ip = target.get("ip")
        if not ip:
            continue
        name = target.get("host", "")
        for svc in target.get("services", []):
            port = int(svc.get("port", 0) or 0)
            if not port:
                continue
            kind = svc.get("kind")
            if (kind or "tcp") not in kinds:
                continue
            if kind == "dns":
                continue  # le DNS est utilisé par les autres sessions (voir resolve) et seul
            proto = svc.get("protocol", "tcp")
            if proto != "tcp":
                continue
            fn = {
                "http": lambda u, ip=ip, p=port: u.web(ip, p, tls=False),
                "https": lambda u, ip=ip, p=port: u.web(ip, p, tls=True),
                "ssh": lambda u, ip=ip, p=port: u.ssh(ip, p),
                "ftp": lambda u, ip=ip, p=port: u.ftp(ip, p),
                "smtp": lambda u, ip=ip, p=port: u.smtp(ip, p, me),
                "mysql": lambda u, ip=ip, p=port: u.mysql(ip, p),
                "telnet": lambda u, ip=ip, p=port: u.telnet(ip, p),
            }.get(kind, lambda u, ip=ip, p=port: tcp_touch(ip, p))
            actions.append((WEIGHTS.get(kind, WEIGHTS["other"]), f"{kind or 'tcp'} {ip}:{port}", ip, name, fn))
        if "icmp" in kinds:
            actions.append((WEIGHTS["ping"], f"ping {ip}", ip, name, lambda u, ip=ip: u.ping(ip)))
    return actions


def dns_servers(targets):
    return [(t["ip"], int(s.get("port", 53))) for t in targets if t.get("ip")
            for s in t.get("services", []) if s.get("kind") == "dns"]


def worker(index, config, actions, resolvers, stop):
    profile = config.get("profile", DEFAULT_PROFILE)
    (low, high), think, _ = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])
    seed = config.get("seed")
    rng = random.Random(None if seed is None else seed + index)
    domain = config["domain"]
    user = User(rng, think, config["account"], domain)
    names = [n for _, _, _, n, _ in actions if n] or ["serveur"]
    weights = [a[0] for a in actions]

    while not stop.is_set():
        try:
            if resolvers and rng.random() < 0.08:
                # requête DNS isolée (un nom existant, parfois un nom inexistant)
                server, port = rng.choice(resolvers)
                name = rng.choice(names) if rng.random() < 0.8 else f"intranet-{rng.randint(1, 9)}"
                dns_query(server, port, f"{name}.{domain}", rng.choice([1, 1, 1, 28]))
            elif actions:
                _, label, _ip, name, fn = rng.choices(actions, weights)[0]
                if resolvers and name and rng.random() < 0.6:
                    server, port = rng.choice(resolvers)
                    dns_query(server, port, f"{name}.{domain}")  # on résout avant de se connecter
                try:
                    fn(user)
                except Exception as exc:  # noqa: BLE001 - une session ratée ne doit pas tuer l'agent
                    log(f"session {label} : {exc}")
        except Exception as exc:  # noqa: BLE001
            log(f"action : {exc}")
        time.sleep(rng.uniform(low, high))


def main():
    config = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    profile = config.get("profile", DEFAULT_PROFILE)
    _, _, workers = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])
    kinds = set(config.get("kinds") or ["icmp"])
    targets = config.get("targets", [])
    me = socket.gethostname().lower()
    actions = build_actions(targets, kinds, me)
    resolvers = dns_servers(targets) if "dns" in kinds else []

    if not actions and not resolvers:
        log("aucune action à générer : agent de trafic inactif")
        # On reste en vie : l'arrêt se fait en supprimant le conteneur.
        while True:
            time.sleep(3600)

    log(f"agent de trafic « {profile} » démarré ({len(actions)} session(s) possible(s), "
        f"{workers} en parallèle, types : {','.join(sorted(kinds))})")
    stop = threading.Event()
    threads = [threading.Thread(target=worker, args=(i, config, actions, resolvers, stop), daemon=True)
               for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
