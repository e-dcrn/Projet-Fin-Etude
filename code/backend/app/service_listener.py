"""
Services exécutés DANS chaque serveur de la topologie
(python3 -c <ce fichier> '<services JSON>' '<annuaire JSON>').

Chaque service déclaré sur un serveur est un VRAI service : un démon standard,
ou un serveur de la bibliothèque standard Python qui parle le vrai protocole.
Le trafic qu'ils échangent avec les clients (agent bénin, attaques, terminal)
est donc authentique, comme sur un vrai réseau :

  | service | implémentation                                              |
  | ------- | ----------------------------------------------------------- |
  | http    | serveur HTTP/1.1 (http.server) : site avec pages, images,   |
  |         | feuilles de style, fichiers à télécharger, API JSON, login  |
  | https   | le même site, chiffré en TLS (certificat auto-signé)        |
  | ssh     | OpenSSH (sshd), avec SFTP                                   |
  | ftp     | vsftpd (mode passif, téléversement autorisé)                |
  | telnet  | telnetd (busybox) + /bin/login                              |
  | smtp    | OpenSMTPD : accepte et distribue le courrier du domaine     |
  | dns     | dnsmasq : résout <nom-de-l-équipement>.lab pour toute la    |
  |         | topologie (annuaire fourni par le moteur)                   |
  | mysql   | MariaDB, avec une base de démonstration « boutique »        |

Un service au nom inconnu (ou dont le démon manque) retombe sur un simulateur :
le port est réellement ouvert et renvoie une bannière, ce qui suffit à un scan.

Compte de démonstration (réseau ISOLÉ, identifiants volontairement faibles,
pour que la force brute « réussisse » et illustre l'attaque) :
    utilisateur « labuser », mot de passe « password123 ».

Autonome : bibliothèque standard + démons présents dans l'image du serveur.
"""

import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Compte de démonstration pour les services authentifiés (lab isolé).
LAB_USER = "labuser"
LAB_PASSWORD = "password123"
LAB_HOME = f"/home/{LAB_USER}"
WEB_ROOT = "/srv/www"
DOMAIN = "lab"

BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_9.6\r\n",
    "ftp": b"220 FTP server ready\r\n",
    "smtp": b"220 mail.lab ESMTP\r\n",
    "pop3": b"+OK POP3 server ready\r\n",
    "imap": b"* OK IMAP4rev1 server ready\r\n",
    "telnet": b"\r\nlogin: ",
    "mysql": b"J\x00\x00\x00\n8.0.36\x00",
}


def log(message):
    print(message, flush=True)


def run(cmd, **kwargs):
    """Exécute une commande, renvoie True si elle réussit (sortie ignorée)."""
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs).returncode == 0


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


_user_lock = threading.Lock()


def ensure_lab_user():
    """Crée le compte de démonstration (idempotent), avec quelques fichiers dans
    son dossier : ce que l'on consulte ou télécharge en SSH / FTP."""
    with _user_lock:
        if os.path.isdir(LAB_HOME) and os.path.exists(f"{LAB_HOME}/notes.txt"):
            return
        if shutil.which("useradd"):
            run(["useradd", "-m", "-s", "/bin/sh", LAB_USER])
        else:  # busybox
            run(["adduser", "-D", LAB_USER])
        subprocess.run(["chpasswd"], input=f"{LAB_USER}:{LAB_PASSWORD}".encode(),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rng = random.Random(7)
        write(f"{LAB_HOME}/notes.txt", "\n".join(f"Note {i} : {lorem(rng, 12)}" for i in range(40)) + "\n")
        write(f"{LAB_HOME}/data/ventes.csv", "date,produit,quantite,prix\n" + "".join(
            f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d},produit-{rng.randint(1, 50)},"
            f"{rng.randint(1, 20)},{rng.uniform(2, 300):.2f}\n" for _ in range(3000)))
        write(f"{LAB_HOME}/data/rapport.pdf", os.urandom(350_000))
        write(f"{LAB_HOME}/backup/archive.tar.gz", os.urandom(2_500_000))
        for i in range(1, 6):
            write(f"{LAB_HOME}/photos/photo-{i}.jpg", os.urandom(rng.randint(80_000, 900_000)))
        os.makedirs(f"{LAB_HOME}/upload", exist_ok=True)
        run(["chown", "-R", f"{LAB_USER}:{LAB_USER}", LAB_HOME])


WORDS = ("réseau sonde trafic serveur paquet routeur service client analyse flux détection "
         "machine apprentissage modèle attaque données capture protocole session requête").split()


def lorem(rng, n):
    return " ".join(rng.choice(WORDS) for _ in range(n)).capitalize() + "."


def wait_for_port(port, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# Web (HTTP / HTTPS)
# ---------------------------------------------------------------------------

_site_lock = threading.Lock()


def build_site():
    """Génère (une fois) un petit site : pages de tailles variées qui chargent
    style, script et images, fichiers à télécharger. Un navigateur qui le
    parcourt produit des flux réalistes (plusieurs requêtes par connexion,
    réponses de quelques Ko à plusieurs Mo)."""
    with _site_lock:
        if os.path.exists(f"{WEB_ROOT}/index.html"):
            return
        rng = random.Random(42)
        write(f"{WEB_ROOT}/static/style.css", "body{font-family:sans-serif}\n" + "".join(
            f".c{i}{{margin:{i % 7}px;color:#{rng.randint(0, 0xFFFFFF):06x}}}\n" for i in range(1500)))
        write(f"{WEB_ROOT}/static/app.js", "".join(
            f"function f{i}(x){{return x*{i}+{rng.randint(0, 99)};}}\n" for i in range(2500)))
        write(f"{WEB_ROOT}/static/logo.png", os.urandom(18_000))
        images = []
        for i in range(1, 13):
            name = f"/static/img/image-{i}.jpg"
            write(WEB_ROOT + name, os.urandom(rng.randint(15_000, 400_000)))
            images.append(name)
        downloads = {"guide.pdf": 450_000, "catalogue.pdf": 1_200_000, "logiciel.zip": 4_000_000, "video.mp4": 9_000_000}
        for name, size in downloads.items():
            write(f"{WEB_ROOT}/downloads/{name}", os.urandom(size))

        pages = ["index", "produits", "services", "contact", "blog", "aide"] + [f"article-{i}" for i in range(1, 15)]
        for page in pages:
            imgs = rng.sample(images, rng.randint(1, 5))
            body = "".join(f"<p>{lorem(rng, rng.randint(20, 80))}</p>\n" for _ in range(rng.randint(5, 120)))
            links = "".join(f'<a href="/{p}.html">{p}</a> ' for p in rng.sample(pages, 6))
            html = (
                "<!doctype html><html><head><meta charset=utf-8><title>Intranet - " + page + "</title>"
                '<link rel=stylesheet href="/static/style.css"><script src="/static/app.js"></script></head><body>'
                '<img src="/static/logo.png"><nav>' + links + "</nav>" + body
                + "".join(f'<img src="{src}">' for src in imgs)
                + "".join(f'<a href="/downloads/{d}">{d}</a> ' for d in downloads) + "</body></html>"
            )
            write(f"{WEB_ROOT}/{page}.html", html)
        log("site web généré dans " + WEB_ROOT)


PRODUCTS = [{"id": i, "nom": f"produit-{i}", "prix": round(5 + i * 3.7 % 290, 2), "stock": (i * 13) % 70}
            for i in range(1, 201)]


class WebHandler(BaseHTTPRequestHandler):
    """Serveur web de l'intranet : fichiers statiques, API JSON, formulaire de connexion."""

    protocol_version = "HTTP/1.1"  # connexions persistantes, comme un vrai serveur
    server_version = "nginx/1.26.1"
    sys_version = ""

    def log_message(self, *args):  # pas de journal par requête (bruit)
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        if path == "/":
            path = "/index.html"
        if path == "/api/status":
            return self._send(200, json.dumps({"status": "ok", "time": int(time.time())}).encode(), "application/json")
        if path == "/api/produits":
            page = int((parse_qs(url.query).get("page") or ["1"])[0] or 1)
            items = PRODUCTS[(page - 1) * 20: page * 20]
            return self._send(200, json.dumps({"page": page, "produits": items}).encode(), "application/json")
        full = os.path.normpath(WEB_ROOT + path)
        if not full.startswith(WEB_ROOT) or not os.path.isfile(full):
            return self._send(404, b"<h1>404 Not Found</h1>")
        ctype = {
            ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "application/javascript",
            ".png": "image/png", ".jpg": "image/jpeg", ".pdf": "application/pdf",
            ".zip": "application/zip", ".mp4": "video/mp4",
        }.get(os.path.splitext(full)[1], "application/octet-stream")
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        data = parse_qs(self.rfile.read(length).decode(errors="replace")) if length else {}
        if self.path.startswith("/login"):
            ok = data.get("user", [""])[0] == LAB_USER and data.get("password", [""])[0] == LAB_PASSWORD
            if ok:
                return self._send(302, b"", headers={"Location": "/index.html", "Set-Cookie": "session=" + os.urandom(8).hex()})
            return self._send(401, b"<h1>Identifiants invalides</h1>")
        return self._send(200, json.dumps({"recu": len(data)}).encode(), "application/json")


def start_web(port, tls):
    build_site()
    server = ThreadingHTTPServer(("0.0.0.0", port), WebHandler)
    server.daemon_threads = True
    if tls:
        cert, key = "/etc/ssl/lab-cert.pem", "/etc/ssl/lab-key.pem"
        if not os.path.exists(cert):
            if not run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", f"/CN={socket.gethostname()}.{DOMAIN}", "-keyout", key, "-out", cert]):
                return False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"{'HTTPS' if tls else 'HTTP'} réel en écoute sur {port}")
    return True


# ---------------------------------------------------------------------------
# Démons standards
# ---------------------------------------------------------------------------

def start_sshd(port, _hosts):
    """Vrai serveur OpenSSH (avec SFTP pour scp / sftp)."""
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        return False
    ensure_lab_user()
    run(["ssh-keygen", "-A"])                  # clés d'hôte
    os.makedirs("/var/empty", exist_ok=True)   # répertoire de séparation de privilèges
    subprocess.Popen(
        [sshd, "-D", "-p", str(port),
         "-o", "PasswordAuthentication=yes",
         "-o", "PermitRootLogin=no",
         "-o", "UsePAM=no",
         "-o", "Subsystem=sftp internal-sftp",
         "-o", f"PidFile=/run/sshd-{port}.pid"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    log(f"SSH (OpenSSH) réel en écoute sur {port} — compte {LAB_USER}")
    return True


# Comptes locaux, pas d'anonyme ; mode passif sur une plage fixe.
VSFTPD_CONF = """listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
seccomp_sandbox=NO
pam_service_name=vsftpd
listen_port={port}
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
"""


def start_vsftpd(port, _hosts):
    """Vrai serveur FTP vsftpd."""
    vsftpd = shutil.which("vsftpd")
    if not vsftpd:
        return False
    ensure_lab_user()
    conf_path = f"/etc/vsftpd-lab-{port}.conf"
    write(conf_path, VSFTPD_CONF.format(port=port))
    # PAM : authentifier les utilisateurs locaux via /etc/shadow.
    write("/etc/pam.d/vsftpd", "auth required pam_unix.so\naccount required pam_unix.so\n")
    os.makedirs("/var/empty", exist_ok=True)
    subprocess.Popen([vsftpd, conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"FTP (vsftpd) réel en écoute sur {port} — compte {LAB_USER}")
    return True


def start_telnetd(port, _hosts):
    """Vrai serveur Telnet (busybox telnetd) avec connexion par /bin/login."""
    telnetd = shutil.which("telnetd")
    if not telnetd:
        return False
    ensure_lab_user()
    subprocess.Popen([telnetd, "-F", "-p", str(port), "-l", "/bin/login"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"Telnet (telnetd) réel en écoute sur {port} — compte {LAB_USER}")
    return True


SMTPD_CONF = """table vusers file:/etc/smtpd/lab-vusers
listen on 0.0.0.0 port {port}
action "livrer" mbox virtual <vusers>
match from any for any action "livrer"
"""


def start_smtpd(port, _hosts):
    """Vrai serveur de messagerie OpenSMTPD : tout courrier reçu est distribué
    dans la boîte de labuser (réseau isolé, aucun relais vers l'extérieur)."""
    smtpd = shutil.which("smtpd")
    if not smtpd:
        return False
    ensure_lab_user()
    write("/etc/smtpd/lab-vusers", f"@ {LAB_USER}\n")
    conf = f"/etc/smtpd/lab-{port}.conf"
    write(conf, SMTPD_CONF.format(port=port))
    os.chmod(conf, 0o600)
    os.makedirs("/var/spool/smtpd", exist_ok=True)
    os.chmod("/var/spool/smtpd", 0o711)  # exigé par OpenSMTPD
    subprocess.Popen([smtpd, "-d", "-f", conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"SMTP (OpenSMTPD) réel en écoute sur {port}")
    return True


def host_slug(name):
    out = "".join(c if c.isalnum() else "-" for c in name.lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")


def start_dnsmasq(port, hosts):
    """Vrai serveur DNS (dnsmasq), autorité sur le domaine « lab » : chaque
    équipement de la topologie y a un nom (ex. serveur-web.lab)."""
    dnsmasq = shutil.which("dnsmasq")
    if not dnsmasq:
        return False
    lines = []
    for name, ip in (hosts or {}).items():
        slug = host_slug(name)
        if slug and ip:
            lines.append(f"{ip} {slug}.{DOMAIN} {slug}")
    write("/etc/lab-hosts", "\n".join(lines) + "\n")
    subprocess.Popen(
        [dnsmasq, "-k", "--no-resolv", "--no-hosts", "--addn-hosts=/etc/lab-hosts",
         f"--port={port}", f"--local=/{DOMAIN}/", f"--domain={DOMAIN}", "--user=root",
         # Sans option d'interface, dnsmasq ne répond qu'aux machines de SES réseaux
         # (« local-service ») : les postes situés derrière un routeur n'auraient pas de réponse.
         "--interface=*",
         "--log-facility=-", "--quiet-dhcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    log(f"DNS (dnsmasq) réel en écoute sur {port} — {len(lines)} nom(s) en .{DOMAIN}")
    return True


MYSQL_INIT = f"""
CREATE DATABASE IF NOT EXISTS boutique;
CREATE USER IF NOT EXISTS '{LAB_USER}'@'%' IDENTIFIED BY '{LAB_PASSWORD}';
GRANT ALL PRIVILEGES ON boutique.* TO '{LAB_USER}'@'%';
USE boutique;
CREATE TABLE IF NOT EXISTS produits (id INT PRIMARY KEY, nom VARCHAR(64), prix DECIMAL(8,2), stock INT);
CREATE TABLE IF NOT EXISTS commandes (id INT AUTO_INCREMENT PRIMARY KEY, produit INT, quantite INT,
  client VARCHAR(64), cree TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
INSERT IGNORE INTO produits VALUES {",".join(f"({p['id']},'{p['nom']}',{p['prix']},{p['stock']})" for p in PRODUCTS)};
FLUSH PRIVILEGES;
"""


def start_mariadb(port, _hosts):
    """Vrai serveur MySQL (MariaDB) avec une base « boutique » et le compte labuser."""
    mariadbd = shutil.which("mariadbd") or shutil.which("mysqld")
    install = shutil.which("mariadb-install-db") or shutil.which("mysql_install_db")
    if not mariadbd or not install:
        return False
    datadir = "/var/lib/mysql"
    os.makedirs("/run/mysqld", exist_ok=True)
    run(["chown", "-R", "mysql:mysql", "/run/mysqld"])
    if not os.path.isdir(f"{datadir}/mysql"):
        run([install, "--user=mysql", f"--datadir={datadir}", "--skip-test-db", "--auth-root-authentication-method=socket"])
    subprocess.Popen(
        [mariadbd, "--user=mysql", f"--datadir={datadir}", f"--port={port}", "--bind-address=0.0.0.0",
         "--skip-networking=0", "--skip-name-resolve", "--socket=/run/mysqld/mysqld.sock"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    def init():
        if not wait_for_port(port, 60):
            log("MySQL (MariaDB) : le serveur n'a pas démarré")
            return
        client = shutil.which("mariadb") or shutil.which("mysql")
        ok = client and run([client, "--socket=/run/mysqld/mysqld.sock", "-uroot"], input=MYSQL_INIT.encode())
        log(f"MySQL (MariaDB) réel en écoute sur {port} — base « boutique », compte {LAB_USER}"
            + ("" if ok else " (initialisation de la base incomplète)"))

    threading.Thread(target=init, daemon=True).start()
    return True


# service (nom normalisé) → fonction de démarrage du vrai service
REAL_SERVICES = {
    "http": lambda port, hosts: start_web(port, tls=False),
    "https": lambda port, hosts: start_web(port, tls=True),
    "ssh": start_sshd,
    "ftp": start_vsftpd,
    "telnet": start_telnetd,
    "smtp": start_smtpd,
    "dns": start_dnsmasq,
    "mysql": start_mariadb,
}


# ---------------------------------------------------------------------------
# Simulateur (bannière / écho UDP) pour les services inconnus
# ---------------------------------------------------------------------------

def handle_tcp(conn, name):
    with conn:
        conn.settimeout(5)
        try:
            conn.sendall(BANNERS.get(name, b""))
            while conn.recv(4096):  # garde la session ouverte jusqu'à ce que le client parte
                pass
        except OSError:
            pass


def serve_tcp(port, name):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_tcp, args=(conn, name), daemon=True).start()


def serve_udp(port, name):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("0.0.0.0", port))
    while True:
        data, addr = srv.recvfrom(4096)
        srv.sendto(data, addr)  # écho : suffit pour qu'un scan UDP voie le port ouvert


def service_kind(name, port, protocol):
    """Type de service réel à lancer, d'après le nom déclaré (ou le port usuel)."""
    name = (name or "").strip().lower()
    if name in REAL_SERVICES:
        return name
    if name.startswith("https") or port in (443, 8443):
        return "https"
    if name.startswith("http") or port in (80, 8080):
        return "http"
    by_port = {22: "ssh", 21: "ftp", 23: "telnet", 25: "smtp", 53: "dns", 3306: "mysql"}
    return by_port.get(port) if not name else None


def main():
    services = json.loads(sys.argv[1]) if len(sys.argv) > 1 else []
    hosts = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    for svc in services:
        port = int(svc["port"])
        name = (svc.get("name") or "").strip().lower()
        protocol = svc.get("protocol", "tcp")
        kind = service_kind(name, port, protocol)
        try:
            if kind and REAL_SERVICES[kind](port, hosts):
                continue
        except Exception as exc:  # noqa: BLE001 - un service raté ne doit pas éteindre le serveur
            log(f"service {name or kind} : {exc} — repli sur le simulateur")

        target = serve_udp if protocol == "udp" else serve_tcp
        threading.Thread(target=target, args=(port, name), daemon=True).start()
        log(f"service {name or '?'} (simulé) en écoute sur {port}/{protocol}")

    threading.Event().wait()  # le serveur reste allumé même sans service


if __name__ == "__main__":
    main()
