"""
Services exécutés DANS chaque serveur de la topologie
(python3 -c <ce fichier> '<services JSON>').

Deux niveaux de réalisme, choisis automatiquement selon le service déclaré :

  - services « réels » : SSH (openssh) et FTP (vsftpd) sont lancés comme de
    VRAIS démons, avec un compte de démonstration. Une connexion ou une
    attaque par force brute produit alors un échange authentique (négociation,
    tentatives d'authentification qui échouent puis réussissent) — le trafic
    dont une sonde IDS a besoin pour apprendre à reconnaître ces attaques.
  - autres services : un simulateur ouvre réellement le port et répond de façon
    plausible (bannière SMTP/POP…, réponse HTTP), suffisant pour qu'un scan le
    voie ouvert.

Compte de démonstration (réseau ISOLÉ, identifiants volontairement faibles,
pour que la force brute « réussisse » et illustre l'attaque) :
    utilisateur « labuser », mot de passe « password123 ».

Autonome : uniquement la bibliothèque standard + les démons présents dans
l'image du serveur. Si un démon manque, le service retombe sur la bannière
simulée (le port reste ouvert).
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading

# Compte de démonstration pour les services authentifiés (lab isolé).
LAB_USER = "labuser"
LAB_PASSWORD = "password123"

BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_9.6\r\n",
    "ftp": b"220 FTP server ready\r\n",
    "smtp": b"220 mail.lab ESMTP Postfix\r\n",
    "pop3": b"+OK POP3 server ready\r\n",
    "imap": b"* OK IMAP4rev1 server ready\r\n",
    "telnet": b"\r\nlogin: ",
    "mysql": b"J\x00\x00\x00\n8.0.36\x00",
}
HTTP_BODY = b"<!doctype html><html><body><h1>It works!</h1></body></html>"


def log(message):
    print(message, flush=True)


def run(cmd):
    """Exécute une commande, renvoie True si elle réussit (sortie ignorée)."""
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def ensure_lab_user():
    """Crée le compte de démonstration (idempotent) avec son mot de passe faible."""
    if shutil.which("useradd"):
        run(["useradd", "-m", "-s", "/bin/sh", LAB_USER])
    else:  # busybox
        run(["adduser", "-D", LAB_USER])
    subprocess.run(["chpasswd"], input=f"{LAB_USER}:{LAB_PASSWORD}".encode(),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# Démons réels
# ---------------------------------------------------------------------------

def start_sshd(port):
    """Lance un vrai serveur OpenSSH sur le port donné. False si openssh absent."""
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        return False
    ensure_lab_user()
    run(["ssh-keygen", "-A"])              # clés d'hôte
    os.makedirs("/var/empty", exist_ok=True)  # répertoire de séparation de privilèges
    subprocess.Popen(
        [sshd, "-D", "-p", str(port),
         "-o", "PasswordAuthentication=yes",
         "-o", "PermitRootLogin=no",
         "-o", "UsePAM=no",
         "-o", "PidFile=/run/sshd.pid"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    log(f"SSH (openssh) réel en écoute sur {port} — compte {LAB_USER}")
    return True


# Configuration vsftpd : comptes locaux, pas d'anonyme (la force brute vise labuser).
VSFTPD_CONF = """listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=NO
seccomp_sandbox=NO
pam_service_name=vsftpd
listen_port={port}
"""


def start_vsftpd(port):
    """Lance un vrai serveur vsftpd sur le port donné. False si vsftpd absent."""
    vsftpd = shutil.which("vsftpd")
    if not vsftpd:
        return False
    ensure_lab_user()
    conf_path = "/etc/vsftpd-lab.conf"
    with open(conf_path, "w") as f:
        f.write(VSFTPD_CONF.format(port=port))
    # PAM : authentifier les utilisateurs locaux via /etc/shadow.
    os.makedirs("/etc/pam.d", exist_ok=True)
    with open("/etc/pam.d/vsftpd", "w") as f:
        f.write("auth required pam_unix.so\naccount required pam_unix.so\n")
    os.makedirs("/var/empty", exist_ok=True)
    subprocess.Popen([vsftpd, conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"FTP (vsftpd) réel en écoute sur {port} — compte {LAB_USER}")
    return True


# service (nom normalisé) → fonction de démarrage du vrai démon
REAL_DAEMONS = {"ssh": start_sshd, "ftp": start_vsftpd}


# ---------------------------------------------------------------------------
# Simulateur (bannière / HTTP / UDP) pour les autres services
# ---------------------------------------------------------------------------

def http_response(name):
    return (
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Type: text/html\r\n"
        b"Content-Length: " + str(len(HTTP_BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + HTTP_BODY
    )


def handle_tcp(conn, name):
    with conn:
        conn.settimeout(5)
        try:
            if name.startswith("http"):
                conn.recv(4096)
                conn.sendall(http_response(name))
                return
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


def main():
    services = json.loads(sys.argv[1]) if len(sys.argv) > 1 else []
    for svc in services:
        port = int(svc["port"])
        name = (svc.get("name") or "").strip().lower()
        protocol = svc.get("protocol", "tcp")

        # Service authentifié connu (SSH, FTP) : on tente le vrai démon.
        daemon = REAL_DAEMONS.get(name) if protocol == "tcp" else None
        if daemon and daemon(port):
            continue

        # Sinon : simulateur (bannière / HTTP / écho UDP).
        target = serve_udp if protocol == "udp" else serve_tcp
        t = threading.Thread(target=target, args=(port, name), daemon=True)
        t.start()
        log(f"service {name or '?'} (simulé) en écoute sur {port}/{protocol}")

    threading.Event().wait()  # le serveur reste allumé même sans service


if __name__ == "__main__":
    main()
