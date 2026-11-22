"""
Services d'un serveur de la topologie (programme principal du conteneur, voir le Dockerfile).

  | service | port | implémentation                                             |
  | ------- | ---- | ---------------------------------------------------------- |
  | HTTP    | 80   | serveur web Python : pages, images, fichiers, API, login   |
  | SSH     | 22   | OpenSSH (sshd), avec SFTP                                  |
  | FTP     | 21   | vsftpd (configuration : vsftpd.conf)                       |

Ce sont de vrais services : le trafic échangé avec les clients (agent bénin,
attaques) est authentique, comme sur un vrai réseau.

Compte de démonstration (créé dans le Dockerfile) : labuser / password123.
"""

import json
import os
import random
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LAB_USER = "labuser"
LAB_PASSWORD = "password123"
HOME = f"/home/{LAB_USER}"
WEB_ROOT = "/srv/www"

WORDS = ("réseau sonde trafic serveur paquet routeur service client analyse flux détection "
         "machine apprentissage modèle attaque données capture protocole session requête").split()


def lorem(rng, n):
    return " ".join(rng.choice(WORDS) for _ in range(n)).capitalize() + "."


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def create_user_files():
    """Quelques fichiers dans le dossier de labuser : ce qu'on consulte ou télécharge en SSH / FTP."""
    rng = random.Random(7)
    write(f"{HOME}/notes.txt", "\n".join(f"Note {i} : {lorem(rng, 12)}" for i in range(40)) + "\n")
    write(f"{HOME}/data/ventes.csv", "date,produit,quantite,prix\n" + "".join(
        f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d},produit-{rng.randint(1, 50)},"
        f"{rng.randint(1, 20)},{rng.uniform(2, 300):.2f}\n" for _ in range(3000)))
    write(f"{HOME}/data/rapport.pdf", os.urandom(350_000))
    write(f"{HOME}/backup/archive.tar.gz", os.urandom(2_500_000))
    for i in range(1, 6):
        write(f"{HOME}/photos/photo-{i}.jpg", os.urandom(rng.randint(80_000, 900_000)))
    os.makedirs(f"{HOME}/upload", exist_ok=True)
    subprocess.run(["chown", "-R", f"{LAB_USER}:{LAB_USER}", HOME])


def create_website():
    """Petit site : pages de tailles variées qui chargent style, script et images,
    et fichiers à télécharger. Un navigateur qui le parcourt produit des flux réalistes."""
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
        body = "".join(f"<p>{lorem(rng, rng.randint(20, 80))}</p>\n" for _ in range(rng.randint(5, 120)))
        links = "".join(f'<a href="/{p}.html">{p}</a> ' for p in rng.sample(pages, 6))
        html = (
            "<!doctype html><html><head><meta charset=utf-8><title>Intranet - " + page + "</title>"
            '<link rel=stylesheet href="/static/style.css"><script src="/static/app.js"></script></head><body>'
            '<img src="/static/logo.png"><nav>' + links + "</nav>" + body
            + "".join(f'<img src="{src}">' for src in rng.sample(images, rng.randint(1, 5)))
            + "".join(f'<a href="/downloads/{d}">{d}</a> ' for d in downloads) + "</body></html>"
        )
        write(f"{WEB_ROOT}/{page}.html", html)


PRODUCTS = [{"id": i, "nom": f"produit-{i}", "prix": round(5 + i * 3.7 % 290, 2)} for i in range(1, 201)]
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "application/javascript",
                 ".png": "image/png", ".jpg": "image/jpeg", ".pdf": "application/pdf",
                 ".zip": "application/zip", ".mp4": "video/mp4"}


class WebHandler(BaseHTTPRequestHandler):
    """Serveur web de l'intranet : fichiers du site, API JSON, formulaire de connexion."""

    protocol_version = "HTTP/1.1"  # connexions persistantes, comme un vrai serveur
    server_version = "nginx/1.26.1"
    sys_version = ""

    def log_message(self, *args):  # pas de journal par requête
        pass

    def send(self, code, body, content_type="text/html; charset=utf-8", headers={}):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/api/status":
            return self.send(200, json.dumps({"status": "ok", "time": int(time.time())}).encode(), "application/json")
        if url.path == "/api/produits":
            page = int(parse_qs(url.query).get("page", ["1"])[0])
            items = PRODUCTS[(page - 1) * 20: page * 20]
            return self.send(200, json.dumps({"page": page, "produits": items}).encode(), "application/json")
        path = os.path.normpath(WEB_ROOT + (url.path if url.path != "/" else "/index.html"))
        if not path.startswith(WEB_ROOT) or not os.path.isfile(path):
            return self.send(404, b"<h1>404 Not Found</h1>")
        with open(path, "rb") as f:
            self.send(200, f.read(), CONTENT_TYPES.get(os.path.splitext(path)[1], "application/octet-stream"))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode())
        if form.get("user") == [LAB_USER] and form.get("password") == [LAB_PASSWORD]:
            return self.send(302, b"", headers={"Location": "/index.html", "Set-Cookie": "session=" + os.urandom(8).hex()})
        return self.send(401, b"<h1>Identifiants invalides</h1>")


def main():
    create_user_files()
    create_website()

    # SSH : les protections d'OpenSSH contre la force brute sont désactivées, sinon
    # elles coupent l'attaque du lab (« Connection reset »).
    subprocess.Popen(["/usr/sbin/sshd", "-D", "-p", "22",
                      "-o", "PasswordAuthentication=yes", "-o", "PermitRootLogin=no",
                      "-o", "Subsystem=sftp internal-sftp",
                      "-o", "PerSourcePenalties=no", "-o", "MaxStartups=100"])
    print("SSH en écoute sur 22", flush=True)

    os.makedirs("/var/empty", exist_ok=True)
    subprocess.Popen(["vsftpd", "/etc/vsftpd/vsftpd.conf"])
    print("FTP en écoute sur 21", flush=True)

    print("HTTP en écoute sur 80", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 80), WebHandler).serve_forever()


if __name__ == "__main__":
    main()
