"""
Simulateur de services, exécuté DANS chaque serveur de la topologie
(python3 -c <ce fichier> '<services JSON>').

Ouvre réellement chaque port déclaré dans l'interface et répond de façon
plausible (bannière SSH/FTP/SMTP, réponse HTTP…), afin qu'un scan ou une
connexion produise un trafic réaliste observable par la sonde IDS.

Autonome : uniquement la bibliothèque standard.
"""

import json
import socket
import sys
import threading

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
    threads = []
    for svc in services:
        target = serve_udp if svc.get("protocol") == "udp" else serve_tcp
        name = (svc.get("name") or "").strip().lower()
        t = threading.Thread(target=target, args=(int(svc["port"]), name), daemon=True)
        t.start()
        threads.append(t)
        print(f"service {name or '?'} en écoute sur {svc['port']}/{svc.get('protocol', 'tcp')}", flush=True)
    threading.Event().wait()  # le serveur reste allumé même sans service


if __name__ == "__main__":
    main()
