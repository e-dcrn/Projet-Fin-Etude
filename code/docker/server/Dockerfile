# Serveur : chaque service ouvert est un vrai service, lancé par
# backend/app/service_listener.py (que le moteur passe en commande au démarrage).
FROM python:3.12-alpine

# openssh (SSH), vsftpd (FTP), busybox-extras (telnetd), opensmtpd (SMTP), dnsmasq (DNS),
# mariadb (MySQL), openssl (certificat du site HTTPS). HTTP/HTTPS : serveur web Python.
# shadow : useradd/chpasswd pour le compte de démonstration. curl : tests depuis le terminal.
RUN apk add --no-cache openssh vsftpd busybox-extras opensmtpd dnsmasq mariadb mariadb-client \
        openssl shadow curl
