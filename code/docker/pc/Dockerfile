# PC : poste client. Le moteur le démarre avec « sleep infinity » ; on s'en sert
# depuis le terminal de l'interface (busybox fournit déjà ping, nc, wget, nslookup…).
FROM alpine:3.20

# Clients pour tester chaque service d'un serveur à la main :
#   curl (HTTP, HTTPS, FTP, SMTP), openssh-client (ssh, scp, sftp),
#   busybox-extras (telnet, ftpget, ftpput), mariadb-client (MySQL), bind-tools (dig).
# nmap et hydra : pour rejouer une attaque à la main. Les attaques lancées depuis
# l'interface passent toujours par la boîte à outils (docker/toolbox).
RUN apk add --no-cache curl openssh-client busybox-extras mariadb-client bind-tools \
        nmap nmap-scripts hydra
