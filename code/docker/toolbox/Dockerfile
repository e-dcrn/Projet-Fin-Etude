# Boîte à outils : conteneur éphémère lancé « dans » un équipement (il partage sa pile
# réseau : même IP, mêmes interfaces), sans rien installer dans l'équipement lui-même.
# Il sert à :
#   - générer du trafic bénin (backend/app/traffic_agent.py, d'où Python) ;
#   - lancer les attaques : nmap (reconnaissance), hydra (force brute) ;
#   - capturer le trafic : tcpdump (capture d'un lien, datasets, détection en direct) ;
#   - passer un switch en mode « hub » au déploiement (voir deployer._enable_hub_mode).
FROM python:3.12-alpine

# Clients du trafic bénin : curl (web), openssh-client + sshpass (SSH, SFTP),
# mariadb-client (MySQL) ; FTP, SMTP, DNS et Telnet passent par la bibliothèque Python.
RUN apk add --no-cache nmap nmap-scripts hydra tcpdump curl openssh-client sshpass mariadb-client
