# Boîte à outils : conteneur éphémère lancé « dans » un équipement (il partage sa pile
# réseau : même IP, mêmes interfaces), sans rien installer dans l'équipement lui-même.
# Il sert à :
#   - générer du trafic bénin (backend/app/traffic_agent.py, d'où Python) ;
#   - lancer les attaques : nmap (reconnaissance), hydra (force brute) ;
#   - capturer le trafic : tcpdump (datasets, détection en direct) ;
#   - passer un switch en mode « hub » (service hub-mode des docker-compose.yml).
FROM python:3.12-alpine

# sshpass + openssh-client : sessions SSH du trafic bénin (HTTP et FTP passent par Python).
RUN apk add --no-cache nmap nmap-scripts hydra tcpdump openssh-client sshpass
