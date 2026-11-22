# Serveur : trois vrais services, lancés par services.py.
#   HTTP : petit site web écrit en Python (bibliothèque standard)
#   SSH  : OpenSSH
#   FTP  : vsftpd
FROM python:3.12-alpine

RUN apk add --no-cache openssh vsftpd

# Compte de démonstration (réseau ISOLÉ, mot de passe volontairement faible :
# la force brute doit « réussir » pour illustrer l'attaque).
RUN adduser -D -s /bin/sh labuser && echo "labuser:password123" | chpasswd

# Clés d'hôte SSH, et configuration du serveur FTP.
RUN ssh-keygen -A
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf

COPY services.py /services.py
CMD ["python3", "-u", "/services.py"]
