# Services des serveurs et trafic bénin — IDS Lab

Ce document décrit **ce qui tourne réellement** dans les serveurs de la topologie, **comment** c'est lancé,
**comment le vérifier** à la main, et **ce que fait le trafic bénin** généré par le lab.

> Pourquoi c'est important : un IDS à base de machine learning apprend à partir de flux réseau. Si les
> services sont faux (une simple bannière) ou le trafic « normal » trop pauvre, le modèle apprend des
> artefacts du lab au lieu du comportement d'un vrai réseau. Ici, tous les services connus sont de vrais
> services, et le trafic bénin est fait de vraies sessions d'utilisateurs.

Sommaire :

1. [Déclarer un service sur un serveur](#1-déclarer-un-service-sur-un-serveur)
2. [Les services un par un](#2-les-services-un-par-un)
3. [Compte et contenu de démonstration](#3-compte-et-contenu-de-démonstration)
4. [Vérifier un service à la main](#4-vérifier-un-service-à-la-main)
5. [Le trafic bénin](#5-le-trafic-bénin)
6. [Services et attaques](#6-services-et-attaques)
7. [Exemples de topologies](#7-exemples-de-topologies)
8. [Fonctionnement interne](#8-fonctionnement-interne)
9. [Dépannage](#9-dépannage)
10. [Limites connues](#10-limites-connues)

---

## 1. Déclarer un service sur un serveur

1. Cliquer sur un **Serveur** du schéma.
2. Dans le panneau de droite, section **Ports ouverts**, ajouter un service à partir de la liste proposée
   (le port est prérempli et reste modifiable) :

   | Service proposé | Port | Protocole |
   | --------------- | ---- | --------- |
   | HTTP (web)                   | 80   | TCP |
   | HTTPS (web chiffré)          | 443  | TCP |
   | SSH (accès distant)          | 22   | TCP |
   | FTP (transfert de fichiers)  | 21   | TCP |
   | Telnet                       | 23   | TCP |
   | SMTP (messagerie)            | 25   | TCP |
   | DNS                          | 53   | UDP (le serveur répond aussi en TCP) |
   | MySQL (base de données)      | 3306 | TCP |

3. **✔ Valider la topologie** : les services sont démarrés quand le réseau est créé. Modifier les services
   d'un serveur demande de revalider la topologie.

**Comment le type de service est reconnu.** C'est le **nom** du service qui compte : un service nommé
`ssh` sur le port 2222 est un vrai SSH sur le port 2222. Variantes acceptées : un nom qui commence par
`http` (ex. `http-alt`) est un serveur web, par `https` un serveur web chiffré. Un service **sans nom**
est reconnu par son port usuel (22 → SSH, 443 → HTTPS…). Un nom inconnu (ex. `pop3`) donne un service
**simulé** (voir [section 2](#services-simulés)).

Les PC, routeurs et sondes IDS n'ont aucun service ouvert.

---

## 2. Les services un par un

Résumé :

| Service | Implémentation | Vrai ? |
| ------- | -------------- | ------ |
| HTTP    | serveur web HTTP/1.1 écrit en Python (`http.server`) | ✅ vrai protocole, vrai contenu |
| HTTPS   | le même, chiffré en TLS (certificat auto-signé généré par `openssl`) | ✅ vrai TLS |
| SSH     | **OpenSSH** (`sshd`), avec SFTP | ✅ démon standard |
| FTP     | **vsftpd** | ✅ démon standard |
| Telnet  | **telnetd** (busybox) + `/bin/login` | ✅ démon standard |
| SMTP    | **OpenSMTPD** | ✅ démon standard |
| DNS     | **dnsmasq** | ✅ démon standard |
| MySQL   | **MariaDB** 11 | ✅ démon standard |
| autre nom | simulateur (bannière / écho UDP) | ❌ simulé |

### HTTP — site intranet

- **Serveur** : serveur web HTTP/1.1 de la bibliothèque standard Python, multi-thread, avec **connexions
  persistantes** (plusieurs requêtes sur une même connexion TCP, comme un vrai serveur). Il s'annonce
  comme `nginx/1.26.1` dans l'en-tête `Server` (c'est ce qu'affiche nmap) : c'est un choix de réalisme,
  le serveur reste un serveur Python.
- **Contenu** (`/srv/www`, généré au premier démarrage, identique sur tous les serveurs) :
  - 20 pages : `index`, `produits`, `services`, `contact`, `blog`, `aide`, `article-1` à `article-14`
    (`.html`), de 6 à environ 50 Ko. Chaque page charge `/static/style.css`, `/static/app.js`,
    `/static/logo.png` et 1 à 5 images (`/static/img/image-N.jpg`, de 15 à 400 Ko) ;
  - fichiers à télécharger dans `/downloads/` : `guide.pdf` (450 Ko), `catalogue.pdf` (1,2 Mo),
    `logiciel.zip` (4 Mo), `video.mp4` (9 Mo) ;
  - API JSON : `GET /api/status`, `GET /api/produits?page=N` (200 produits, 20 par page) ;
  - formulaire de connexion : `POST /login` avec `user` et `password` → `302` (redirection + cookie de
    session) si les identifiants sont bons, `401` sinon. `POST` sur une autre adresse renvoie un accusé
    de réception JSON.
- Les images et fichiers sont des octets aléatoires : seule leur **taille** compte pour le trafic.

### HTTPS

- Le même site que HTTP, servi en **TLS**. Le certificat est auto-signé (`CN=<nom-du-serveur>.lab`),
  généré au démarrage par `openssl` : un client doit accepter un certificat non vérifié (`curl -k`).
- Sur le réseau, la sonde ne voit que du TLS chiffré, comme sur un vrai réseau.

### SSH

- **OpenSSH** (`sshd`) avec authentification par mot de passe (`PasswordAuthentication=yes`), connexion
  `root` interdite (`PermitRootLogin=no`), et **SFTP** activé (`internal-sftp`) : `scp` et `sftp`
  fonctionnent.
- Compte : `labuser` / `password123`, shell `/bin/sh`, fichiers de démonstration dans son dossier
  (voir [section 3](#3-compte-et-contenu-de-démonstration)).

### FTP

- **vsftpd** : comptes locaux uniquement (pas d'accès anonyme), **dépôt autorisé** (`write_enable`),
  **mode passif** sur les ports **40000 à 40100** (les transferts de données ouvrent une seconde
  connexion vers l'un de ces ports : c'est normal de les voir dans une capture).
- Compte : `labuser` / `password123`, mêmes fichiers que SSH ; les dépôts vont dans `upload/`.

### Telnet

- **telnetd** (busybox), qui lance `/bin/login` : on se connecte avec `labuser` / `password123` et on
  obtient un shell. Tout passe en clair, y compris le mot de passe (intéressant à montrer dans la capture).

### SMTP

- **OpenSMTPD** : accepte le courrier pour **n'importe quel destinataire** et le distribue dans la boîte
  de `labuser` (`/var/mail/labuser`). Aucun relais vers l'extérieur (le réseau est isolé).
- Pas d'authentification ni de chiffrement (STARTTLS non proposé).

### DNS

- **dnsmasq**, faisant autorité sur le domaine **`lab`** : **chaque équipement de la topologie** a un nom
  `<nom-de-l-équipement>.lab`, construit à partir du nom affiché sur le schéma, en minuscules, les
  caractères spéciaux remplacés par `-`. Exemples : `Serveur-Web` → `serveur-web.lab`,
  `PC 1` → `pc-1.lab`.
- L'adresse donnée est celle de la **première interface** de l'équipement (un routeur a donc un seul nom).
  Les sondes IDS n'ont pas de nom (pas d'adresse fixe).
- Un nom inconnu en `.lab` renvoie `NXDOMAIN` (« ce nom n'existe pas ») ; un nom hors de `.lab`
  (ex. `www.google.com`) n'est pas résolu (pas d'accès à Internet).
- Le serveur répond en UDP et en TCP, à toutes les machines de la topologie, y compris celles situées
  derrière un routeur.

### MySQL

- **MariaDB 11**, à l'écoute sur toutes les adresses. Démarrage un peu plus long (quelques secondes
  après la mise sous tension) : la base est créée au premier démarrage.
- Base **`boutique`**, accessible à `labuser` / `password123` (le compte `root` n'est accessible que
  depuis le serveur lui-même) :

  | Table | Colonnes | Contenu initial |
  | ----- | -------- | --------------- |
  | `produits`  | `id`, `nom`, `prix`, `stock` | 200 produits |
  | `commandes` | `id`, `produit`, `quantite`, `client`, `cree` (horodatage) | vide ; remplie par le trafic bénin |

- MariaDB n'est installé dans l'image que pour être lancé si un service MySQL est déclaré : un serveur
  sans MySQL ne le démarre pas.

### Services simulés

Un service dont le nom n'est pas reconnu (ex. `pop3`, `imap`, `rdp`) est **simulé** : le port est
réellement ouvert, et le serveur envoie une bannière plausible (`+OK POP3 server ready`…) puis garde la
connexion ouverte sans rien faire. En UDP, il renvoie ce qu'il reçoit (écho). C'est suffisant pour qu'un
scan voie le port ouvert, mais il n'y a pas de vrai protocole derrière.

---

## 3. Compte et contenu de démonstration

Tous les services authentifiés (SSH, FTP, Telnet, MySQL, formulaire web) utilisent le même compte :

| Utilisateur | Mot de passe |
| ----------- | ------------ |
| `labuser`   | `password123` |

Le mot de passe est **volontairement faible** : c'est la cible des scénarios de force brute, qui doivent
« réussir » pour illustrer l'attaque. Le réseau du lab est isolé de la machine hôte et d'Internet.

Dossier de `labuser` (`/home/labuser`, visible en SSH, SFTP, FTP et Telnet) :

| Fichier | Taille |
| ------- | ------ |
| `notes.txt` | ~4 Ko (texte) |
| `data/ventes.csv` | ~3 000 lignes |
| `data/rapport.pdf` | 350 Ko |
| `photos/photo-1.jpg` … `photo-5.jpg` | 80 à 900 Ko |
| `backup/archive.tar.gz` | 2,5 Mo |
| `upload/` | vide au départ ; reçoit les dépôts FTP / SFTP |

Le contenu est regénéré à chaque déploiement (les dépôts et courriels précédents sont perdus).

---

## 4. Vérifier un service à la main

Ouvrir un **terminal** en cliquant sur un PC ou un serveur allumé (pastille verte). Les PC disposent de
`curl`, `wget`, `nc`, `nslookup`, `ping` et `traceroute` ; les serveurs ont en plus `ssh`, `mariadb`
et `netstat`. Remplacer les adresses par celles de votre topologie (ici l'exemple « Mini-entreprise » :
Serveur-Web en `10.0.20.10`, Serveur-Fichiers en `10.0.20.11`).

| Service | Depuis un PC | Résultat attendu |
| ------- | ------------ | ---------------- |
| HTTP  | `curl http://10.0.20.10/` | le code HTML de la page d'accueil |
| HTTP (API) | `curl http://10.0.20.10/api/produits?page=2` | du JSON |
| HTTP (connexion) | `curl -i -d "user=labuser&password=password123" http://10.0.20.10/login` | `HTTP/1.1 302 Found` |
| HTTPS | `curl -k https://10.0.20.10/` | la même page, via TLS |
| FTP   | `curl ftp://labuser:password123@10.0.20.11/` | la liste des fichiers |
| FTP (téléchargement) | `curl ftp://labuser:password123@10.0.20.11/notes.txt` | le contenu de `notes.txt` |
| SMTP  | `printf "Subject: test\r\n\r\nBonjour\r\n" > m.txt` puis `curl smtp://10.0.20.11 --mail-from pc-1@lab --mail-rcpt labuser@lab -T m.txt` | pas d'erreur (courriel accepté) |
| DNS   | `nslookup serveur-web.lab 10.0.20.11` | `Address: 10.0.20.10` |
| Telnet | `curl telnet://10.0.20.11:23` | invite `login:` (`Ctrl+C` pour quitter) |
| SSH (bannière) | `nc 10.0.20.11 22` | `SSH-2.0-OpenSSH_…` |
| tout port | `nc -zv 10.0.20.11 21` | `open` |

Depuis le **terminal d'un serveur** (qui a les clients SSH et MySQL) :

```sh
ssh labuser@10.0.20.11                                   # mot de passe : password123
mariadb -h 10.0.20.10 -u labuser -ppassword123 --skip-ssl boutique -e "SELECT * FROM produits LIMIT 5;"
netstat -tlnu                                            # ports en écoute sur CE serveur
cat /var/mail/labuser                                    # courriels reçus (serveur SMTP)
```

Pour **voir le trafic** d'un service : sélectionner le câble du serveur puis **Capturer le trafic**,
et relancer une commande ci-dessus. Les protocoles en clair (HTTP, FTP, SMTP, Telnet, DNS) sont lisibles
dans la capture ; HTTPS, SSH et l'authentification MySQL sont chiffrés ou binaires.

---

## 5. Le trafic bénin

Le trafic bénin est le trafic « normal » de référence : la sonde IDS doit le laisser passer sans alerte.
Il est généré par un **agent** (`backend/app/traffic_agent.py`) qui imite un utilisateur ; on le lance
depuis **📡 Trafic**, et le générateur de datasets (**🗂 Datasets**) le fait tourner pendant toute la durée
d'un dataset.

### Comment on le lance

Dans **📡 Trafic** :

- **Presets** : raccourcis qui cochent des types et choisissent une fréquence (« Navigation web »,
  « Pings réseau », « Connexions services », « Mixte intense ») ;
- **Type de trafic** : `Ping (ICMP)`, `Web (HTTP, HTTPS)`, `Services (SSH, FTP, SMTP, MySQL, DNS…)` ;
- **Fréquence** : voir le tableau plus bas ;
- **Émetteurs** : les équipements qui génèrent du trafic (un agent par émetteur) ;
- **Destinataires** : les équipements visés. Seuls les **services ouverts** des destinataires reçoivent
  des sessions (un PC n'a pas de service : il ne reçoit que des pings).

**▶ Démarrer** lance un agent par émetteur ; le bouton 📡 Trafic reste jaune « (actif) » tant qu'un agent
tourne. **■ Tout arrêter** ou **Arrêter** (par émetteur) les arrêtent.

L'agent tourne dans un conteneur à part qui **partage l'adresse IP de l'émetteur** : pour le réseau et
pour la sonde, c'est bien l'émetteur qui parle. Rien n'est installé sur l'équipement lui-même.

### Ce que fait l'agent

Chaque action est une **session complète** avec un vrai client, contre les vrais services décrits plus
haut :

| Type coché | Session | Détail |
| ---------- | ------- | ------ |
| Web | **API** (12 % des sessions web) | 2 à 8 appels à `/api/status` ou `/api/produits` sur la même connexion |
| Web | **Connexion par formulaire** (8 %) | ouvre `contact.html`, envoie `POST /login`, puis navigue ; se trompe de mot de passe 15 % du temps et réessaie |
| Web | **Navigation** (le reste) | 1 à 4 pages ; pour chaque page : la page puis ses ressources (style, script, logo, images) **sur la même connexion**, comme un navigateur ; 10 % de chances de télécharger un fichier ; temps de lecture entre deux pages |
| Services | **SSH : commandes** (70 %) | connexion réussie, 1 à 5 commandes (`ls`, `cat notes.txt`, `df -h`, `uptime`…) séparées de pauses de frappe |
| Services | **SSH : copie** (30 %) | `scp` (SFTP) : téléchargement d'un fichier (70 %) ou dépôt d'un fichier de 5 Ko à 1,5 Mo (30 %) |
| Services | **FTP** | connexion, listing, puis 1 à 3 transferts : téléchargement (75 %) ou dépôt de 2 Ko à 800 Ko (25 %) |
| Services | **SMTP** | un courriel de 3 à 400 lignes à `equipe`, `support`, `direction`, `compta` ou `labuser` `@lab` ; pièce jointe de 20 à 600 Ko dans 30 % des cas |
| Services | **MySQL** | connexion à `boutique`, 1 à 6 requêtes (lecture de produits, commande passée, mise à jour du stock…), parfois des pauses entre les requêtes |
| Services | **Telnet** | connexion, 1 à 3 commandes, déconnexion |
| Services | **DNS** | 60 % des sessions commencent par la résolution du nom du serveur visé (`serveur-web.lab`) ; en plus, quelques requêtes isolées (8 % des actions), dont 20 % pour un nom inexistant et 25 % de type AAAA (IPv6) |
| Services | autre service (simulé) | ouverture de connexion, lecture de la bannière, fermeture |
| Ping | **ICMP** | 1 à 4 pings ; taille 56 octets le plus souvent, parfois 100, 500 ou 1000 |

Le **DNS** n'est utilisé que si l'un des destinataires a un service DNS et que le type « Services » est
coché.

**Poids des sessions** : quand un émetteur choisit sa prochaine action, la navigation web domine,
comme sur un vrai réseau :

| HTTP | HTTPS | SSH | MySQL | FTP | SMTP | Ping | Telnet | autre |
| ---- | ----- | --- | ----- | --- | ---- | ---- | ------ | ----- |
| 5    | 5     | 2   | 2     | 1,5 | 1,5  | 1,5  | 0,5    | 0,5   |

**Erreurs de mot de passe.** Un vrai utilisateur se trompe parfois : en SSH, FTP et MySQL, une connexion
sur 20 commence par **un** mauvais mot de passe, suivi du bon. Ce n'est pas une force brute (une seule
erreur, puis une connexion réussie) : c'est volontaire, pour que l'IDS apprenne la différence et ne
lève pas d'alerte au premier échec.

### Fréquence

| Fréquence | Pause entre deux sessions | Temps de lecture / frappe | Sessions en parallèle |
| --------- | ------------------------- | ------------------------- | --------------------- |
| Lente     | 8 à 12 s    | normal (×1)    | 1 |
| Modérée   | 2 à 4 s     | ×0,6           | 1 |
| Soutenue  | 0,6 à 1,4 s | ×0,35          | 2 |
| Intense   | 0,2 à 0,45 s | ×0,15         | 3 |

Les « sessions en parallèle » imitent un utilisateur qui fait plusieurs choses à la fois (plusieurs
onglets, un transfert pendant la navigation).

### Pendant la génération d'un dataset

- Le trafic bénin tourne pendant **toute** la durée du dataset, y compris pendant les attaques.
- Pendant une attaque, l'agent bénin de la **machine d'attaque** est mis en pause : ainsi, tout flux de la
  source vers la cible pendant la fenêtre de l'attaque est bien de l'attaque, et l'étiquetage est exact.
- Les **variantes de test** changent, entre autres, l'intensité du trafic bénin.

---

## 6. Services et attaques

Les scénarios (**⚡ Scénarios**, **🗂 Datasets**) visent ces mêmes services :

| Attaque | Service visé | Outil | Ce qui se passe |
| ------- | ------------ | ----- | --------------- |
| Balayage de découverte | — (tout le sous-réseau) | nmap | découverte des machines allumées |
| Scan de ports (connect) | 200 ports les plus courants | nmap `-sT` | les ports ouverts apparaissent |
| Scan de ports furtif (SYN) | tous les ports | nmap `-sS` | idem, sans connexion complète |
| Identification des services | tous les ports ouverts | nmap `-sV` | nmap reconnaît les vrais services (OpenSSH, vsftpd, MariaDB, « nginx »…) |
| Scan approfondi | tous | nmap `-A` | identification + scripts + système |
| Force brute SSH | SSH (22) | hydra | 8 mots de passe essayés ; le dernier (`password123`) réussit |
| Force brute FTP | FTP (21) | hydra | idem sur vsftpd |

Pour que les forces brutes fonctionnent, la cible doit avoir le service correspondant (un service nommé
`ssh` ou `ftp`).

---

## 7. Exemples de topologies

| Exemple | Serveur | Services |
| ------- | ------- | -------- |
| Petit LAN avec serveur web | Serveur-Web | HTTP |
| Mini-entreprise : LAN, DMZ et sonde IDS | Serveur-Web | HTTP, HTTPS, MySQL |
|                                         | Serveur-Fichiers | FTP, SSH, SMTP, DNS |

« Mini-entreprise » expose tous les protocoles : c'est l'exemple à utiliser pour générer des datasets
riches. Les autres exemples n'ont pas de serveur (seulement du ping) : on peut y ajouter un serveur et
ses services.

---

## 8. Fonctionnement interne

| Élément | Fichier |
| ------- | ------- |
| Démarrage des services dans un serveur | `backend/app/service_listener.py` |
| Agent de trafic bénin | `backend/app/traffic_agent.py` |
| Lancement / arrêt des agents, scénarios d'attaque | `backend/app/traffic.py` |
| Images Docker et paquets installés | `backend/config/devices.toml` |
| Liste des services proposés dans l'interface | `src/config/deviceTypes.js` (`SERVICE_PRESETS`) |
| Cibles du trafic (IP et services des destinataires) | `src/utils/trafficTargets.js` |

**Démarrage d'un serveur.** Au déploiement, le moteur crée le conteneur du serveur avec comme commande
`service_listener.py`, à qui il passe deux arguments : la liste des services déclarés (port, protocole,
nom) et l'**annuaire** de la topologie (nom de chaque équipement → adresse IP, pour le DNS). Le script
lance chaque démon, puis reste actif. Son journal (`docker logs idslab-server-N`) indique ce qui a
démarré, par exemple :

```
HTTP réel en écoute sur 80
HTTPS réel en écoute sur 443
MySQL (MariaDB) réel en écoute sur 3306 — base « boutique », compte labuser
```

Si un démon manque dans l'image ou échoue au démarrage, le service retombe sur le simulateur et le
journal l'indique (`service … (simulé) en écoute sur …`).

**Images.** Les serveurs utilisent `python:3.12-alpine` enrichie des paquets `openssh`, `vsftpd`,
`busybox-extras` (telnetd), `opensmtpd`, `dnsmasq`, `mariadb`, `mariadb-client`, `openssl`, `curl` et
`shadow`. L'agent de trafic utilise une image à part (`[traffic]` dans `devices.toml`) avec `curl`,
`openssh-client`, `sshpass` et `mariadb-client` ; FTP, SMTP, DNS et Telnet passent par la bibliothèque
standard Python. Ces images sont construites **une seule fois**, au premier déploiement qui en a besoin,
puis mises en cache (le premier déploiement est donc plus long). Changer la liste des paquets dans
`devices.toml` reconstruit automatiquement l'image.

**Correspondance nom → service.** Le serveur (`service_kind` dans `service_listener.py`) et l'agent
(`service_kind` dans `traffic_agent.py`) appliquent la même règle (nom, puis port usuel si pas de nom) ;
les tests `backend/tests/test_benign.py` vérifient qu'ils restent d'accord.

---

## 9. Dépannage

| Symptôme | Cause / solution |
| -------- | ---------------- |
| Un service ne répond pas juste après la validation | MySQL met quelques secondes à démarrer (création de la base) : réessayer. |
| `curl: (60) SSL certificate problem` en HTTPS | Certificat auto-signé : ajouter `-k`. |
| `nslookup` ne répond pas | Vérifier qu'un serveur a bien un service `dns` et que la topologie a été **revalidée** depuis. |
| Un service s'affiche « simulé » dans le journal du serveur | Nom de service non reconnu (voir [section 1](#1-déclarer-un-service-sur-un-serveur)) ou démon absent de l'image. |
| Le trafic bénin ne touche pas un serveur | Le serveur n'est pas coché dans **Destinataires**, le type correspondant (Web / Services) n'est pas coché, ou le serveur n'a pas ce service. |
| Rien n'est capturé dans un dataset pour un service | La sonde ne voit que le trafic qui passe par son point de capture : choisir la Sonde IDS reliée au switch des serveurs. |
| Voir ce que fait un agent bénin | `docker logs <conteneur>` (conteneurs portant le label `idslab.role=traffic`) : seules les sessions en erreur y sont journalisées. |

---

## 10. Limites connues

- **Un seul compte** (`labuser`) : tous les utilisateurs simulés se connectent avec lui.
- **Contenu synthétique** : les images et fichiers sont des octets aléatoires ; seuls leur nombre et leur
  taille ressemblent à un vrai site.
- **Pas de Internet** : pas de DNS externe, pas de mise à jour, pas de trafic sortant.
- **SMTP sans authentification ni STARTTLS**, MySQL sans TLS (`--skip-ssl` côté client).
- **Comportement humain approché** : les pauses et les choix sont aléatoires, mais il n'y a ni cycle
  jour/nuit, ni profils d'utilisateurs différents (comptable, développeur…). Ce sont des pistes pour
  enrichir encore le trafic bénin.
- Les services UDP autres que DNS sont simulés (écho) et ne reçoivent pas de trafic bénin.
