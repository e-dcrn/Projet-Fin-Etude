# IDS Lab – Éditeur et simulateur de topologie

Démonstrateur pédagogique d'attaques contre un IDS basé sur du machine learning.
On construit une topologie réseau par glisser-déposer, à la manière de Cisco Packet Tracer
(interface web, React), puis le **moteur de simulation** (`backend/`, Python) l'instancie
réellement avec Docker : chaque équipement devient une machine qui génère du vrai trafic.

> L'interface ne parle jamais de Docker : pour l'utilisateur, il configure de vrais équipements.

## Démarrage rapide

L'application a deux parties, lancées chacune dans **son propre terminal** :

| Partie | Rôle | Commande | Adresse |
| ------ | ---- | -------- | ------- |
| Moteur de simulation (`code/backend/`, Python) | crée réellement le réseau avec Docker | `uvicorn app.main:app --port 8000 --reload` | http://localhost:8000/api |
| Interface (`code/`, React) | éditeur de topologie dans le navigateur | `npm run dev` | http://localhost:5173 |

Première installation : suivre dans l'ordre [Prérequis](#prérequis), [1. Moteur](#1-lancer-le-moteur-de-simulation-backend),
[2. Interface](#2-lancer-linterface) et [3. Premier essai](#3-premier-essai).
Ensuite, il suffit de relancer les deux commandes ci-dessus (moteur d'abord, Docker démarré).

## Prérequis

| Outil | Version | Vérifier | Installer |
| ----- | ------- | -------- | --------- |
| **Docker** | Docker Desktop (macOS, Windows) ou Docker Engine (Linux), **démarré** | `docker info` (pas d'erreur) | [docker.com](https://docs.docker.com/get-docker/) |
| **Python** | 3.9 ou plus récent | `python3 --version` (Windows : `py --version`) | [python.org](https://www.python.org/downloads/) |
| **Node.js** | 20.19+ ou 22.12+ (22 LTS recommandé), avec `npm` | `node -v` | voir ci-dessous |
| **Git** | — | `git --version` | [git-scm.com](https://git-scm.com/) |

- **Internet** est nécessaire au premier déploiement : le moteur télécharge les images des équipements
  et y ajoute quelques outils (`curl`, `tcpdump`), soit environ 100 Mo, mis en cache ensuite.
- **Linux** : l'utilisateur doit pouvoir utiliser Docker sans `sudo`
  (`sudo usermod -aG docker $USER`, puis se reconnecter).
- **Systèmes testés** : macOS avec Docker Desktop. Linux devrait fonctionner à l'identique.
  Windows n'a pas été testé : en cas de problème, utiliser WSL 2 (Ubuntu) et y suivre les commandes Linux.

Node.js trop ancien ? Vite 8 refuse de démarrer en dessous de 20.19 :

- avec [nvm](https://github.com/nvm-sh/nvm) (macOS / Linux) : `cd code && nvm install && nvm use` (lit le fichier `.nvmrc`) ;
- avec [nvm-windows](https://github.com/coreybutler/nvm-windows) : `nvm install 22` puis `nvm use 22` ;
- sinon : installer la version LTS depuis [nodejs.org](https://nodejs.org/).

Récupérer le projet :

```bash
git clone https://github.com/e-dcrn/Projet-Fin-Etude.git
cd Projet-Fin-Etude
```

## 1. Lancer le moteur de simulation (backend)

Depuis la racine du dépôt, **Docker démarré** :

```bash
cd code/backend
python3 -m venv .venv                         # une seule fois : environnement Python isolé
source .venv/bin/activate                     # à chaque nouveau terminal
pip install -r requirements.txt               # une fois, puis après un pull qui modifie requirements.txt
uvicorn app.main:app --port 8000 --reload     # laisser ce terminal ouvert
```

Sous Windows (PowerShell), remplacer les deux premières lignes après `cd` par `py -m venv .venv` et
`.venv\Scripts\Activate.ps1` (si PowerShell refuse : `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`).

Le moteur est prêt quand le terminal affiche `Application startup complete`. Vérification :
http://localhost:8000/api/health doit répondre `{"ok":true}` (sinon, voir [Dépannage](#dépannage)).

`--reload` redémarre le moteur à chaque modification du code (`app/`). Sans cette option, il faut
l'arrêter (`Ctrl+C`) et le relancer après un `git pull` : sinon il garde l'ancienne version, et les
fonctions ajoutées depuis (terminal, capture…) sont refusées (« le moteur a refusé la connexion »).

Tests (n'ont pas besoin de Docker) : `pip install -r requirements-dev.txt` puis `python -m pytest`.

## 2. Lancer l'interface

Dans un **second terminal**, depuis la racine du dépôt :

```bash
cd code
npm ci           # une fois, puis après chaque pull qui modifie package-lock.json
npm run dev      # laisser ce terminal ouvert
```

Ouvrir **http://localhost:5173** (le navigateur s'ouvre normalement tout seul). La barre d'outils doit
indiquer « Réseau arrêté » ; « Moteur de simulation hors ligne » signifie que l'étape 1 n'a pas abouti.
Les modifications du code sont rechargées à chaud. `Ctrl+C` pour arrêter le serveur.

> `npm ci` et `npm install` donnent le même résultat sur un clone propre ; `npm ci` est préférable
> car il respecte strictement le `package-lock.json`, ce qui garantit que les deux membres du
> binôme ont exactement les mêmes dépendances. Utiliser `npm install <paquet>` uniquement pour
> **ajouter** une dépendance, puis commiter `package.json` **et** `package-lock.json`.

Autres commandes :

| Commande          | Rôle                                             |
| ----------------- | ------------------------------------------------ |
| `npm run dev`     | Serveur de développement (hot reload)            |
| `npm run build`   | Build de production dans `dist/`                 |
| `npm run preview` | Sert le build de production en local pour tester |

## 3. Premier essai

1. Glisser depuis la palette (à gauche) un **PC**, un **Switch** puis un second **PC** sur le canvas.
2. Cliquer sur **🔌 Câble**, puis sur PC-1 et sur Switch-1 ; puis sur PC-2 et sur Switch-1. Les adresses
   IP sont attribuées automatiquement (`10.0.1.10`, `10.0.1.11`). `Échap` pour quitter le mode câble.
3. **✔ Valider la topologie** : le réseau est créé (le premier lancement est plus long, voir Prérequis).
   Les équipements allumés portent une pastille verte.
4. Cliquer sur **PC-1** : son terminal s'ouvre en bas. Taper `ping -c 3 10.0.1.11`.
5. Sélectionner le câble PC-2 ↔ Switch-1 puis **Capturer le trafic** (ou double-clic sur le câble),
   relancer le ping depuis PC-1 : les paquets ICMP apparaissent dans la capture.
6. **■ Arrêter** (barre d'outils) éteint le réseau.

## Arrêter et nettoyer

- **■ Arrêter** dans l'interface supprime toutes les machines et réseaux créés. `Ctrl+C` dans les deux
  terminaux arrête l'interface et le moteur ; un réseau en cours de fonctionnement reste alors allumé
  (il réapparaît au prochain lancement du moteur et peut être arrêté depuis l'interface).
- Tout ce que le projet crée dans Docker porte le label `idslab.managed=true`. Nettoyage manuel complet
  (moteur arrêté ; « requires at least 1 argument » signifie simplement qu'il n'y a rien à supprimer) :

```bash
docker rm -f $(docker ps -aq --filter label=idslab.managed=true)
docker network rm $(docker network ls -q --filter label=idslab.managed=true)
docker image rm $(docker image ls -q 'idslab/*')   # images construites (curl, tcpdump) ; recréées au besoin
```

## Configuration (optionnelle)

Rien n'est à configurer pour un usage local. Pour adapter :

| Où | Variable / fichier | Rôle |
| -- | ------------------ | ---- |
| Interface : `code/.env` (non versionné, partir de `cp .env.example .env`) | `VITE_API_BASE_URL` | URL du moteur (défaut `http://localhost:8000/api`) |
| Moteur : variable d'environnement | `IDSLAB_CORS_ORIGINS` | origines autorisées à utiliser le moteur, séparées par des virgules (défaut : toute page servie depuis `localhost` / `127.0.0.1`, quel que soit le port) |
| Moteur : variable d'environnement | `IDSLAB_DEVICES_CONFIG` | autre fichier de configuration des équipements (défaut `backend/config/devices.toml`) |
| Moteur : `backend/config/devices.toml` | — | image Docker et outils de chaque type d'équipement, outil de capture |

## Dépannage

| Symptôme | Cause / solution |
| -------- | ---------------- |
| « Moteur de simulation hors ligne » dans la barre d'outils | Le moteur n'est pas lancé (étape 1), ou Docker n'est pas démarré (`docker info`). |
| `permission denied … docker.sock` (Linux) | L'utilisateur n'est pas dans le groupe `docker` : voir [Prérequis](#prérequis). |
| `python3: command not found` (Windows) | Utiliser `py` à la place de `python3`. |
| `uvicorn: command not found` | L'environnement Python n'est pas activé : `source .venv/bin/activate` (dans `code/backend`). |
| `address already in use` au lancement du moteur | Un autre moteur tourne déjà sur le port 8000 : l'arrêter (`Ctrl+C` dans son terminal). |
| `NotOpenSSLWarning: urllib3 v2 only supports OpenSSL…` | Avertissement du Python fourni par macOS, sans conséquence. |
| « Le moteur de simulation a refusé la connexion » (terminal, capture) | Le moteur a été lancé avant une mise à jour du code et sans `--reload` : le relancer. |
| Premier déploiement très long, ou « vérifiez la connexion Internet » | Téléchargement des images (voir Prérequis) : vérifier l'accès à Internet. |
| « … déjà utilisé sur la machine hôte » au déploiement | Le réseau d'un switch chevauche un réseau Docker existant (ex. `172.17.0.0/16`) : changer le réseau du switch. |
| `npm error engine Unsupported engine` ou `Vite requires Node.js version…` | Node trop ancien : voir [Prérequis](#prérequis). |
| `Port 5173 is in use` | Un autre serveur tourne déjà : Vite prend automatiquement le port suivant (regarder l'URL affichée dans le terminal) ; le moteur l'accepte. |
| Erreur `Cannot find module @rolldown/binding-…` | `node_modules` copié depuis une autre machine/OS : supprimer `node_modules` puis relancer `npm ci`. |
| `npm warn allow-scripts … fsevents` (macOS) | Avertissement sans conséquence : `fsevents` est une dépendance optionnelle livrée précompilée. Rien à faire. |
| Page blanche | Ouvrir la console du navigateur (F12) pour voir l'erreur. |

## Utilisation

| Action                      | Comment                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| Ajouter un équipement       | Glisser un élément de la palette (gauche) sur le canvas : l'icône se pose là où on la lâche |
| Déplacer                    | Glisser l'équipement sur le canvas                                       |
| Relier                      | Bouton **🔌 Câble**, puis clic sur un équipement, puis sur un **switch** (ou l'inverse) |
| Annuler / quitter le câblage | `Échap` (1ᵉʳ appui : annule le câble en cours ; 2ᵉ appui : quitte le mode) |
| Configurer                  | Cliquer sur un équipement ou un câble : le panneau de droite s'affiche   |
| Supprimer                   | Sélectionner un équipement ou un câble, puis `Suppr` / `Retour arrière`, ou le bouton du panneau |
| Créer le réseau             | **✔ Valider la topologie** : bilan des problèmes, puis création avec barre de progression |
| Éteindre le réseau          | **■ Arrêter** (visible quand le réseau est en fonctionnement)            |
| Ouvrir un terminal          | Cliquer sur un **PC** ou un **serveur** allumé (pastille verte) : son terminal s'ouvre dans un onglet en bas de l'écran (`ping`, `traceroute`, `curl`, `ip route`…) |
| Capturer le trafic d'un lien | Sélectionner un câble puis **Capturer le trafic** (ou double-clic sur le câble), réseau démarré : vue « Wireshark » dans un onglet du panneau du bas ; le câble capturé est animé |
| Gérer les onglets du bas    | Un onglet par terminal ou capture, les sessions continuent en arrière-plan ; `×` ferme la session (et arrête ce qui y tourne) ; glisser le bord supérieur du panneau pour le redimensionner |

### Modèle : nœuds, réseaux et interfaces

- Un **switch est un réseau** (un segment de niveau 2). Les autres équipements sont des nœuds.
- Un **câble relie toujours un nœud à un switch** ; on ne relie pas deux PC ni deux switches entre eux.
- Chaque câble est une **interface** du nœud (`eth0`, `eth1`… attribués automatiquement) et porte
  sa configuration : **adresse IP et masque**. Un routeur relié à trois switches a trois interfaces,
  chacune avec sa propre adresse.
- Un câble a **deux extrémités**, affichées sur le canvas : l'**interface de l'équipement** (`eth0`…)
  et le **port du switch** (`Fa0/1`, `Fa0/2`…, attribués automatiquement, comme dans Packet Tracer).
- Un switch (niveau 2) **n'a pas d'adresse IP**. Il porte le **réseau** (LAN) des équipements qui y sont
  branchés (`réseau 10.0.1.0/24` sous son icône) : leurs interfaces doivent appartenir à ce réseau.

### Adressage automatique (IPAM)

Aucune adresse n'est à saisir : l'IPAM (`src/utils/ipam.js`) les attribue au fil de la construction.

| Élément | Attribution automatique |
| ------- | ----------------------- |
| Switch  | premier réseau libre à sa création : `10.0.1.0/24`, `10.0.2.0/24`… (modifiable : les adresses automatiques suivent) |
| Interface de routeur | premières adresses du réseau : `.1`, `.2`… (les passerelles) |
| Interface de PC / serveur | à partir de `.10` |
| Passerelle d'un PC / serveur | adresse du routeur relié au même switch |
| Sonde IDS | pas d'adresse fixe (elle écoute le segment) |

- Les attributions sont **stables** : une adresse automatique ne change pas tant qu'elle reste valide ;
  seules les interfaces nouvelles, ou devenues invalides (réseau du switch modifié, conflit), sont réadressées.
- **Saisir** une adresse, un masque ou une passerelle passe le champ en **mode manuel** (badge
  « manuel ») : l'IPAM ne le modifie plus et n'attribue jamais cette adresse à un autre équipement.
  **↺ Automatique** rend la main à l'IPAM.
- La dernière adresse de chaque réseau (`.254` en /24) n'est jamais attribuée : le moteur la réserve au segment.
- Les tables de routage des routeurs restent à saisir (seuls les réseaux directement connectés sont routés d'office).

### Configuration par équipement

| Équipement | Éditable |
| ---------- | -------- |
| PC         | nom ; IP + masque par interface (automatiques par défaut) ; passerelle par défaut (automatique : routeur du même switch) |
| Serveur    | idem PC ; **ports ouverts** (service, port, TCP/UDP) — les ports répondent réellement (bannière SSH/FTP/SMTP, page HTTP…) |
| Routeur    | nom ; interfaces nommées (`eth0`, `eth1`… renommables) avec IP + masque ; **table de routage** (destination, passerelle, interface de sortie). Les réseaux directement connectés sont affichés (« C ») |
| Switch     | nom ; **réseau des équipements branchés** (attribué automatiquement, modifiable) ; VLAN optionnel (1–4094, informatif) ; ports occupés (`Fa0/1 → PC-1 eth0`) |
| Sonde IDS  | nom ; **segment surveillé** (un switch auquel elle est reliée) ; IP facultative (attribuée automatiquement si vide) |

Les contrôles de cohérence (IP invalides ou en double, sous-réseaux incohérents ou qui se chevauchent,
passerelle injoignable, route vers une interface inexistante…) s'affichent en direct dans le panneau
de l'élément concerné ; les **erreurs** bloquent la création du réseau, les **avertissements** non.
Le serveur refait les mêmes vérifications.

## Format JSON (contrat interface ↔ backend, version 2)

```json
{
  "version": 2,
  "generatedAt": "2026-10-10T09:00:00.000Z",
  "nodes": [
    { "id": "pc-1", "type": "pc", "name": "PC-1", "position": { "x": 120, "y": 80 },
      "config": { "gateway": "10.0.1.1" } },
    { "id": "server-1", "type": "server", "name": "Serveur-1", "position": { "x": 520, "y": 80 },
      "config": { "gateway": "10.0.2.1", "services": [{ "port": 80, "protocol": "tcp", "name": "http" }] } },
    { "id": "router-1", "type": "router", "name": "Routeur-1", "position": { "x": 320, "y": 240 },
      "config": { "routes": [{ "destination": "10.0.3.0/24", "gateway": "10.0.2.254", "interface": "eth1" }] } },
    { "id": "ids-1", "type": "ids", "name": "IDS-1", "position": { "x": 520, "y": 400 },
      "config": { "monitoredSegment": "switch-2" } }
  ],
  "networks": [
    { "id": "switch-1", "name": "Switch-1", "position": { "x": 120, "y": 240 }, "vlan": null, "subnet": "10.0.1.0/24" },
    { "id": "switch-2", "name": "Switch-2", "position": { "x": 520, "y": 240 }, "vlan": 20, "subnet": "10.0.2.0/24" }
  ],
  "links": [
    { "id": "link-pc-1-switch-1", "node": "pc-1", "network": "switch-1", "interface": "eth0", "port": "Fa0/1", "ip": "10.0.1.10", "mask": "255.255.255.0" },
    { "id": "link-router-1-switch-1", "node": "router-1", "network": "switch-1", "interface": "eth0", "port": "Fa0/2", "ip": "10.0.1.1", "mask": "255.255.255.0" },
    { "id": "link-router-1-switch-2", "node": "router-1", "network": "switch-2", "interface": "eth1", "port": "Fa0/1", "ip": "10.0.2.1", "mask": "255.255.255.0" },
    { "id": "link-server-1-switch-2", "node": "server-1", "network": "switch-2", "interface": "eth0", "port": "Fa0/2", "ip": "10.0.2.20", "mask": "255.255.255.0" },
    { "id": "link-ids-1-switch-2", "node": "ids-1", "network": "switch-2", "interface": "eth0", "port": "Fa0/3", "ip": "", "mask": "" }
  ]
}
```

`mask` accepte `255.255.255.0`, `/24` ou `24`. `subnet` (réseau du switch) est facultatif pour le
moteur : vide, il est déduit des adresses des interfaces reliées. `port` (port du switch) est informatif. `position` (coordonnées du canvas, milieu du bord
supérieur de l'équipement) ne sert qu'à l'affichage.

## Moteur de simulation (backend)

### Correspondance équipements → Docker

| Topologie | Instanciation |
| --------- | ------------- |
| Switch    | réseau Docker `bridge` (plage = réseau du switch) |
| PC / serveur | container attaché à ses réseaux, avec les IP choisies ; la route par défaut pointe vers la passerelle configurée (sans passerelle : pas de route par défaut) |
| Routeur   | container multi-réseaux, `net.ipv4.ip_forward=1`, interfaces nommées comme dans l'UI, routes statiques appliquées |
| Serveur   | + simulateur de services (`app/service_listener.py`) qui ouvre réellement les ports déclarés |
| Sonde IDS | container attaché au segment, interface en mode promiscuous ; le bridge du segment est passé en **mode hub** (`ageing_time = 0`) pour que la sonde reçoive une copie de tout le trafic (équivalent d'un port miroir) |

Les images par type sont définies dans **`backend/config/devices.toml`** (jamais exposé à l'interface).
Les machines n'ont pas d'accès à Internet : seules les routes configurées dans l'UI existent.
Une adresse de chaque sous-réseau (la plus haute libre) est réservée au pont Docker côté hôte :
un sous-réseau doit donc garder au moins une adresse libre.

### API et suivi de la progression

| Méthode | Route | Rôle |
| ------- | ----- | ---- |
| `POST`  | `/api/deployments` | Valide la topologie (400 + `errors` si incohérente), lance la création en tâche de fond → `{ id }` |
| `GET`   | `/api/deployments/{id}/events` | Progression en **Server-Sent Events** : `progress {step, total, label}`, `warning`, `done`, `error` |
| `GET`   | `/api/lab` | État du réseau instancié (équipements allumés) |
| `DELETE`| `/api/lab` | Éteint et supprime le réseau |
| `GET`   | `/api/health` | Disponibilité du moteur |
| `WS`    | `/api/devices/{id}/terminal?cols=&rows=` | Terminal interactif sur un PC ou un serveur allumé |
| `WS`    | `/api/devices/{id}/interfaces/{interface}/capture` | Capture du trafic d'un lien (paquets bruts) |

La création est longue (téléchargements, démarrages) : elle tourne dans un thread, et l'interface
suit les événements avec `EventSource` (reprise automatique après coupure grâce à `Last-Event-ID`).
Un seul déploiement à la fois ; chaque déploiement supprime d'abord le précédent, et un échec
nettoie tout ce qui avait été créé. Toutes les ressources portent le label `idslab.managed=true`.

### Terminal des équipements

Chaque onglet de terminal ouvre une **WebSocket** ; le backend lance un shell dans la machine
(`exec` Docker avec TTY) et relaie les octets dans les deux sens (`app/terminal.py`) :

- navigateur → serveur : messages JSON `{"type": "input", "data"}` (frappes) et `{"type": "resize", "cols", "rows"}` ;
- serveur → navigateur : sortie brute du terminal en messages binaires (affichée par **xterm.js**),
  et messages JSON `ready`, `exit` (`exit` tapé, équipement éteint) ou `error` (`message` affichable).

Chaque session a son propre shell et son propre thread de lecture : plusieurs terminaux peuvent être
ouverts en même temps, y compris sur la même machine. À la fermeture de l'onglet, tous les processus
lancés depuis la session (un `ping` en cours…) sont arrêtés. L'en-tête `Origin` est contrôlé
(mêmes règles que CORS, voir `IDSLAB_CORS_ORIGINS`) : un site web ouvert dans le navigateur ne peut pas obtenir de shell.

### Capture du trafic d'un lien (vue « Wireshark »)

Un lien relie l'interface d'un équipement (`eth0`…) au port d'un switch : la capture se fait sur
cette interface. Un **conteneur d'analyse éphémère** partage la pile réseau de l'équipement
(`network_mode=container:…`) et y lance `tcpdump` (`app/capture.py`) : rien n'est installé ni visible
dans l'équipement. Son image (`[capture]` dans `devices.toml`) est préparée au déploiement.

- Le flux pcap est découpé en paquets et relayé par WebSocket : messages binaires, chaque paquet
  précédé d'un en-tête de 16 octets (secondes, microsecondes, longueur capturée, longueur réelle).
- Le navigateur décode les paquets (`src/utils/packetDissector.js`) : Ethernet/802.1Q, ARP, IPv4/IPv6,
  ICMP/ICMPv6, IGMP, TCP (numéros de séquence relatifs), UDP, DNS, HTTP, TLS, SSH, FTP/SMTP/POP/IMAP/Telnet.
- Interface : liste des paquets (couleurs de Wireshark), détail par couche, dump hexadécimal (le champ
  sélectionné y est surligné), **filtres d'affichage** à la syntaxe Wireshark (`src/utils/displayFilter.js` :
  `icmp`, `tcp.port == 80`, `ip.addr == 10.0.1.0/24`, `&&`, `||`, `!`, `contains`…), arrêt / nouvelle
  capture, **export `.pcap`** à ouvrir dans Wireshark. Limite : 50 000 paquets par capture.
- Fermer l'onglet arrête la capture et supprime le conteneur d'analyse ; l'arrêt du réseau aussi.
  Les conteneurs d'analyse orphelins (session interrompue brutalement) sont supprimés à la capture suivante.

Busybox fournit `ping`, `traceroute`, `wget`, `nc`… ; `curl` est ajouté via l'option `packages` de
`devices.toml` (image dérivée construite au premier déploiement, puis mise en cache).

## Architecture

```
code/
├── index.html / package.json / vite.config.js …
├── src/
│   ├── App.jsx, main.jsx, styles/app.css
│   ├── config/deviceTypes.js         # Catalogue des équipements, valeurs par défaut, services proposés
│   ├── components/
│   │   ├── TopologyEditor.jsx        # Assemblage
│   │   ├── Toolbar.jsx               # Câble, Valider, état du réseau, Arrêter
│   │   ├── Palette.jsx / TopologyCanvas.jsx / DeviceNode.jsx
│   │   ├── PropertiesPanel.jsx       # Équipement ou câble sélectionné
│   │   ├── properties/               # Sections du panneau : interfaces, routage, ports, champs
│   │   ├── DeployDialog.jsx          # Bilan, barre de progression, résultat
│   │   ├── Dock.jsx                  # Panneau du bas : onglets de terminaux et de captures
│   │   ├── TerminalView.jsx          # xterm.js ↔ WebSocket d'un équipement
│   │   ├── CaptureView.jsx           # Vue « Wireshark » d'un lien (liste, détail, hexa, filtres)
│   │   ├── CableEdge.jsx             # Câble avec l'interface et le port à chaque extrémité
│   │   └── icons/DeviceIcons.jsx
│   ├── hooks/
│   │   ├── useTopology.js            # État nœuds/câbles + actions métier
│   │   ├── useCableTool.js           # « clic A puis clic B »
│   │   ├── useDeployment.js          # Cycle de vie du déploiement, état du réseau
│   │   └── useDock.js                # Onglets ouverts (terminaux, captures), onglet actif
│   ├── utils/
│   │   ├── ipv4.js                   # Calculs d'adressage
│   │   ├── ipam.js                   # Attribution automatique des réseaux, adresses et passerelles
│   │   ├── packetDissector.js        # Décodage des paquets capturés (≈ dissecteurs Wireshark)
│   │   ├── displayFilter.js          # Filtres d'affichage (syntaxe Wireshark)
│   │   ├── pcap.js                   # Découpage du flux reçu, export .pcap
│   │   ├── validators.js             # Contrôles par champ et de cohérence globale
│   │   ├── topologyQueries.js        # Lectures dérivées (interfaces d'un nœud, sous-réseau d'un switch)
│   │   └── serializeTopology.js      # État React Flow → JSON v2
│   └── services/topologyApi.js       # Appels HTTP + suivi SSE + URL des terminaux et captures
└── backend/
    ├── requirements.txt / requirements-dev.txt
    ├── config/devices.toml           # Type d'équipement → image (côté serveur uniquement)
    ├── app/
    │   ├── main.py                   # API FastAPI + flux SSE + WebSocket des terminaux et captures
    │   ├── models.py                 # Schéma de la topologie (pydantic)
    │   ├── planner.py                # Validation + topologie → plan (sous-réseaux, routes…)
    │   ├── deployer.py               # Exécution du plan avec le SDK Docker
    │   ├── jobs.py                   # Tâches de fond et événements de progression
    │   ├── service_listener.py       # Simulateur de services exécuté dans les serveurs
    │   ├── terminal.py               # Sessions de terminal (exec TTY ↔ WebSocket)
    │   ├── capture.py                # Sessions de capture (tcpdump ↔ WebSocket, découpage pcap)
    │   ├── sessions.py               # Registre des sessions WebSocket (fermeture à l'arrêt)
    │   └── settings.py               # Lecture de devices.toml
    └── tests/                        # test_planner.py, test_capture.py, test_settings.py (pytest)
```

### Points d'extension

- **Ajouter un type d'équipement** (pare-feu, machine attaquante…) : entrée dans `src/config/deviceTypes.js`
  (+ icône), type accepté dans `backend/app/models.py`, image dans `backend/config/devices.toml`.
- **Brancher la vraie sonde ML** : remplacer l'image `ids` dans `devices.toml` ; elle écoute sur
  l'interface reliée au segment surveillé, qui reçoit tout le trafic de ce segment.

## Stack

- Interface : [React](https://react.dev/) 19, [React Flow](https://reactflow.dev/) (`@xyflow/react` v12),
  [Vite](https://vite.dev/) 8, [xterm.js](https://xtermjs.org/) (`@xterm/xterm` v6) pour les terminaux
- Moteur : Python 3.9+, [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
  (HTTP, Server-Sent Events, WebSockets), [Docker SDK for Python](https://docker-py.readthedocs.io/),
  pydantic ; tests avec pytest
- Machines simulées : images Alpine Linux (busybox, `curl`) ; capture avec `tcpdump`
