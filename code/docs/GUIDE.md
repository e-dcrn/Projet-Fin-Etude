# Guide complet du projet — IDS Lab

Ce document est **le point d'entrée** pour comprendre le projet sans le connaître : ce qu'il fait,
comment il est construit, comment le lancer, quoi montrer, quoi tester, et comment répondre aux
questions qu'on peut nous poser. Les autres documents détaillent chaque partie :

| Document | Contenu |
| -------- | ------- |
| [`README.md`](../../README.md) (racine) | présentation du dépôt, démarrage rapide |
| [`code/README.md`](../README.md) | installation détaillée, dépannage, utilisation de l'interface, format JSON |
| [`code/docs/ARCHITECTURE.md`](ARCHITECTURE.md) | vue d'ensemble technique et feuille de route |
| [`code/docs/SERVICES.md`](SERVICES.md) | services des serveurs, trafic bénin, commandes de test |
| [`code/concap/README.md`](../concap/README.md) | ConCap : scénarios et mise en route (optionnel) |
| [`latex/etat_de_l_art_attaques_ml_nids.pdf`](../../latex/etat_de_l_art_attaques_ml_nids.pdf) | état de l'art sur les attaques contre les NIDS à base de ML |

Sommaire :

1. [Le projet en une page](#1-le-projet-en-une-page)
2. [Vocabulaire](#2-vocabulaire)
3. [Architecture](#3-architecture)
4. [Installer et lancer](#4-installer-et-lancer)
5. [La démonstration pas à pas](#5-la-démonstration-pas-à-pas)
6. [Comment ça marche](#6-comment-ça-marche)
7. [Pourquoi pas ConCap tel quel](#7-pourquoi-pas-concap-tel-quel)
8. [Choix techniques](#8-choix-techniques)
9. [Quoi tester](#9-quoi-tester)
10. [Limites connues](#10-limites-connues)
11. [Questions probables et réponses](#11-questions-probables-et-réponses)
12. [Où trouver quoi dans le code](#12-où-trouver-quoi-dans-le-code)

---

## 1. Le projet en une page

**Sujet du PFE** : les attaques contre les systèmes de détection d'intrusion réseau (NIDS) fondés sur
le machine learning — évasion, empoisonnement, portes dérobées (voir l'état de l'art dans `latex/` et
les articles dans `docs/`).

**Le problème** : pour étudier ces attaques, il faut un IDS qui fonctionne, entraîné sur des données
qu'on maîtrise, et un réseau où on peut lancer des attaques et observer si elles sont détectées. Les
jeux de données publics (CIC-IDS2017…) ne permettent pas de rejouer une attaque modifiée et de voir
la réaction de l'IDS.

**Notre réponse : IDS Lab**, un laboratoire réseau complet dans le navigateur.

- On **dessine** un réseau (PC, serveurs, routeurs, switches, sonde IDS), à la manière de Cisco Packet
  Tracer.
- Le réseau devient **réel** : chaque équipement est une machine Linux (un conteneur Docker) qui envoie
  de vrais paquets ; les serveurs font tourner de vrais services (web, SSH, FTP, mail, DNS, MySQL…).
- On **génère des datasets** étiquetés sur ce réseau : du trafic normal (« bénin ») et des attaques
  (scans nmap, force brute hydra).
- On **entraîne** un modèle de machine learning (random forest) et on l'**évalue** sur des données
  qu'il n'a jamais vues.
- On **active la détection** : une sonde IDS analyse le trafic en direct, toutes les 5 secondes, et
  le bilan compte les attaques détectées, les attaques manquées et les fausses alertes.

Tout se fait dans la même interface, sans outil externe. **La suite du PFE** est l'évasion : modifier
une attaque pour que l'IDS ne la voie plus, et le montrer en direct dans ce même laboratoire.

---

## 2. Vocabulaire

| Terme | Signification |
| ----- | ------------- |
| **IDS / NIDS** | système de détection d'intrusion (réseau) : il observe le trafic et lève une alerte quand il reconnaît une attaque |
| **ML-IDS** | IDS dont la décision est prise par un modèle de machine learning entraîné sur des exemples |
| **Sonde IDS** | l'équipement qui observe le trafic et fait tourner le modèle |
| **Port miroir** | port d'un switch qui reçoit une copie du trafic : la sonde voit tout sans être sur le chemin des paquets |
| **Paquet** | unité de base du trafic (un en-tête IP, TCP/UDP, des données) |
| **Flux** (flow) | une conversation entre deux machines : même adresse source, adresse destination, ports et protocole. Le modèle classe des flux, pas des paquets |
| **Features** | les caractéristiques numériques d'un flux : durée, nombre de paquets et d'octets dans chaque sens, temps entre paquets, drapeaux TCP… |
| **CICFlowMeter** | l'outil de référence qui transforme une capture (pcap) en flux avec environ 80 features ; il a servi à construire CIC-IDS2017/2018 |
| **pcap** | fichier de capture de paquets (lisible dans Wireshark) |
| **Dataset étiqueté** | un tableau de flux où chaque ligne porte la bonne réponse (« BENIGN » ou le nom de l'attaque) |
| **Trafic bénin** | le trafic normal des utilisateurs, qui ne doit pas déclencher d'alerte |
| **Vérité terrain** | ce qui s'est réellement passé (quelle attaque, de qui vers qui, quand), qu'on compare aux décisions du modèle |
| **Faux positif / fausse alerte** | trafic bénin classé comme attaque |
| **Faux négatif / attaque manquée** | attaque classée comme bénigne |
| **Random forest** | ensemble d'arbres de décision qui votent ; le modèle utilisé ici |
| **Évasion** | modifier une attaque pour que le modèle la classe comme bénigne |
| **Empoisonnement** | corrompre les données d'entraînement pour dégrader le modèle |
| **Conteneur** | une machine Linux légère, isolée, qui partage le noyau de l'hôte (Docker) |

---

## 3. Architecture

Trois couches : une **interface** dans le navigateur, un **moteur** Python qui fait tout le travail,
et un **réseau de conteneurs** Docker créé à la demande.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ INTERFACE WEB (navigateur) — React 19 + React Flow, Vite        code/src/  │
│ éditeur de topologie · panneaux Trafic, Scénarios, Datasets, IDS,          │
│ Détection · terminaux et captures des équipements                          │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │ HTTP (API REST), flux d'événements, WebSocket
┌───────────────────────────────▼────────────────────────────────────────────┐
│ MOTEUR DE SIMULATION — Python, FastAPI                   code/backend/app/ │
│  plan + déploiement      trafic + attaques        capture + features       │
│  planner.py, deployer.py traffic.py, agent bénin  capture.py, cicflowmeter │
│  datasets                entraînement             détection en direct      │
│  datasets.py             training.py              detection.py             │
└───────────────┬───────────────────────────────────────────┬────────────────┘
                │ SDK Docker                                 │ fichiers
┌───────────────▼────────────────────────────────┐ ┌────────▼───────────────┐
│ RÉSEAU DU LAB (conteneurs Docker)               │ │ DISQUE  backend/data/  │
│  PC (clients, agent bénin, attaques)            │ │  datasets : pcap, CSV  │
│  Routeurs (routage IP)                          │ │  modèles : joblib      │
│  Serveurs (vrais services)                      │ │  métadonnées JSON      │
│  Sonde IDS (port miroir sur un switch)          │ └────────────────────────┘
│  Switches = réseaux Docker (bridges Linux)      │
└────────────────────────────────────────────────┘
```

**Principe important** : l'interface ne parle jamais de Docker. Pour l'utilisateur, il configure des
équipements réseau. C'est le moteur qui traduit chaque action en conteneurs, captures et calculs.

**Communication interface ↔ moteur** :

- **API REST** (`/api/...`) pour les actions : déployer, lancer du trafic, générer un dataset, entraîner…
- **flux d'événements** (Server-Sent Events) pour suivre les tâches longues avec une barre de progression
  (déploiement, génération de datasets, entraînement) ;
- **WebSocket** pour ce qui est interactif et continu : terminaux, captures, animation des paquets.

**Stockage** : pas de base de données. Datasets et modèles sont des fichiers dans `backend/data/`
(ignoré par git), téléchargeables depuis l'interface.

---

## 4. Installer et lancer

Détails, Windows et dépannage : [`code/README.md`](../README.md).

**Prérequis** : Docker (démarré), Python 3.9 ou plus, Node.js 20.19+ ou 22.12+, Git, et Internet pour
le premier déploiement (téléchargement des images).

**Premier lancement** (deux terminaux) :

```bash
git clone https://github.com/e-dcrn/Projet-Fin-Etude.git
cd Projet-Fin-Etude/code

# Terminal 1 : le moteur
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000 --reload

# Terminal 2 : l'interface (depuis Projet-Fin-Etude/code)
npm ci
npm run dev
```

Ouvrir **http://localhost:5173**. La barre d'outils affiche « Réseau arrêté » quand tout va bien
(« Moteur de simulation hors ligne » = le moteur n'est pas lancé ou Docker est arrêté).

**Les fois suivantes** : Docker démarré, puis `source .venv/bin/activate && uvicorn app.main:app --port 8000 --reload`
dans `code/backend`, et `npm run dev` dans `code`.

**Le premier déploiement est long** (quelques minutes) : le moteur télécharge et prépare les images des
équipements, une seule fois. Les suivants prennent quelques secondes.

**Arrêter** : **■ Arrêter** dans l'interface supprime le réseau ; `Ctrl+C` dans les deux terminaux.

---

## 5. La démonstration pas à pas

Le scénario complet, celui qu'on montre en soutenance. La génération des datasets est l'étape la plus
longue (plusieurs minutes ; l'interface affiche la durée estimée avant de lancer).

### Étape 1 — Créer la topologie

- **📂 Exemples de topologies** → **« Mini-entreprise : LAN, DMZ et sonde IDS »** : 3 PC dans un LAN,
  un routeur, une DMZ avec Serveur-Web (HTTP, HTTPS, MySQL) et Serveur-Fichiers (FTP, SSH, SMTP, DNS),
  et une sonde IDS qui surveille la DMZ.
- **✔ Valider la topologie** : le moteur vérifie la topologie puis crée le réseau. Les équipements
  allumés portent une pastille verte ; le bouton Valider laisse la place à **■ Arrêter**.
- *(Facultatif)* Cliquer sur PC-1 pour ouvrir son terminal et tester un service (voir
  [SERVICES.md, test rapide](SERVICES.md#test-rapide--une-commande-par-service)), ou capturer un câble.

Pour construire une topologie à la main : glisser les équipements depuis la palette, relier avec
**🔌 Câble** (toujours équipement ↔ switch), ouvrir les services d'un serveur (section **Ports ouverts**),
choisir le switch surveillé par la sonde (section **Surveillance**).

### Étape 2 — Générer les datasets

**🗂 Datasets** → **Nouveau dataset** :

- **Sonde** : la Sonde IDS (choix par défaut) ;
- **Trafic bénin** : émetteurs, types (ping, web, services), fréquence ;
- **Attaques** : ajouter des lignes (attaque, source, cible, vitesse, répétitions), par exemple un scan
  de ports et une force brute SSH depuis PC-1 vers Serveur-Fichiers ;
- **Variantes de test** : laisser **2**.

**▶ Générer** → on obtient **3 datasets** : la base (pour l'entraînement) et 2 variantes (pour le
test), qui rejouent les mêmes attaques depuis d'autres machines, à d'autres vitesses, avec un trafic
bénin d'une autre intensité.

### Étape 3 — Entraîner et évaluer le modèle

**🧠 IDS** → **Entraîner un modèle** : entraînement sur la base, test sur les 2 variantes (proposé par
défaut), classes binaires, random forest de 100 arbres. Le rapport affiche le taux d'attaques
détectées, le taux de fausses alertes, l'exactitude, le F1, un résultat par variante, la matrice de
confusion et les features les plus utiles.

### Étape 4 — Activer la détection

**🛡 Détection** → choisir la Sonde IDS et le modèle → **▶ Démarrer la détection**. Le bouton reste jaune
« (active) ».

### Étape 5 — Trafic bénin : la sonde ne doit pas alerter

**📡 Trafic** → preset (ex. « Mixte intense ») → **▶ Démarrer**. Dans le panneau Détection, le nombre de
flux analysés augmente ; les alertes restent à zéro, ou presque (comptées comme fausses alertes).

### Étape 6 — Attaque : la sonde doit la détecter

**⚡ Scénarios** → source, scénario (ex. « Force brute SSH »), cible, vitesse → **⚡ Lancer le scénario**.
Les alertes apparaissent, les équipements impliqués sont entourés de rouge, et le bilan compte
l'attaque comme **détectée** (ou **manquée** si le modèle l'a ratée). **■ Arrêter** interrompt une
attaque en cours ; **Effacer** remet le bilan à zéro.

### Ce qu'on peut montrer en plus

- La **capture** d'un câble pendant une attaque : on voit les paquets nmap ou les tentatives hydra.
- Telnet en clair dans la capture : le mot de passe passe lettre par lettre ; en SSH, tout est chiffré.
- La **matrice de confusion** et les **features les plus utiles** : ce que le modèle a appris.
- Une attaque à une vitesse jamais vue à l'entraînement : est-elle encore détectée ?

---

## 6. Comment ça marche

### 6.1 Le réseau

| Sur le schéma | Dans Docker | Détail |
| ------------- | ----------- | ------ |
| Switch | un réseau Docker (bridge Linux) | un segment de niveau 2 avec son sous-réseau IP |
| PC | conteneur Alpine Linux | avec les clients de chaque service (curl, ssh, telnet, mariadb, dig…), plus nmap et hydra pour les tests à la main |
| Serveur | conteneur Python | lance les vrais démons des services déclarés |
| Routeur | conteneur avec `ip_forward=1` | une interface par réseau, une table de routage |
| Sonde IDS | conteneur relié au switch surveillé | le switch est passé en mode hub |

**Déploiement en deux temps** : le **planificateur** (`planner.py`) vérifie la topologie et la traduit
en plan (réseaux, adresses IP attribuées automatiquement, interfaces, routes, services) ; le
**déployeur** (`deployer.py`) exécute ce plan avec le SDK Docker et envoie sa progression à
l'interface. Le réseau est **isolé** : la route par défaut vers l'hôte est supprimée.

**Le port miroir** : un switch normal apprend où se trouve chaque adresse MAC et n'envoie à chaque port
que le trafic qui lui est destiné ; la sonde ne verrait donc rien. Le moteur règle le bridge Linux du
switch surveillé avec `ageing_time = 0` : il n'apprend plus aucune adresse et diffuse tout, comme un
hub. La sonde reçoit ainsi une copie de tout le trafic du segment.

### 6.2 Les services des serveurs

Tous les services proposés sont de vrais logiciels : serveur web HTTP/1.1 (site intranet de 20 pages,
images, fichiers, API JSON, formulaire de connexion), le même en HTTPS (TLS 1.3, certificat
auto-signé généré par openssl), OpenSSH, vsftpd, telnetd, OpenSMTPD, dnsmasq (un nom `.lab` par
équipement) et MariaDB (base « boutique »). Compte de démonstration : `labuser` / `password123`.
Détails et commandes de test : [`SERVICES.md`](SERVICES.md).

### 6.3 Le trafic bénin

Un **agent** imite un utilisateur ; chaque action est une **session complète** avec un vrai client :
navigation web (une page puis ses ressources sur la même connexion, comme un navigateur), sessions SSH
avec des commandes, transferts FTP et SFTP, courriels, requêtes MySQL, résolutions DNS, pings. La
navigation web pèse le plus lourd. L'agent se trompe parfois **une fois** de mot de passe avant de
réussir : l'IDS doit apprendre qu'une erreur isolée n'est pas une force brute.

L'agent tourne dans un **conteneur à part qui partage la pile réseau** de l'émetteur (même IP, mêmes
interfaces) : pour le réseau et la sonde, c'est bien le PC qui parle, et rien n'est installé sur le PC.

### 6.4 Les attaques

| Scénario | Outil | Classe dans le dataset |
| -------- | ----- | ---------------------- |
| Balayage de découverte | nmap `-sn` | ping-sweep |
| Scan de ports (connect, 200 ports) | nmap `-sT` | port-scan |
| Scan de ports furtif (SYN, tous les ports) | nmap `-sS` | syn-scan |
| Identification des services | nmap `-sV` | service-detection |
| Scan approfondi | nmap `-A` | aggressive-scan |
| Force brute SSH | hydra | ssh-patator |
| Force brute FTP | hydra | ftp-patator |

Quatre vitesses : nmap `-T2` à `-T5`, hydra 1 à 16 connexions parallèles. Les attaques partent de
n'importe quel équipement, de la même façon que l'agent bénin (conteneur qui partage sa pile réseau).

### 6.5 Des paquets aux features

1. La sonde capture le trafic (tcpdump) dans un pcap.
2. Le pcap est **découpé en fenêtres de 5 secondes**.
3. **CICFlowMeter** (l'image conteneurisée reprise de ConCap) transforme chaque fenêtre en flux, avec
   les colonnes standard des jeux CIC-IDS (environ 80 features par flux).
4. Si l'image CICFlowMeter n'est pas disponible, un extracteur interne (`flows.py`) prend le relais.

**Pourquoi des fenêtres de 5 s ?** La détection en direct analyse le trafic par tranches de 5 s. Si
l'entraînement analysait le pcap entier, tous les pings entre deux machines formeraient un seul flux
d'une minute, alors qu'en détection ce seraient des flux de quelques millisecondes : le modèle ne les
reconnaîtrait pas. Entraînement et détection doivent voir les flux **de la même façon**.

### 6.6 L'étiquetage

Un flux est étiqueté avec le nom de l'attaque s'il va **de la source vers la cible pendant la fenêtre
de temps** de cette attaque (avec une marge de 1 s avant et 2 s après) ; sinon il est « BENIGN ».
Pour que cette règle soit exacte, l'agent bénin de la machine d'attaque est **mis en pause** pendant
l'attaque : tout ce qui part de la source vers la cible à ce moment-là vient bien de l'attaque.

### 6.7 Les datasets et leurs variantes

Un dataset est produit à partir d'un **programme** : la Sonde IDS (seul point de capture possible), le trafic bénin,
les attaques jouées l'une après l'autre, et les durées (bénin seul au début, entre les attaques, à la
fin). Le moteur enregistre le pcap, le CSV étiqueté et un fichier de métadonnées (paramètres, fenêtres
d'attaque, décompte des étiquettes, **topologie** utilisée).

Les **variantes de test** rejouent le même programme en changeant, de façon déterministe, la machine
d'attaque, la vitesse de chaque attaque et l'intensité du trafic bénin. On teste ainsi si le modèle
a appris le **comportement** de l'attaque, et non « telle machine à telle vitesse ».

### 6.8 L'entraînement

- **Modèle** : random forest (scikit-learn), 100 arbres par défaut, profondeur réglable.
- **Classes** : binaire (BENIGN / ATTACK) ou multiclasse (une classe par attaque).
- **`class_weight="balanced"`** : les attaques sont minoritaires ; leurs erreurs comptent plus.
- **Features retirées** : `Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Timestamp` (identifiants), et
  `Dst Port` par défaut. Sinon le modèle apprendrait « cette adresse attaque » au lieu d'un
  comportement.
- **Nettoyage** : les valeurs infinies et manquantes de CICFlowMeter sont remplacées par 0, les
  colonnes constantes sont retirées.
- **Données de test** : des datasets séparés (les variantes) ou la fin chronologique du jeu. **Pas de
  découpage aléatoire des lignes** : des flux presque identiques se retrouveraient des deux côtés et les
  scores seraient trompeusement bons.

**Les métriques du rapport** :

| Métrique | Définition | Ce qu'on veut |
| -------- | ---------- | ------------- |
| Attaques détectées | part des flux d'attaque classés comme attaque (rappel) | proche de 100 % |
| Fausses alertes | part des flux bénins classés comme attaque | proche de 0 % |
| Exactitude | part des flux bien classés | attention : trompeuse si les classes sont déséquilibrées |
| F1 macro | moyenne des F1 de chaque classe | sensible aux classes minoritaires |

### 6.9 La détection en direct

1. La sonde capture en continu, en fichiers de 5 s (`tcpdump -G 5`).
2. Chaque fenêtre terminée passe dans CICFlowMeter (un conteneur permanent, pour aller vite).
3. Le modèle classe chaque flux et donne une confiance.
4. Chaque verdict est comparé à la **vérité terrain** : les attaques lancées depuis l'interface sont
   connues (source, cible, début, fin). On obtient **détectée**, **manquée**, **fausse alerte** ou
   **bénin correct**.
5. Les équipements impliqués dans une alerte récente sont entourés de rouge.

Les deux évaluations se complètent : le rapport d'entraînement donne des **chiffres reproductibles**
(même jeu de test pour comparer des modèles) ; la détection montre le comportement **en direct**, sur
le vrai trafic du réseau.

---

## 7. Pourquoi pas ConCap tel quel

[ConCap](https://github.com/idlab-discover/ConCap) est un framework de recherche qui génère des datasets
d'IDS : un scénario YAML décrit un attaquant et une ou plusieurs cibles ; ConCap (un outil en ligne de
commande écrit en Go) lance ces conteneurs sur **Kubernetes**, capture le trafic **sur la cible**
(tcpdump, filtré par défaut sur les échanges attaquant ↔ cible), remet les paquets dans l'ordre, puis
passe le pcap entier à un extracteur de flux (CICFlowMeter, ou Argus, nfstream, RustiFlow). Les
étiquettes du scénario (catégorie, sous-catégorie) sont conservées dans le fichier YAML du scénario
terminé, pas ajoutées comme colonne à chaque flux. C'était le point de départ prévu ; nous avons gardé
sa méthode et son extracteur de features, mais pas l'outil lui-même.

| Problème | ConCap | Ce dont le projet avait besoin |
| -------- | ------ | ------------------------------ |
| Infrastructure | un cluster Kubernetes (k3s dans la documentation officielle), kubectl, Go, nœuds étiquetés `concap-role=attacker` / `target`, secret d'accès au registre d'images ghcr | Docker seul, sur un ordinateur portable, piloté depuis l'interface |
| Topologie | un attaquant et des cibles sur le réseau plat du cluster : ni routeur, ni switch, ni sous-réseaux (seuls un débit, un délai et une file d'attente sont réglables côté cible) | la topologie dessinée : LAN, DMZ, routeurs, plusieurs réseaux |
| Point de capture | tcpdump sur la cible | la sonde IDS sur un port miroir, là où tourne la détection |
| Trafic bénin | aucun générateur de trafic de fond : la capture ne contient que l'échange attaquant ↔ cible | un trafic bénin continu, présent pendant les attaques |
| Étiquetage | une étiquette par scénario, gardée dans le YAML ; les CSV sortent sans colonne d'étiquette, à ajouter soi-même | par fenêtre de temps et par couple source → cible, dans un trafic mélangé |
| Découpage des flux | CICFlowMeter sur le pcap entier : flux longs | fenêtres de 5 s, identiques à la détection |
| Outils d'attaque | des scénarios d'exemple (nmap, hydra, medusa, patator), mais les images d'attaque et de cible sont à fournir | nmap et hydra dans l'image du lab, lancés depuis n'importe quel équipement |
| Usage | ligne de commande | génération, entraînement et détection dans la même interface |

*Sources : [README](https://github.com/idlab-discover/ConCap) et [runbook k3s](https://github.com/idlab-discover/ConCap/blob/main/docs/K3S_RUNBOOK.md) du dépôt officiel, consultés le 6 novembre 2026.*

**L'argument décisif est le point de vue.** Un modèle apprend les flux tels qu'ils sont vus à l'endroit
de la capture. Entraîné sur ce que voit une cible isolée dans un cluster, sans trafic bénin autour et
avec des flux non découpés, il serait évalué sur ce que voit une sonde au milieu d'une DMZ, en
fenêtres de 5 s : les features n'auraient pas les mêmes distributions, et les scores ne voudraient
rien dire.

**Ce qui a été repris de ConCap** : la méthode (scénario → capture → CICFlowMeter → étiquetage connu
d'avance), l'**image CICFlowMeter conteneurisée** utilisée telle quelle (nos CSV ont les mêmes colonnes
que ceux de ConCap et de CIC-IDS), et des noms de classes proches des jeux CIC (SSH-Patator…). Deux
scénarios ConCap restent fournis dans `code/concap/` pour produire des datasets en masse hors du lab
si besoin : même format, donc mélangeables.

---

## 8. Choix techniques

| Besoin | Choix | Alternatives écartées | Raison |
| ------ | ----- | --------------------- | ------ |
| Interface | React 19 + React Flow, Vite | Packet Tracer, GNS3 | éditeur web sur mesure, intégré au pipeline ML ; Packet Tracer simule les paquets, il n'exécute pas de vrais logiciels |
| Moteur | Python, FastAPI, SDK Docker | Node.js | même langage que scikit-learn et pandas ; FastAPI gère REST, événements et WebSocket |
| Machines | conteneurs Docker | machines virtuelles, Mininet, Kubernetes | des dizaines de machines en quelques secondes ; Mininet demande Linux ; Kubernetes trop lourd pour un portable |
| Switch | bridge Linux (réseau Docker) | Open vSwitch | inclus dans Docker |
| Port miroir | bridge en mode hub (`ageing_time = 0`) | SPAN Open vSwitch, sonde en coupure | la sonde voit tout sans être sur le chemin ; une sonde en coupure couperait le réseau si elle tombe |
| Services | vrais démons | bannières simulées | une bannière ne produit pas les échanges d'une vraie session |
| Trafic bénin | agent maison, vrais clients | rejeu de pcap publics | un pcap rejoué ne correspond ni aux adresses ni aux services de la topologie |
| Attaques | nmap, hydra | scripts maison | outils de référence, ceux des jeux CIC-IDS |
| Features | CICFlowMeter (+ repli interne) | features maison | format standard : comparable à la littérature |
| Datasets | générés dans le lab | ConCap tel quel | voir [section 7](#7-pourquoi-pas-concap-tel-quel) |
| Modèle | random forest | réseaux de neurones, SVM | rapide, explicable, sans normalisation, très utilisé en NIDS |
| Stockage | fichiers (`backend/data/`) | base de données | simple, inspectable, téléchargeable |

---

## 9. Quoi tester

### 9.1 Tests automatiques

```bash
cd code/backend && source .venv/bin/activate
pip install -r requirements-dev.txt     # une fois
python -m pytest                        # 91 tests, sans Docker, quelques secondes

cd code && npm run build                # l'interface compile
```

| Fichier de test | Ce qu'il vérifie |
| --------------- | ---------------- |
| `test_planner.py` | traduction topologie → plan (adresses, routes, erreurs détectées) |
| `test_examples.py` | chaque exemple de topologie est accepté, et toute machine joint toute autre (aller et retour) |
| `test_capture.py` | découpage du flux de capture en paquets, horodatages |
| `test_flows.py` | extracteur de flux interne et étiquetage |
| `test_datasets.py` | programmes de datasets, variantes, étiquetage par fenêtres |
| `test_training.py` | préparation des features, découpages, entraînement, métriques |
| `test_detection.py` | classement des verdicts (détectée, manquée, fausse alerte) |
| `test_benign.py` | correspondance des services, sessions de l'agent bénin, requêtes DNS |
| `test_settings.py` | origines autorisées à appeler le moteur (CORS) |

### 9.2 Tests manuels (checklist)

- [ ] L'interface affiche « Réseau arrêté » au démarrage (moteur joignable).
- [ ] Un exemple se déploie ; tous les équipements ont une pastille verte.
- [ ] Depuis le terminal de PC-1, `ping` vers une autre machine (et à travers le routeur).
- [ ] Chaque service répond depuis PC-1 ([test rapide](SERVICES.md#test-rapide--une-commande-par-service)).
- [ ] La capture d'un câble montre les paquets ; l'export pcap s'ouvre dans Wireshark.
- [ ] 📡 Trafic : les agents démarrent, le bouton reste jaune « (actif) », les paquets s'animent.
- [ ] ⚡ Scénarios : un scan se termine, ses flux étiquetés se téléchargent ; **■ Arrêter** interrompt une attaque.
- [ ] 🗂 Datasets : la génération produit la base + 2 variantes ; CSV, pcap et méta se téléchargent.
- [ ] 🧠 IDS : l'entraînement produit un rapport avec un résultat par variante.
- [ ] 🛡 Détection : peu ou pas d'alertes sur le trafic bénin ; une attaque est comptée détectée.
- [ ] **■ Arrêter** supprime le réseau ; le bouton ✔ Valider revient.

---

## 10. Limites connues

- **Trafic bénin synthétique** : de vraies sessions, mais un seul compte, un contenu généré, pas de
  cycle jour/nuit ni de profils d'utilisateurs différents.
- **Timing** : toutes les machines sont sur le même hôte ; la latence est quasi nulle, ce qui change
  les features temporelles par rapport à un vrai réseau.
- **Attaques connues seulement** : un modèle supervisé ne reconnaît que les familles vues à
  l'entraînement (scans, force brute).
- **Un modèle par topologie** : les datasets mémorisent leur topologie ; l'interface prévient en cas de
  mélange.
- **Pas de modification à chaud** : changer la topologie (ports ouverts compris) demande d'arrêter puis
  de recréer le réseau.
- **Flux à cheval** : un flux qui chevauche deux fenêtres de 5 s est analysé en deux morceaux.
- **Pas d'évasion encore** : c'est la prochaine étape du PFE.

---

## 11. Questions probables et réponses

**Pourquoi construire un laboratoire au lieu d'utiliser CIC-IDS2017 ?**
CIC-IDS2017 est un jeu figé : on peut y entraîner un modèle, mais on ne peut pas y lancer une attaque
modifiée et voir si l'IDS la détecte. Pour étudier l'évasion, il faut un réseau où rejouer des
attaques et un IDS qui tourne en direct. Le lab produit en plus des données au même format
(CICFlowMeter), donc comparables.

**Le trafic est-il réel ou simulé ?**
Réel : de vrais paquets, émis par de vrais logiciels (curl, OpenSSH, nmap, hydra…) entre de vraies
machines Linux (conteneurs). Ce qui est artificiel, c'est le comportement des utilisateurs (choisi par
un agent) et le timing (tout sur un même hôte).

**Pourquoi Docker et pas des machines virtuelles ?**
Un conteneur démarre en moins d'une seconde et pèse quelques Mo ; une topologie de 10 machines tient
sur un portable. Pour le réseau, un conteneur a sa propre pile (interfaces, IP, routes), ce qui suffit.
Limite : tous partagent le noyau de l'hôte.

**Comment la sonde voit-elle le trafic sans être sur le chemin ?**
Le switch surveillé est un bridge Linux réglé en mode hub (`ageing_time = 0`) : il recopie chaque trame
vers tous ses ports, comme un port miroir (SPAN) sur un vrai switch.

**Pourquoi des flux et pas des paquets ?**
C'est l'approche standard des NIDS à base de ML (jeux CIC, UNSW-NB15…) : un flux résume une
conversation (durée, volumes, rythmes), ce qui caractérise bien un scan ou une force brute, et réduit
énormément le volume à classer.

**Le modèle peut-il analyser du trafic chiffré (HTTPS, SSH) ?**
Oui : les features CICFlowMeter n'utilisent jamais le contenu des paquets, seulement les tailles, les
temps et les drapeaux. Une force brute SSH reste reconnaissable à ses nombreuses connexions courtes.

**Comment êtes-vous sûrs des étiquettes ?**
Les attaques sont lancées par le lab, qui connaît la source, la cible, le début et la fin. Un flux de
la source vers la cible pendant cette fenêtre est une attaque ; l'agent bénin de la source est mis en
pause pendant l'attaque pour qu'aucun flux bénin ne soit mal étiqueté.

**Pourquoi retirer les adresses IP des features ?**
Sinon le modèle apprend un raccourci (« PC-1 attaque ») au lieu du comportement. Les variantes de test
changent justement la machine d'attaque : un modèle qui aurait appris les IP échouerait.

**Pourquoi ne pas faire un découpage aléatoire train/test ?**
Des flux successifs d'une même attaque sont presque identiques ; découpés au hasard, ils se
retrouveraient des deux côtés et le modèle serait testé sur ce qu'il a déjà vu. Les scores
seraient trompeusement bons. On teste sur des datasets séparés ou sur la fin chronologique.

**Pourquoi un random forest ?**
Très utilisé et performant dans la littérature NIDS sur des données tabulaires, rapide à entraîner
et à appliquer en direct, sans normalisation des features, et explicable (importance des features).
C'est aussi une bonne cible pour l'évasion : ses décisions reposent sur des seuils.

**Pourquoi l'exactitude ne suffit pas ?**
Les attaques sont minoritaires : un modèle qui dirait toujours « bénin » aurait une exactitude élevée
et ne détecterait rien. On regarde donc le taux d'attaques détectées, le taux de fausses alertes et le
F1 macro.

**Pourquoi avoir ajouté des erreurs de mot de passe dans le trafic bénin ?**
Un vrai utilisateur se trompe parfois. Sans ces erreurs, le modèle pourrait apprendre « un échec
d'authentification = attaque » et lever de fausses alertes. Une erreur isolée suivie d'une connexion
réussie n'est pas une force brute.

**Pourquoi des fenêtres de 5 secondes ?**
Assez courtes pour une détection quasi immédiate, assez longues pour qu'un flux contienne plusieurs
paquets. Le point essentiel est que l'entraînement utilise **les mêmes** fenêtres que la détection.

**Pourquoi ne pas avoir utilisé ConCap ?** Voir la [section 7](#7-pourquoi-pas-concap-tel-quel) : il
demande Kubernetes, ignore la topologie, capture sur la cible au lieu de la sonde, ne produit pas de
trafic bénin autour des attaques, n'étiquette pas chaque flux, et analyse le pcap entier au lieu de
fenêtres de 5 s comme la détection. On a repris sa méthode et son CICFlowMeter.

**Le modèle généralise-t-il à un autre réseau ?**
Pas forcément : il est entraîné sur une topologie et un trafic bénin donnés. C'est une limite connue des
ML-IDS (le « concept drift »). Le lab permet de le mesurer : entraîner sur une topologie, tester sur
une autre.

**Quel lien avec les attaques contre les ML-IDS (le sujet) ?**
Le lab fournit la cible (un ML-IDS qui fonctionne) et le terrain (un réseau où lancer des attaques).
L'étape suivante est l'évasion : modifier une attaque détectée (cadence, tailles, bourrage) pour que
ses flux passent pour du bénin, en s'appuyant sur les features les plus utiles du rapport, et montrer
en direct que la détection ne réagit plus. Les mêmes outils permettent d'étudier l'empoisonnement
(injecter des flux mal étiquetés dans un dataset d'entraînement).

**Est-ce dangereux de lancer nmap et hydra ?**
Non : le réseau du lab est isolé de l'hôte et d'Internet (pas de route vers l'extérieur), et les
attaques ne visent que les équipements de la topologie.

---

## 12. Où trouver quoi dans le code

```
code/
├── src/                          # Interface (React)
│   ├── components/               # Toolbar, TopologyCanvas, panneaux (Trafic, Scénarios, Détection),
│   │                             # dialogues (Datasets, Modèles), terminal, capture
│   ├── hooks/                    # état et appels au moteur (useDeployment, useTraffic, useDetection…)
│   ├── services/topologyApi.js   # toutes les requêtes vers le moteur
│   └── config/                   # types d'équipements, services proposés, exemples
├── examples/topologies/          # topologies d'exemple (JSON)
├── backend/
│   ├── config/devices.toml       # images Docker de chaque type d'équipement
│   ├── app/
│   │   ├── main.py               # API (routes FastAPI)
│   │   ├── planner.py            # topologie → plan (IP, routes, services)
│   │   ├── deployer.py           # plan → conteneurs et réseaux Docker, mode hub
│   │   ├── service_listener.py   # vrais services dans les serveurs
│   │   ├── traffic.py            # trafic bénin et scénarios d'attaque
│   │   ├── traffic_agent.py      # agent bénin (sessions d'un utilisateur)
│   │   ├── capture.py            # captures des câbles (WebSocket)
│   │   ├── simulation.py         # animation des paquets
│   │   ├── cicflowmeter.py       # pcap → flux CICFlowMeter, fenêtres de 5 s
│   │   ├── flows.py              # extracteur de flux interne (repli)
│   │   ├── datasets.py           # génération des datasets et variantes
│   │   ├── training.py           # entraînement et évaluation
│   │   ├── detection.py          # détection en direct, vérité terrain
│   │   └── store.py, jobs.py     # stockage sur disque, suivi des tâches longues
│   ├── tests/                    # pytest
│   └── data/                     # datasets et modèles générés (non versionné)
├── concap/                       # scénarios ConCap (optionnel)
└── docs/                         # ce guide, ARCHITECTURE.md, SERVICES.md
```
