# Architecture du projet — IDS Lab

Ce document explique comment le projet s'articule, en **trois parties** reliées par
un **pont** commun. Il est fait pour s'y retrouver quand on est perdu dans l'ensemble.

> En une phrase : on **démontre** des attaques dans un bac à sable interactif, on
> **entraîne** un IDS à base de ML sur un vrai dataset, et le **pont** entre les deux
> est un format de données commun (features CICFlowMeter) — si bien qu'un modèle
> entraîné sur le dataset fonctionne tel quel sur le trafic du démonstrateur.

---

## Vue d'ensemble

```
          ┌──────────────────────────┐        ┌──────────────────────────┐
          │   PARTIE A — DÉMONTRER    │        │   PARTIE B — ENTRAÎNER    │
          │   (ce dépôt, Docker)      │        │   (dataset + ML-IDS)      │
          │                          │        │                          │
          │  • éditeur de topologie   │        │  • ConCap (scénarios k8s) │
          │  • vrai trafic & attaques │        │    → datasets étiquetés   │
          │  • animation des paquets  │        │  • + jeux publics CIC-IDS │
          │  • capture → pcap         │        │  • entraînement du modèle │
          └─────────────┬────────────┘        └─────────────┬────────────┘
                        │                                   │
                        │        PONT — features CICFlowMeter (mêmes ~90 colonnes)
                        └──────────────────┬────────────────┘
                                           ▼
                             Un modèle entraîné (Partie B) qui
                             analyse le trafic du démonstrateur
                             (Partie A) → détection en direct.
```

Les trois parties :

| Partie | Rôle | Où |
| ------ | ---- | -- |
| **A — Démontrer** | Bac à sable interactif : on construit un réseau, on génère du trafic/des attaques, on **voit** les paquets circuler. | Ce dépôt (`code/`). |
| **B — Entraîner** | Produire un **dataset étiquetté** et entraîner/évaluer un **ML-IDS**. | ConCap (`concap/`) + jeux publics + code d'entraînement (à venir). |
| **Pont** | Un **format de features commun** (CICFlowMeter) pour que A et B parlent la même langue. | `backend/app/cicflowmeter.py`. |

---

## Partie A — Démontrer (le système actuel)

Un démonstrateur « à la Packet Tracer » : interface web (React) + moteur (Python/FastAPI)
qui **instancie réellement** le réseau avec Docker. Chaque équipement est un vrai
conteneur qui génère du **vrai trafic**.

Chaîne : **interface** (`src/`) → **API** (`backend/app/main.py`) → **moteur Docker**
(`backend/app/deployer.py`) → conteneurs (PC, serveurs, switches, routeurs).

Briques principales :

| Brique | Fichiers | Rôle |
| ------ | -------- | ---- |
| Éditeur de topologie | `src/components/TopologyEditor.jsx`, `TopologyCanvas.jsx` | Construire le réseau par glisser-déposer. |
| Déploiement | `backend/app/deployer.py`, `planner.py` | Créer réseaux + conteneurs Docker. |
| Services serveurs | `backend/app/service_listener.py` | Vrais démons SSH (openssh) / FTP (vsftpd) → force brute réaliste. |
| Trafic de fond (bénin) | `backend/app/traffic.py`, `traffic_agent.py` ; `src/components/TrafficPanel.jsx` | Trafic « normal » : types (ping/web/services), émetteurs et destinataires cochables + fréquence. |
| Scénarios d'audit | `backend/app/traffic.py` ; `src/components/ScenarioPanel.jsx` | Attaques (reconnaissance nmap, force brute hydra) étiquetées → flux CSV. Panneau distinct du trafic bénin. |
| Capture | `backend/app/capture.py` | Capturer le trafic d'un lien → **export pcap**. |
| Animation des paquets | `backend/app/simulation.py` ; `src/hooks/useSimulation.js`, `src/components/SimulationLayer.jsx` | Chaque paquet réel → une boule animée, en temps réel. |
| Export de flux | `backend/app/flows.py` **et** `cicflowmeter.py` | pcap d'un scénario → flux étiquetés (CSV). |

C'est la partie **pédagogique et de monstration** : idéale pour montrer une attaque,
une évasion, et le trafic qui circule.

---

## Partie B — Entraîner (dataset + ML-IDS)

Pour qu'un ML-IDS soit crédible, il faut un **dataset étiquetté** réaliste. Deux sources,
combinées :

1. **Jeux publics** (CIC-IDS2017/2018) → socle reconnu, comparable à la littérature.
2. **ConCap** (`concap/`) → génère **tes** attaques (nmap, hydra…) au **même format**,
   pour que le modèle connaisse exactement ce que tu démontreras.

ConCap = une « usine à datasets » : un scénario (1 attaquant + cible(s)) lance de vrais
conteneurs, capture le trafic, le passe à CICFlowMeter, et étiquette chaque flux. Il
tourne sur Kubernetes. Voir [`concap/README.md`](../concap/README.md) pour la mise en route
et les scénarios fournis.

> Pourquoi ConCap **en plus** du démonstrateur ? Le démonstrateur **montre** ;
> ConCap **produit un dataset en masse, reproductible, au format standard**. Ce sont
> deux métiers différents.

Sur le réalisme (important pour ta soutenance) : le trafic généré (ici ou dans ConCap)
est fait de **vrais paquets**, mais les **distributions** diffèrent d'un vrai réseau —
surtout le **timing** (tout sur un hôte → latence quasi nulle) et la **variété du trafic
bénin**. D'où : (a) régler des conditions réseau (`network: delay/queueSize` dans les
scénarios ConCap), et (b) s'appuyer sur un jeu public pour le socle d'entraînement.

---

## Le pont — features CICFlowMeter

C'est la pièce qui rend tout cohérent. Un modèle de ML n'apprend pas sur des paquets
bruts mais sur des **flux** décrits par des **features** (durée, nombre/taille de paquets
par sens, débits, inter-arrivées, drapeaux TCP…). Le standard de fait est **CICFlowMeter**
(~90 colonnes), utilisé par les jeux CIC-IDS **et** par ConCap.

Pour que le modèle entraîné en Partie B fonctionne sur le trafic de la Partie A, **tout
le monde doit produire les mêmes colonnes**. C'est le rôle de
[`backend/app/cicflowmeter.py`](../backend/app/cicflowmeter.py) : il lance la **vraie**
image CICFlowMeter (celle de ConCap) en Docker sur un pcap et renvoie le CSV de flux
étiqueté.

```
pcap ──> cicflowmeter.py (image CICFlowMeter de ConCap, via Docker)
     ──> CSV ~90 colonnes (identique à CIC-IDS / ConCap)
     ──> étiquetage par le scénario (attaque / BENIGN)
```

Il reste un **exporteur interne** (`flows.py`) comme **repli** si Docker/l'image ne sont
pas disponibles (autonome, testé), mais le chemin par défaut vise les features standard.

---

## Flux de bout en bout (cible)

```
      Partie B (hors ligne)                         Partie A (en direct)
┌───────────────────────────────┐          ┌──────────────────────────────────┐
│ ConCap + jeux publics CIC-IDS │          │ démonstrateur : topologie + trafic │
│   → CSV CICFlowMeter étiqueté │          │   → capture pcap d'un lien         │
└───────────────┬───────────────┘          │   → cicflowmeter.py → CSV features │
                │                           └───────────────┬──────────────────┘
                ▼                                           │
       entraînement du modèle ML-IDS                        ▼
                │                               le modèle classe les flux en direct
                └───────────────► modèle ◄──────────────────┘  (bénin / alerte)
```

---

## État actuel et feuille de route

| # | Élément | Statut |
| - | ------- | ------ |
| — | Démonstrateur (topologie, trafic, attaques, animation, capture/pcap) | ✅ en place |
| 1 | **Pont CICFlowMeter réel** (`cicflowmeter.py`) branché sur l'export de flux des scénarios, avec repli sur `flows.py` | ✅ implémenté et **validé en conditions réelles** (scénario nmap joué dans le lab → CSV 94 colonnes CICFlowMeter, 200 flux étiquetés `port-scan`). |
| 2 | **ConCap** (scénarios `nmap`, `hydra` + guide) | ✅ scénarios et guide fournis (`concap/`). ▶ **À faire par toi** : monter un cluster (k3s/kind) et lancer — ça tourne sur ta machine, je ne peux pas l'installer à ta place. |
| 3 | **Détection IDS en direct** dans le démonstrateur | ⏳ à venir — **dépend d'un modèle entraîné** (Partie B). Conçu ci-dessous ; pas encore codé (il n'y a pas encore de modèle). |

### Comment le point 3 se branchera (quand un modèle existera)

1. Entraîner un modèle (Partie B) sur le dataset CICFlowMeter → fichier de modèle.
2. Côté moteur : sur un lien en capture, convertir le trafic en flux via `cicflowmeter.py`,
   passer les features au modèle, obtenir `bénin / alerte` par flux.
3. Côté interface : afficher le verdict (ex. colorer le lien ou la boule en rouge sur une
   alerte). Idéal pour montrer **détection** puis **évasion** en soutenance.

---

## Pour démarrer la Partie B

1. **Clarifier avec le prof** : ConCap obligatoire, ou un dataset public suffit-il pour le socle ?
2. **Socle** : récupérer CIC-IDS2017/2018 (features CICFlowMeter déjà fournies).
3. **Compléments** : générer tes attaques avec ConCap (`concap/README.md`).
4. **Entraînement** : notebook/script scikit-learn (ou autre) sur le CSV combiné.
5. **Boucler** : brancher le modèle dans le démonstrateur (point 3).
