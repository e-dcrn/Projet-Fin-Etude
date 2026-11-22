# IDS Lab : démonstrateur d'attaques contre un ML-NIDS

Projet VAP SSR 2026-2027, encadré par Grégory Blanc. Sujet : étudier des attaques de l'état de l'art
(évasion, empoisonnement, porte dérobée) contre des détecteurs d'intrusion réseau à base de machine
learning, dans un environnement réseau réel.

IDS Lab est un laboratoire réseau dans le navigateur. On choisit l'une des trois topologies prêtes (des
fichiers Docker Compose) ; chaque équipement est un conteneur Docker qui échange de vrais paquets, puis on génère des datasets étiquetés, on
entraîne un modèle, et une sonde IDS analyse le trafic en direct.

```
Réseau et vrais services → Trafic bénin et attaques → Datasets étiquetés → Entraînement → Détection en direct
```

**État** : la chaîne ci-dessus fonctionne. Première attaque contre le modèle implémentée : **évasion**, en deux
variantes — par temporisation (inefficace contre un détecteur par-flux) et par mimétisme du trafic bénin
(efficace : la force brute FTP furtive tombe à 9,4 % de détection). Voir
[`code/docs/rapports/rapport_evasion.md`](code/docs/rapports/rapport_evasion.md).

## Organisation du dépôt

| Emplacement | Contenu |
| ----------- | ------- |
| `code/` | Application : interface (`src/`, React + React Flow) et moteur (`backend/`, Python + Docker) |
| `code/topologies/` | Les trois topologies : un `docker-compose.yml` (ce que Docker lance) et un `topology.json` (le dessin) chacune |
| `code/docker/` | Images du serveur (HTTP, SSH, FTP) et de la boîte à outils (trafic, attaques, captures) |
| [`code/docs/DOCUMENTATION.md`](code/docs/DOCUMENTATION.md) | **Documentation technique complète** |
| `code/docs/rapports/` | Rapport sur la panne de l'IDS, **rapport d'évasion** (temporisation vs mimétisme), journal des décisions du projet |
| `docs/` | Articles de l'état de l'art |
| `latex/` | État de l'art et présentations de réunion |
| `Sujet.pdf` | Sujet du projet |

## Installation

Prérequis : **Docker** démarré, avec **Docker Compose v2** (`docker compose`), **Python 3.9+**, **Node.js 20.19+ ou 22.12+**, Git, et Internet au
premier déploiement. Sous Linux, l'utilisateur doit être dans le groupe `docker`.

> **Docker Compose v2 est obligatoire.** Sans lui, « Démarrer le réseau » échoue avec
> `unknown shorthand flag: 'p' in -p`. Vérifier avec `docker compose version` ; sous Ubuntu/Debian,
> l'installer avec `sudo apt install docker-compose-v2` (l'ancien `docker-compose` 1.x ne convient pas).

```bash
git clone https://github.com/e-dcrn/Projet-Fin-Etude.git
cd Projet-Fin-Etude/code
```

Terminal 1, le moteur :

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000 --reload
```

Terminal 2, l'interface (depuis `code/`) :

```bash
npm ci
npm run dev
```

Ouvrir http://localhost:5173. La barre d'outils doit indiquer « Réseau arrêté ». Le premier démarrage
prend plusieurs minutes (construction des images), les suivants quelques secondes.

Sous Windows : utiliser WSL 2 (non testé autrement). Autres problèmes :
[dépannage](code/docs/DOCUMENTATION.md#13-dépannage).

## Parcours de démonstration

Les boutons sont dans la barre d'outils. Un bouton reste jaune tant que ce qu'il a lancé tourne.

1. **Topologie** : ouvrir le menu des topologies (il décrit chacune en une ligne), choisir « Petit LAN » →
   **▶ Démarrer le réseau** (`docker compose up`). Tous les équipements portent une pastille verte.
2. **Datasets** : **🗂 Datasets** → **Nouveau dataset**. Choisir le trafic bénin, ajouter des attaques
   (attaque, source, cible, vitesse, répétitions), laisser 2 variantes → **▶ Générer**. On obtient 3
   datasets : la base pour l'entraînement, 2 variantes pour le test. **Inclure toutes les attaques à montrer** : le
   modèle ne reconnaît que ce qu'il a appris.
3. **Entraînement** : **🧠 IDS** → **Entraîner un modèle**. La base entraîne, les variantes testent. Le
   rapport donne les attaques détectées, les fausses alertes, le résultat par variante, la matrice de
   confusion, l'importance des features et la **détection par type d'attaque**, à vérifier avant une démo.
4. **Détection** : **🛡 Détection** → modèle → **▶ Démarrer**.
5. **Trafic bénin** : **⚡ Simulation** → **▶ Démarrer** (section Trafic bénin). Les flux analysés augmentent,
   avec peu ou pas d'alertes.
6. **Attaque** : **⚡ Simulation** → source, attaque, cible, vitesse → **⚡ Lancer l'attaque**. Chaque flux classé
   attaque s'affiche comme détecté et les flux manqués sont signalés ; un flux bénin classé attaque à tort
   apparaît en **fausse alerte** (ambre), avec son compteur dans le bilan de détection. Quand l'attaque se
   termine, sa carte affiche le **résultat de l'attaque** (vert si elle a abouti) :
   mot de passe trouvé, ports ouverts ou machines actives. Ce résultat est **indépendant de la détection** :
   une attaque peut réussir tout en passant inaperçue — c'est tout l'intérêt d'une évasion.
7. **Évasions** (la cible est le Serveur, qui expose un FTP) :
   - **par temporisation** (échoue) : lancer la **Force brute FTP** en vitesse « Évasion (furtif, temporisé) ».
     Elle étale les essais dans le temps mais garde la même signature par-flux → **détectée**, bien qu'elle
     trouve le mot de passe.
   - **par mimétisme** (réussit) : lancer la **Force brute FTP (furtive, évasion)**. Elle maquille la taille des
     paquets pour imiter une vraie session → **majoritairement manquée**, tout en trouvant le mot de passe
     (badge vert). C'est le cas où le résultat de l'attaque et l'absence de détection se lisent ensemble.

   Voir le rapport d'évasion.

**■ Arrêter** supprime le réseau. Datasets et modèles restent sur le disque (`code/backend/data/`).
