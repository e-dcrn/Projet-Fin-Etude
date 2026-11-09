# IDS Lab : démonstrateur d'attaques contre un ML-NIDS

Projet VAP SSR 2026-2027, encadré par Grégory Blanc. Sujet : étudier des attaques de l'état de l'art
(évasion, empoisonnement, porte dérobée) contre des détecteurs d'intrusion réseau à base de machine
learning, dans un environnement réseau réel.

IDS Lab est un laboratoire réseau dans le navigateur. On dessine une topologie, chaque équipement
devient un conteneur Docker qui échange de vrais paquets, puis on génère des datasets étiquetés, on
entraîne un modèle, et une sonde IDS analyse le trafic en direct.

```
Réseau et vrais services → Trafic bénin et attaques → Datasets étiquetés → Entraînement → Détection en direct
```

**État** : la chaîne ci-dessus fonctionne. Reste le cœur du sujet : les attaques contre le modèle.

## Organisation du dépôt

| Emplacement | Contenu |
| ----------- | ------- |
| `code/` | Application : interface (`src/`, React + React Flow) et moteur (`backend/`, Python + Docker) |
| [`code/docs/DOCUMENTATION.md`](code/docs/DOCUMENTATION.md) | **Documentation technique complète** |
| `code/docs/rapports/` | Rapport sur la panne de l'IDS, journal des décisions du projet |
| `docs/` | Articles de l'état de l'art |
| `latex/` | État de l'art et présentations de réunion |
| `Sujet.pdf` | Sujet du projet |

## Installation

Prérequis : **Docker** démarré, **Python 3.9+**, **Node.js 20.19+ ou 22.12+**, Git, et Internet au
premier déploiement. Sous Linux, l'utilisateur doit être dans le groupe `docker`.

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

Ouvrir http://localhost:5173. La barre d'outils doit indiquer « Réseau arrêté ». Le premier déploiement
prend plusieurs minutes (construction des images), les suivants quelques secondes.

Sous Windows : utiliser WSL 2 (non testé autrement). Autres problèmes :
[dépannage](code/docs/DOCUMENTATION.md#13-dépannage).

## Parcours de démonstration

Les boutons sont dans la barre d'outils. Un bouton reste jaune tant que ce qu'il a lancé tourne.

1. **Topologie** : **📂 Exemples** → « Mini-entreprise : LAN, DMZ et sonde IDS » → **✔ Valider la
   topologie**. Tous les équipements portent une pastille verte.
2. **Datasets** : **🗂 Datasets** → **Nouveau dataset**. Choisir le trafic bénin, ajouter des attaques
   (attaque, source, cible, vitesse, répétitions), laisser 2 variantes → **▶ Générer**. On obtient 3
   datasets : la base pour l'entraînement, 2 variantes pour le test. **Inclure toutes les attaques à montrer** : le
   modèle ne reconnaît que ce qu'il a appris.
3. **Entraînement** : **🧠 IDS** → **Entraîner un modèle**. La base entraîne, les variantes testent. Le
   rapport donne les attaques détectées, les fausses alertes, le résultat par variante, la matrice de
   confusion, l'importance des features et la **détection par type d'attaque**, à vérifier avant une démo.
4. **Détection** : **🛡 Détection** → sonde et modèle → **▶ Démarrer**.
5. **Trafic bénin** : **📡 Trafic** → preset → **▶ Démarrer**. Les flux analysés augmentent, avec peu ou
   pas d'alertes.
6. **Attaque** : **⚡ Scénarios** → source, attaque, cible (dans le segment surveillé) → **⚡ Lancer**. Le
   bilan compte l'attaque détectée ou manquée, et les équipements impliqués sont entourés de rouge.

**■ Arrêter** supprime le réseau. Datasets et modèles restent sur le disque (`code/backend/data/`).
