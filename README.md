# Projet de fin d'études – Attaques contre un IDS basé sur du machine learning

Démonstrateur pédagogique inspiré de Cisco Packet Tracer : on construit une topologie réseau dans
une interface web, puis de vraies machines (containers Docker) sont instanciées : on peut ouvrir
leur terminal, observer le trafic de chaque lien comme dans Wireshark, et l'analyser avec une
sonde IDS fondée sur du machine learning, entraînée sur des datasets générés dans le lab.

## Organisation du dépôt

| Dossier   | Contenu |
| --------- | ------- |
| `code/`   | Application : interface web (React + React Flow + Vite) et moteur de simulation (`code/backend/`, Python + Docker). **Voir [`code/README.md`](code/README.md)** pour l'installation et le lancement. |
| `code/docs/` | Documentation technique : [architecture](code/docs/ARCHITECTURE.md), [services des serveurs et trafic bénin](code/docs/SERVICES.md). |
| `docs/`   | Bibliographie et articles sur les attaques contre les NIDS à base de ML. |
| `latex/`  | Sources LaTeX des présentations. |
| `Sujet.pdf` | Sujet du projet. |

## Démarrage rapide

Prérequis : **Docker** (démarré), **Python 3.9+**, **Node.js 20.19+ ou 22.12+**
(détails, Windows et dépannage : [`code/README.md`](code/README.md#prérequis)).

```bash
git clone https://github.com/e-dcrn/Projet-Fin-Etude.git
cd Projet-Fin-Etude/code

# Terminal 1 : moteur de simulation
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000 --reload

# Terminal 2 : interface (depuis Projet-Fin-Etude/code)
npm ci
npm run dev
```

Puis ouvrir http://localhost:5173 et suivre le [premier essai](code/README.md#3-premier-essai), puis le
[parcours complet](code/README.md#4-parcours-complet--de-la-topologie-à-la-détection) :

1. créer une topologie (ou charger un exemple) et la valider ;
2. générer les datasets sur cette topologie : un pour l'entraînement, deux pour le test ;
3. entraîner le modèle et le tester sur ces datasets ;
4. activer la détection ;
5. générer du trafic bénin : la sonde ne doit pas lever d'alerte ;
6. lancer un scénario d'attaque : la sonde doit le détecter.
