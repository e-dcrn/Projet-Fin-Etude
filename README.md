# Projet de fin d'études – Attaques contre un IDS basé sur du machine learning

Démonstrateur pédagogique inspiré de Cisco Packet Tracer : on construit une topologie réseau dans
une interface web, puis de vraies machines (containers Docker) sont instanciées : on peut ouvrir
leur terminal, observer le trafic de chaque lien comme dans Wireshark, et à terme l'analyser avec
des sondes IDS fondées sur du machine learning.

## Organisation du dépôt

| Dossier   | Contenu |
| --------- | ------- |
| `code/`   | Application : interface web (React + React Flow + Vite) et moteur de simulation (`code/backend/`, Python + Docker). **Voir [`code/README.md`](code/README.md)** pour l'installation et le lancement. |
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

Puis ouvrir http://localhost:5173 et suivre le [premier essai](code/README.md#3-premier-essai).
