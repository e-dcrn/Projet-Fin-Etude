# Projet de fin d'études – Attaques contre un IDS basé sur du machine learning

Démonstrateur pédagogique inspiré de Cisco Packet Tracer : on construit une topologie réseau dans
une interface web. À terme, de vraies machines (containers Docker) seront instanciées pour générer
du trafic analysé par des sondes IDS fondées sur du machine learning.

## Organisation du dépôt

| Dossier   | Contenu |
| --------- | ------- |
| `code/`   | Application web (React + React Flow + Vite) : éditeur de topologie. **Voir [`code/README.md`](code/README.md)** pour l'installation et le lancement. |
| `Docs/`   | Bibliographie et articles sur les attaques contre les NIDS à base de ML. |
| `Latex/`  | Sources LaTeX des présentations. |
| `Sujet.pdf` | Sujet du projet. |

## Démarrage rapide

Prérequis : Node.js 20.19+ ou 22.12+ (voir [`code/README.md`](code/README.md#prérequis)).

```bash
git clone https://github.com/e-dcrn/Projet-Fin-Etude.git
cd Projet-Fin-Etude/code
npm ci
npm run dev
```

Puis ouvrir http://localhost:5173.
