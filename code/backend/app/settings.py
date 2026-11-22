"""Constantes du moteur : emplacements, préfixe des ressources Docker, origines autorisées."""

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"                     # datasets et modèles sauvegardés
TOPOLOGIES_DIR = BACKEND_DIR.parent / "topologies"  # un dossier par topologie (docker-compose.yml + topology.json)

# Nom du projet Docker Compose (« name: idslab » dans chaque docker-compose.yml)
# et préfixe des labels des conteneurs auxiliaires (« idslab.role »…).
PREFIX = "idslab"

# Origines autorisées par CORS : l'interface servie en local, quel que soit son port
# (Vite passe à 5174, 5175… si 5173 est occupé).
LOCAL_ORIGIN_REGEX = r"https?://(localhost|127\.0\.0\.1)(:\d+)?"
