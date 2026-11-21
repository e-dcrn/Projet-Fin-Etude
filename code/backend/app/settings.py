"""Constantes du moteur : emplacements, préfixe des ressources Docker, origines autorisées."""

from __future__ import annotations

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"                   # datasets et modèles sauvegardés
DOCKER_DIR = BACKEND_DIR.parent / "docker"        # un Dockerfile par rôle : pc, server, router, ids, toolbox

# Préfixe des ressources Docker créées (noms, labels, images « idslab/pc »…).
# Tout ce qui porte le label « idslab.managed » est supprimé à l'arrêt du réseau.
PREFIX = "idslab"

# Origines autorisées par CORS : l'interface servie en local, quel que soit son port
# (Vite passe à 5174, 5175… si 5173 est occupé).
LOCAL_ORIGIN_REGEX = r"https?://(localhost|127\.0\.0\.1)(:\d+)?"
