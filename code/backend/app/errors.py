"""
Erreurs destinées à l'utilisateur.

Toute opération impossible lève une UserError dont le message est affichable
tel quel dans l'interface ; main.py la convertit en réponse HTTP avec le code
`status` (un seul gestionnaire pour toute l'API).
"""


class UserError(Exception):
    """Opération impossible (conflit avec l'état du lab, demande invalide…)."""

    status = 409


class NotFoundError(UserError):
    """Enregistrement (dataset, modèle, scénario…) introuvable."""

    status = 404


class EngineUnavailable(UserError):
    """Le moteur Docker ne répond pas."""

    status = 503

    def __init__(self) -> None:
        super().__init__("Le moteur de simulation n'est pas démarré sur la machine hôte.")
