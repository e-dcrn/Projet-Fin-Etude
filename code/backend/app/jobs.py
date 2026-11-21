"""
Tâches longues exécutées en arrière-plan (déploiement du réseau, génération
d'un dataset, entraînement d'un modèle).

Une tâche tourne dans un thread et met à jour son état au fur et à mesure.
L'interface lit cet état toutes les secondes avec GET /api/jobs/{id} (polling) :

  {
    "id": "...",
    "status": "running" | "done" | "failed",
    "total": 7,                       # nombre d'étapes prévues
    "steps": ["Nettoyage…", "…"],     # étapes commencées (la dernière est en cours)
    "warnings": ["…"],                # problèmes non bloquants
    "error": "…" ou null,             # message d'échec
    "result": {...}                   # ce que renvoie le travail (dataset, modèle…)
  }
"""

from __future__ import annotations

import logging
import threading
import uuid

from .errors import UserError

log = logging.getLogger(__name__)


class JobCancelled(Exception):
    """Levée dans le travail quand l'utilisateur a demandé l'annulation."""


class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex
        self.status = "running"
        self.total = 0
        self.steps = []
        self.warnings = []
        self.error = None
        self.result = {}
        self.cancel_requested = threading.Event()

    @property
    def finished(self):
        return self.status != "running"

    # -- appelées par le travail pour signaler sa progression
    def begin(self, total):
        self.total = total

    def step(self, label):
        self.steps.append(label)

    def warn(self, message):
        self.warnings.append(message)

    # -- annulation
    def cancel(self):
        self.cancel_requested.set()

    def sleep(self, seconds):
        """Attend `seconds` secondes, ou s'arrête tout de suite si l'annulation est demandée."""
        if self.cancel_requested.wait(seconds):
            raise JobCancelled()

    def check_cancelled(self):
        if self.cancel_requested.is_set():
            raise JobCancelled()

    # -- exécution, dans le thread
    def run(self, work):
        try:
            self.result = work(self) or {}
            self.status = "done"
        except JobCancelled:
            self.error = "Opération annulée."
            self.status = "failed"
        except UserError as exc:
            self.error = str(exc)
            self.status = "failed"
        except Exception:
            log.exception("Échec inattendu d'une tâche de fond")
            self.error = "Erreur inattendue (voir les journaux du serveur)."
            self.status = "failed"

    def to_dict(self):
        return {
            "id": self.id,
            "status": self.status,
            "total": self.total,
            "steps": list(self.steps),
            "warnings": list(self.warnings),
            "error": self.error,
            "result": self.result,
        }


class JobRegistry:
    """
    Une seule tâche à la fois par type (« deploy », « dataset », « training »).
    On garde la dernière tâche de chaque type pour que l'interface puisse la suivre.
    """

    def __init__(self):
        self.last = {}  # type → dernière tâche lancée

    def busy(self, kind):
        job = self.last.get(kind)
        return job is not None and not job.finished

    def current(self, kind):
        """Tâche en cours de ce type, ou None."""
        return self.last[kind] if self.busy(kind) else None

    def start(self, kind, work):
        if self.busy(kind):
            raise UserError("Une tâche du même type est déjà en cours.")
        job = Job()
        self.last[kind] = job
        threading.Thread(target=job.run, args=(work,), daemon=True).start()
        return job

    def get(self, job_id):
        for job in self.last.values():
            if job.id == job_id:
                return job
        return None
