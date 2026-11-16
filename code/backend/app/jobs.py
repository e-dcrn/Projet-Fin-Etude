"""
Tâches longues exécutées en arrière-plan (déploiement du réseau, génération
d'un dataset, entraînement d'un modèle).

Une tâche tourne dans un thread et publie une suite d'événements que
l'interface suit en temps réel (Server-Sent Events, voir main.py). Les
événements sont conservés : un client qui se reconnecte reprend là où il
s'était arrêté.

Événements (champ `type`) :
  progress  { step, total, label }   une nouvelle étape commence
  warning   { message }              problème non bloquant
  done      { total, ... }           tâche terminée (+ ce que renvoie le travail)
  error     { message }              échec ; tout a été nettoyé
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

from .errors import UserError

log = logging.getLogger(__name__)


class JobCancelled(Exception):
    """Levée dans le travail quand l'utilisateur a demandé l'annulation."""


class Job:
    def __init__(self) -> None:
        self.id = uuid.uuid4().hex
        self.events: List[dict] = []
        self.finished = False
        self._step = 0
        self._total = 0
        self._lock = threading.Lock()
        self._cancel = threading.Event()

    def _emit(self, type_: str, **data) -> None:
        with self._lock:
            self.events.append({"type": type_, "time": time.time(), **data})

    # -- progression, appelée par le travail
    def begin(self, total: int) -> None:
        self._total = total

    def step(self, label: str) -> None:
        self._step += 1
        self._emit("progress", step=self._step, total=self._total, label=label)

    def warn(self, message: str) -> None:
        self._emit("warning", message=message)

    def events_since(self, index: int) -> List[dict]:
        with self._lock:
            return self.events[index:]

    # -- annulation
    def cancel(self) -> None:
        self._cancel.set()

    def sleep(self, seconds: float) -> None:
        """Attend `seconds` secondes, ou lève JobCancelled dès que l'annulation est demandée."""
        if self._cancel.wait(seconds):
            raise JobCancelled()

    def check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise JobCancelled()

    def run(self, work: Callable[["Job"], Optional[dict]]) -> None:
        try:
            result = work(self) or {}
            self._emit("done", total=self._total, **result)
        except JobCancelled:
            self._emit("error", message="Opération annulée.")
        except UserError as exc:
            self._emit("error", message=str(exc))
        except Exception:  # noqa: BLE001 - toute erreur doit être remontée à l'interface
            log.exception("Échec inattendu d'une tâche de fond")
            self._emit("error", message="Erreur inattendue (voir les journaux du serveur).")
        finally:
            self.finished = True


class JobRegistry:
    """
    Tâches de fond, une seule à la fois par type (« deploy », « dataset »,
    « training ») : l'infrastructure est unique. On garde la dernière tâche de
    chaque type, pour qu'un client puisse en suivre ou reprendre la progression.
    """

    def __init__(self) -> None:
        self._last: Dict[str, Job] = {}  # type → dernière tâche lancée
        self._lock = threading.Lock()

    def busy(self, kind: str) -> bool:
        job = self._last.get(kind)
        return job is not None and not job.finished

    def current(self, kind: str) -> Optional[Job]:
        """Tâche en cours de ce type (None si aucune) : l'interface peut en reprendre le suivi."""
        return self._last[kind] if self.busy(kind) else None

    def start(self, kind: str, work: Callable[[Job], Optional[dict]]) -> Job:
        """Lance la tâche ; lève UserError si une tâche du même type tourne déjà."""
        with self._lock:
            if self.busy(kind):
                raise UserError("Une tâche du même type est déjà en cours.")
            job = self._last[kind] = Job()
        threading.Thread(target=job.run, args=(work,), daemon=True, name=f"{kind}-{job.id[:8]}").start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return next((job for job in self._last.values() if job.id == job_id), None)
