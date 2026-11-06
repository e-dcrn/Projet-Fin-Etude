"""
Tâches longues exécutées en arrière-plan (déploiement du réseau, génération
d'un dataset).

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
from typing import Callable, Dict, List, Optional, Tuple, Type

from .deployer import DeploymentError, EngineUnavailable, Reporter

log = logging.getLogger(__name__)


class JobCancelled(Exception):
    """Levée dans le travail quand l'utilisateur a demandé l'annulation."""


class Job(Reporter):
    def __init__(self, user_errors: Tuple[Type[Exception], ...], failure: str) -> None:
        self.id = uuid.uuid4().hex
        self.events: List[dict] = []
        self.finished = False
        self._step = 0
        self._total = 0
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._user_errors = user_errors  # erreurs dont le message est affichable tel quel
        self._failure = failure          # message affiché pour toute autre erreur

    def _emit(self, type_: str, **data) -> None:
        with self._lock:
            self.events.append({"type": type_, "time": time.time(), **data})

    # -- Reporter
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
        except self._user_errors as exc:
            self._emit("error", message=str(exc))
        except EngineUnavailable:
            self._emit("error", message="Le moteur de simulation ne répond plus.")
        except Exception:  # noqa: BLE001 - toute erreur doit être remontée à l'interface
            log.exception("Échec inattendu d'une tâche de fond")
            self._emit("error", message=self._failure)
        finally:
            self.finished = True


class JobRegistry:
    """Une seule tâche à la fois par registre : l'infrastructure est unique."""

    def __init__(
        self,
        name: str = "deploy",
        user_errors: Tuple[Type[Exception], ...] = (DeploymentError,),
        failure: str = "Erreur inattendue pendant la création du réseau (voir les journaux du serveur).",
    ) -> None:
        self._jobs: Dict[str, Job] = {}
        self._current: Optional[Job] = None
        self._lock = threading.Lock()
        self._name = name
        self._user_errors = user_errors
        self._failure = failure

    @property
    def busy(self) -> bool:
        return self._current is not None and not self._current.finished

    @property
    def current(self) -> Optional[Job]:
        """Tâche en cours (None si aucune) : l'interface peut en reprendre le suivi."""
        return self._current if self.busy else None

    def start(self, work: Callable[[Job], Optional[dict]]) -> Optional[Job]:
        with self._lock:
            if self.busy:
                return None
            job = Job(self._user_errors, self._failure)
            self._jobs = {job.id: job}  # on ne garde que le dernier
            self._current = job
        threading.Thread(target=job.run, args=(work,), daemon=True, name=f"{self._name}-{job.id[:8]}").start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)
