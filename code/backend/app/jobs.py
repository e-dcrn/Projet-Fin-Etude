"""
Tâches de déploiement exécutées en arrière-plan.

Le déploiement est long (téléchargements, démarrages) : il tourne dans un
thread et publie une suite d'événements que l'interface suit en temps réel
(Server-Sent Events, voir main.py). Les événements sont conservés : un client
qui se reconnecte reprend là où il s'était arrêté.

Événements (champ `type`) :
  progress  { step, total, label }   une nouvelle étape commence
  warning   { message }              problème non bloquant
  done      { total }                réseau opérationnel
  error     { message }              échec ; tout a été nettoyé
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

from .deployer import DeploymentError, EngineUnavailable, Reporter

log = logging.getLogger(__name__)


class Job(Reporter):
    def __init__(self) -> None:
        self.id = uuid.uuid4().hex
        self.events: List[dict] = []
        self.finished = False
        self._step = 0
        self._total = 0
        self._lock = threading.Lock()

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

    def run(self, work: Callable[["Job"], None]) -> None:
        try:
            work(self)
            self._emit("done", total=self._total)
        except DeploymentError as exc:
            self._emit("error", message=str(exc))
        except EngineUnavailable:
            self._emit("error", message="Le moteur de simulation ne répond plus.")
        except Exception:  # noqa: BLE001 - toute erreur doit être remontée à l'interface
            log.exception("Échec inattendu du déploiement")
            self._emit("error", message="Erreur inattendue pendant la création du réseau (voir les journaux du serveur).")
        finally:
            self.finished = True


class JobRegistry:
    """Un seul déploiement à la fois : l'infrastructure est unique."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._current: Optional[Job] = None
        self._lock = threading.Lock()

    @property
    def busy(self) -> bool:
        return self._current is not None and not self._current.finished

    def start(self, work: Callable[[Job], None]) -> Optional[Job]:
        with self._lock:
            if self.busy:
                return None
            job = Job()
            self._jobs = {job.id: job}  # on ne garde que le dernier
            self._current = job
        threading.Thread(target=job.run, args=(work,), daemon=True, name=f"deploy-{job.id[:8]}").start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)
