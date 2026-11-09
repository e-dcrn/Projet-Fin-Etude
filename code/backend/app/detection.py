"""
Détection en direct : un modèle ML-IDS entraîné (voir training.py) analyse le
trafic du réseau instancié, depuis une Sonde IDS.

Une Sonde IDS est reliée à un switch dont elle surveille le segment : au
déploiement, ce switch passe en mode « hub » (voir deployer._enable_hub_mode),
l'équivalent d'un port miroir. La sonde reçoit donc une copie de tout le
trafic du segment, sans être sur le chemin des paquets (NIDS passif).

Chaîne de détection, par fenêtres de WINDOW_SEC secondes :

  1. tcpdump tourne sur l'interface de la sonde (conteneur d'analyse qui
     partage sa pile réseau) et écrit un pcap par fenêtre (-G) ;
  2. chaque fenêtre terminée est convertie en flux par un conteneur
     CICFlowMeter permanent (mêmes features que les datasets) ;
  3. le modèle classe chaque flux (bénin / attaque) ;
  4. le verdict est comparé à la VÉRITÉ TERRAIN : les attaques lancées depuis
     l'interface (scénarios d'audit, programmes de dataset) sont connues, avec
     leur source, leur cible et leur fenêtre de temps (même règle que l'étiquetage
     des datasets). On obtient ainsi, en conditions réelles, les attaques
     détectées, manquées, et les fausses alertes.

Limite connue : un flux à cheval sur deux fenêtres est vu en deux morceaux
(features un peu différentes de celles d'un flux complet). Les flux courts
(scans, requêtes web) ne sont pas concernés.
"""

from __future__ import annotations

import io
import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

import joblib
import pandas as pd
from docker.errors import DockerException, NotFound

from .cicflowmeter import FLOW_WINDOW_SEC, FlowMeterWorker, parse_timestamp
from .datasets import AttackRun
from .traffic import ATTACKS, TrafficError, TrafficManager, docker_time
from .training import BENIGN, ModelStore, TrainingError, feature_matrix

log = logging.getLogger(__name__)

WINDOW_SEC = FLOW_WINDOW_SEC  # durée d'une fenêtre d'analyse (la même que pour les datasets)
MAX_EVENTS = 300       # événements (alertes, attaques manquées) conservés
WINDOW_DIR = "/tmp/ids"
WINDOW_RE = re.compile(r"^w-(\d+)\.pcap$")
INTERFACE_RE = re.compile(r"^[\w.@-]+$")


class DetectionError(Exception):
    """Opération impossible ; le message est affichable tel quel."""


def outcome_of(predicted_attack: bool, truly_attack: bool) -> str:
    """Issue d'un verdict comparé à la vérité terrain."""
    if predicted_attack:
        return "detected" if truly_attack else "false-alarm"
    return "missed" if truly_attack else "benign"


@dataclass
class Session:
    ids: str
    ids_name: str
    interface: str
    model_meta: dict
    bundle: dict
    capture: object = None
    worker: Optional[FlowMeterWorker] = None
    thread: Optional[threading.Thread] = None
    stop: threading.Event = field(default_factory=threading.Event)
    started_at: float = field(default_factory=time.time)
    last_window_at: Optional[float] = None
    running: bool = True
    error: Optional[str] = None
    stats: Dict[str, int] = field(default_factory=lambda: {
        "flows": 0, "alerts": 0, "detected": 0, "missed": 0, "falseAlarms": 0, "benign": 0,
    })
    by_attack: Dict[str, Dict[str, int]] = field(default_factory=dict)  # flux détectés / manqués, par type d'attaque
    events: Deque[dict] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    attacks: Dict[str, AttackRun] = field(default_factory=dict)  # vérité terrain, par conteneur d'attaque
    finished: set = field(default_factory=set)                   # attaques terminées (fenêtre définitive)


class DetectionManager:
    def __init__(self, traffic: TrafficManager, models: ModelStore):
        self.traffic = traffic
        self.lab = traffic.lab
        self.models = models
        self._session: Optional[Session] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ commandes

    def start(self, ids_node: str, model_id: str) -> dict:
        self.stop()
        try:
            device = self.traffic.require_device(ids_node, "Sonde IDS")
        except TrafficError as exc:
            raise DetectionError(str(exc)) from exc
        if device.labels.get(f"{self.lab.settings.prefix}.type") != "ids":
            raise DetectionError("Choisissez une Sonde IDS : elle seule reçoit une copie du trafic du segment.")
        try:
            meta = self.models.get(model_id)
            bundle = joblib.load(self.models.file_path(model_id, "model.joblib"))
        except TrainingError as exc:
            raise DetectionError(str(exc)) from exc

        interface = self.traffic.primary_interface(device)
        if not INTERFACE_RE.match(interface):
            raise DetectionError("Interface de la sonde inattendue.")
        session = Session(ids=ids_node, ids_name=self.traffic.name_of(device), interface=interface,
                          model_meta=meta, bundle=bundle)
        try:
            # Une fenêtre = un fichier ; -U : chaque paquet est écrit aussitôt.
            session.capture = self.lab.start_netns_helper(
                device, self.lab.settings.capture,
                ["sh", "-c", f"mkdir -p {WINDOW_DIR} && exec tcpdump -i {interface} -U -G {WINDOW_SEC} "
                             f"-w {WINDOW_DIR}/w-%s.pcap"],
                role="idscapture", attached=ids_node,
            )
            session.worker = FlowMeterWorker(self.lab, role="idsflowmeter")
        except DockerException as exc:
            self._cleanup(session)
            log.error("Démarrage de la détection : %s", exc)
            raise DetectionError("Impossible de démarrer la détection sur la sonde.") from exc

        session.thread = threading.Thread(target=self._loop, args=(session,), daemon=True, name="detection")
        with self._lock:
            self._session = session
        session.thread.start()
        log.info("Détection démarrée sur %s avec le modèle %s", session.ids_name, meta["name"])
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            session = self._session
        if session and session.running:
            session.stop.set()
            if session.thread:
                session.thread.join(timeout=10)
        return self.status()

    def reset(self) -> dict:
        """
        Efface le bilan et les événements, pour refaire un essai. Détection en
        cours : elle continue, repartie de zéro ; détection arrêtée : on oublie
        la dernière session.
        """
        with self._lock:
            session = self._session
            if session is not None and not session.running:
                self._session = None
            elif session is not None:
                session.events.clear()
                session.stats = {key: 0 for key in session.stats}
                session.by_attack = {}
        return self.status()

    def status(self) -> dict:
        with self._lock:
            session = self._session
        if session is None:
            return {"running": False, "windowSec": WINDOW_SEC}
        meta = session.model_meta
        return {
            "running": session.running,
            "windowSec": WINDOW_SEC,
            "ids": {"node": session.ids, "name": session.ids_name},
            "model": {"id": meta["id"], "name": meta["name"]},
            "startedAt": session.started_at,
            "lastWindowAt": session.last_window_at,
            "error": session.error,
            "stats": dict(session.stats),
            "byAttack": [{"label": k, **v} for k, v in sorted(session.by_attack.items())],
            "events": self._shown_events(session),
        }

    @staticmethod
    def _shown_events(session: Session, limit: int = 100) -> List[dict]:
        """
        Événements affichés, du plus récent au plus ancien. Les erreurs du modèle
        (attaques manquées, fausses alertes) sont toujours gardées : un scan de
        200 ports détecté ne doit pas faire disparaître la seule attaque manquée.
        """
        events = list(reversed(session.events))
        errors = [e for e in events if e["outcome"] != "detected"][:limit // 2]
        detected = [e for e in events if e["outcome"] == "detected"][:limit - len(errors)]
        return sorted(errors + detected, key=lambda e: e["time"] or 0, reverse=True)

    # ------------------------------------------------------------------ boucle d'analyse

    def _loop(self, session: Session) -> None:
        try:
            while not session.stop.wait(1.0):
                try:
                    self._tick(session)
                except (NotFound, DetectionError) as exc:
                    session.error = str(exc) if isinstance(exc, DetectionError) else "La sonde a disparu (réseau arrêté ?)."
                    break
                except Exception as exc:  # noqa: BLE001 - une fenêtre ratée ne doit pas arrêter la détection
                    log.warning("Détection : fenêtre ignorée (%s)", exc)
                    session.error = f"Fenêtre ignorée : {exc}"
        finally:
            session.running = False
            self._cleanup(session)
            log.info("Détection arrêtée sur %s", session.ids_name)

    def _tick(self, session: Session) -> None:
        capture = session.capture
        capture.reload()
        if capture.status != "running":
            raise DetectionError("La capture de la sonde s'est arrêtée.")
        listing = capture.exec_run(["sh", "-c", f"ls {WINDOW_DIR}"]).output.decode(errors="replace").split()
        now = time.time()
        # Une fenêtre est terminée quand sa période est écoulée : tcpdump écrit alors dans la suivante.
        done = sorted(
            (int(m.group(1)), name) for name in listing if (m := WINDOW_RE.match(name))
            and int(m.group(1)) + WINDOW_SEC + 1 <= now
        )
        for _, name in done:
            path = f"{WINDOW_DIR}/{name}"
            try:
                pcap = self.traffic.extract_file(capture, path)
            except (NotFound, ValueError):
                continue
            finally:
                capture.exec_run(["rm", "-f", path])
            if len(pcap) > 24:  # plus que l'en-tête pcap : il y a des paquets
                csv_text = session.worker.convert(pcap)
                if csv_text:
                    self._classify(session, csv_text)
            session.last_window_at = time.time()
            session.error = None

    def _classify(self, session: Session, csv_text: str) -> None:
        frame = pd.read_csv(io.StringIO(csv_text), low_memory=False)
        frame.columns = [c.strip() for c in frame.columns]
        if frame.empty:
            return
        bundle = session.bundle
        features = feature_matrix(frame, bundle["excludePort"], bundle["features"])
        model = bundle["model"]
        predicted = model.predict(features)
        confidence = model.predict_proba(features).max(axis=1)
        runs = self._known_attacks(session)

        stats = session.stats
        for row, label, conf in zip(frame.to_dict("records"), predicted, confidence):
            src, dst = str(row.get("Src IP", "")), str(row.get("Dst IP", ""))
            moment = parse_timestamp(str(row.get("Timestamp", "")))
            truth = next((r.subcategory for r in runs if r.matches(src, dst, moment)), BENIGN)
            outcome = outcome_of(label != BENIGN, truth != BENIGN)
            stats["flows"] += 1
            stats["alerts"] += label != BENIGN
            stats[{"detected": "detected", "missed": "missed", "false-alarm": "falseAlarms", "benign": "benign"}[outcome]] += 1
            if truth != BENIGN:
                counters = session.by_attack.setdefault(truth, {"detected": 0, "missed": 0})
                counters[outcome] += 1
            if outcome != "benign":
                session.events.append({
                    "time": moment, "src": src, "dst": dst, "dstPort": int(row.get("Dst Port", 0) or 0),
                    "protocol": int(row.get("Protocol", 0) or 0), "predicted": str(label),
                    "confidence": round(float(conf), 3), "truth": truth, "outcome": outcome,
                })

    def _known_attacks(self, session: Session) -> List[AttackRun]:
        """Attaques lancées depuis l'interface (vérité terrain), avec leur fenêtre de temps."""
        prefix = self.lab.settings.prefix
        for role in ("scenario", "dataset"):
            for helper in self.lab.helpers(role):
                labels = helper.labels
                attack = ATTACKS.get(labels.get(f"{prefix}.attack", ""))
                if attack is None or helper.id in session.finished:
                    continue
                run = session.attacks.get(helper.id)
                state = helper.attrs.get("State", {})
                start = docker_time(state.get("StartedAt", ""))
                end = docker_time(state.get("FinishedAt", "")) if helper.status != "running" else time.time()
                if run is None:
                    source = self.lab.find_device(labels.get(f"{prefix}.attached", ""))
                    if source is None or start is None:
                        continue
                    category, subcategory = attack["label"]
                    run = AttackRun(
                        attack=labels[f"{prefix}.attack"], name=attack["name"], category=category,
                        subcategory=subcategory, needs=attack["needs"], source=labels.get(f"{prefix}.attached", ""),
                        source_name=self.traffic.name_of(source), source_ip=self.traffic.device_ip(source),
                        target=labels.get(f"{prefix}.target", ""), speed="", start=start,
                    )
                    session.attacks[helper.id] = run
                run.end = end
                if helper.status != "running":
                    session.finished.add(helper.id)
        return list(session.attacks.values())

    @staticmethod
    def _cleanup(session: Session) -> None:
        if session.worker:
            session.worker.close()
        if session.capture is not None:
            try:
                session.capture.remove(force=True)
            except DockerException:
                pass
