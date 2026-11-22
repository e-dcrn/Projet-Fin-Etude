"""
Détection en direct : un modèle ML-IDS entraîné (voir training.py) analyse le
trafic du réseau instancié, depuis une Sonde IDS.

Une Sonde IDS est reliée à un switch dont elle surveille le segment : au
démarrage, ce switch passe en mode « hub » (service hub-mode du docker-compose.yml),
l'équivalent d'un port miroir. La sonde reçoit donc une copie de tout le
trafic du segment, sans être sur le chemin des paquets (NIDS passif).

Chaîne de détection, par fenêtres de WINDOW_SEC secondes :

  1. tcpdump tourne sur l'interface de la sonde (conteneur d'analyse qui
     partage sa pile réseau) et écrit un pcap par fenêtre (-G) ;
  2. chaque fenêtre terminée est convertie en flux par un conteneur
     CICFlowMeter permanent (mêmes features que les datasets) ;
  3. le modèle classe chaque flux (bénin / attaque) ;
  4. le modèle ne voit QUE les paquets (jamais les étiquettes) : il devine. La VÉRITÉ
     TERRAIN (ce qui a été lancé depuis l'interface : attaques avec source/cible/fenêtre,
     et PC émettant du trafic bénin) sert à qualifier son verdict après coup :
       - flux classé ATTACK correspondant à une attaque lancée  → attaque détectée ;
       - flux classé ATTACK sur du trafic bénin lancé depuis l'UI → FAUSSE ALERTE ;
       - flux classé ATTACK d'origine inconnue (terminal)        → affiché comme détecté ;
       - flux classé BÉNIN correspondant à une attaque lancée     → attaque manquée.

Limite connue : un flux à cheval sur deux fenêtres est vu en deux morceaux
(features un peu différentes de celles d'un flux complet). Les flux courts
(scans, requêtes web) ne sont pas concernés.
"""

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
from fastapi import HTTPException

from .cicflowmeter import FLOW_WINDOW_SEC, FlowMeterWorker, parse_timestamp
from .datasets import AttackRun
from .traffic import ATTACKS, TrafficManager, docker_time
from .training import BENIGN, ModelStore, feature_matrix
from .settings import PREFIX

log = logging.getLogger(__name__)

WINDOW_SEC = FLOW_WINDOW_SEC  # durée d'une fenêtre d'analyse (la même que pour les datasets)
MAX_EVENTS = 300       # événements (alertes, attaques manquées) conservés
WINDOW_DIR = "/tmp/ids"
WINDOW_RE = re.compile(r"^w-(\d+)\.pcap$")


def outcome_of(predicted_attack: bool, truly_attack: bool, known_benign: bool) -> str:
    """Issue d'un flux, en croisant le verdict du modèle et la vérité terrain.

    - modèle = attaque, attaque réellement lancée      → « alert »        (vraie détection)
    - modèle = attaque, trafic bénin lancé depuis l'UI → « false_alarm »  (fausse alerte)
    - modèle = attaque, origine inconnue (terminal)    → « alert »        (on ne peut pas prouver que c'est faux)
    - modèle = bénin,  attaque réellement lancée       → « missed »       (attaque manquée)
    - modèle = bénin,  reste                            → « benign »
    """
    if predicted_attack:
        if truly_attack:
            return "alert"
        return "false_alarm" if known_benign else "alert"
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
        "flows": 0, "alerts": 0, "false_alarms": 0, "missed": 0, "benign": 0,
    })
    by_attack: Dict[str, Dict[str, int]] = field(default_factory=dict)  # flux détectés / manqués, par type d'attaque
    events: Deque[dict] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    attacks: Dict[str, AttackRun] = field(default_factory=dict)  # vérité terrain, par conteneur d'attaque
    finished: set = field(default_factory=set)                   # attaques terminées (fenêtre définitive)
    benign_ips: set = field(default_factory=set)                 # IP des PC avec un agent bénin lancé (trafic « bénin connu »)


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
        device = self.traffic.require_device(ids_node, "Sonde IDS")
        meta = self.models.get(model_id)
        bundle = joblib.load(self.models.file_path(model_id, "model.joblib"))
        interface = self.traffic.primary_interface(device)

        session = Session(ids=ids_node, ids_name=self.traffic.name_of(device), interface=interface,
                          model_meta=meta, bundle=bundle)
        # tcpdump écrit un pcap par fenêtre (-G WINDOW_SEC) ; -U : chaque paquet écrit aussitôt.
        session.capture = self.lab.start_netns_helper(
            device,
            ["sh", "-c", f"mkdir -p {WINDOW_DIR} && exec tcpdump -i {interface} -U -G {WINDOW_SEC} "
                         f"-w {WINDOW_DIR}/w-%s.pcap"],
            role="idscapture", attached=ids_node,
        )
        session.worker = FlowMeterWorker(self.lab, role="idsflowmeter")

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
        Événements affichés, du plus récent au plus ancien. Les attaques manquées
        sont toujours gardées : un scan de 200 ports détecté ne doit pas faire
        disparaître la seule attaque manquée.
        """
        events = list(reversed(session.events))
        missed = [e for e in events if e["outcome"] == "missed"][:limit // 2]
        flagged = [e for e in events if e["outcome"] in ("alert", "false_alarm")][:limit - len(missed)]
        return sorted(missed + flagged, key=lambda e: e["time"] or 0, reverse=True)

    # ------------------------------------------------------------------ boucle d'analyse

    def _loop(self, session: Session) -> None:
        try:
            while not session.stop.wait(1.0):
                try:
                    self._tick(session)
                except NotFound:
                    session.error = "La sonde a disparu (réseau arrêté ?)."
                    break
                except HTTPException as exc:
                    session.error = exc.detail
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
            raise HTTPException(500, "La capture de la sonde s'est arrêtée.")
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
        benign_ips = self._benign_ips(session)

        stats = session.stats
        for row, label, conf in zip(frame.to_dict("records"), predicted, confidence):
            src, dst = str(row.get("Src IP", "")), str(row.get("Dst IP", ""))
            moment = parse_timestamp(str(row.get("Timestamp", "")))
            truth = next((r.subcategory for r in runs if r.matches(src, dst, moment)), BENIGN)
            # Trafic « bénin connu » : un flux dont une extrémité est un PC où tourne
            # (ou a tourné) un agent bénin lancé depuis le panneau Simulation.
            known_benign = src in benign_ips or dst in benign_ips
            outcome = outcome_of(label != BENIGN, truth != BENIGN, known_benign)
            stats["flows"] += 1
            stats[{"alert": "alerts", "false_alarm": "false_alarms",
                   "missed": "missed", "benign": "benign"}[outcome]] += 1
            if truth != BENIGN:
                counters = session.by_attack.setdefault(truth, {"detected": 0, "missed": 0})
                counters["detected" if outcome == "alert" else "missed"] += 1
            if outcome != "benign":
                session.events.append({
                    "time": moment, "src": src, "dst": dst, "dstPort": int(row.get("Dst Port", 0) or 0),
                    "protocol": int(row.get("Protocol", 0) or 0), "predicted": str(label),
                    "confidence": round(float(conf), 3), "truth": truth, "outcome": outcome,
                })

    def _known_attacks(self, session: Session) -> List[AttackRun]:
        """Attaques lancées depuis l'interface (vérité terrain), avec leur fenêtre de temps."""
        for role in ("scenario", "dataset"):
            for helper in self.lab.helpers(role):
                labels = helper.labels
                attack = ATTACKS.get(labels.get(f"{PREFIX}.attack", ""))
                if attack is None or helper.id in session.finished:
                    continue
                state = helper.attrs.get("State", {})
                start = docker_time(state.get("StartedAt", ""))
                end = docker_time(state.get("FinishedAt", "")) if helper.status != "running" else time.time()
                run = session.attacks.get(helper.id)
                if run is None:  # première fois qu'on voit cette attaque : on la mémorise
                    source = self.lab.find_device(labels.get(f"{PREFIX}.attached", ""))
                    if source is None or start is None:
                        continue
                    category, subcategory = attack["label"]
                    run = AttackRun(
                        attack=labels[f"{PREFIX}.attack"], name=attack["name"], category=category,
                        subcategory=subcategory, needs=attack["needs"], source=labels.get(f"{PREFIX}.attached", ""),
                        source_name=self.traffic.name_of(source), source_ip=self.traffic.device_ip(source),
                        target=labels.get(f"{PREFIX}.target", ""), speed="", start=start,
                    )
                    session.attacks[helper.id] = run
                run.end = end
                if helper.status != "running":
                    session.finished.add(helper.id)
        return list(session.attacks.values())

    def _benign_ips(self, session: Session) -> set:
        """IP des PC où un agent bénin a été lancé depuis l'interface (trafic « bénin connu »).

        On accumule sur toute la session : même si l'agent est mis en pause le temps
        d'une attaque, son IP reste connue comme source de trafic bénin.
        """
        for helper in self.lab.helpers("traffic"):
            device = self.lab.find_device(helper.labels.get(f"{PREFIX}.attached", ""))
            ip = self.traffic.device_ip(device) if device is not None else ""
            if ip:
                session.benign_ips.add(ip)
        return session.benign_ips

    @staticmethod
    def _cleanup(session: Session) -> None:
        if session.worker:
            session.worker.close()
        if session.capture is not None:
            try:
                session.capture.remove(force=True)
            except DockerException:
                pass
