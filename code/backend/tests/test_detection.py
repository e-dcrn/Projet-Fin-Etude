"""Tests de la détection en direct (app/detection.py) : verdicts comparés à la vérité terrain."""

import io
import threading

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from app.datasets import AttackRun
from app.detection import DetectionManager, Session, docker_time, outcome_of
from app.training import feature_matrix

T0 = 1793354400.0  # 2026-10-30 10:00:00 UTC

CSV = """Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Label
a,10.0.1.11,40000,10.0.1.10,22,6,2026-10-30 10:00:05.000000,50,1,NeedManualLabel
b,10.0.1.11,40001,10.0.1.10,23,6,2026-10-30 10:00:06.000000,800000,30,NeedManualLabel
c,10.0.1.12,50000,10.0.1.10,80,6,2026-10-30 10:00:05.000000,60,1,NeedManualLabel
d,10.0.1.12,50001,10.0.1.10,80,6,2026-10-30 10:00:07.000000,700000,25,NeedManualLabel
"""


def test_docker_time():
    assert docker_time("2026-10-30T10:00:00.500000000Z") == T0 + 0.5
    assert docker_time("2026-10-30T10:00:00Z") == T0
    assert docker_time("0001-01-01T00:00:00Z") is None


def test_outcome_of():
    assert outcome_of(True, True) == "detected"
    assert outcome_of(False, True) == "missed"
    assert outcome_of(True, False) == "false-alarm"
    assert outcome_of(False, False) == "benign"


def test_classify_compares_verdicts_with_ground_truth():
    # Modèle jouet : un flux court d'un seul paquet est une attaque.
    train = pd.DataFrame({"Flow Duration": [40, 70, 900000, 600000], "Tot Fwd Pkts": [1, 1, 20, 35]})
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(train, ["ATTACK", "ATTACK", "BENIGN", "BENIGN"])
    bundle = {"model": model, "features": list(train.columns), "mode": "binary", "excludePort": True}
    session = Session(ids="ids-1", ids_name="IDS-1", interface="eth0", model_meta={}, bundle=bundle)

    # Vérité terrain : un scan de 10.0.1.11 vers 10.0.1.10 entre 10:00:00 et 10:00:10.
    run = AttackRun(attack="tcp-connect-scan", name="Scan", category="reconnaissance", subcategory="port-scan",
                    needs="ip", source="pc-1", source_name="PC-1", source_ip="10.0.1.11", target="10.0.1.10",
                    speed="", start=T0, end=T0 + 10)
    manager = DetectionManager.__new__(DetectionManager)
    manager._known_attacks = lambda _session: [run]

    manager._classify(session, CSV)
    # a : scan détecté ; b : flux du scan classé bénin (manqué) ; c : fausse alerte ; d : bénin.
    assert session.stats == {"flows": 4, "alerts": 2, "detected": 1, "missed": 1, "falseAlarms": 1, "benign": 1}
    outcomes = sorted(e["outcome"] for e in session.events)
    assert outcomes == ["detected", "false-alarm", "missed"]
    detected = next(e for e in session.events if e["outcome"] == "detected")
    assert detected["truth"] == "port-scan" and detected["dstPort"] == 22


def test_feature_matrix_matches_model_features_order():
    frame = pd.read_csv(io.StringIO(CSV))
    features = feature_matrix(frame, True, ["Tot Fwd Pkts", "Flow Duration", "Absente"])
    assert list(features.columns) == ["Tot Fwd Pkts", "Flow Duration", "Absente"]


def test_shown_events_keep_model_errors_visible():
    session = Session(ids="ids-1", ids_name="IDS-1", interface="eth0", model_meta={}, bundle={})
    session.events.append({"time": T0, "outcome": "missed"})
    for i in range(200):
        session.events.append({"time": T0 + 1 + i, "outcome": "detected"})
    shown = DetectionManager._shown_events(session)
    assert len(shown) == 100
    assert any(e["outcome"] == "missed" for e in shown)
    assert shown[0]["time"] == T0 + 200  # le plus récent en premier


def test_reset_clears_running_session_and_forgets_stopped_one():
    manager = DetectionManager.__new__(DetectionManager)
    manager._lock = threading.Lock()
    session = Session(ids="ids-1", ids_name="IDS-1", interface="eth0", model_meta={"id": "m", "name": "M", "mode": "binary"}, bundle={})
    session.stats["detected"] = 5
    session.events.append({"time": T0, "outcome": "detected"})
    manager._session = session
    status = manager.reset()
    assert status["running"] and status["stats"]["detected"] == 0 and status["events"] == []
    session.running = False
    assert manager.reset() == {"running": False, "windowSec": 5}
