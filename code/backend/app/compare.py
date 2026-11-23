"""
Comparaison de deux runs déjà enregistrés : on rejoue un modèle entraîné sur les
flux stockés d'un dataset (flows.csv) pour obtenir, flux par flux, la décision du
modèle (détecté / raté) et les quelques features sur lesquelles il décide.

C'est le pendant « hors ligne » de detection.py : même modèle, mêmes features,
mais appliqué à un pcap déjà capturé plutôt qu'au trafic en direct. Sert à mettre
côte à côte une attaque classique et sa variante furtive (voir la vue « Comparer »
de l'interface).
"""

from __future__ import annotations

import joblib
import numpy as np
import pandas as pd

from .store import RecordStore
from .training import BENIGN, feature_matrix

# Features montrées dans l'interface : surtout des tailles de paquet et du volume,
# c'est-à-dire ce sur quoi le random forest décide (cf. rapport d'évasion).
KEY_FEATURES = [
    "Packet Length Mean",
    "Average Packet Size",
    "Flow Bytes/s",
    "Total Length of Fwd Packet",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Flow Duration",
]
# Axes du nuage de points (migration des flux d'attaque vers la zone bénigne).
SCATTER_X = "Packet Length Mean"
SCATTER_Y = "Flow Bytes/s"


def _num(value) -> float:
    """Valeur numérique propre (NaN/inf → 0.0) pour le JSON."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if np.isfinite(f) else 0.0


def score_dataset(datasets: RecordStore, models: RecordStore, dataset_id: str, model_id: str) -> dict:
    """
    Rejoue le modèle `model_id` sur les flux du dataset `dataset_id`. Renvoie,
    par flux : identité (5-uplet), vérité terrain (`Label`), décision du modèle
    (`predicted`, `detected`, `confidence`), les `KEY_FEATURES`, et les
    coordonnées (`x`, `y`) du nuage. Plus un `summary` : rappel par étiquette,
    nom et durée du run.
    """
    flows_path = datasets.file_path(dataset_id, "flows.csv")  # 404 si inconnu
    frame = pd.read_csv(flows_path, low_memory=False)
    frame.columns = [c.strip() for c in frame.columns]

    bundle = joblib.load(models.file_path(model_id, "model.joblib"))
    features = feature_matrix(frame, bundle["excludePort"], bundle["features"])
    model = bundle["model"]
    predicted = model.predict(features)
    confidence = model.predict_proba(features).max(axis=1)

    flows = []
    by_label: dict = {}
    for row, pred, conf in zip(frame.to_dict("records"), predicted, confidence):
        label = str(row.get("Label", BENIGN) or BENIGN)
        pred = str(pred)
        detected = pred != BENIGN
        flows.append({
            "src": str(row.get("Src IP", "")),
            "dst": str(row.get("Dst IP", "")),
            "srcPort": int(row.get("Src Port", 0) or 0),
            "dstPort": int(row.get("Dst Port", 0) or 0),
            "protocol": int(row.get("Protocol", 0) or 0),
            "label": label,
            "predicted": pred,
            "detected": detected,
            "confidence": round(float(conf), 3),
            "features": {k: _num(row.get(k)) for k in KEY_FEATURES},
            "x": _num(row.get(SCATTER_X)),
            "y": _num(row.get(SCATTER_Y)),
        })
        agg = by_label.setdefault(label, {"count": 0, "detected": 0})
        agg["count"] += 1
        agg["detected"] += int(detected)

    # Rappel par étiquette : pertinent pour les attaques (Label != BENIGN).
    for label, agg in by_label.items():
        agg["isAttack"] = label != BENIGN
        agg["recall"] = round(agg["detected"] / agg["count"], 3) if agg["count"] else 0.0

    meta = datasets.get(dataset_id)
    return {
        "datasetId": dataset_id,
        "modelId": model_id,
        "name": meta.get("name", dataset_id),
        "durationSec": meta.get("durationSec"),
        "attacks": [
            {"subcategory": a.get("subcategory"), "name": a.get("name"),
             "speed": a.get("speed"), "durationSec": a.get("durationSec")}
            for a in meta.get("attacks", [])
        ],
        "scatterAxes": {"x": SCATTER_X, "y": SCATTER_Y},
        "keyFeatures": KEY_FEATURES,
        "summary": {"total": len(flows), "byLabel": by_label},
        "flows": flows,
    }
