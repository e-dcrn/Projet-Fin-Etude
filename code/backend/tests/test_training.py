"""Tests de l'entraînement et de l'évaluation du ML-IDS (app/training.py)."""

import io
import random

import joblib
import numpy as np
import pandas as pd
import pytest

from app.datasets import DatasetStore
from app.jobs import Job
from app.training import (
    ModelStore, Trainer, TrainingError, evaluate, feature_matrix, targets, temporal_split,
)

COLUMNS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
           "Flow Duration", "Tot Fwd Pkts", "Flow Byts/s", "Constant", "Label"]


def _csv(seed, start_minute=0):
    """Flux synthétiques : scans (courts, 1 paquet) et navigation web (longs, nombreux paquets)."""
    rng = random.Random(seed)
    lines = [",".join(COLUMNS)]
    for i in range(120):
        attack = i % 3 == 0
        label = "port-scan" if attack else "BENIGN"
        duration = rng.randint(10, 200) if attack else rng.randint(50_000, 900_000)
        packets = 1 if attack else rng.randint(6, 40)
        rate = "Infinity" if i % 17 == 0 else str(rng.random() * 1000)
        ts = f"2026-10-30 10:{start_minute + i // 60:02d}:{i % 60:02d}.000000"
        lines.append(",".join(map(str, [
            f"f{i}", "10.0.1.11" if attack else "10.0.1.12", 40000 + i, "10.0.1.10",
            rng.randint(1, 1000) if attack else 80, 6, ts, duration, packets, rate, 7, label,
        ])))
    return "\n".join(lines) + "\n"


@pytest.fixture
def stores(tmp_path):
    datasets = DatasetStore(tmp_path / "datasets")
    for n in (1, 2):
        datasets.save(f"20261030-10000{n}", {"id": f"20261030-10000{n}", "name": f"ds{n}", "engine": "CICFlowMeter"},
                      {"flows.csv": _csv(seed=n, start_minute=n * 5)})
    return datasets, ModelStore(tmp_path / "models")


def _spec(**overrides):
    spec = {"name": "", "train": ["20261030-100001"], "test": ["20261030-100002"], "split": "dataset",
            "testFraction": 0.3, "mode": "binary", "model": "random-forest", "nEstimators": 20,
            "maxDepth": None, "excludePort": True}
    spec.update(overrides)
    return spec


def test_feature_matrix_drops_identifiers_port_and_cleans_values():
    frame = pd.read_csv(io.StringIO(_csv(seed=1)))
    features = feature_matrix(frame, exclude_port=True)
    assert not {"Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp", "Label", "Dst Port"} & set(features.columns)
    assert np.isfinite(features.to_numpy()).all()  # « Infinity » de CICFlowMeter neutralisé
    assert "Dst Port" in feature_matrix(frame, exclude_port=False).columns
    # Jeu de test : mêmes colonnes, même ordre, colonne absente remplie de zéros.
    test = feature_matrix(frame.drop(columns=["Flow Duration"]), True, list(features.columns))
    assert list(test.columns) == list(features.columns)
    assert (test["Flow Duration"] == 0).all()


def test_binary_targets():
    labels = pd.Series(["BENIGN", "port-scan", "ssh-patator"])
    assert list(targets(labels, "binary")) == ["BENIGN", "ATTACK", "ATTACK"]
    assert list(targets(labels, "multiclass")) == ["BENIGN", "port-scan", "ssh-patator"]


def test_temporal_split_keeps_latest_flows_for_test():
    frame = pd.read_csv(io.StringIO(_csv(seed=1))).sample(frac=1, random_state=0)  # ordre mélangé
    train, test = temporal_split(frame, 0.25)
    assert len(test) == 30
    assert train["Timestamp"].max() < test["Timestamp"].min()


def test_evaluate_detection_and_false_positives():
    y_true = pd.Series(["BENIGN", "BENIGN", "BENIGN", "BENIGN", "port-scan", "port-scan"])
    y_pred = np.array(["BENIGN", "BENIGN", "BENIGN", "port-scan", "port-scan", "BENIGN"])
    metrics = evaluate(y_true, y_pred, ["BENIGN", "port-scan"])
    assert metrics["classes"] == ["BENIGN", "port-scan"]
    assert metrics["detectionRate"] == 0.5
    assert metrics["falsePositiveRate"] == 0.25
    assert metrics["confusion"] == [[3, 1], [1, 1]]


def test_train_on_one_dataset_and_test_on_another(stores):
    datasets, models = stores
    trainer = Trainer(datasets, models)
    job = Job((TrainingError,), "erreur")
    result = trainer.run(trainer.prepare(_spec()), job)
    meta = result["model"]
    assert meta["metrics"]["accuracy"] > 0.95  # les deux classes sont bien séparables
    assert meta["train"]["counts"] == {"BENIGN": 80, "ATTACK": 40}
    assert "Constant" not in [f["name"] for f in meta["topFeatures"]]
    assert [d["id"] for d in meta["metrics"]["byDataset"]] == ["20261030-100002"]
    assert meta["metrics"]["byDataset"][0]["rows"] == 120
    assert meta["trainSeconds"] >= 0
    saved = joblib.load(models.file_path(meta["id"], "model.joblib"))
    assert saved["mode"] == "binary" and "Dst Port" not in saved["features"]


def test_prepare_rejects_datasets_prepared_differently(stores, tmp_path):
    datasets, models = stores
    datasets.save("20261030-100003", {"id": "20261030-100003", "name": "fenêtré", "engine": "CICFlowMeter",
                                      "flowWindowSec": 5}, {"flows.csv": _csv(seed=3)})
    trainer = Trainer(datasets, models)
    with pytest.raises(TrainingError):
        trainer.prepare(_spec(test=["20261030-100003"]))
    assert trainer.prepare(_spec(train=["20261030-100003"], split="temporal", test=[])).flow_window == 5


def test_prepare_rejects_leaky_or_incomplete_requests(stores):
    trainer = Trainer(*stores)
    with pytest.raises(TrainingError):  # même dataset des deux côtés
        trainer.prepare(_spec(test=["20261030-100001"]))
    with pytest.raises(TrainingError):  # pas de jeu de test
        trainer.prepare(_spec(test=[]))
    with pytest.raises(TrainingError):  # dataset inconnu
        trainer.prepare(_spec(train=["20991231-000000"]))
    # Découpage temporel : un seul dataset suffit.
    assert trainer.prepare(_spec(split="temporal", test=[])).test == []
