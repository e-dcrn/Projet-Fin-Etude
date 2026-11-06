"""
Entraînement et évaluation d'un ML-IDS sur les datasets étiquetés (voir datasets.py).

Une tâche de fond (voir jobs.py) :

  1. charge les CSV CICFlowMeter des datasets choisis ;
  2. prépare les features : on retire les identifiants du flux (IP, ports
     source, Flow ID, Timestamp) qui feraient apprendre un raccourci (« telle IP
     = attaque ») au lieu d'un comportement, on nettoie les inf / NaN fréquents
     dans les sorties de CICFlowMeter, on écarte les colonnes constantes ;
  3. entraîne le modèle (random forest pour l'instant) ;
  4. l'évalue sur des données qu'il n'a JAMAIS vues : un autre dataset (le plus
     sûr), ou la fin chronologique du jeu (découpage temporel). Un découpage
     aléatoire des lignes mettrait des flux quasi identiques des deux côtés et
     gonflerait les scores : il n'est volontairement pas proposé ;
  5. sauvegarde le modèle (model.joblib) et ses métriques (meta.json) dans
     data/models/<id>/.

Les étiquettes sont soit binaires (BENIGN / ATTACK), soit celles des attaques
(port-scan, ssh-patator…) : classification multiclasse.
"""

from __future__ import annotations

import io
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from .datasets import DatasetError, DatasetStore
from .jobs import Job
from .settings import BACKEND_DIR
from .store import RecordStore

log = logging.getLogger(__name__)

MODELS_DIR = Path(os.environ.get("IDSLAB_DATA_DIR", BACKEND_DIR / "data")) / "models"

FILES = {
    "model.joblib": "application/octet-stream",
    "meta.json": "application/json",
}

BENIGN = "BENIGN"
ATTACK = "ATTACK"

# Colonnes jamais utilisées comme features : identifiants du flux et étiquette.
ID_COLUMNS = ("Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp", "Label")
# Port de destination : informatif, mais dans un petit lab il devient vite un
# raccourci (« tout ce qui ne vise pas le port 80 est une attaque ») : exclu par défaut.
PORT_COLUMN = "Dst Port"

MODELS = {"random-forest": "Random forest"}
MODES = {"binary": "Binaire (BENIGN / ATTACK)", "multiclass": "Multiclasse (une classe par attaque)"}
SPLITS = {"dataset": "Dataset(s) de test séparé(s)", "temporal": "Découpage temporel (fin du jeu en test)"}

TOP_FEATURES = 15


class TrainingError(Exception):
    """Entraînement impossible ; le message est affichable tel quel."""


class ModelStore(RecordStore):
    """Modèles entraînés sauvegardés sur disque : un dossier par modèle (voir store.py)."""

    def __init__(self, root: Path = MODELS_DIR):
        super().__init__(root, FILES, TrainingError, "Modèle")


@dataclass
class TrainingPlan:
    name: str
    train: List[dict]          # métadonnées des datasets d'entraînement
    test: List[dict]           # métadonnées des datasets de test (split « dataset »)
    split: str
    test_fraction: float
    mode: str
    model: str
    n_estimators: int
    max_depth: Optional[int]
    exclude_port: bool
    flow_window: Optional[int] = None  # découpage des flux des datasets (s) ; None : non découpés


# --------------------------------------------------------------------------- préparation des données


def load_frames(store: DatasetStore, datasets: List[dict]) -> pd.DataFrame:
    """Concatène les CSV de plusieurs datasets (colonne _dataset : id d'origine)."""
    frames = []
    for meta in datasets:
        frame = pd.read_csv(store.file_path(meta["id"], "flows.csv"), low_memory=False)
        frame.columns = [c.strip() for c in frame.columns]
        frame["_dataset"] = meta["id"]
        frames.append(frame)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def targets(labels: pd.Series, mode: str) -> pd.Series:
    """Étiquettes à apprendre : celles du dataset (multiclasse) ou BENIGN / ATTACK (binaire)."""
    labels = labels.astype(str).str.strip()
    return labels if mode == "multiclass" else labels.where(labels == BENIGN, ATTACK)


def feature_matrix(frame: pd.DataFrame, exclude_port: bool, columns: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Features numériques d'un jeu de flux. Sans `columns` (jeu d'entraînement),
    on retient les colonnes utiles ; sinon (jeu de test), on reprend exactement
    celles de l'entraînement, dans le même ordre.
    """
    dropped = set(ID_COLUMNS) | {"_dataset"} | ({PORT_COLUMN} if exclude_port else set())
    if columns is None:
        columns = [c for c in frame.columns if c not in dropped]
    data = frame.reindex(columns=columns)
    data = data.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return data


def drop_constant(features: pd.DataFrame) -> pd.DataFrame:
    """Écarte les colonnes constantes (aucune information pour le modèle)."""
    return features.loc[:, features.nunique(dropna=False) > 1]


def temporal_split(frame: pd.DataFrame, test_fraction: float) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Les flux les plus anciens pour l'entraînement, les plus récents pour le test."""
    stamps = pd.to_datetime(frame["Timestamp"], format="%Y-%m-%d %H:%M:%S.%f", errors="coerce")
    ordered = frame.assign(_ts=stamps).sort_values("_ts", kind="stable").drop(columns="_ts")
    cut = int(round(len(ordered) * (1 - test_fraction)))
    return ordered.iloc[:cut], ordered.iloc[cut:]


def evaluate(y_true: pd.Series, y_pred: np.ndarray, train_classes: List[str]) -> dict:
    """Métriques de détection sur le jeu de test (par classe et globales)."""
    classes = sorted(set(y_true) | set(y_pred) | set(train_classes), key=lambda c: (c != BENIGN, c))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0,
    )
    truth_attack = y_true != BENIGN
    pred_attack = y_pred != BENIGN
    benign_total = int((~truth_attack).sum())
    attack_total = int(truth_attack.sum())
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macroF1": float(np.mean([f for f, s in zip(f1, support) if s > 0])) if support.sum() else 0.0,
        # Vue « IDS » : une attaque est détectée si elle n'est pas classée BENIGN (quelle que soit sa classe).
        "detectionRate": float((truth_attack & pred_attack).sum() / attack_total) if attack_total else None,
        "falsePositiveRate": float((~truth_attack & pred_attack).sum() / benign_total) if benign_total else None,
        "classes": classes,
        "perClass": [
            {"label": c, "precision": float(p), "recall": float(r), "f1": float(f), "support": int(s)}
            for c, p, r, f, s in zip(classes, precision, recall, f1, support)
        ],
        "confusion": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
        "unseenClasses": sorted(set(y_true) - set(train_classes)),
    }


def topologies(datasets: List[dict]) -> List[dict]:
    """Topologies (distinctes, par empreinte) sur lesquelles des datasets ont été générés."""
    seen: Dict[str, dict] = {}
    for meta in datasets:
        topology = meta.get("topology") or {}
        if topology.get("signature"):
            seen.setdefault(topology["signature"], {"name": topology.get("name", ""), "signature": topology["signature"]})
    return list(seen.values())


def _counts(series: pd.Series) -> Dict[str, int]:
    return {str(k): int(v) for k, v in series.value_counts().items()}


# --------------------------------------------------------------------------- tâche de fond


class Trainer:
    def __init__(self, datasets: DatasetStore, models: ModelStore):
        self.datasets = datasets
        self.models = models

    def _dataset(self, dataset_id: str) -> dict:
        try:
            return self.datasets.get(dataset_id)
        except DatasetError as exc:
            raise TrainingError(f"Dataset {dataset_id} : {exc}") from exc

    def prepare(self, spec: dict) -> TrainingPlan:
        """Vérifie la demande de l'interface (avant de lancer la tâche)."""
        if spec["model"] not in MODELS:
            raise TrainingError(f"Modèle inconnu « {spec['model']} ».")
        if spec["mode"] not in MODES:
            raise TrainingError(f"Mode inconnu « {spec['mode']} ».")
        if spec["split"] not in SPLITS:
            raise TrainingError(f"Découpage inconnu « {spec['split']} ».")
        train = [self._dataset(i) for i in dict.fromkeys(spec.get("train") or [])]
        test = [self._dataset(i) for i in dict.fromkeys(spec.get("test") or [])] if spec["split"] == "dataset" else []
        if not train:
            raise TrainingError("Choisissez au moins un dataset d'entraînement.")
        if spec["split"] == "dataset":
            if not test:
                raise TrainingError("Choisissez au moins un dataset de test (différent de ceux d'entraînement).")
            shared = {m["id"] for m in train} & {m["id"] for m in test}
            if shared:
                raise TrainingError("Un même dataset ne peut pas servir à la fois à l'entraînement et au test.")
        engines = {m.get("engine") for m in train + test}
        if len(engines) > 1:
            raise TrainingError("Ces datasets n'ont pas les mêmes colonnes (CICFlowMeter et exporteur interne mélangés).")
        # Des flux découpés en fenêtres et des flux entiers n'ont pas les mêmes caractéristiques.
        windows = {m.get("flowWindowSec") for m in train + test}
        if len(windows) > 1:
            raise TrainingError(
                "Ces datasets n'ont pas été préparés de la même façon (flux découpés en fenêtres ou non) : "
                "régénérez les plus anciens."
            )

        default_name = f"{MODELS[spec['model']]} · {'binaire' if spec['mode'] == 'binary' else 'multiclasse'}"
        return TrainingPlan(
            name=(spec.get("name") or "").strip()[:80] or default_name,
            train=train, test=test, split=spec["split"], test_fraction=float(spec["testFraction"]),
            mode=spec["mode"], model=spec["model"], n_estimators=int(spec["nEstimators"]),
            max_depth=int(spec["maxDepth"]) if spec.get("maxDepth") else None,
            exclude_port=bool(spec.get("excludePort", True)),
            flow_window=next(iter(windows)),
        )

    def run(self, plan: TrainingPlan, job: Job) -> dict:
        job.begin(5)
        began = time.time()

        job.step("Chargement des datasets")
        if len(topologies(plan.train + plan.test)) > 1:
            job.warn("Ces datasets viennent de topologies différentes : le trafic n'y a pas les mêmes caractéristiques.")
        if plan.split == "dataset":
            train_frame = load_frames(self.datasets, plan.train)
            test_frame = load_frames(self.datasets, plan.test)
        else:
            train_frame, test_frame = temporal_split(load_frames(self.datasets, plan.train), plan.test_fraction)
        if train_frame.empty or test_frame.empty:
            raise TrainingError("Pas assez de flux pour entraîner puis tester le modèle.")
        job.check_cancelled()

        job.step("Préparation des features")
        y_train = targets(train_frame["Label"], plan.mode)
        y_test = targets(test_frame["Label"], plan.mode)
        if y_train.nunique() < 2:
            raise TrainingError(
                f"Le jeu d'entraînement ne contient qu'une classe ({y_train.iloc[0]}) : il faut des flux bénins ET des attaques."
            )
        x_train = drop_constant(feature_matrix(train_frame, plan.exclude_port))
        x_test = feature_matrix(test_frame, plan.exclude_port, list(x_train.columns))
        if y_test.nunique() < 2:
            job.warn(f"Le jeu de test ne contient qu'une classe ({y_test.iloc[0]}) : certaines métriques n'ont pas de sens.")
        job.check_cancelled()

        job.step(f"Entraînement ({MODELS[plan.model].lower()}, {plan.n_estimators} arbres, {len(x_train)} flux)")
        # class_weight « balanced » : les datasets du lab sont très déséquilibrés (beaucoup
        # plus de flux d'attaque que de bénin, ou l'inverse) ; sans lui le modèle ignore la minorité.
        model = RandomForestClassifier(
            n_estimators=plan.n_estimators, max_depth=plan.max_depth, class_weight="balanced",
            n_jobs=-1, random_state=42,
        )
        fit_began = time.perf_counter()
        model.fit(x_train, y_train)
        train_seconds = time.perf_counter() - fit_began
        job.check_cancelled()

        job.step(f"Évaluation sur {len(x_test)} flux jamais vus")
        # Classes du test absentes de l'entraînement : signalées dans le rapport (metrics.unseenClasses).
        predicted = model.predict(x_test)
        metrics = evaluate(y_test.reset_index(drop=True), predicted, list(model.classes_))
        # Score sur chaque dataset de test séparément : un modèle qui réussit l'un et rate
        # l'autre ne se voit pas dans la moyenne.
        names = {m["id"]: m["name"] for m in plan.test or plan.train}
        metrics["byDataset"] = []
        for dataset_id, rows in test_frame.reset_index(drop=True).groupby("_dataset").groups.items():
            part = evaluate(y_test.reset_index(drop=True).iloc[rows].reset_index(drop=True), predicted[rows], list(model.classes_))
            metrics["byDataset"].append({
                "id": dataset_id, "name": names.get(dataset_id, dataset_id), "rows": len(rows),
                **{k: part[k] for k in ("accuracy", "macroF1", "detectionRate", "falsePositiveRate")},
            })
        importances = sorted(zip(x_train.columns, model.feature_importances_), key=lambda kv: kv[1], reverse=True)

        job.step("Sauvegarde du modèle")
        model_id = self.models.new_id()
        buffer = io.BytesIO()
        # Tout ce qu'il faut pour classer de nouveaux flux (détection en direct, à venir).
        joblib.dump({"model": model, "features": list(x_train.columns), "mode": plan.mode,
                     "excludePort": plan.exclude_port, "flowWindowSec": plan.flow_window}, buffer)
        meta = {
            "id": model_id,
            "name": plan.name,
            "createdAt": datetime.fromtimestamp(began, timezone.utc).isoformat(timespec="seconds"),
            "durationSec": round(time.time() - began, 1),
            "trainSeconds": round(train_seconds, 3),
            "model": plan.model,
            "mode": plan.mode,
            "params": {"nEstimators": plan.n_estimators, "maxDepth": plan.max_depth,
                       "excludePort": plan.exclude_port, "split": plan.split,
                       "testFraction": plan.test_fraction if plan.split == "temporal" else None},
            "train": {"datasets": [{"id": m["id"], "name": m["name"]} for m in plan.train],
                      "rows": len(x_train), "counts": _counts(y_train)},
            "test": {"datasets": [{"id": m["id"], "name": m["name"]} for m in (plan.test or plan.train)],
                     "rows": len(x_test), "counts": _counts(y_test)},
            "featureCount": len(x_train.columns),
            # Conditions d'utilisation : la détection en direct les compare aux siennes.
            "flowWindowSec": plan.flow_window,
            "topologies": topologies(plan.train),
            "topFeatures": [{"name": n, "importance": float(v)} for n, v in importances[:TOP_FEATURES]],
            "metrics": metrics,
        }
        self.models.save(model_id, meta, {"model.joblib": buffer.getvalue()})
        log.info("Modèle %s : exactitude %.3f, F1 macro %.3f", model_id, metrics["accuracy"], metrics["macroF1"])
        return {"model": meta}
