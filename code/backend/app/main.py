"""
API HTTP du moteur de simulation.

  GET    /api/lab                         topologie en cours et état de ses équipements
  POST   /api/lab                         démarre une topologie { topology: "1-petit-lan" } (docker compose up)
  DELETE /api/lab                         arrête le réseau (docker compose down)

  GET    /api/lab/traffic                 activité de trafic (agents bénins, scénarios) + catalogues
  POST   /api/lab/traffic/benign          démarre le trafic de fond sur un équipement
  DELETE /api/lab/traffic/benign          arrête le trafic de fond (tous, ou ?node=)
  POST   /api/lab/scenarios               lance une attaque → description du scénario
  POST   /api/lab/scenarios/stop          interrompt les scénarios en cours (?id=… pour un seul)
  DELETE /api/lab/scenarios               supprime les scénarios terminés

  GET    /api/jobs/{id}                   état d'une tâche de fond, redemandé toutes les secondes (voir jobs.py)
  POST   /api/jobs/{id}/cancel            annule une tâche de fond

  GET    /api/datasets                    datasets sauvegardés (voir datasets.py) + génération en cours
  POST   /api/datasets                    lance la génération d'un dataset → { id } (tâche de fond)
  GET    /api/datasets/{id}/files/{name}  télécharge flows.csv, capture.pcap ou meta.json
  DELETE /api/datasets/{id}               supprime un dataset

  GET    /api/models                      modèles entraînés (voir training.py) + entraînement en cours
  POST   /api/models                      lance l'entraînement d'un modèle → { id } (tâche de fond)
  GET    /api/models/{id}/files/{name}    télécharge model.joblib ou meta.json
  DELETE /api/models/{id}                 supprime un modèle

  GET    /api/lab/detection               état de la détection en direct (verdicts, vérité terrain)
  POST   /api/lab/detection               démarre la détection : une Sonde IDS + un modèle entraîné
  DELETE /api/lab/detection               arrête la détection
  POST   /api/lab/detection/reset         efface le bilan et les événements (nouvel essai)

Une erreur prévue est une HTTPException : FastAPI la renvoie sous la forme
{ "detail": "message" }, que l'interface affiche tel quel.

Lancement : uvicorn app.main:app --port 8000 --reload   (depuis code/backend)
"""

import logging
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .compare import score_dataset
from .datasets import FILES as DATASET_FILES, DatasetBuilder, DatasetStore
from .detection import DetectionManager
from .jobs import JobRegistry
from .lab import LabManager
from .settings import LOCAL_ORIGIN_REGEX
from .training import FILES as MODEL_FILES, ModelStore, Trainer
from .traffic import BENIGN_PROFILES, TrafficManager, attack_catalog, speed_catalog

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s : %(message)s")

lab = LabManager()
traffic = TrafficManager(lab)
datasets = DatasetStore()
dataset_builder = DatasetBuilder(traffic, datasets)
models = ModelStore()
trainer = Trainer(datasets, models)
detection = DetectionManager(traffic, models)
jobs = JobRegistry()           # tâches de fond : « dataset », « training »

app = FastAPI(title="IDS Lab – moteur de simulation")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=LOCAL_ORIGIN_REGEX,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- réseau

class StartRequest(BaseModel):
    topology: str  # nom d'un dossier de code/topologies/


@app.get("/api/lab")
def lab_status():
    return lab.status()


@app.post("/api/lab")
def lab_start(req: StartRequest):
    """Démarre une topologie. Peut prendre quelques minutes la première fois (construction des images)."""
    detection.stop()
    lab.start(req.topology)
    return lab.status()


@app.delete("/api/lab")
def lab_stop():
    detection.stop()
    lab.stop()
    return lab.status()


# --------------------------------------------------------------------------- tâches de fond

def find_job(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "Tâche inconnue.")
    return job


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    """État actuel d'une tâche de fond (l'interface le redemande toutes les secondes)."""
    return find_job(job_id).to_dict()


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    find_job(job_id).cancel()
    return {"ok": True}


def current_job_id(kind: str) -> Optional[str]:
    job = jobs.current(kind)
    return job.id if job else None


# --------------------------------------------------------------------------- trafic

class Target(BaseModel):
    ip: str
    server: bool = False  # un serveur offre HTTP, SSH et FTP ; les autres machines répondent au ping


class BenignRequest(BaseModel):
    node: str
    profile: str = "moderate"
    dest: str = "all"           # libellé des destinataires (affichage)
    kinds: List[str] = []       # types de trafic : « icmp », « http », « ssh », « ftp »
    targets: List[Target] = []


class ScenarioRequest(BaseModel):
    source: str  # équipement d'où part le scénario
    attack: str  # identifiant dans le catalogue (voir traffic.ATTACKS)
    target: str  # cible : adresse IP ou sous-réseau selon le scénario
    speed: str = "fast"  # vitesse (voir traffic.SPEEDS)


@app.get("/api/lab/traffic")
def traffic_overview():
    return {
        **traffic.overview(),
        "profiles": [{"id": k, "label": v} for k, v in BENIGN_PROFILES.items()],
        "attacks": attack_catalog(),
        "speeds": speed_catalog(),
    }


@app.post("/api/lab/traffic/benign")
def start_benign(req: BenignRequest):
    targets = [t.model_dump() for t in req.targets]
    return traffic.start_benign(req.node, req.profile, targets, req.dest, req.kinds)


@app.delete("/api/lab/traffic/benign")
def stop_benign(node: Optional[str] = None):
    return {"stopped": traffic.stop_benign(node)}


@app.post("/api/lab/scenarios", status_code=201)
def run_scenario(req: ScenarioRequest):
    return traffic.run_scenario(req.source, req.attack, req.target, req.speed)


@app.post("/api/lab/scenarios/stop")
def stop_scenarios(id: Optional[str] = None):
    return {"stopped": traffic.stop_scenarios(id)}


@app.delete("/api/lab/scenarios")
def clear_scenarios():
    return {"cleared": traffic.clear_scenarios()}


# --------------------------------------------------------------------------- datasets

class DatasetBenign(BaseModel):
    node: str
    targets: List[Target] = []


class DatasetAttack(BaseModel):
    source: str
    attack: str
    target: str
    speed: str = "fast"
    repeat: int = Field(1, ge=1, le=10)         # borné ici : le champ de l'interface accepte toute saisie


# Les bornes des durées et du nombre de variantes sont imposées par l'interface (DatasetDialog).
class DatasetRequest(BaseModel):
    name: str = ""
    probe: str                                  # Sonde IDS : seul point de capture d'un dataset
    benign: List[DatasetBenign] = []
    kinds: List[str] = []                       # types de trafic bénin : « icmp », « http », « ssh », « ftp »
    profile: str = "moderate"
    attacks: List[DatasetAttack] = []
    warmup: int = 30                            # trafic bénin seul avant la première attaque (s)
    gap: int = 10                               # trafic bénin seul entre deux attaques (s)
    cooldown: int = 20                          # trafic bénin seul après la dernière attaque (s)
    maxAttack: int = 60                         # durée maximale d'une attaque (s)
    variants: int = 0                           # variantes de test générées ensuite (voir datasets.make_variant)


@app.get("/api/datasets")
def list_datasets():
    return {"datasets": datasets.list(), "job": current_job_id("dataset")}


@app.post("/api/datasets", status_code=202)
def create_dataset(req: DatasetRequest):
    plan = dataset_builder.prepare(req.model_dump())
    job = jobs.start("dataset", lambda job: dataset_builder.run(plan, job))
    return {"id": job.id}


@app.get("/api/datasets/{dataset_id}/files/{name}")
def dataset_file(dataset_id: str, name: str):
    path = datasets.file_path(dataset_id, name)
    return FileResponse(path, media_type=DATASET_FILES[name], filename=f"dataset-{dataset_id}-{name}")


@app.get("/api/datasets/{dataset_id}/scored")
def dataset_scored(dataset_id: str, model: str):
    """Rejoue un modèle sur les flux stockés d'un run (pour la vue « Comparer »)."""
    return score_dataset(datasets, models, dataset_id, model)


@app.delete("/api/datasets/{dataset_id}")
def delete_dataset(dataset_id: str):
    datasets.delete(dataset_id)
    return {"ok": True}


# --------------------------------------------------------------------------- modèles (ML-IDS)

class TrainingRequest(BaseModel):
    name: str = ""
    train: List[str]                            # datasets d'entraînement
    test: List[str]                             # datasets de test (jamais vus à l'entraînement)
    # Bornés ici : les champs numériques de l'interface acceptent toute saisie.
    nEstimators: int = Field(100, ge=10, le=500)
    maxDepth: Optional[int] = Field(None, ge=2, le=100)
    excludePort: bool = True                    # ne pas utiliser Dst Port comme feature


@app.get("/api/models")
def list_models():
    return {"models": models.list(), "job": current_job_id("training")}


@app.post("/api/models", status_code=202)
def create_model(req: TrainingRequest):
    plan = trainer.prepare(req.model_dump())
    job = jobs.start("training", lambda job: trainer.run(plan, job))
    return {"id": job.id}


@app.get("/api/models/{model_id}/files/{name}")
def model_file(model_id: str, name: str):
    path = models.file_path(model_id, name)
    return FileResponse(path, media_type=MODEL_FILES[name], filename=f"modele-{model_id}-{name}")


@app.delete("/api/models/{model_id}")
def delete_model(model_id: str):
    models.delete(model_id)
    return {"ok": True}


# --------------------------------------------------------------------------- détection en direct

class DetectionRequest(BaseModel):
    ids: str    # Sonde IDS qui reçoit la copie du trafic du segment surveillé
    model: str  # modèle entraîné (voir training.py)


@app.get("/api/lab/detection")
def detection_status():
    return detection.status()


@app.post("/api/lab/detection", status_code=201)
def start_detection(req: DetectionRequest):
    return detection.start(req.ids, req.model)


@app.delete("/api/lab/detection")
def stop_detection():
    return detection.stop()


@app.post("/api/lab/detection/reset")
def reset_detection():
    return detection.reset()
