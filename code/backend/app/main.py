"""
API HTTP du moteur de simulation.

  GET    /api/lab                         état du réseau instancié
  DELETE /api/lab                         arrêt et suppression du réseau
  POST   /api/deployments                 lance l'instanciation d'une topologie → { id } (tâche de fond)
  WS     /api/devices/{id}/terminal       terminal interactif sur un PC ou un serveur (voir terminal.py)
  WS     /api/devices/{id}/interfaces/{if}/capture   capture du trafic d'un lien (voir capture.py)

  GET    /api/jobs/{id}                   état d'une tâche de fond, redemandé toutes les secondes (voir jobs.py)
  POST   /api/jobs/{id}/cancel            annule une tâche de fond

  GET    /api/lab/traffic                 activité de trafic (agents bénins, scénarios) + catalogues
  POST   /api/lab/traffic/benign          démarre le trafic de fond sur un équipement
  DELETE /api/lab/traffic/benign          arrête le trafic de fond (tous, ou ?node=)
  POST   /api/lab/scenarios               lance un scénario d'audit → description du scénario
  GET    /api/lab/scenarios/{id}/logs     résultat (sortie) d'un scénario
  POST   /api/lab/scenarios/stop          interrompt les scénarios en cours (?id=… pour un seul)
  DELETE /api/lab/scenarios               supprime les scénarios terminés

  GET    /api/datasets                    datasets sauvegardés (voir datasets.py) + génération en cours
  POST   /api/datasets                    lance la génération d'un dataset → { id } (tâche de fond)
  GET    /api/datasets/{id}/files/{name}  télécharge flows.csv, capture.pcap ou meta.json
  DELETE /api/datasets/{id}               supprime un dataset

  GET    /api/models                      modèles entraînés (voir training.py) + entraînement en cours + options
  POST   /api/models                      lance l'entraînement d'un modèle → { id } (tâche de fond)
  GET    /api/models/{id}/files/{name}    télécharge model.joblib ou meta.json
  DELETE /api/models/{id}                 supprime un modèle

  GET    /api/lab/detection               état de la détection en direct (verdicts, vérité terrain)
  POST   /api/lab/detection               démarre la détection : une Sonde IDS + un modèle entraîné
  DELETE /api/lab/detection               arrête la détection
  POST   /api/lab/detection/reset         efface le bilan et les événements (nouvel essai)

Toute erreur destinée à l'utilisateur est une UserError (voir errors.py) : elle
devient une réponse { errors: [message…] } avec son code HTTP.

Lancement : uvicorn app.main:app --port 8000 --reload   (depuis code/backend)
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Callable, List, Optional

from docker.errors import DockerException
from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .capture import CaptureSession
from .datasets import FILES as DATASET_FILES, DatasetBuilder, DatasetStore
from .deployer import LabManager
from .detection import DetectionManager
from .errors import NotFoundError, UserError
from .jobs import JobRegistry
from .models import Service, Topology
from .planner import TopologyError, build_plan
from .sessions import Session, SessionRegistry
from .settings import LOCAL_ORIGIN_REGEX, origin_allowed
from .terminal import TerminalSession
from .training import FILES as MODEL_FILES, MODELS, SPLITS, ModelStore, Trainer
from .traffic import BENIGN_PROFILES, TrafficManager, attack_catalog, speed_catalog

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s : %(message)s")
log = logging.getLogger(__name__)

lab = LabManager()
traffic = TrafficManager(lab)
datasets = DatasetStore()
dataset_builder = DatasetBuilder(traffic, datasets)
models = ModelStore()
trainer = Trainer(datasets, models)
detection = DetectionManager(traffic, models)
jobs = JobRegistry()           # tâches de fond : « deploy », « dataset », « training »
sessions = SessionRegistry()   # terminaux et captures ouverts


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    await asyncio.to_thread(sessions.close_all)


app = FastAPI(title="IDS Lab – moteur de simulation", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=LOCAL_ORIGIN_REGEX,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(UserError)
async def user_error(_request: Request, exc: UserError):
    messages = exc.errors if isinstance(exc, TopologyError) else [str(exc)]
    return JSONResponse(status_code=exc.status, content={"errors": messages})


def ensure_not_deploying() -> None:
    if jobs.busy("deploy"):
        raise UserError("Un déploiement est en cours.")


# --------------------------------------------------------------------------- réseau

@app.get("/api/lab")
def lab_status():
    return lab.status()


@app.delete("/api/lab")
def lab_stop():
    ensure_not_deploying()
    detection.stop()
    lab.teardown()
    return {"ok": True}


@app.post("/api/deployments", status_code=202)
def create_deployment(topology: Topology):
    plan = build_plan(topology)
    lab.client  # vérifie que Docker répond avant de lancer la tâche
    job = jobs.start("deploy", lambda job: lab.deploy(plan, job))
    return {"id": job.id}


# --------------------------------------------------------------------------- tâches de fond

def find_job(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise NotFoundError("Tâche inconnue.")
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
    ip: str = ""
    name: str = ""
    services: List[Service] = []


class BenignRequest(BaseModel):
    node: str
    profile: str = "moderate"
    dest: str = "all"           # libellé des destinataires (affichage)
    kinds: List[str] = []       # types de trafic : « icmp », un service (« http », « ssh »…) ou un groupe (« web », « service »)
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


@app.get("/api/lab/scenarios/{scenario_id}/logs")
def scenario_logs(scenario_id: str):
    return {"logs": traffic.scenario_logs(scenario_id)}


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
    repeat: int = Field(1, ge=1, le=10)


class DatasetRequest(BaseModel):
    name: str = ""
    probe: str = ""                             # Sonde IDS : seul point de capture d'un dataset
    benign: List[DatasetBenign] = []
    kinds: List[str] = []                       # types de trafic bénin : « icmp » et un par service (« http », « ssh »…)
    profile: str = "moderate"
    attacks: List[DatasetAttack] = []
    warmup: int = Field(30, ge=0, le=600)       # trafic bénin seul avant la première attaque (s)
    gap: int = Field(10, ge=0, le=600)          # trafic bénin seul entre deux attaques (s)
    cooldown: int = Field(20, ge=0, le=600)     # trafic bénin seul après la dernière attaque (s)
    maxAttack: int = Field(60, ge=5, le=600)    # durée maximale d'une attaque (s)
    variants: int = Field(0, ge=0, le=5)        # variantes de test générées ensuite (voir datasets.make_variant)


@app.get("/api/datasets")
def list_datasets():
    return {"datasets": datasets.list(), "job": current_job_id("dataset")}


@app.post("/api/datasets", status_code=202)
def create_dataset(req: DatasetRequest):
    ensure_not_deploying()
    plan = dataset_builder.prepare(req.model_dump())
    job = jobs.start("dataset", lambda job: dataset_builder.run(plan, job))
    return {"id": job.id}


@app.get("/api/datasets/{dataset_id}/files/{name}")
def dataset_file(dataset_id: str, name: str):
    path = datasets.file_path(dataset_id, name)
    return FileResponse(path, media_type=DATASET_FILES[name], filename=f"dataset-{dataset_id}-{name}")


@app.delete("/api/datasets/{dataset_id}")
def delete_dataset(dataset_id: str):
    datasets.delete(dataset_id)
    return {"ok": True}


# --------------------------------------------------------------------------- modèles (ML-IDS)

class TrainingRequest(BaseModel):
    name: str = ""
    train: List[str]                            # datasets d'entraînement
    test: List[str] = []                        # datasets de test (split « dataset »)
    split: str = "dataset"                      # « dataset » ou « temporal »
    testFraction: float = Field(0.3, ge=0.1, le=0.5)  # part du jeu gardée pour le test (split « temporal »)
    model: str = "random-forest"
    nEstimators: int = Field(100, ge=10, le=500)
    maxDepth: Optional[int] = Field(None, ge=2, le=100)
    excludePort: bool = True                    # ne pas utiliser Dst Port comme feature


def options(catalog: dict) -> list:
    return [{"id": k, "label": v} for k, v in catalog.items()]


@app.get("/api/models")
def list_models():
    return {
        "models": models.list(),
        "job": current_job_id("training"),
        "options": {"models": options(MODELS), "splits": options(SPLITS)},
    }


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


# --------------------------------------------------------------------------- terminal et capture (WebSockets)

async def open_session(websocket: WebSocket, factory: Callable[[], Session]) -> Optional[Session]:
    """
    Accepte la WebSocket et ouvre la session côté équipement.
    En cas d'échec, envoie { type: "error", message } puis ferme.
    """
    # Les WebSockets échappent à CORS : sans ce contrôle, n'importe quelle page
    # ouverte dans le navigateur pourrait obtenir un shell sur les équipements.
    origin = websocket.headers.get("origin")
    if origin is not None and not origin_allowed(origin):
        await websocket.close(code=1008)
        return None

    await websocket.accept()
    try:
        return await asyncio.to_thread(factory)
    except UserError as exc:
        message = str(exc)
    except DockerException as exc:
        log.error("Ouverture d'une session : %s", exc)
        message = "Opération impossible sur cet équipement."
    await websocket.send_json({"type": "error", "message": message})
    await websocket.close()
    return None


@app.websocket("/api/devices/{node_id}/terminal")
async def device_terminal(websocket: WebSocket, node_id: str, cols: int = 80, rows: int = 24):
    session = await open_session(websocket, lambda: TerminalSession(lab, node_id, cols, rows))
    if session:
        await sessions.serve(session, websocket)


@app.websocket("/api/devices/{node_id}/interfaces/{interface}/capture")
async def link_capture(websocket: WebSocket, node_id: str, interface: str):
    session = await open_session(websocket, lambda: CaptureSession(lab, node_id, interface))
    if session:
        await sessions.serve(session, websocket)
