"""
API HTTP du moteur de simulation.

  GET    /api/health                      le moteur est-il joignable ?
  GET    /api/lab                         état du réseau instancié
  DELETE /api/lab                         arrêt et suppression du réseau
  POST   /api/deployments                 lance l'instanciation d'une topologie → { id }
  GET    /api/deployments/{id}/events     progression en Server-Sent Events
  WS     /api/devices/{id}/terminal       terminal interactif sur un PC ou un serveur (voir terminal.py)
  WS     /api/devices/{id}/interfaces/{if}/capture   capture du trafic d'un lien (voir capture.py)

  GET    /api/lab/traffic                 activité de trafic (agents bénins, scénarios) + catalogues
  POST   /api/lab/traffic/benign          démarre le trafic de fond sur un équipement
  DELETE /api/lab/traffic/benign          arrête le trafic de fond (tous, ou ?node=)
  POST   /api/lab/scenarios               lance un scénario d'audit → description du scénario
  GET    /api/lab/scenarios/{id}/logs     résultat (sortie) d'un scénario
  DELETE /api/lab/scenarios               supprime les scénarios terminés
  WS     /api/lab/simulation              flux des paquets du réseau en temps réel (voir simulation.py)

Lancement : uvicorn app.main:app --port 8000 --reload   (depuis code/backend)
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Callable, List, Optional

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from docker.errors import DockerException
from pydantic import BaseModel
from starlette.websockets import WebSocketDisconnect

from .deployer import DeploymentError, EngineUnavailable, LabManager
from .jobs import JobRegistry
from .models import Service, Topology
from .planner import TopologyError, build_plan
from .settings import load_settings
from .capture import CaptureSession
from .sessions import Session, SessionError, SessionRegistry
from .terminal import TerminalSession
from .traffic import BENIGN_PROFILES, TrafficError, TrafficManager, attack_catalog
from .simulation import SimulationCapture

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s : %(message)s")

settings = load_settings()
lab = LabManager(settings)
traffic = TrafficManager(lab)
jobs = JobRegistry()
sessions = SessionRegistry()  # terminaux et captures ouverts


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    await asyncio.to_thread(sessions.close_all)


app = FastAPI(title="IDS Lab – moteur de simulation", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_methods=["*"],
    allow_headers=["*"],
)

ENGINE_DOWN = "Le moteur de simulation n'est pas démarré sur la machine hôte."


def error_response(status: int, *errors: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"errors": list(errors)})


@app.exception_handler(EngineUnavailable)
async def engine_unavailable(_request: Request, _exc: EngineUnavailable):
    return error_response(503, ENGINE_DOWN)


@app.get("/api/health")
def health():
    lab.client  # lève EngineUnavailable si besoin
    return {"ok": True}


@app.get("/api/lab")
def lab_status():
    return {**lab.status(), "deploying": jobs.busy}


@app.delete("/api/lab")
def lab_stop():
    if jobs.busy:
        return error_response(409, "Un déploiement est en cours.")
    lab.teardown()
    return {"ok": True}


# --------------------------------------------------------------------------- trafic

class Target(BaseModel):
    ip: str = ""
    name: str = ""
    services: List[Service] = []


class BenignRequest(BaseModel):
    node: str
    profile: str = "moderate"
    dest: str = "all"           # libellé des destinataires (affichage)
    kinds: List[str] = []       # types de trafic : « icmp », « http », « service »
    targets: List[Target] = []


class ScenarioRequest(BaseModel):
    source: str  # équipement d'où part le scénario
    attack: str  # identifiant dans le catalogue (voir traffic.ATTACKS)
    target: str  # cible : adresse IP ou sous-réseau selon le scénario


def traffic_guard(fn):
    """Exécute une opération de trafic en traduisant TrafficError en réponse 409."""
    try:
        return fn()
    except TrafficError as exc:
        return error_response(409, str(exc))


@app.get("/api/lab/traffic")
def traffic_overview():
    overview = traffic.overview()
    return {
        **overview,
        "profiles": [{"id": k, "label": v} for k, v in BENIGN_PROFILES.items()],
        "attacks": attack_catalog(),
    }


@app.post("/api/lab/traffic/benign")
def start_benign(req: BenignRequest):
    lab.client  # vérifie la disponibilité du moteur
    targets = [t.model_dump() for t in req.targets]
    return traffic_guard(lambda: traffic.start_benign(req.node, req.profile, targets, req.dest, req.kinds))


@app.delete("/api/lab/traffic/benign")
def stop_benign(node: Optional[str] = None):
    lab.client
    return {"stopped": traffic.stop_benign(node)}


@app.post("/api/lab/scenarios", status_code=201)
def run_scenario(req: ScenarioRequest):
    lab.client
    return traffic_guard(lambda: traffic.run_scenario(req.source, req.attack, req.target))


@app.get("/api/lab/scenarios/{scenario_id}/logs")
def scenario_logs(scenario_id: str):
    lab.client
    return traffic_guard(lambda: {"logs": traffic.scenario_logs(scenario_id)})


@app.get("/api/lab/scenarios/{scenario_id}/flows")
def scenario_flows(scenario_id: str):
    lab.client
    try:
        csv_text = traffic.scenario_flows_csv(scenario_id)
    except TrafficError as exc:
        return error_response(409, str(exc))
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="flux-{scenario_id}.csv"'},
    )


@app.delete("/api/lab/scenarios")
def clear_scenarios():
    lab.client
    return {"cleared": traffic.clear_scenarios()}


@app.websocket("/api/lab/simulation")
async def lab_simulation(websocket: WebSocket):
    """Diffuse chaque paquet du réseau (capture temps réel) pour l'animer dans l'interface."""
    origin = websocket.headers.get("origin")
    if origin is not None and not settings.origin_allowed(origin):
        await websocket.close(code=1008)
        return
    await websocket.accept()

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    capture = SimulationCapture(lab)

    def on_packet(event: dict) -> None:
        if queue.qsize() < 4000:  # borne : sous un flot intense, on laisse tomber le surplus
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except RuntimeError:
                pass

    try:
        await asyncio.to_thread(capture.start, on_packet)
    except EngineUnavailable:
        await websocket.send_json({"type": "error", "message": ENGINE_DOWN})
        await websocket.close()
        return

    async def send_packets() -> None:
        while True:
            event = await queue.get()
            await websocket.send_json({"type": "packet", **event})

    async def watch_close() -> None:
        while True:  # rien à recevoir : on attend juste la fermeture côté navigateur
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                raise WebSocketDisconnect(message.get("code", 1000))

    out = watch = None
    try:
        out = asyncio.ensure_future(send_packets())
        watch = asyncio.ensure_future(watch_close())
        await asyncio.wait({out, watch}, return_when=asyncio.FIRST_COMPLETED)
    except (WebSocketDisconnect, RuntimeError, OSError):
        pass
    finally:
        for task in (out, watch):
            if task is not None:
                task.cancel()
        await asyncio.gather(*(t for t in (out, watch) if t), return_exceptions=True)
        await asyncio.to_thread(capture.stop)
        try:
            await websocket.close()
        except (RuntimeError, OSError):
            pass


@app.post("/api/deployments", status_code=202)
def create_deployment(topology: Topology):
    try:
        plan = build_plan(topology)
    except TopologyError as exc:
        return error_response(400, *exc.errors)

    lab.client  # vérifie la disponibilité avant de lancer la tâche
    job = jobs.start(lambda reporter: lab.deploy(plan, reporter))
    if job is None:
        return error_response(409, "Un déploiement est déjà en cours.")
    return {"id": job.id}


@app.get("/api/deployments/{job_id}/events")
async def deployment_events(job_id: str, request: Request):
    job = jobs.get(job_id)
    if job is None:
        return error_response(404, "Déploiement inconnu.")

    # Reprise après reconnexion : EventSource renvoie le dernier id reçu
    last_id = request.headers.get("last-event-id")
    start = int(last_id) + 1 if last_id and last_id.isdigit() else 0

    async def stream():
        index, idle = start, 0.0
        while True:
            events = job.events_since(index)
            for event in events:
                yield f"id: {index}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                index += 1
            if job.finished and not job.events_since(index):
                return
            if await request.is_disconnected():
                return
            idle = 0.0 if events else idle + 0.2
            if idle >= 15:  # commentaire SSE : garde la connexion ouverte
                yield ": keep-alive\n\n"
                idle = 0.0
            await asyncio.sleep(0.2)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def open_session(websocket: WebSocket, factory: Callable[[], Session]) -> Optional[Session]:
    """
    Accepte la WebSocket et ouvre la session côté équipement.
    En cas d'échec, envoie { type: "error", message } puis ferme.
    """
    # Les WebSockets échappent à CORS : sans ce contrôle, n'importe quelle page
    # ouverte dans le navigateur pourrait obtenir un shell sur les équipements.
    origin = websocket.headers.get("origin")
    if origin is not None and not settings.origin_allowed(origin):
        await websocket.close(code=1008)
        return None

    await websocket.accept()
    try:
        return await asyncio.to_thread(factory)
    except SessionError as exc:
        message = str(exc)
    except EngineUnavailable:
        message = ENGINE_DOWN
    except (DockerException, DeploymentError) as exc:
        logging.getLogger(__name__).error("Ouverture d'une session : %s", exc)
        message = str(exc) if isinstance(exc, DeploymentError) else "Opération impossible sur cet équipement."
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
