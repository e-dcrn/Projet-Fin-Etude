"""
Terminal interactif sur un équipement (PC ou serveur).

Un shell est lancé dans la machine (exec avec TTY) et son entrée-sortie est
reliée au navigateur par une WebSocket, où xterm.js l'affiche.

Protocole (voir main.py, route /api/devices/{id}/terminal) :
  navigateur → serveur  (texte JSON)
      { "type": "input",  "data": "<frappes clavier>" }
      { "type": "resize", "cols": 120, "rows": 30 }
  serveur → navigateur
      binaire                                 sortie brute du terminal
      { "type": "ready" }                     shell ouvert
      { "type": "exit", "message": "…" }      fin de session (exit, équipement éteint)
      { "type": "error", "message": "…" }     ouverture impossible

Chaque WebSocket a son propre shell et son propre thread de lecture : les
sessions sont indépendantes, y compris sur une même machine. À la fermeture,
tous les processus lancés depuis la session (shell, ping en cours…) sont tués.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import uuid
from typing import Optional

from docker.errors import DockerException, NotFound
from starlette.websockets import WebSocket, WebSocketDisconnect

from .deployer import LabManager
from .sessions import SessionError

log = logging.getLogger(__name__)

# Équipements sur lesquels un terminal peut être ouvert
TERMINAL_TYPES = ("pc", "server")

# bash s'il est installé, sinon le shell de base ; -l : charge /etc/profile (invite « hôte:~# »)
SHELL = ["/bin/sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"]

# Variable posée sur le shell et héritée par tout ce qu'il lance : permet de
# retrouver les processus de la session pour les arrêter à la fermeture.
SESSION_VAR = "TERM_SESSION_ID"
KILL_SCRIPT = (
    'for p in /proc/[0-9]*; do '
    f'if tr "\\0" "\\n" < "$p/environ" 2>/dev/null | grep -qx "{SESSION_VAR}=$1"; then kill -KILL "${{p##*/}}" 2>/dev/null; fi; '
    "done; true"
)

READ_SIZE = 64 * 1024


class TerminalError(SessionError):
    pass


def _clamp(value, low: int, high: int, default: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


class TerminalSession:
    def __init__(self, lab: LabManager, node_id: str, cols: int, rows: int):
        self.id = uuid.uuid4().hex
        self._lab = lab
        self._client = lab.client
        self._closed = False
        self._lock = threading.Lock()

        container = lab.find_device(node_id)
        if container is None or container.status != "running":
            raise TerminalError("Cet équipement est éteint : validez la topologie pour le démarrer.")
        if container.labels.get(f"{lab.settings.prefix}.type") not in TERMINAL_TYPES:
            raise TerminalError("Le terminal n'est disponible que sur les PC et les serveurs.")
        self.container = container
        self.name = container.labels.get(f"{lab.settings.prefix}.name", node_id)

        api = self._client.api
        self._exec_id = api.exec_create(
            container.id,
            SHELL,
            stdin=True,
            tty=True,
            environment={"TERM": "xterm-256color", SESSION_VAR: self.id},
            workdir="/root",
        )["Id"]
        raw = api.exec_start(self._exec_id, socket=True, tty=True)
        # Socket brute : en mode TTY le flux n'est pas multiplexé, on relaie les octets tels quels
        self._sock: socket.socket = getattr(raw, "_sock", raw)
        self.resize(cols, rows)
        log.info("Terminal %s ouvert sur %s", self.id[:8], self.name)

    # ------------------------------------------------------------------ E/S bloquantes

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def resize(self, cols, rows) -> None:
        cols, rows = _clamp(cols, 2, 1000, 80), _clamp(rows, 2, 1000, 24)
        try:
            self._client.api.exec_resize(self._exec_id, height=rows, width=cols)
        except DockerException as exc:  # le shell peut ne pas être encore prêt : sans gravité
            log.debug("Redimensionnement ignoré : %s", exc)

    def device_stopped(self) -> bool:
        try:
            self.container.reload()
            return self.container.status != "running"
        except NotFound:
            return True
        except DockerException:
            return False

    def close(self) -> None:
        """Arrête les processus de la session puis ferme la connexion (idempotent)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            self.container.exec_run(["sh", "-c", KILL_SCRIPT, "sh", self.id])
        except DockerException:
            pass  # équipement déjà éteint : plus rien à arrêter
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()
        log.info("Terminal %s fermé (%s)", self.id[:8], self.name)

    # ------------------------------------------------------------------ relais

    def _pump(self, loop: asyncio.AbstractEventLoop, queue: "asyncio.Queue[Optional[bytes]]") -> None:
        """Thread de lecture : sortie du shell → file asyncio (None = fin du flux)."""
        try:
            while True:
                data = self._sock.recv(READ_SIZE)
                if not data:
                    break
                loop.call_soon_threadsafe(queue.put_nowait, data)
        except OSError:
            pass
        finally:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:  # boucle arrêtée (arrêt du serveur)
                pass

    async def run(self, websocket: WebSocket) -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        threading.Thread(target=self._pump, args=(loop, queue), daemon=True, name=f"term-{self.id[:8]}").start()

        async def downstream() -> None:
            while True:
                data = await queue.get()
                if data is None:
                    return
                await websocket.send_bytes(data)

        async def upstream() -> None:
            while True:
                try:
                    message = json.loads(await websocket.receive_text())
                except (ValueError, KeyError):
                    continue  # message illisible (ou binaire) : ignoré
                kind = message.get("type") if isinstance(message, dict) else None
                if kind == "input" and isinstance(message.get("data"), str):
                    await asyncio.to_thread(self.write, message["data"].encode())
                elif kind == "resize":
                    await asyncio.to_thread(self.resize, message.get("cols"), message.get("rows"))

        # Tout ce qui suit l'ouverture est sous try/finally : la session est libérée
        # même si le navigateur s'est déjà déconnecté (envoi de « ready » impossible).
        down = up = None
        try:
            await websocket.send_json({"type": "ready", "name": self.name})
            down = asyncio.ensure_future(downstream())
            up = asyncio.ensure_future(upstream())
            done, _ = await asyncio.wait({down, up}, return_when=asyncio.FIRST_COMPLETED)
            if down in done and down.exception() is None:
                # Le shell s'est terminé : exit tapé par l'utilisateur, ou équipement éteint
                stopped = await asyncio.to_thread(self.device_stopped)
                message = f"{self.name} a été éteint." if stopped else "Session terminée."
                try:
                    await websocket.send_json({"type": "exit", "message": message})
                    await websocket.close()
                except (WebSocketDisconnect, RuntimeError, OSError):
                    pass
        except (WebSocketDisconnect, RuntimeError, OSError):
            pass  # navigateur déjà parti
        finally:
            tasks = [t for t in (down, up) if t is not None]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.to_thread(self.close)
