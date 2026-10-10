"""
Sessions interactives reliées à une WebSocket (terminal, capture de trafic).

Chaque session possède une ressource côté équipement (shell, outil de capture)
qui doit être libérée quand la WebSocket se ferme, ou à l'arrêt du serveur.
"""

from __future__ import annotations

import threading
from typing import Protocol, Set

from starlette.websockets import WebSocket


class SessionError(Exception):
    """Ouverture impossible ; le message est affichable tel quel."""


class Session(Protocol):
    async def run(self, websocket: WebSocket) -> None: ...  # relaie jusqu'à la fin, puis libère
    def close(self) -> None: ...  # libération idempotente


class SessionRegistry:
    """Sessions ouvertes, pour pouvoir toutes les fermer à l'arrêt du serveur."""

    def __init__(self) -> None:
        self._sessions: Set[Session] = set()
        self._lock = threading.Lock()

    async def serve(self, session: Session, websocket: WebSocket) -> None:
        with self._lock:
            self._sessions.add(session)
        try:
            await session.run(websocket)
        finally:
            with self._lock:
                self._sessions.discard(session)

    def close_all(self) -> None:
        with self._lock:
            sessions, self._sessions = list(self._sessions), set()
        for session in sessions:
            session.close()
