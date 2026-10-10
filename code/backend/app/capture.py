"""
Capture du trafic d'un lien (vue « Wireshark » de l'interface).

Un lien relie l'interface d'un équipement (eth0…) au port d'un switch : on
capture sur cette interface, côté équipement. Un conteneur d'analyse partage
la pile réseau de l'équipement et y lance tcpdump (voir
LabManager.start_capture_helper) ; son flux pcap est découpé en paquets et
relayé au navigateur, qui les décode.

Protocole (route /api/devices/{id}/interfaces/{interface}/capture) :
  serveur → navigateur
      binaire     un ou plusieurs paquets, chacun précédé d'un en-tête de
                  16 octets little-endian : secondes, microsecondes,
                  longueur capturée, longueur réelle (en-tête d'un enregistrement pcap)
      { "type": "ready" }                    capture démarrée
      { "type": "stopped", "message": "…" }  fin de capture (équipement éteint…)
      { "type": "error", "message": "…" }    capture impossible
  navigateur → serveur : rien ; fermer la WebSocket arrête la capture.
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
import threading
import time
from typing import Optional

from docker.errors import DockerException, NotFound
from starlette.websockets import WebSocket, WebSocketDisconnect

from .deployer import LabManager
from .sessions import SessionError

log = logging.getLogger(__name__)

INTERFACE_PATTERN = re.compile(r"^[a-z][a-z0-9]{0,14}$")

# -p : ne pas passer l'interface en mode promiscuous (l'équipement n'en voit
# rien) ; -U : écrire chaque paquet dès sa capture ; -s 0 : paquets entiers.
TCPDUMP = ["tcpdump", "-i", "{interface}", "-p", "-U", "-s", "0", "-w", "-"]

# Nombre magique pcap → (boutisme, horodatage en nanosecondes)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
PCAP_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 16
BATCH_SIZE = 256 * 1024  # regroupe les paquets en rafale dans un même message


class CaptureError(SessionError):
    pass


# Conteneurs de capture des sessions ouvertes : tout autre conteneur de capture
# est orphelin (session interrompue brutalement) et supprimé à la capture suivante.
_live_helpers = set()
_live_lock = threading.Lock()


class PcapStream:
    """Découpe un flux pcap (reçu par morceaux quelconques) en paquets."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._format: Optional[tuple] = None

    def feed(self, chunk: bytes):
        """Ajoute des octets ; renvoie les paquets complets, au format d'en-tête normalisé (voir module)."""
        self._buffer += chunk
        packets = []
        if self._format is None:
            if len(self._buffer) < PCAP_HEADER_SIZE:
                return packets
            magic = bytes(self._buffer[:4])
            if magic not in PCAP_MAGIC:
                raise ValueError("flux pcap invalide")
            self._format = PCAP_MAGIC[magic]
            del self._buffer[:PCAP_HEADER_SIZE]

        endian, nanoseconds = self._format
        offset = 0
        while len(self._buffer) - offset >= RECORD_HEADER_SIZE:
            sec, frac, captured, original = struct.unpack_from(endian + "IIII", self._buffer, offset)
            end = offset + RECORD_HEADER_SIZE + captured
            if len(self._buffer) < end:
                break
            usec = frac // 1000 if nanoseconds else frac
            packets.append(struct.pack("<IIII", sec, usec, captured, original) + bytes(self._buffer[offset + RECORD_HEADER_SIZE : end]))
            offset = end
        del self._buffer[:offset]
        return packets


class CaptureSession:
    def __init__(self, lab: LabManager, node_id: str, interface: str):
        if not INTERFACE_PATTERN.match(interface):
            raise CaptureError("Nom d'interface invalide.")
        device = lab.find_device(node_id)
        if device is None or device.status != "running":
            raise CaptureError("Cet équipement est éteint : validez la topologie pour démarrer le réseau.")
        self.name = device.labels.get(f"{lab.settings.prefix}.name", node_id)
        self.interface = interface
        self.device = device
        self._client = lab.client
        self._closed = False
        self._lock = threading.Lock()
        self._stderr = bytearray()

        with _live_lock:
            lab.remove_capture_helpers(keep=set(_live_helpers))
            self.helper = lab.start_capture_helper(device)
            _live_helpers.add(self.helper.id)
        try:
            command = [part.format(interface=interface) for part in TCPDUMP]
            exec_id = self._client.api.exec_create(self.helper.id, command, stdout=True, stderr=True)["Id"]
            self._stream = self._client.api.exec_start(exec_id, stream=True, demux=True)
        except DockerException:
            self.close()
            raise
        log.info("Capture ouverte sur %s (%s)", self.name, interface)

    def close(self) -> None:
        """Supprime le conteneur d'analyse : tcpdump s'arrête et le flux se termine (idempotent)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            self.helper.remove(force=True)
        except NotFound:
            pass  # déjà supprimé (arrêt du réseau)
        except DockerException as exc:
            log.warning("Suppression de l'outil de capture de %s impossible : %s", self.name, exc)
        with _live_lock:
            _live_helpers.discard(self.helper.id)
        log.info("Capture fermée sur %s (%s)", self.name, self.interface)

    def _pump(self, loop: asyncio.AbstractEventLoop, queue: "asyncio.Queue[Optional[bytes]]") -> None:
        """Thread de lecture : sortie de tcpdump → paquets dans la file asyncio (None = fin)."""
        pcap = PcapStream()
        try:
            for stdout, stderr in self._stream:
                if stderr:
                    self._stderr += stderr
                if stdout:
                    for packet in pcap.feed(stdout):
                        loop.call_soon_threadsafe(queue.put_nowait, packet)
        except Exception as exc:  # noqa: BLE001 - flux coupé (capture arrêtée, équipement éteint…)
            log.debug("Fin du flux de capture : %s", exc)
        finally:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:  # boucle arrêtée (arrêt du serveur)
                pass

    def _stopped(self) -> bool:
        """L'équipement ou l'outil de capture a-t-il été éteint / supprimé ?"""
        for container in (self.helper, self.device):
            try:
                container.reload()
                if container.status != "running":
                    return True
            except NotFound:
                return True
            except DockerException:
                pass
        return False

    def _end_message(self) -> dict:
        errors = [line for line in self._stderr.decode(errors="replace").splitlines() if "tcpdump:" in line and "listening on" not in line]
        if errors and not self._stopped():
            log.warning("Capture sur %s (%s) : %s", self.name, self.interface, " / ".join(errors))
            return {"type": "error", "message": f"Capture impossible sur l'interface {self.interface} de {self.name}."}
        # L'arrêt du réseau supprime l'équipement et l'outil de capture dans un ordre
        # quelconque : tcpdump peut s'arrêter un instant avant ; on laisse le temps de le constater.
        for _ in range(8):
            if self._stopped():
                return {"type": "stopped", "message": f"{self.name} a été éteint (réseau arrêté) : capture arrêtée."}
            time.sleep(0.25)
        return {"type": "stopped", "message": "Capture terminée."}

    async def run(self, websocket: WebSocket) -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        threading.Thread(target=self._pump, args=(loop, queue), daemon=True, name=f"capture-{self.name}").start()

        async def downstream() -> None:
            while True:
                packet = await queue.get()
                if packet is None:
                    return
                batch, size = [packet], len(packet)
                while size < BATCH_SIZE and not queue.empty():
                    packet = queue.get_nowait()
                    if packet is None:
                        await websocket.send_bytes(b"".join(batch))
                        return
                    batch.append(packet)
                    size += len(packet)
                await websocket.send_bytes(b"".join(batch))

        async def upstream() -> None:
            while True:  # rien à recevoir : on attend juste la fermeture côté navigateur
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    raise WebSocketDisconnect(message.get("code", 1000))

        # Tout ce qui suit l'ouverture est sous try/finally : la session est libérée
        # même si le navigateur s'est déjà déconnecté (envoi de « ready » impossible).
        down = up = None
        try:
            await websocket.send_json({"type": "ready"})
            down = asyncio.ensure_future(downstream())
            up = asyncio.ensure_future(upstream())
            done, _ = await asyncio.wait({down, up}, return_when=asyncio.FIRST_COMPLETED)
            if down in done and down.exception() is None:
                end = await asyncio.to_thread(self._end_message)
                try:
                    await websocket.send_json(end)
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
