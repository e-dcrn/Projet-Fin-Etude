"""
Capture temps réel de tous les paquets du réseau, pour une visualisation à la
Packet Tracer : chaque paquet réellement émis devient une « boule » animée dans
l'interface (voir useSimulation / SimulationLayer).

Principe : sur chaque équipement, un tcpdump léger capture uniquement les
paquets SORTANTS dont la source est l'équipement lui-même (`-Q out` + filtre
« src host <ses IP> »). Chaque paquet est ainsi capturé une seule fois, à son
origine (un routeur ne ré-émet pas de doublon, car il relaie une source qui
n'est pas la sienne). On en extrait un résumé { ts, src, dst, proto, len } que
l'interface transforme en animation le long du chemin source → destination.

La sortie texte de tcpdump est analysée directement (plus simple et plus robuste
que le binaire pcap, et indépendante du type de lien).
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Callable, List, Optional

from docker.errors import DockerException

from .deployer import LabManager

log = logging.getLogger(__name__)

# « 1790.44 eth0  Out IP 10.0.1.11.44856 > 10.0.1.10.80: Flags [S], …, length 0 »
# ou « 1790.44 eth0  Out ARP, Request who-has 10.0.1.10 tell 10.0.1.11, length 28 »
# On isole d'abord l'horodatage et le sens (Out), puis on reconnaît IP ou ARP.
_PREFIX = re.compile(r"^(\d+\.\d+)\s+\S+\s+Out\s+(.*)$")
_IP = re.compile(r"^IP\s+(\S+)\s+>\s+(\S+):\s+(.*)$")
# ARP (broadcast) : chaque « qui-a » part de l'équipement vers tout le segment ;
# l'interface les anime en plusieurs boules (voir useSimulation).
_ARP_REQUEST = re.compile(r"^ARP, Request who-has (\S+) tell ([0-9.]+)")
_ARP_REPLY = re.compile(r"^ARP, Reply ([0-9.]+) is-at")
_LENGTH = re.compile(r"length (\d+)")

# tcpdump : sortant seulement, toutes interfaces, non bufferisé, sans résolution, horodaté epoch.
_TCPDUMP = ["tcpdump", "-Q", "out", "-i", "any", "-l", "-n", "-tt"]

PacketCallback = Callable[[dict], None]


def _ip_only(endpoint: str) -> str:
    """« 10.0.1.11.44856 » → « 10.0.1.11 » ; « 10.0.1.10 » inchangé."""
    parts = endpoint.split(".")
    return ".".join(parts[:4]) if len(parts) >= 4 else endpoint


def parse_line(line: str) -> Optional[dict]:
    """
    Une ligne tcpdump → événement de paquet, ou None si non pertinente.

      - IP   : { ts, src, dst, proto, len }
      - ARP  : { ts, proto:"arp", arp:"request"|"reply", sender, target? }
               (« request » : sender interroge tout le segment pour target ;
                « reply »  : sender répond — le destinataire est retrouvé côté
                interface à partir de la requête correspondante.)
    """
    prefix = _PREFIX.match(line.strip())
    if not prefix:
        return None
    ts = float(prefix.group(1))
    rest = prefix.group(2)

    ip = _IP.match(rest)
    if ip:
        src, dst, tail = ip.groups()
        event = {"ts": ts, "src": _ip_only(src), "dst": _ip_only(dst)}
        if "ICMP" in tail:
            event["proto"] = "icmp"
            # request / reply : l'interface n'anime qu'une boule aller-retour par
            # ping (déclenchée par la requête), et ignore la réponse.
            if "echo request" in tail:
                event["icmp"] = "request"
            elif "echo reply" in tail:
                event["icmp"] = "reply"
            else:
                event["icmp"] = "other"
        elif "Flags" in tail or "tcp" in tail:
            event["proto"] = "tcp"
        elif "UDP" in tail:
            event["proto"] = "udp"
        else:
            event["proto"] = "other"
        length = _LENGTH.search(tail)
        event["len"] = int(length.group(1)) if length else 0
        return event

    request = _ARP_REQUEST.match(rest)
    if request:
        target, sender = request.groups()
        return {"ts": ts, "proto": "arp", "arp": "request", "sender": sender, "target": target.rstrip(",")}

    reply = _ARP_REPLY.match(rest)
    if reply:
        return {"ts": ts, "proto": "arp", "arp": "reply", "sender": reply.group(1)}

    return None


class SimulationCapture:
    """Capture tous les paquets du réseau et les pousse (un par un) à un callback."""

    def __init__(self, lab: LabManager):
        self.lab = lab
        self._helpers: List = []
        self._threads: List[threading.Thread] = []
        self._on_packet: Optional[PacketCallback] = None
        self._closed = False

    def _device_ips(self, container) -> List[str]:
        nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        return [n["IPAddress"] for n in nets.values() if n.get("IPAddress")]

    def start(self, on_packet: PacketCallback) -> None:
        """Démarre un tcpdump par équipement. À appeler une seule fois."""
        self._on_packet = on_packet
        prefix = self.lab.settings.prefix
        for container in self.lab.client.containers.list(filters={"label": self.lab.label}):
            node = container.labels.get(f"{prefix}.node")
            if not node or container.status != "running":
                continue
            ips = self._device_ips(container)
            if not ips:
                continue
            command = [*_TCPDUMP, " or ".join(f"src host {ip}" for ip in ips)]
            try:
                helper = self.lab.start_netns_helper(
                    container, self.lab.settings.capture, command, role="simcapture", attached=node,
                )
            except DockerException as exc:
                log.warning("Capture de simulation sur %s impossible : %s", node, exc)
                continue
            self._helpers.append(helper)
            thread = threading.Thread(target=self._pump, args=(helper, node), daemon=True, name=f"sim-{node}")
            thread.start()
            self._threads.append(thread)
        log.info("Simulation : capture démarrée sur %d équipement(s)", len(self._helpers))

    def _pump(self, helper, node: str) -> None:
        """Lit la sortie de tcpdump ligne par ligne et émet chaque paquet."""
        buffer = b""
        try:
            for chunk in helper.logs(stream=True, follow=True):
                buffer += chunk
                *lines, buffer = buffer.split(b"\n")
                for raw in lines:
                    event = parse_line(raw.decode(errors="replace"))
                    callback = self._on_packet
                    if event and callback and not self._closed:
                        event["node"] = node
                        callback(event)
        except Exception as exc:  # noqa: BLE001 - flux coupé à l'arrêt
            log.debug("Fin de la capture de simulation sur %s : %s", node, exc)

    def stop(self) -> None:
        """Supprime les captures (idempotent)."""
        self._closed = True
        self._on_packet = None
        for helper in self._helpers:
            try:
                helper.remove(force=True)
            except DockerException:
                pass
        self._helpers = []
