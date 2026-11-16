"""Chargement de la configuration serveur (config/devices.toml)."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.9 / 3.10
    import tomli as tomllib

BACKEND_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BACKEND_DIR / "config" / "devices.toml"
DATA_DIR = BACKEND_DIR / "data"  # datasets et modèles sauvegardés

# Types d'équipements instanciés comme machines (les switches deviennent des réseaux)
MACHINE_TYPES = ("pc", "server", "router", "ids")

# Origines autorisées : l'interface servie en local, quel que soit son port
# (Vite passe à 5174, 5175… si 5173 est occupé).
LOCAL_ORIGIN_REGEX = r"https?://(localhost|127\.0\.0\.1)(:\d+)?"


@dataclass(frozen=True)
class DeviceRuntime:
    image: str
    command: List[str]
    cap_add: List[str]
    packages: List[str]  # paquets ajoutés à l'image (outils réseau : curl…)


@dataclass(frozen=True)
class Settings:
    prefix: str
    helper_image: str
    capture: DeviceRuntime  # outil de capture du trafic (tcpdump), lancé à côté d'un équipement
    traffic: DeviceRuntime  # boîte à outils de génération de trafic (agent bénin, attaques), lancée à côté d'un équipement
    devices: Dict[str, DeviceRuntime]


def origin_allowed(origin: str) -> bool:
    """Même règle que CORS, appliquée aussi aux WebSockets (qui y échappent)."""
    return re.fullmatch(LOCAL_ORIGIN_REGEX, origin) is not None


def load_settings(path: Path = CONFIG_PATH) -> Settings:
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    defaults = raw["defaults"]

    def runtime(entry: dict) -> DeviceRuntime:
        return DeviceRuntime(
            image=entry["image"],
            command=defaults["command"],
            cap_add=defaults["cap_add"],
            packages=entry.get("packages", []),
        )

    return Settings(
        prefix=raw["lab"]["prefix"],
        helper_image=raw["lab"]["helper_image"],
        capture=runtime(raw["capture"]),
        traffic=runtime(raw["traffic"]),
        devices={device_type: runtime(raw["devices"][device_type]) for device_type in MACHINE_TYPES},
    )
