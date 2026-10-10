"""Chargement de la configuration serveur (config/devices.toml)."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.9 / 3.10
    import tomli as tomllib

BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = BACKEND_DIR / "config" / "devices.toml"

# Types d'équipements instanciés comme machines (les switches deviennent des réseaux)
MACHINE_TYPES = ("pc", "server", "router", "ids")

# Origines autorisées par défaut : l'interface servie en local, quel que soit son port
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
    devices: Dict[str, DeviceRuntime]
    cors_origins: List[str]  # origines autorisées explicitement (IDSLAB_CORS_ORIGINS)
    cors_origin_regex: Optional[str]  # sinon : toute origine locale

    def origin_allowed(self, origin: str) -> bool:
        """Même règle que CORS, appliquée aussi aux WebSockets (qui y échappent)."""
        if origin in self.cors_origins:
            return True
        return bool(self.cors_origin_regex and re.fullmatch(self.cors_origin_regex, origin))


def load_settings(path: Path | None = None) -> Settings:
    path = Path(path or os.environ.get("IDSLAB_DEVICES_CONFIG", DEFAULT_CONFIG_PATH))
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    lab = raw.get("lab", {})
    defaults = raw.get("defaults", {})
    devices = {}
    for device_type in MACHINE_TYPES:
        entry = raw.get("devices", {}).get(device_type)
        if not entry or "image" not in entry:
            raise ValueError(f"{path} : aucune image définie pour le type « {device_type} »")
        devices[device_type] = DeviceRuntime(
            image=entry["image"],
            command=list(entry.get("command", defaults.get("command", ["sleep", "infinity"]))),
            cap_add=list(entry.get("cap_add", defaults.get("cap_add", []))),
            packages=list(entry.get("packages", defaults.get("packages", []))),
        )

    capture = raw.get("capture", {})
    capture_runtime = DeviceRuntime(
        image=capture.get("image", "alpine:3.20"),
        command=["sleep", "infinity"],
        cap_add=["NET_ADMIN", "NET_RAW"],
        packages=list(capture.get("packages", ["tcpdump"])),
    )

    origins = os.environ.get("IDSLAB_CORS_ORIGINS", "")
    return Settings(
        prefix=lab.get("prefix", "idslab"),
        helper_image=lab.get("helper_image", "alpine:3.20"),
        capture=capture_runtime,
        devices=devices,
        cors_origins=[o.strip() for o in origins.split(",") if o.strip()],
        cors_origin_regex=None if origins.strip() else LOCAL_ORIGIN_REGEX,
    )
