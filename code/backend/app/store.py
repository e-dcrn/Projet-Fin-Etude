"""
Stockage sur disque des artefacts produits par le démonstrateur (datasets,
modèles entraînés) : un dossier par enregistrement, identifié par sa date de
création, avec un meta.json qui le décrit et des fichiers téléchargeables.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from pathlib import Path
from typing import Dict, List, Type, Union

log = logging.getLogger(__name__)

# Identifiant d'un enregistrement : sa date de création (AAAAMMJJ-HHMMSS[-n]).
ID_RE = re.compile(r"^\d{8}-\d{6}(?:-\d+)?$")


class RecordStore:
    """
    Enregistrements d'un même type sous `root`. `files` liste les fichiers
    téléchargeables (nom → type MIME) ; `error` est l'exception levée pour un
    identifiant ou un fichier inconnu (message affichable tel quel).
    """

    def __init__(self, root: Path, files: Dict[str, str], error: Type[Exception], what: str):
        self.root = Path(root)
        self.files = files
        self._error = error
        self._what = what  # « Dataset », « Modèle »… pour les messages

    def _dir(self, record_id: str) -> Path:
        if not ID_RE.match(record_id or ""):
            raise self._error(f"{self._what} introuvable.")
        path = self.root / record_id
        if not (path / "meta.json").is_file():
            raise self._error(f"{self._what} introuvable.")
        return path

    def new_id(self) -> str:
        base = time.strftime("%Y%m%d-%H%M%S")
        candidate, n = base, 1
        while (self.root / candidate).exists():
            n += 1
            candidate = f"{base}-{n}"
        return candidate

    def save(self, record_id: str, meta: dict, payload: Dict[str, Union[str, bytes]]) -> None:
        path = self.root / record_id
        path.mkdir(parents=True, exist_ok=True)
        for name, content in payload.items():
            target = path / name
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")
        # meta.json en dernier : un dossier sans lui n'est pas (encore) un enregistrement.
        (path / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    def list(self) -> List[dict]:
        if not self.root.is_dir():
            return []
        metas = []
        for path in self.root.iterdir():
            meta_file = path / "meta.json"
            if ID_RE.match(path.name) and meta_file.is_file():
                try:
                    metas.append(json.loads(meta_file.read_text(encoding="utf-8")))
                except (OSError, ValueError) as exc:
                    log.warning("%s %s illisible : %s", self._what, path.name, exc)
        return sorted(metas, key=lambda m: m.get("id", ""), reverse=True)

    def get(self, record_id: str) -> dict:
        return json.loads((self._dir(record_id) / "meta.json").read_text(encoding="utf-8"))

    def file_path(self, record_id: str, name: str) -> Path:
        if name not in self.files:
            raise self._error("Fichier inconnu.")
        return self._dir(record_id) / name

    def delete(self, record_id: str) -> None:
        shutil.rmtree(self._dir(record_id))
