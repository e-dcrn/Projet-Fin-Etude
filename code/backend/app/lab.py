"""
Le réseau simulé (« lab ») : démarrage et arrêt d'une topologie avec Docker Compose.

Chaque topologie est un dossier de code/topologies/ :

  docker-compose.yml   ce que Docker lance : un service par équipement, un network
                       par switch, avec les adresses IP écrites à la main ;
  topology.json        ce que l'interface dessine (noms, positions, adresses).

  démarrer : docker compose -f topologies/<id>/docker-compose.yml up -d --build
  arrêter  : docker compose -p idslab down

Les conteneurs « auxiliaires » (trafic bénin, attaques, captures) ne font pas partie
de la topologie : le moteur les lance à la demande (start_netns_helper). Ils portent
le label « idslab.managed », ce qui permet de les retrouver et de les supprimer.
"""

import subprocess
from pathlib import Path

import docker
from fastapi import HTTPException

from .settings import PREFIX, TOPOLOGIES_DIR

# Droits réseau donnés aux conteneurs auxiliaires : NET_ADMIN pour la capture,
# NET_RAW pour ping et les scans.
CAP_ADD = ["NET_ADMIN", "NET_RAW"]

# Labels posés par Docker Compose sur chaque conteneur d'une topologie.
COMPOSE_PROJECT = "com.docker.compose.project"
COMPOSE_SERVICE = "com.docker.compose.service"
COMPOSE_DIR = "com.docker.compose.project.working_dir"


def labels(**extra):
    """Labels d'un conteneur auxiliaire : { "idslab.managed": "true", "idslab.role": "traffic", … }"""
    result = {LabManager.label: "true"}
    for key, value in extra.items():
        result[f"{PREFIX}.{key}"] = value
    return result


def compose(*args):
    """Lance une commande « docker compose … » ; en cas d'échec, renvoie son message à l'interface."""
    result = subprocess.run(["docker", "compose", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise HTTPException(500, f"docker compose a échoué : {result.stderr.strip()[-1500:]}")


class LabManager:
    label = f"{PREFIX}.managed"

    def __init__(self):
        self._client = None

    @property
    def client(self):
        """Connexion à Docker, ouverte à la première utilisation."""
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------------ démarrage et arrêt

    def start(self, topology_id):
        compose_file = TOPOLOGIES_DIR / topology_id / "docker-compose.yml"
        if not compose_file.is_file():
            raise HTTPException(404, "Topologie inconnue.")
        self.stop()
        # --build : construit les images (server, toolbox) ; instantané si les Dockerfiles n'ont pas changé.
        compose("-f", str(compose_file), "up", "-d", "--build")

    def stop(self):
        """Supprime les conteneurs auxiliaires, puis la topologie (conteneurs et réseaux)."""
        for helper in self.helpers():
            try:
                helper.remove(force=True)
            except docker.errors.APIError:
                pass  # déjà en train de disparaître (fin d'une attaque, par exemple)
        compose("-p", PREFIX, "down", "--timeout", "1")

    def devices(self):
        """
        Conteneurs de la topologie en cours. Les conteneurs auxiliaires sont écartés :
        leur image (toolbox) est construite par Compose et leur transmet ses labels Compose.
        """
        found = self.client.containers.list(all=True, filters={"label": f"{COMPOSE_PROJECT}={PREFIX}"})
        return [c for c in found if self.label not in c.labels]

    def status(self):
        """Topologie en cours et état de ses équipements, pour l'interface."""
        devices = self.devices()
        topology = Path(devices[0].labels[COMPOSE_DIR]).name if devices else None
        return {
            "running": bool(devices),
            "topology": topology,
            "devices": [{"id": c.labels[COMPOSE_SERVICE], "running": c.status == "running"} for c in devices],
        }

    # ------------------------------------------------------------------ retrouver les conteneurs

    def find_device(self, node_id):
        """Conteneur d'un équipement de la topologie (pc-1, server-1…), ou None."""
        found = [c for c in self.devices() if c.labels[COMPOSE_SERVICE] == node_id]
        return found[0] if found else None

    def helpers(self, role=None):
        """Conteneurs auxiliaires (tous, ou ceux d'un rôle : « traffic », « scenario »…)."""
        wanted = [self.label] + ([f"{PREFIX}.role={role}"] if role else [])
        return self.client.containers.list(all=True, filters={"label": wanted})

    def start_netns_helper(self, device, command, role, **extra_labels):
        """
        Lance un conteneur auxiliaire (image « toolbox ») qui partage le réseau
        d'un équipement : même IP, mêmes interfaces. Tout ce qu'il envoie semble
        venir de l'équipement. Sert au trafic bénin, aux attaques et aux captures.
        """
        return self.client.containers.run(
            "idslab/toolbox",
            command,
            network_mode=f"container:{device.id}",
            cap_add=CAP_ADD,
            labels=labels(role=role, **extra_labels),
            init=True,
            detach=True,
        )
