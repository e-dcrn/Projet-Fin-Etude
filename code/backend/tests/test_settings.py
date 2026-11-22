import re

import pytest

from app.settings import LOCAL_ORIGIN_REGEX, TOPOLOGIES_DIR


def origin_allowed(origin):
    """Règle appliquée par le CORSMiddleware de Starlette (fullmatch)."""
    return re.fullmatch(LOCAL_ORIGIN_REGEX, origin) is not None


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5180"])
def test_any_local_port_allowed(origin):
    assert origin_allowed(origin)


@pytest.mark.parametrize("origin", ["https://evil.example", "http://localhost.evil.example", "http://192.168.1.2:5173"])
def test_other_origins_refused(origin):
    assert not origin_allowed(origin)


def test_every_topology_has_a_compose_file_and_a_drawing():
    folders = [d for d in TOPOLOGIES_DIR.iterdir() if d.is_dir()]
    assert len(folders) == 3
    for folder in folders:
        assert (folder / "docker-compose.yml").is_file()
        assert (folder / "topology.json").is_file()
