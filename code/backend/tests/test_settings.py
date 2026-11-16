import pytest

from app.planner import TYPE_LABELS
from app.settings import DOCKER_DIR, origin_allowed


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5180"])
def test_any_local_port_allowed(origin):
    assert origin_allowed(origin)


@pytest.mark.parametrize("origin", ["https://evil.example", "http://localhost.evil.example", "http://192.168.1.2:5173"])
def test_other_origins_refused(origin):
    assert not origin_allowed(origin)


@pytest.mark.parametrize("role", [*TYPE_LABELS, "toolbox"])
def test_every_role_has_a_dockerfile(role):
    assert (DOCKER_DIR / role / "Dockerfile").is_file()
