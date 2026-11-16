import pytest

from app.settings import MACHINE_TYPES, load_settings, origin_allowed


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5180"])
def test_any_local_port_allowed(origin):
    assert origin_allowed(origin)


@pytest.mark.parametrize("origin", ["https://evil.example", "http://localhost.evil.example", "http://192.168.1.2:5173"])
def test_other_origins_refused(origin):
    assert not origin_allowed(origin)


def test_config_defines_every_machine_type():
    settings = load_settings()
    assert set(settings.devices) == set(MACHINE_TYPES)
