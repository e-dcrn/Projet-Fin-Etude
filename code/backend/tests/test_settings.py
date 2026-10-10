import pytest

from app.settings import LOCAL_ORIGIN_REGEX, load_settings


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.delenv("IDSLAB_CORS_ORIGINS", raising=False)
    return load_settings()


def test_any_local_port_allowed_by_default(settings):
    assert settings.cors_origin_regex == LOCAL_ORIGIN_REGEX
    for origin in ("http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5180"):
        assert settings.origin_allowed(origin)


@pytest.mark.parametrize("origin", ["https://evil.example", "http://localhost.evil.example", "http://192.168.1.2:5173"])
def test_other_origins_refused(settings, origin):
    assert not settings.origin_allowed(origin)


def test_explicit_origins(monkeypatch):
    monkeypatch.setenv("IDSLAB_CORS_ORIGINS", "http://lab.local:8080")
    settings = load_settings()
    assert settings.origin_allowed("http://lab.local:8080")
    assert not settings.origin_allowed("http://localhost:5173")
