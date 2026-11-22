"""Unit tests for deployment, server, and container configuration (FIX-P13)."""

from pathlib import Path

from logmorph.config import settings
from logmorph.core.server import get_uvicorn_config


def test_settings_uvicorn_defaults():
    """Verify production defaults for keep-alive and request limit."""
    assert settings.UVICORN_KEEP_ALIVE_TIMEOUT == 30
    assert settings.UVICORN_MAX_REQUESTS == 10000


def test_uvicorn_config_factory():
    """Verify get_uvicorn_config properly binds settings to Uvicorn config instance."""
    cfg = get_uvicorn_config(
        app="logmorph.main:app",
        host="0.0.0.0",
        port=8000,
        workers=2,
    )

    assert cfg.timeout_keep_alive == 30
    assert cfg.limit_max_requests == 10000
    assert cfg.proxy_headers is True
    assert cfg.workers == 2


def test_uvicorn_config_explicit_overrides():
    """Verify explicit parameters override settings defaults."""
    cfg = get_uvicorn_config(
        timeout_keep_alive=45,
        limit_max_requests=5000,
    )
    assert cfg.timeout_keep_alive == 45
    assert cfg.limit_max_requests == 5000


def test_dockerfile_contains_keepalive_and_max_request_flags():
    """Verify Dockerfile CMD includes keep-alive and request recycling flags."""
    dockerfile_path = Path("Dockerfile")
    assert dockerfile_path.exists(), "Dockerfile must exist in repo root"

    content = dockerfile_path.read_text(encoding="utf-8")
    assert "--timeout-keep-alive 30" in content, (
        "Dockerfile CMD missing --timeout-keep-alive 30 flag"
    )
    assert "--limit-max-requests 10000" in content, (
        "Dockerfile CMD missing --limit-max-requests 10000 flag"
    )


def test_render_yaml_contains_keepalive_and_max_request_flags():
    """Verify render.yaml dockerCommand includes keep-alive and request recycling flags."""
    render_yaml_path = Path("render.yaml")
    assert render_yaml_path.exists(), "render.yaml must exist in repo root"

    content = render_yaml_path.read_text(encoding="utf-8")
    assert "--timeout-keep-alive 30" in content, (
        "render.yaml missing --timeout-keep-alive 30 flag"
    )
    assert "--limit-max-requests 10000" in content, (
        "render.yaml missing --limit-max-requests 10000 flag"
    )
