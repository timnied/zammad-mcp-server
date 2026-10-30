"""Tests for *_FILE secret loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from zammad_mcp_server.client import ZammadClient
from zammad_mcp_server.identity import OboConfig
from zammad_mcp_server.secrets_env import env_or_file


def test_env_wins_over_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = tmp_path / "s"
    secret.write_text("from-file\n")
    monkeypatch.setenv("X_SECRET", "from-env")
    monkeypatch.setenv("X_SECRET_FILE", str(secret))
    assert env_or_file("X_SECRET") == "from-env"


def test_file_is_read_and_stripped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = tmp_path / "s"
    secret.write_text("  from-file \n")
    monkeypatch.delenv("X_SECRET", raising=False)
    monkeypatch.setenv("X_SECRET_FILE", str(secret))
    assert env_or_file("X_SECRET") == "from-file"


def test_unset_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("X_SECRET", raising=False)
    monkeypatch.delenv("X_SECRET_FILE", raising=False)
    assert env_or_file("X_SECRET") is None


def test_missing_or_empty_file_fails_loudly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("X_SECRET", raising=False)
    monkeypatch.setenv("X_SECRET_FILE", str(tmp_path / "nope"))
    with pytest.raises(ValueError, match="cannot be read"):
        env_or_file("X_SECRET")
    empty = tmp_path / "empty"
    empty.write_text("\n")
    monkeypatch.setenv("X_SECRET_FILE", str(empty))
    with pytest.raises(ValueError, match="empty"):
        env_or_file("X_SECRET")


def test_zammad_token_and_proxy_secret_from_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = tmp_path / "token"
    token.write_text("file-token\n")
    proxy = tmp_path / "proxy"
    proxy.write_text("file-proxy\n")
    monkeypatch.delenv("ZAMMAD_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("ZAMMAD_HTTP_TOKEN_FILE", str(token))
    monkeypatch.setenv("MCP_OBO_SOURCE", "header")
    monkeypatch.delenv("MCP_OBO_PROXY_SECRET", raising=False)
    monkeypatch.setenv("MCP_OBO_PROXY_SECRET_FILE", str(proxy))
    assert ZammadClient().http_token == "file-token"
    assert OboConfig.from_env().proxy_secret == "file-proxy"
