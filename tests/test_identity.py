"""Unit tests for on-behalf-of identity resolution."""

from __future__ import annotations

import base64
import json

import pytest

from zammad_mcp_server.identity import IdentityError, OboConfig, resolve_identity


def _jwt(payload: dict[str, object]) -> str:
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    return ".".join([b64(b'{"alg":"RS256"}'), b64(json.dumps(payload).encode()), b64(b"signature")])


HEADER_CFG = OboConfig(source="header")
JWT_CFG = OboConfig(source="jwt")


def test_off_returns_none_and_ignores_headers() -> None:
    assert resolve_identity(OboConfig(), {"x-mcp-user": "a@b.de"}) is None


def test_header_mode_reads_header_case_insensitively() -> None:
    assert resolve_identity(HEADER_CFG, {"X-MCP-User": "tim@indico-solutions.com"}) == (
        "tim@indico-solutions.com"
    )


def test_header_mode_fails_closed_without_header() -> None:
    with pytest.raises(IdentityError, match="No caller identity"):
        resolve_identity(HEADER_CFG, {})
    with pytest.raises(IdentityError):
        resolve_identity(HEADER_CFG, {"x-mcp-user": "   "})


@pytest.mark.parametrize(
    "bad",
    [
        "a b@x.de",
        "a@x.de,admin@x.de",
        "a@x.de\r\nX-Evil: 1",
        'a"@x.de',
        "a;b@x.de",
        "x" * 300,
        "../etc",
    ],
)
def test_invalid_identities_are_rejected(bad: str) -> None:
    with pytest.raises(IdentityError):
        resolve_identity(HEADER_CFG, {"x-mcp-user": bad})


@pytest.mark.parametrize("ok", ["tim@indico-solutions.com", "tim.n", "42", "o'brien@x.de"])
def test_plausible_identities_are_accepted(ok: str) -> None:
    assert resolve_identity(HEADER_CFG, {"x-mcp-user": ok}) == ok


def test_custom_header_name_and_lowercase() -> None:
    cfg = OboConfig(source="header", header="x-forwarded-user", lowercase=True)
    assert resolve_identity(cfg, {"x-forwarded-user": "Tim@Indico-Solutions.com"}) == (
        "tim@indico-solutions.com"
    )


def test_allowed_domains() -> None:
    cfg = OboConfig(source="header", allowed_domains=frozenset({"indico-solutions.com"}))
    assert resolve_identity(cfg, {"x-mcp-user": "a@indico-solutions.com"})
    with pytest.raises(IdentityError, match="domain"):
        resolve_identity(cfg, {"x-mcp-user": "a@evil.com"})
    with pytest.raises(IdentityError, match="domain"):
        resolve_identity(cfg, {"x-mcp-user": "no-domain-user"})
    with pytest.raises(IdentityError, match="domain"):
        resolve_identity(cfg, {"x-mcp-user": "a@indico-solutions.com.evil.com"})


def test_proxy_secret_required_when_configured() -> None:
    cfg = OboConfig(source="header", proxy_secret="s3cret")
    with pytest.raises(IdentityError, match="trusted gateway"):
        resolve_identity(cfg, {"x-mcp-user": "a@b.de"})
    with pytest.raises(IdentityError, match="trusted gateway"):
        resolve_identity(cfg, {"x-mcp-user": "a@b.de", "x-mcp-proxy-secret": "wrong"})
    assert (
        resolve_identity(cfg, {"x-mcp-user": "a@b.de", "x-mcp-proxy-secret": "s3cret"}) == "a@b.de"
    )


def test_jwt_mode_prefers_claims_in_order() -> None:
    token = _jwt({"upn": "upn@x.de", "email": "mail@x.de", "preferred_username": "pu@x.de"})
    assert resolve_identity(JWT_CFG, {"authorization": f"Bearer {token}"}) == "pu@x.de"
    token = _jwt({"email": "mail@x.de", "upn": "upn@x.de"})
    assert resolve_identity(JWT_CFG, {"authorization": f"Bearer {token}"}) == "upn@x.de"


@pytest.mark.parametrize(
    "authorization",
    ["", "Basic abc", "Bearer", "Bearer not.a.jwt", "Bearer a.b", f"Bearer {_jwt({'sub': 'x'})}"],
)
def test_jwt_mode_fails_closed(authorization: str) -> None:
    with pytest.raises(IdentityError):
        resolve_identity(JWT_CFG, {"authorization": authorization})


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(__import__("os").environ):
        if key.startswith("MCP_OBO_"):
            monkeypatch.delenv(key)
    assert OboConfig.from_env().enabled is False
    monkeypatch.setenv("MCP_OBO_SOURCE", "header")
    monkeypatch.setenv("MCP_OBO_HEADER", "X-Gateway-User")
    monkeypatch.setenv("MCP_OBO_ALLOWED_DOMAINS", "@Indico-Solutions.com, example.org")
    monkeypatch.setenv("MCP_OBO_LOWERCASE", "true")
    cfg = OboConfig.from_env()
    assert cfg.enabled and cfg.header == "x-gateway-user" and cfg.lowercase
    assert cfg.allowed_domains == {"indico-solutions.com", "example.org"}
    monkeypatch.setenv("MCP_OBO_SOURCE", "magic")
    with pytest.raises(ValueError, match="MCP_OBO_SOURCE"):
        OboConfig.from_env()
