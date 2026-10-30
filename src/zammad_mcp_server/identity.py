"""Per-request user identity for Zammad's ``X-On-Behalf-Of`` impersonation.

Deployment model
----------------
The MCP server runs behind a gateway (agentgateway) that has already authenticated the
caller (Entra ID). The gateway tells this server *who* the caller is, and the server
calls Zammad with one service account plus ``X-On-Behalf-Of: <user>`` so Zammad's
history, notifications and permissions apply to the real user.

Trust boundary
--------------
The identity is taken from the incoming HTTP request, **never from a tool argument**
(a model-controlled argument would let a prompt-injected model impersonate anyone).
This server does not validate signatures: it trusts whoever can reach its port. The
container therefore must only be reachable from the gateway (internal Docker network,
no published port), and the gateway must set/overwrite the identity header itself.
``MCP_OBO_PROXY_SECRET`` adds a shared-secret check as defense in depth.

Modes (``MCP_OBO_SOURCE``)
--------------------------
``none``    Off (default). Calls run as the service account.
``header``  Identity from the request header ``MCP_OBO_HEADER`` (default ``x-mcp-user``).
``jwt``     Identity from a claim of the (already gateway-validated) Bearer token in the
            ``Authorization`` header. The payload is decoded but NOT verified here.

Fail closed: when a mode is active and no valid identity is present the request is
rejected before anything is sent to Zammad. There is no fallback to the service account.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

from zammad_mcp_server.secrets_env import env_or_file

# Zammad accepts a user id, login or email. This pattern allows all three while
# excluding whitespace, control characters, quotes, commas and anything that could
# be used for header injection.
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._%+@'-]{1,254}$")

VALID_SOURCES = ("none", "header", "jwt")


class IdentityError(PermissionError):
    """No usable caller identity (fail closed)."""


@dataclass(frozen=True)
class OboConfig:
    """Configuration for on-behalf-of identity resolution."""

    source: str = "none"
    header: str = "x-mcp-user"
    jwt_claims: tuple[str, ...] = ("preferred_username", "upn", "email")
    allowed_domains: frozenset[str] = frozenset()
    lowercase: bool = False
    proxy_secret: str | None = None
    proxy_secret_header: str = "x-mcp-proxy-secret"

    @property
    def enabled(self) -> bool:
        return self.source != "none"

    @classmethod
    def from_env(cls) -> OboConfig:
        source = os.getenv("MCP_OBO_SOURCE", "none").strip().lower() or "none"
        if source not in VALID_SOURCES:
            raise ValueError(
                f"Unknown MCP_OBO_SOURCE: {source!r} (valid: {', '.join(VALID_SOURCES)})"
            )
        claims_raw = os.getenv("MCP_OBO_JWT_CLAIMS", "preferred_username,upn,email")
        claims = tuple(c.strip() for c in claims_raw.split(",") if c.strip())
        domains = frozenset(
            d.strip().lower().lstrip("@")
            for d in os.getenv("MCP_OBO_ALLOWED_DOMAINS", "").split(",")
            if d.strip()
        )
        lowercase = os.getenv("MCP_OBO_LOWERCASE", "false").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        config = cls(
            source=source,
            header=(os.getenv("MCP_OBO_HEADER", "x-mcp-user").strip() or "x-mcp-user").lower(),
            jwt_claims=claims,
            allowed_domains=domains,
            lowercase=lowercase,
            proxy_secret=env_or_file("MCP_OBO_PROXY_SECRET"),
            proxy_secret_header=(
                os.getenv("MCP_OBO_PROXY_SECRET_HEADER", "x-mcp-proxy-secret").strip().lower()
            ),
        )
        if source == "jwt" and not claims:
            raise ValueError("MCP_OBO_JWT_CLAIMS must name at least one claim")
        return config


def current_request_headers() -> dict[str, str]:
    """Lower-cased headers of the HTTP request being served ({} on stdio).

    A header that occurs more than once is joined with ", " (HTTP semantics). For the
    identity header this makes a client-forged copy next to the gateway's own copy fail
    validation (a comma is not a legal identity character) instead of silently picking
    one of them.
    """
    from fastmcp.server.dependencies import get_http_request

    try:
        request = get_http_request()
    except RuntimeError:
        return {}
    merged: dict[str, str] = {}
    for name, value in request.headers.items():
        key = name.lower()
        merged[key] = f"{merged[key]}, {value}" if key in merged else str(value)
    return merged


def _claim_from_bearer(authorization: str, claims: tuple[str, ...]) -> str | None:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    for name in claims:
        value = payload.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def resolve_identity(config: OboConfig, headers: Mapping[str, str] | None = None) -> str | None:
    """Return the caller's identity, ``None`` when OBO is off, or raise IdentityError."""
    if not config.enabled:
        return None
    hdrs = {
        k.lower(): v
        for k, v in (headers if headers is not None else current_request_headers()).items()
    }

    if config.proxy_secret is not None:
        supplied = hdrs.get(config.proxy_secret_header, "")
        if not hmac.compare_digest(supplied.encode(), config.proxy_secret.encode()):
            raise IdentityError("Request did not come from the trusted gateway")

    if config.source == "header":
        raw = (hdrs.get(config.header) or "").strip()
    else:  # jwt
        raw = _claim_from_bearer(hdrs.get("authorization", ""), config.jwt_claims) or ""

    if not raw:
        raise IdentityError(
            "No caller identity on the request (on-behalf-of is enabled, refusing to "
            "fall back to the service account)"
        )
    if config.lowercase:
        raw = raw.lower()
    if not _IDENTITY_RE.fullmatch(raw):
        raise IdentityError("Caller identity has an invalid format")
    if config.allowed_domains:
        domain = raw.rpartition("@")[2].lower() if "@" in raw else ""
        if domain not in config.allowed_domains:
            raise IdentityError("Caller identity is not in an allowed domain")
    return raw
