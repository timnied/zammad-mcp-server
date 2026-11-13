"""Zammad OAuth authorization-code login with a localhost callback."""

from __future__ import annotations

import base64
import hashlib
import secrets
import sys
import threading
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx

OAUTH_CALLBACK_PORT = 8765
OAUTH_CALLBACK_PATH = "/callback"
OAUTH_LOGIN_TIMEOUT_SECONDS = 180.0


class OAuthLoginError(Exception):
    """The authorization-code login did not produce an access token."""


def make_pkce_pair() -> tuple[str, str]:
    """Return a PKCE verifier and its S256 challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(
    zammad_url: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> str:
    """Build Zammad's Doorkeeper authorize URL."""
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{zammad_url.rstrip('/')}/oauth/authorize?{query}"


def exchange_authorization_code(
    zammad_url: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    http_client: httpx.Client,
) -> str:
    """Exchange an authorization code for a bearer access token."""
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret is not None:
        form["client_secret"] = client_secret
    response = http_client.post(
        f"{zammad_url.rstrip('/')}/oauth/token",
        data=form,
        headers={"Accept": "application/json"},
    )
    if response.status_code >= 400:
        raise OAuthLoginError(
            f"Zammad rejected the authorization code ({response.status_code}). "
            "Check the OAuth application callback URL and client id."
        )
    payload: Any = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str):
        raise OAuthLoginError("Zammad did not return an access_token.")
    access_token: str = payload["access_token"]
    return access_token


def _states_match(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)


class _CallbackResult:
    def __init__(self) -> None:
        self.code: str | None = None
        self.error: str | None = None
        self.done = threading.Event()


def _callback_handler(result: _CallbackResult, expected_state: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != OAUTH_CALLBACK_PATH:
                self.send_error(404)
                return
            params = urllib.parse.parse_qs(parsed.query)
            returned_state = params.get("state", [""])[0]
            if not _states_match(returned_state, expected_state):
                result.error = "OAuth state did not match."
                body = b"Login failed. You can close this window."
            elif "error" in params:
                result.error = params["error"][0]
                body = b"Zammad denied the login. You can close this window."
            elif "code" not in params:
                result.error = "Zammad did not return an authorization code."
                body = b"Login failed. You can close this window."
            else:
                result.code = params["code"][0]
                body = b"Zammad login succeeded. You can close this window."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            result.done.set()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def run_oauth_login(
    zammad_url: str,
    client_id: str,
    client_secret: str | None,
    *,
    port: int,
    timeout_seconds: float,
    opener: Callable[[str], None],
    http_client: httpx.Client,
) -> str:
    """Open Zammad's authorize page, take the callback, and return a bearer token."""
    verifier, challenge = make_pkce_pair()
    state = secrets.token_urlsafe(24)
    result = _CallbackResult()
    try:
        server = ThreadingHTTPServer(
            ("127.0.0.1", port),
            _callback_handler(result, state),
        )
    except OSError as exc:
        raise OAuthLoginError(f"Cannot listen on 127.0.0.1:{port} for the OAuth callback.") from exc
    bound_port = int(server.server_address[1])
    redirect_uri = f"http://127.0.0.1:{bound_port}{OAUTH_CALLBACK_PATH}"
    authorize_url = build_authorize_url(zammad_url, client_id, redirect_uri, state, challenge)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        print(
            "Register this callback on the Zammad OAuth application if you have not yet: "
            f"{redirect_uri}",
            file=sys.stderr,
        )
        opener(authorize_url)
        if not result.done.wait(timeout_seconds):
            raise OAuthLoginError(
                f"Timed out waiting for the Zammad OAuth callback on {redirect_uri}."
            )
        if result.error is not None or result.code is None:
            raise OAuthLoginError(result.error or "OAuth callback did not include a code.")
        return exchange_authorization_code(
            zammad_url,
            client_id,
            client_secret,
            redirect_uri,
            result.code,
            verifier,
            http_client,
        )
    finally:
        server.shutdown()
        server.server_close()
