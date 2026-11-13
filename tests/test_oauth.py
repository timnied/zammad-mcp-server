"""OAuth authorization-code login."""

import urllib.parse
import urllib.request

import httpx
import pytest
import respx
from httpx import Response

from zammad_mcp_server.oauth import OAuthLoginError, run_oauth_login


def _open_callback(url: str) -> None:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    redirect = query["redirect_uri"][0]
    state = query["state"][0]
    with urllib.request.urlopen(
        f"{redirect}?code=authcode&state={urllib.parse.quote(state)}"
    ) as response:
        response.read()


def test_login_exchanges_code_with_pkce(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post("https://zammad.example/oauth/token").mock(
        return_value=Response(200, json={"access_token": "token-1", "token_type": "Bearer"})
    )
    with httpx.Client() as http_client:
        token = run_oauth_login(
            "https://zammad.example",
            "client-id",
            None,
            port=0,
            timeout_seconds=5,
            opener=_open_callback,
            http_client=http_client,
        )
    assert token == "token-1"
    body = route.calls.last.request.content
    assert b"code_verifier=" in body
    assert b"client_secret" not in body
    assert b"grant_type=authorization_code" in body


def test_login_rejects_state_mismatch() -> None:
    def opener(url: str) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        redirect = query["redirect_uri"][0]
        with urllib.request.urlopen(f"{redirect}?code=authcode&state=nope") as response:
            response.read()

    with httpx.Client() as http_client, pytest.raises(OAuthLoginError, match="state"):
        run_oauth_login(
            "https://zammad.example",
            "client-id",
            "secret",
            port=0,
            timeout_seconds=5,
            opener=opener,
            http_client=http_client,
        )
