"""End-to-end tests: real MCP server over HTTP against a fake Zammad.

These check what actually reaches Zammad (headers, bodies, number of calls), which unit
tests with mocks cannot prove: tools hidden/blocked, on-behalf-of per request, fail
closed without identity, no spoofing through tool arguments or foreign headers, and
internal-note enforcement.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
import uvicorn
from conftest import create_article_data, create_ticket_data, create_user_data
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

SERVICE_TOKEN = "svc-secret-token"


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


@dataclass
class FakeZammad:
    port: int
    calls: list[Recorded] = field(default_factory=list)

    def api_calls(self) -> list[Recorded]:
        return [c for c in self.calls if c.path.startswith("/api/v1/")]

    def clear(self) -> None:
        self.calls.clear()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def fake_zammad() -> Iterator[FakeZammad]:
    state = FakeZammad(port=_free_port())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _reply(self, code: int, payload: Any) -> None:
            raw = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else None
            path = self.path.split("?")[0]
            state.calls.append(
                Recorded(self.command, path, {k.lower(): v for k, v in self.headers.items()}, body)
            )
            if self.headers.get("Authorization") != f"Token token={SERVICE_TOKEN}":
                return self._reply(401, {"error": "bad token"})
            if self.command == "GET" and path == "/api/v1/tickets/1":
                return self._reply(200, create_ticket_data(1, group="Users", expand=True))
            if self.command == "GET" and path == "/api/v1/tickets/2":
                return self._reply(
                    200, create_ticket_data(2, state="pending close", group="Users", expand=True)
                )
            if self.command in ("PUT", "POST") and path in (
                "/api/v1/tickets/1",
                "/api/v1/tickets/2",
                "/api/v1/tickets",
            ):
                assert isinstance(body, dict)
                # Mirror real Zammad: pending states need pending_time, others reject it.
                if str(body.get("state", "")).startswith("pending") and not body.get(
                    "pending_time"
                ):
                    return self._reply(
                        422, {"error": "Missing required value for field 'pending_time'"}
                    )
                ticket_id = int(path.rsplit("/", 1)[-1]) if path != "/api/v1/tickets" else 50
                return self._reply(
                    200,
                    create_ticket_data(
                        ticket_id,
                        state=body.get("state", "open"),
                        group="Users",
                        expand=True,
                        pending_time=body.get("pending_time"),
                    ),
                )
            if self.command == "GET" and path == "/api/v1/users/me":
                who = self.headers.get("X-On-Behalf-Of") or "service-account"
                return self._reply(200, create_user_data(7, email="me@example.com", login=who))
            if self.command == "POST" and path == "/api/v1/ticket_articles":
                assert isinstance(body, dict)
                return self._reply(
                    200,
                    create_article_data(
                        99,
                        ticket_id=body["ticket_id"],
                        body=body["body"],
                        type=body["type"],
                        internal=body["internal"],
                        to=body.get("to"),
                    ),
                )
            if self.command == "DELETE":
                return self._reply(204, {})
            return self._reply(404, {"error": f"unhandled {self.command} {path}"})

        do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815

    server = ThreadingHTTPServer(("127.0.0.1", state.port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


@dataclass
class McpEndpoint:
    url: str

    def client(self, headers: dict[str, str] | None = None) -> Client[Any]:
        return Client(StreamableHttpTransport(self.url, headers=headers or {}))


def _start_mcp(
    monkeypatch: pytest.MonkeyPatch, fake: FakeZammad, env: dict[str, str]
) -> Iterator[McpEndpoint]:
    from zammad_mcp_server.server import mcp

    base = {
        "ZAMMAD_URL": f"http://127.0.0.1:{fake.port}",
        "ZAMMAD_HTTP_TOKEN": SERVICE_TOKEN,
        "MCP_RATE_LIMIT_PER_MINUTE": "0",
    }
    for key in (
        "MCP_PROFILE",
        "MCP_DENIED_TOOLS",
        "MCP_ALLOWED_TOOLS",
        "MCP_ARTICLE_POLICY",
        "MCP_DEFAULT_PERMISSION",
        "MCP_OBO_SOURCE",
        "MCP_OBO_HEADER",
        "MCP_OBO_PROXY_SECRET",
        "MCP_OBO_ALLOWED_DOMAINS",
        "MCP_OUTBOUND_MAIL",
        "MCP_MAIL_MAX_RECIPIENTS",
        "MCP_MAIL_RATE_LIMIT_PER_MINUTE",
        "MCP_ALLOWED_GROUPS",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in {**base, **env}.items():
        monkeypatch.setenv(key, value)

    port = _free_port()
    config = uvicorn.Config(
        mcp.http_app(path="/mcp"), host="127.0.0.1", port=port, log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, "MCP server did not start"
        time.sleep(0.05)
    try:
        yield McpEndpoint(f"http://127.0.0.1:{port}/mcp")
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def helpdesk(monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad) -> Iterator[McpEndpoint]:
    """Default profile, on-behalf-of from the x-mcp-user header."""
    yield from _start_mcp(monkeypatch, fake_zammad, {"MCP_OBO_SOURCE": "header"})


# ---- tool visibility / blocking ---------------------------------------------------


async def test_blocked_tools_are_hidden_and_allowed_ones_listed(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        names = {t.name for t in await client.list_tools()}
    assert {"get_ticket", "search_tickets", "create_article", "update_ticket"} <= names
    for hidden in (
        "delete_ticket",
        "delete_user",
        "delete_organization",
        "merge_tickets",
        "create_user",
        "update_user",
        "create_group",
    ):
        assert hidden not in names
    assert fake_zammad.api_calls() == []  # listing tools never touches Zammad


async def test_calling_a_blocked_tool_fails_and_sends_nothing_to_zammad(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        with pytest.raises(ToolError):
            await client.call_tool("delete_ticket", {"ticket_id": 1})
        with pytest.raises(ToolError):
            await client.call_tool("create_user", {"email": "evil@example.com"})
    assert fake_zammad.api_calls() == []


# ---- on-behalf-of -----------------------------------------------------------------


async def test_obo_header_reaches_zammad_with_service_token(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        await client.call_tool("get_ticket", {"ticket_id": 1})
    calls = fake_zammad.api_calls()
    assert calls, "no request reached Zammad"
    for call in calls:
        assert call.headers["x-on-behalf-of"] == "alice@example.com"
        assert call.headers["authorization"] == f"Token token={SERVICE_TOKEN}"


async def test_get_current_user_reflects_impersonated_user(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "bob@example.com"}) as client:
        result = await client.call_tool("get_current_user", {})
    assert "bob@example.com" in json.dumps(result.data, default=str)


async def test_concurrent_users_never_mix_identities(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    import asyncio

    users = [f"user{i}@example.com" for i in range(8)]

    async def run(user: str) -> None:
        async with helpdesk.client({"x-mcp-user": user}) as client:
            for _ in range(5):
                await client.call_tool("get_ticket", {"ticket_id": 1})

    await asyncio.gather(*(run(u) for u in users))
    seen = [c.headers["x-on-behalf-of"] for c in fake_zammad.api_calls()]
    assert len(seen) == 8 * 5
    assert {u: seen.count(u) for u in users} == dict.fromkeys(users, 5)


async def test_no_identity_fails_closed_without_calling_zammad(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client() as client:  # no x-mcp-user header
        with pytest.raises(ToolError, match="identity"):
            await client.call_tool("get_ticket", {"ticket_id": 1})
    assert fake_zammad.api_calls() == []


async def test_identity_cannot_be_chosen_via_tool_argument(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        schema = next(t for t in await client.list_tools() if t.name == "get_ticket").inputSchema
        assert "on_behalf_of" not in json.dumps(schema)
        with pytest.raises(ToolError):
            await client.call_tool("get_ticket", {"ticket_id": 1, "on_behalf_of": "admin"})
    assert fake_zammad.api_calls() == []


async def test_foreign_x_on_behalf_of_header_from_client_is_ignored(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    headers = {"x-mcp-user": "alice@example.com", "x-on-behalf-of": "admin@example.com"}
    async with helpdesk.client(headers) as client:
        await client.call_tool("get_ticket", {"ticket_id": 1})
    assert {c.headers["x-on-behalf-of"] for c in fake_zammad.api_calls()} == {"alice@example.com"}


async def test_header_injection_attempt_is_rejected(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com, admin@example.com"}) as client:
        with pytest.raises(ToolError, match="invalid format"):
            await client.call_tool("get_ticket", {"ticket_id": 1})
    assert fake_zammad.api_calls() == []


async def test_proxy_secret_is_enforced(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    env = {"MCP_OBO_SOURCE": "header", "MCP_OBO_PROXY_SECRET": "gw-secret"}
    for endpoint in _start_mcp(monkeypatch, fake_zammad, env):
        async with endpoint.client({"x-mcp-user": "alice@example.com"}) as client:
            with pytest.raises(ToolError, match="trusted gateway"):
                await client.call_tool("get_ticket", {"ticket_id": 1})
        assert fake_zammad.api_calls() == []
        good = {"x-mcp-user": "alice@example.com", "x-mcp-proxy-secret": "gw-secret"}
        async with endpoint.client(good) as client:
            await client.call_tool("get_ticket", {"ticket_id": 1})
        assert fake_zammad.api_calls()


async def test_obo_off_uses_service_account_only(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    for endpoint in _start_mcp(monkeypatch, fake_zammad, {}):
        async with endpoint.client({"x-mcp-user": "alice@example.com"}) as client:
            await client.call_tool("get_ticket", {"ticket_id": 1})
        assert all("x-on-behalf-of" not in c.headers for c in fake_zammad.api_calls())


# ---- internal notes ---------------------------------------------------------------


async def test_article_is_forced_to_internal_note(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        result = await client.call_tool(
            "create_article",
            {
                "ticket_id": 1,
                "body": "Dear customer ...",
                "type": "email",
                "internal": False,
                "to": "customer@example.com",
                "cc": "boss@example.com",
            },
        )
    post = next(c for c in fake_zammad.api_calls() if c.method == "POST")
    assert post.body["type"] == "note"
    assert post.body["internal"] is True
    assert "to" not in post.body and "cc" not in post.body
    assert post.headers["x-on-behalf-of"] == "alice@example.com"
    assert "internal notes" in json.dumps(result.data, default=str)


async def test_plain_internal_note_passes_without_policy_note(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        result = await client.call_tool(
            "create_article", {"ticket_id": 1, "body": "Checked the logs.", "internal": True}
        )
    post = next(c for c in fake_zammad.api_calls() if c.method == "POST")
    assert (post.body["type"], post.body["internal"]) == ("note", True)
    assert "policy_note" not in json.dumps(result.data, default=str)


async def test_article_policy_any_allows_customer_email(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    env = {"MCP_OBO_SOURCE": "header", "MCP_ARTICLE_POLICY": "any"}
    for endpoint in _start_mcp(monkeypatch, fake_zammad, env):
        async with endpoint.client({"x-mcp-user": "alice@example.com"}) as client:
            await client.call_tool(
                "create_article",
                {
                    "ticket_id": 1,
                    "body": "Hello",
                    "type": "email",
                    "internal": False,
                    "to": "customer@example.com",
                },
            )
        post = next(c for c in fake_zammad.api_calls() if c.method == "POST")
        assert (post.body["type"], post.body["internal"], post.body["to"]) == (
            "email",
            False,
            "customer@example.com",
        )


# ---- profile switching on restart --------------------------------------------------


async def test_full_profile_after_helpdesk_restores_tools(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    for endpoint in _start_mcp(monkeypatch, fake_zammad, {"MCP_PROFILE": "readonly"}):
        async with endpoint.client() as client:
            names = {t.name for t in await client.list_tools()}
        assert "create_article" not in names and "get_ticket" in names
    for endpoint in _start_mcp(
        monkeypatch, fake_zammad, {"MCP_PROFILE": "full", "MCP_DEFAULT_PERMISSION": "admin"}
    ):
        async with endpoint.client() as client:
            names = {t.name for t in await client.list_tools()}
        assert {"create_article", "delete_ticket", "merge_tickets"} <= names


async def test_denied_tools_env_hides_tool_and_blocks_call(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    env = {"MCP_PROFILE": "full", "MCP_DENIED_TOOLS": "create_article"}
    for endpoint in _start_mcp(monkeypatch, fake_zammad, env):
        async with endpoint.client() as client:
            assert "create_article" not in {t.name for t in await client.list_tools()}
            with pytest.raises(ToolError):
                await client.call_tool("create_article", {"ticket_id": 1, "body": "x"})
        assert [c for c in fake_zammad.api_calls() if c.method == "POST"] == []


async def test_jwt_source_uses_bearer_claim(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    import base64

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    token = ".".join(
        [
            b64(b'{"alg":"RS256"}'),
            b64(json.dumps({"preferred_username": "carol@example.com"}).encode()),
            b64(b"sig"),
        ]
    )
    for endpoint in _start_mcp(monkeypatch, fake_zammad, {"MCP_OBO_SOURCE": "jwt"}):
        async with endpoint.client({"authorization": f"Bearer {token}"}) as client:
            await client.call_tool("get_ticket", {"ticket_id": 1})
        assert {c.headers["x-on-behalf-of"] for c in fake_zammad.api_calls()} == {
            "carol@example.com"
        }
        # the caller's own bearer token must never be forwarded to Zammad
        assert all(
            c.headers["authorization"] == f"Token token={SERVICE_TOKEN}"
            for c in fake_zammad.api_calls()
        )


async def test_duplicate_identity_header_is_rejected(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    """A gateway that *adds* x-mcp-user next to a client-forged one must not let either win."""
    import httpx

    base = [
        ("accept", "application/json, text/event-stream"),
        ("content-type", "application/json"),
        ("x-mcp-user", "alice@example.com"),
        ("x-mcp-user", "admin@example.com"),
    ]
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    async with httpx.AsyncClient() as http:
        resp = await http.post(helpdesk.url, headers=base, json=init)
        session = resp.headers["mcp-session-id"]
        headers = [*base, ("mcp-session-id", session)]
        await http.post(
            helpdesk.url,
            headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_ticket", "arguments": {"ticket_id": 1}},
        }
        resp = await http.post(helpdesk.url, headers=headers, json=call)
    assert "invalid format" in resp.text
    assert fake_zammad.api_calls() == []


# ---- pending_time -----------------------------------------------------------------

FUTURE = "2099-11-12T09:00:00+01:00"
FUTURE_UTC = "2099-11-12T08:00:00.000Z"


def _puts(fake: FakeZammad) -> list[Recorded]:
    return [c for c in fake.api_calls() if c.method == "PUT"]


async def test_pending_close_sends_pending_time_to_zammad(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        await client.call_tool(
            "update_ticket",
            {"ticket_id": 1, "state": "pending close", "pending_time": FUTURE},
        )
    (put,) = _puts(fake_zammad)
    assert put.path == "/api/v1/tickets/1"
    assert put.body == {"state": "pending close", "pending_time": FUTURE_UTC}


async def test_pending_state_without_pending_time_is_rejected_before_zammad(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        with pytest.raises(ToolError, match="requires pending_time"):
            await client.call_tool("update_ticket", {"ticket_id": 1, "state": "pending reminder"})
    assert _puts(fake_zammad) == []


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"state": "pending close", "pending_time": "2099-11-12T09:00:00"}, "no time zone"),
        ({"state": "pending close", "pending_time": "morgen früh"}, "not a valid ISO 8601"),
        ({"state": "pending close", "pending_time": "2001-01-01T00:00:00Z"}, "in the past"),
        ({"state": "open", "pending_time": FUTURE}, "only be set together"),
        ({"state": "banana"}, "Unknown ticket state"),
        ({"priority": "urgent!"}, "Unknown ticket priority"),
        ({"pending_time": FUTURE}, "pending state"),  # ticket 1 is 'open'
    ],
)
async def test_invalid_pending_input_is_rejected_without_a_put(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad, args: dict[str, str], message: str
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        with pytest.raises(ToolError, match=message):
            await client.call_tool("update_ticket", {"ticket_id": 1, **args})
    assert _puts(fake_zammad) == []


async def test_pending_time_alone_reschedules_an_already_pending_ticket(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        await client.call_tool("update_ticket", {"ticket_id": 2, "pending_time": FUTURE})
    (put,) = _puts(fake_zammad)
    assert put.path == "/api/v1/tickets/2"
    assert put.body == {"pending_time": FUTURE_UTC}


async def test_utc_z_suffix_is_accepted(helpdesk: McpEndpoint, fake_zammad: FakeZammad) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        await client.call_tool(
            "update_ticket",
            {"ticket_id": 1, "state": "pending reminder", "pending_time": "2099-11-12T08:00:00Z"},
        )
    assert _puts(fake_zammad)[0].body == {
        "state": "pending reminder",
        "pending_time": FUTURE_UTC,
    }


async def test_closing_a_ticket_still_works_without_pending_time(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        await client.call_tool("update_ticket", {"ticket_id": 1, "state": "closed"})
    assert _puts(fake_zammad)[0].body == {"state": "closed"}


async def test_create_ticket_supports_pending_time(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        await client.call_tool(
            "create_ticket",
            {
                "title": "Warten auf Hardware",
                "group": "Users",
                "state": "pending reminder",
                "pending_time": FUTURE,
            },
        )
        with pytest.raises(ToolError, match="requires pending_time"):
            await client.call_tool(
                "create_ticket", {"title": "x", "group": "Users", "state": "pending close"}
            )
    posts = [
        c for c in fake_zammad.api_calls() if c.method == "POST" and c.path.endswith("/tickets")
    ]
    assert len(posts) == 1
    assert posts[0].body["state"] == "pending reminder"
    assert posts[0].body["pending_time"] == FUTURE_UTC


async def test_tool_schema_exposes_pending_time(helpdesk: McpEndpoint) -> None:
    async with helpdesk.client({"x-mcp-user": "alice@example.com"}) as client:
        tools = {t.name: t for t in await client.list_tools()}
    for name in ("update_ticket", "create_ticket"):
        assert "pending_time" in tools[name].inputSchema["properties"]


# ---- outbound mail tools ----------------------------------------------------------

MAIL_TOOL_NAMES = {"send_ticket_mail", "create_ticket_with_mail"}
DESTRUCTIVE_NAMES = {
    "delete_ticket",
    "delete_user",
    "delete_organization",
    "merge_tickets",
    "create_user",
    "update_user",
    "create_organization",
    "update_organization",
    "create_group",
}


@pytest.fixture
def mailer(monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad) -> Iterator[McpEndpoint]:
    """Helpdesk profile with the outbound mail tools switched on."""
    yield from _start_mcp(
        monkeypatch,
        fake_zammad,
        {"MCP_OBO_SOURCE": "header", "MCP_OUTBOUND_MAIL": "on", "MCP_MAIL_MAX_RECIPIENTS": "4"},
    )


@pytest.fixture
def limited_mailer(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> Iterator[McpEndpoint]:
    yield from _start_mcp(
        monkeypatch,
        fake_zammad,
        {
            "MCP_OBO_SOURCE": "header",
            "MCP_OUTBOUND_MAIL": "on",
            "MCP_MAIL_RATE_LIMIT_PER_MINUTE": "2",
        },
    )


def _mail_posts(fake: FakeZammad) -> list[Recorded]:
    return [c for c in fake.api_calls() if c.method == "POST"]


ALICE = {"x-mcp-user": "alice@example.com"}


async def test_mail_tools_are_off_by_default(
    helpdesk: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with helpdesk.client(ALICE) as client:
        names = {t.name for t in await client.list_tools()}
        assert not (MAIL_TOOL_NAMES & names)
        with pytest.raises(ToolError):
            await client.call_tool(
                "send_ticket_mail", {"ticket_id": 1, "to": "x@example.org", "body": "hi"}
            )
    assert fake_zammad.api_calls() == []


async def test_mail_tools_listed_but_no_destructive_tool_exposed(mailer: McpEndpoint) -> None:
    async with mailer.client(ALICE) as client:
        names = {t.name for t in await client.list_tools()}
    assert names >= MAIL_TOOL_NAMES
    assert not (DESTRUCTIVE_NAMES & names)


async def test_send_ticket_mail_posts_an_external_email_article(
    mailer: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with mailer.client(ALICE) as client:
        result = await client.call_tool(
            "send_ticket_mail",
            {
                "ticket_id": 1,
                "to": "Vendor@Example.org, other@example.net",
                "cc": "boss@example.com, vendor@example.org",
                "body": "Bitte um Rückmeldung.",
            },
        )
    (post,) = _mail_posts(fake_zammad)
    assert post.path == "/api/v1/ticket_articles"
    assert post.headers["x-on-behalf-of"] == "alice@example.com"
    assert post.body == {
        "ticket_id": 1,
        "subject": "Test Ticket",
        "body": "Bitte um Rückmeldung.",
        "type": "email",
        "internal": False,
        "to": "vendor@example.org, other@example.net",
        "cc": "boss@example.com",
        "sender": "Agent",
        "content_type": "text/plain",
    }
    assert result.data["to"] == ["vendor@example.org", "other@example.net"]
    assert "not confirmed" in result.data["note"]


async def test_send_ticket_mail_uses_a_given_subject(
    mailer: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with mailer.client(ALICE) as client:
        await client.call_tool(
            "send_ticket_mail",
            {"ticket_id": 1, "to": "a@example.org", "body": "x", "subject": "Anfrage Lieferzeit"},
        )
    assert _mail_posts(fake_zammad)[0].body["subject"] == "Anfrage Lieferzeit"


@pytest.mark.parametrize(
    "args",
    [
        {"to": "a@example.org\r\nBcc: evil@example.org"},
        {"to": "Name <a@example.org>"},
        {"to": '"a b"@example.org'},
        {"to": "a@example.org", "cc": "not-an-address"},
        {"to": ""},
        {"to": "a@example.org", "subject": "Hallo\nBcc: evil@example.org"},
        {"to": "a@example.org", "body": "   "},
        {"to": "a@example.org,b@example.org,c@example.org,d@example.org,e@example.org"},
    ],
)
async def test_invalid_mail_is_rejected_before_zammad_is_called(
    mailer: McpEndpoint, fake_zammad: FakeZammad, args: dict[str, str]
) -> None:
    payload = {"ticket_id": 1, "body": "text", **args}
    async with mailer.client(ALICE) as client:
        with pytest.raises(ToolError):
            await client.call_tool("send_ticket_mail", payload)
    assert fake_zammad.api_calls() == []


async def test_mail_tool_schemas_have_no_bcc_and_no_attachments(mailer: McpEndpoint) -> None:
    async with mailer.client(ALICE) as client:
        tools = {t.name: t for t in await client.list_tools() if t.name in MAIL_TOOL_NAMES}
    for tool in tools.values():
        props = set(tool.inputSchema["properties"])
        assert not ({"bcc", "attachments", "internal", "type", "sender"} & props)


async def test_mail_for_a_ticket_outside_the_group_scope_is_denied(
    monkeypatch: pytest.MonkeyPatch, fake_zammad: FakeZammad
) -> None:
    env = {"MCP_OBO_SOURCE": "header", "MCP_OUTBOUND_MAIL": "on", "MCP_ALLOWED_GROUPS": "Other"}
    for endpoint in _start_mcp(monkeypatch, fake_zammad, env):
        async with endpoint.client(ALICE) as client:
            with pytest.raises(ToolError, match="Access denied"):
                await client.call_tool(
                    "send_ticket_mail", {"ticket_id": 1, "to": "a@example.org", "body": "x"}
                )
            with pytest.raises(ToolError, match="Access denied"):
                await client.call_tool(
                    "create_ticket_with_mail",
                    {"title": "t", "group": "Users", "to": "a@example.org", "body": "x"},
                )
    assert _mail_posts(fake_zammad) == []


async def test_create_article_stays_internal_even_with_mail_tools_on(
    mailer: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with mailer.client(ALICE) as client:
        await client.call_tool(
            "create_article",
            {
                "ticket_id": 1,
                "body": "x",
                "type": "email",
                "internal": False,
                "to": "victim@example.org",
            },
        )
    (post,) = _mail_posts(fake_zammad)
    assert post.body["internal"] is True
    assert post.body["type"] == "note"
    assert "to" not in post.body


async def test_mail_quota_is_per_user_and_only_counts_valid_requests(
    limited_mailer: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    ok = {"ticket_id": 1, "to": "a@example.org", "body": "x"}
    async with limited_mailer.client(ALICE) as alice:
        for _ in range(5):  # rejected requests must not use up the budget
            with pytest.raises(ToolError):
                await alice.call_tool("send_ticket_mail", {**ok, "to": "kaputt"})
        await alice.call_tool("send_ticket_mail", ok)
        await alice.call_tool("send_ticket_mail", ok)
        with pytest.raises(ToolError, match="Mail limit"):
            await alice.call_tool("send_ticket_mail", ok)
    async with limited_mailer.client({"x-mcp-user": "bob@example.com"}) as bob:
        await bob.call_tool("send_ticket_mail", ok)  # own budget
    assert len(_mail_posts(fake_zammad)) == 3


async def test_create_ticket_with_mail_sends_the_first_article_as_email(
    mailer: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    async with mailer.client(ALICE) as client:
        result = await client.call_tool(
            "create_ticket_with_mail",
            {
                "title": "Angebot anfragen",
                "group": "Users",
                "to": "sales@example.org",
                "cc": "me@example.com",
                "body": "Bitte senden Sie uns ein Angebot.",
                "priority": "2 normal",
            },
        )
    (post,) = _mail_posts(fake_zammad)
    assert post.path == "/api/v1/tickets"
    assert post.headers["x-on-behalf-of"] == "alice@example.com"
    assert post.body == {
        "title": "Angebot anfragen",
        "group": "Users",
        "customer": "sales@example.org",
        "priority": "2 normal",
        "article": {
            "subject": "Angebot anfragen",
            "body": "Bitte senden Sie uns ein Angebot.",
            "type": "email",
            "internal": False,
            "to": "sales@example.org",
            "cc": "me@example.com",
            "sender": "Agent",
            "content_type": "text/plain",
        },
    }
    assert result.data["mail"]["to"] == ["sales@example.org"]


async def test_create_ticket_with_mail_validates_state_customer_and_recipients(
    mailer: McpEndpoint, fake_zammad: FakeZammad
) -> None:
    base = {"title": "t", "group": "Users", "to": "a@example.org", "body": "x"}
    async with mailer.client(ALICE) as client:
        for extra, match in [
            ({"state": "pending close"}, "requires pending_time"),
            ({"state": "banana"}, "Unknown ticket state"),
            ({"customer": "a@example.org, b@example.org"}, "exactly one"),
            ({"to": "a@example.org\r\nBcc: x@example.org"}, "Invalid address"),
            ({"title": "   "}, "title"),
        ]:
            with pytest.raises(ToolError, match=match):
                await client.call_tool("create_ticket_with_mail", {**base, **extra})
        await client.call_tool(
            "create_ticket_with_mail",
            {**base, "state": "pending reminder", "pending_time": "2099-11-12T09:00:00+01:00"},
        )
    (post,) = _mail_posts(fake_zammad)
    assert post.body["state"] == "pending reminder"
    assert post.body["pending_time"] == "2099-11-12T08:00:00.000Z"
