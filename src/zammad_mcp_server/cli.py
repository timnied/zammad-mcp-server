"""Command-line interface for the Zammad MCP Server."""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from typing import Any, Protocol

import httpx

from zammad_mcp_server.oauth import (
    OAUTH_CALLBACK_PORT,
    OAUTH_LOGIN_TIMEOUT_SECONDS,
    run_oauth_login,
)


class RunnableServer(Protocol):
    """Minimal FastMCP run() surface used by the CLI."""

    def run(self, *args: Any, **kwargs: Any) -> None: ...


def parse_server_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse transport flags with environment-variable fallbacks."""
    parser = argparse.ArgumentParser(
        prog="zammad-mcp-server",
        description="MCP server for Zammad helpdesk (stdio, HTTP, or SSE).",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http", "sse"),
        default=os.getenv("MCP_TRANSPORT", "stdio"),
        help="MCP transport (default: stdio; Docker uses http).",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_SERVER_HOST", "127.0.0.1"),
        help="Bind address for http/sse (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_SERVER_PORT", "8000")),
        help="Bind port for http/sse (default: 8000).",
    )
    parser.add_argument(
        "--path",
        default=os.getenv("MCP_SERVER_PATH"),
        help="URL path for http (/mcp/) or sse (/sse/).",
    )
    return parser.parse_args(argv)


def default_http_path(transport: str) -> str:
    """FastMCP default path for a network transport."""
    if transport == "sse":
        return "/sse/"
    return "/mcp/"


def run_server(mcp: RunnableServer, args: argparse.Namespace) -> None:
    """Start FastMCP with the parsed transport options."""
    if args.transport == "stdio":
        mcp.run()
        return
    path = args.path if args.path else default_http_path(args.transport)
    mcp.run(transport=args.transport, host=args.host, port=args.port, path=path)


def _open_browser(url: str) -> None:
    webbrowser.open(url)


def run_oauth_login_cli(argv: list[str]) -> None:
    """Browser login against a Zammad OAuth application. Prints the bearer token."""
    parser = argparse.ArgumentParser(
        prog="zammad-mcp-server login",
        description=(
            "Send the user to Zammad's OAuth authorize page, catch the callback on "
            f"http://127.0.0.1:{OAUTH_CALLBACK_PORT}/callback, and print a bearer token."
        ),
    )
    parser.add_argument("--url", default=os.getenv("ZAMMAD_URL"), help="Zammad base URL.")
    parser.add_argument("--client-id", required=True, help="OAuth application client id.")
    parser.add_argument(
        "--client-secret",
        help="OAuth client secret. Omit for a public PKCE application.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=OAUTH_CALLBACK_PORT,
        help=f"Local callback port (default {OAUTH_CALLBACK_PORT}).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=OAUTH_LOGIN_TIMEOUT_SECONDS,
        help="Seconds to wait for the browser callback.",
    )
    args = parser.parse_args(argv)
    if not args.url:
        parser.error("Pass --url or set ZAMMAD_URL.")
    with httpx.Client(timeout=30.0) as http_client:
        token = run_oauth_login(
            args.url,
            args.client_id,
            args.client_secret,
            port=args.port,
            timeout_seconds=args.timeout,
            opener=_open_browser,
            http_client=http_client,
        )
    print(f"ZAMMAD_OAUTH2_TOKEN={token}")
    print("Put that value in the MCP client env. Do not commit it.", file=sys.stderr)
