"""Tests for the deny-list fix, tool profiles and the explicit allow-list."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from zammad_mcp_server.access_control import (
    DESTRUCTIVE_TOOLS,
    DIRECTORY_MUTATION_TOOLS,
    MAIL_TOOLS,
    REGISTERED_TOOLS,
    TOOL_REQUIRED_PERMISSION,
    AccessController,
    AccessPolicy,
    Permission,
    Profile,
)

WRITE_TOOLS = {t for t, p in TOOL_REQUIRED_PERMISSION.items() if p is not Permission.READ_ONLY}
READ_TOOLS = set(TOOL_REQUIRED_PERMISSION) - WRITE_TOOLS


def _controller(monkeypatch: pytest.MonkeyPatch, **env: str) -> AccessController:
    for key in (
        "MCP_PROFILE",
        "MCP_DENIED_TOOLS",
        "MCP_ALLOWED_TOOLS",
        "MCP_DEFAULT_PERMISSION",
        "MCP_ARTICLE_POLICY",
        "MCP_ALLOWED_CATEGORIES",
        "MCP_OUTBOUND_MAIL",
        "MCP_MAIL_MAX_RECIPIENTS",
        "MCP_MAIL_RATE_LIMIT_PER_MINUTE",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return AccessController.from_env()


def test_permission_map_covers_every_registered_tool() -> None:
    assert set(TOOL_REQUIRED_PERMISSION) == set(REGISTERED_TOOLS)


def test_permission_map_matches_check_access_calls_in_server() -> None:
    """TOOL_REQUIRED_PERMISSION must not drift from the check_access() calls."""
    source = (Path(__file__).parent.parent / "src/zammad_mcp_server/server.py").read_text()
    found = dict(re.findall(r'check_access\("(\w+)", Permission\.(\w+)\)', source))
    for tool, required in TOOL_REQUIRED_PERMISSION.items():
        assert found.get(tool) == required.name, tool


# ---- the original bug -------------------------------------------------------------


def test_denied_tool_cannot_write_regression(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before the fix MCP_DENIED_TOOLS only affected can_execute(); can_write() stayed
    True, and check_access() uses can_write(), so denied tools still ran."""
    c = _controller(
        monkeypatch,
        MCP_PROFILE="full",
        MCP_DEFAULT_PERMISSION="admin",
        MCP_DENIED_TOOLS="update_ticket,create_user",
    )
    for tool in ("update_ticket", "create_user"):
        assert not c.can_execute(tool)
        assert not c.can_read(tool)
        assert not c.can_write(tool)
        assert not c.can_admin(tool)
    assert c.can_write("create_article")


def test_denied_tools_support_wildcards(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch, MCP_PROFILE="full", MCP_DENIED_TOOLS="delete_*,*_user")
    assert not c.can_write("delete_ticket")
    assert not c.can_write("create_user")
    assert not c.can_read("get_user")
    assert c.can_read("get_ticket")


def test_check_access_blocks_denied_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    from zammad_mcp_server import server

    c = _controller(monkeypatch, MCP_PROFILE="full", MCP_DENIED_TOOLS="create_article")
    monkeypatch.setattr(server, "_access_controller", c)
    monkeypatch.setattr(server, "_client", None)
    with pytest.raises(PermissionError, match="Access denied"):
        server.check_access("create_article", Permission.WRITE)
    server.check_access("get_ticket", Permission.READ_ONLY)  # still fine


# ---- profiles ---------------------------------------------------------------------


def test_default_profile_is_helpdesk(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch)
    assert c.policy.profile is Profile.HELPDESK
    assert c.policy.article_policy == "internal_only"


def test_helpdesk_profile_allows_ticket_work_and_blocks_destructive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = _controller(monkeypatch)  # default permission level is "write"
    for tool in (
        "create_article",
        "update_ticket",
        "create_ticket",
        "add_ticket_tag",
        "remove_ticket_tag",
        "link_tickets",
    ):
        assert c.can_write(tool), tool
    for tool in READ_TOOLS:
        assert c.can_read(tool), tool
    for tool in DESTRUCTIVE_TOOLS | DIRECTORY_MUTATION_TOOLS:
        assert not c.can_execute(tool), tool
        assert not c.can_write(tool), tool


def test_helpdesk_blocks_destructive_even_with_admin_permission_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = _controller(monkeypatch, MCP_DEFAULT_PERMISSION="admin")
    for tool in DESTRUCTIVE_TOOLS:
        assert not c.can_admin(tool), tool


def test_readonly_profile_allows_only_read_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch, MCP_PROFILE="readonly", MCP_DEFAULT_PERMISSION="admin")
    assert {t for t in REGISTERED_TOOLS if c.can_execute(t)} == READ_TOOLS
    assert c.policy.article_policy == "internal_only"


def test_full_profile_keeps_legacy_behaviour(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch, MCP_PROFILE="full", MCP_DEFAULT_PERMISSION="admin")
    assert all(c.can_execute(t) for t in REGISTERED_TOOLS)
    assert c.policy.article_policy == "any"


def test_unknown_profile_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="MCP_PROFILE"):
        _controller(monkeypatch, MCP_PROFILE="yolo")


def test_unknown_tool_is_denied_in_restrictive_profiles() -> None:
    policy = AccessPolicy(profile=Profile.HELPDESK, default_permission=Permission.ADMIN)
    c = AccessController(policy)
    assert not c.can_execute("some_future_tool")


# ---- allow-list -------------------------------------------------------------------


def test_allow_list_is_default_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch, MCP_ALLOWED_TOOLS="get_ticket,search_*,create_article")
    assert c.can_read("get_ticket")
    assert c.can_read("search_tickets")
    assert c.can_write("create_article")
    assert not c.can_execute("update_ticket")  # helpdesk would allow it, allow-list does not
    assert not c.can_execute("get_user")


def test_deny_beats_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(
        monkeypatch, MCP_ALLOWED_TOOLS="get_*,create_article", MCP_DENIED_TOOLS="get_user"
    )
    assert c.can_read("get_ticket")
    assert not c.can_read("get_user")


def test_allow_list_cannot_enable_destructive_tools_in_helpdesk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = _controller(monkeypatch, MCP_ALLOWED_TOOLS="delete_ticket", MCP_DEFAULT_PERMISSION="admin")
    assert not c.can_admin("delete_ticket")  # profile still blocks it


def test_blocked_tools_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch)
    blocked = set(c.get_blocked_tools())
    assert blocked == DESTRUCTIVE_TOOLS | DIRECTORY_MUTATION_TOOLS | MAIL_TOOLS
    assert set(c.get_allowed_tools()) == set(REGISTERED_TOOLS) - blocked


def test_tool_info_reports_accessibility(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch)
    info: dict[str, Any] = {row["tool"]: row for row in c.get_tool_info()}
    assert info["delete_ticket"]["accessible"] == "False"
    assert info["create_article"]["accessible"] == "True"


# ---- rate limit per user ----------------------------------------------------------


def test_rate_limit_is_per_user() -> None:
    c = AccessController(AccessPolicy(rate_limit_per_minute=2))
    c.consume_rate_limit("alice@example.com")
    c.consume_rate_limit("alice@example.com")
    with pytest.raises(PermissionError, match="Rate limit"):
        c.consume_rate_limit("alice@example.com")
    c.consume_rate_limit("bob@example.com")  # bob has his own budget


# ---- outbound mail switch ---------------------------------------------------------


def test_mail_tools_are_registered_write_tools() -> None:
    assert set(REGISTERED_TOOLS) >= MAIL_TOOLS
    for tool in MAIL_TOOLS:
        assert TOOL_REQUIRED_PERMISSION[tool] is Permission.WRITE


def test_mail_tools_are_blocked_by_default_and_enabled_by_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    off = _controller(monkeypatch)
    assert all(not off.can_execute(t) for t in MAIL_TOOLS)
    on = _controller(monkeypatch, MCP_OUTBOUND_MAIL="on")
    assert all(on.can_write(t) for t in MAIL_TOOLS)
    # enabling mail unlocks nothing destructive
    for tool in DESTRUCTIVE_TOOLS | DIRECTORY_MUTATION_TOOLS:
        assert not on.can_execute(tool), tool
    assert set(on.get_blocked_tools()) == DESTRUCTIVE_TOOLS | DIRECTORY_MUTATION_TOOLS


def test_readonly_profile_never_has_mail_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch, MCP_PROFILE="readonly", MCP_OUTBOUND_MAIL="on")
    assert all(not c.can_execute(t) for t in MAIL_TOOLS)


def test_mail_tools_respect_deny_and_allow_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch, MCP_OUTBOUND_MAIL="on", MCP_DENIED_TOOLS="create_ticket_with_mail")
    assert c.can_write("send_ticket_mail")
    assert not c.can_execute("create_ticket_with_mail")
    c = _controller(monkeypatch, MCP_OUTBOUND_MAIL="on", MCP_ALLOWED_TOOLS="get_ticket")
    assert not c.can_execute("send_ticket_mail")


def test_invalid_outbound_mail_value_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="MCP_OUTBOUND_MAIL"):
        _controller(monkeypatch, MCP_OUTBOUND_MAIL="maybe")


def test_mail_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _controller(monkeypatch)
    assert c.policy.mail_max_recipients == 10
    assert c.policy.mail_rate_limit_per_minute == 10
    c = _controller(monkeypatch, MCP_MAIL_MAX_RECIPIENTS="3", MCP_MAIL_RATE_LIMIT_PER_MINUTE="1")
    assert (c.policy.mail_max_recipients, c.policy.mail_rate_limit_per_minute) == (3, 1)


def test_mail_quota_is_per_user_and_separate_from_the_call_rate_limit() -> None:
    c = AccessController(AccessPolicy(rate_limit_per_minute=1, mail_rate_limit_per_minute=2))
    c.consume_mail_quota("alice@example.com")
    c.consume_mail_quota("alice@example.com")
    with pytest.raises(PermissionError, match="Mail limit"):
        c.consume_mail_quota("alice@example.com")
    c.consume_mail_quota("bob@example.com")
    c.consume_rate_limit("alice@example.com")  # general call budget is untouched
