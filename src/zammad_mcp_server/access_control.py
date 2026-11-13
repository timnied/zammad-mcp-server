"""Access control and permission management for Zammad MCP Server."""

from __future__ import annotations

import fnmatch
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

import structlog

logger = structlog.get_logger()


class Permission(Enum):
    """Permission levels for MCP tools."""

    DENIED = auto()
    READ_ONLY = auto()
    WRITE = auto()
    ADMIN = auto()


class ToolCategory(Enum):
    """Categories of MCP tools for access control."""

    TICKETS = "tickets"
    USERS = "users"
    ORGANIZATIONS = "organizations"
    GROUPS = "groups"
    SEARCH = "search"
    ADMIN = "admin"
    SYSTEM = "system"
    ALL = "all"


# Single source of truth: every @mcp.tool() name must appear here.
TOOL_CATEGORIES: dict[str, ToolCategory] = {
    "get_ticket": ToolCategory.TICKETS,
    "search_tickets": ToolCategory.TICKETS,
    "create_ticket": ToolCategory.TICKETS,
    "update_ticket": ToolCategory.TICKETS,
    "delete_ticket": ToolCategory.TICKETS,
    "get_ticket_articles": ToolCategory.TICKETS,
    "create_article": ToolCategory.TICKETS,
    "send_ticket_mail": ToolCategory.TICKETS,
    "create_ticket_with_mail": ToolCategory.TICKETS,
    "get_ticket_stats": ToolCategory.TICKETS,
    "merge_tickets": ToolCategory.TICKETS,
    "link_tickets": ToolCategory.TICKETS,
    "summarize_ticket": ToolCategory.TICKETS,
    "list_ticket_tags": ToolCategory.TICKETS,
    "add_ticket_tag": ToolCategory.TICKETS,
    "remove_ticket_tag": ToolCategory.TICKETS,
    "get_article_attachment": ToolCategory.TICKETS,
    "get_user": ToolCategory.USERS,
    "search_users": ToolCategory.USERS,
    "create_user": ToolCategory.USERS,
    "update_user": ToolCategory.USERS,
    "delete_user": ToolCategory.USERS,
    "get_current_user": ToolCategory.USERS,
    "get_organization": ToolCategory.ORGANIZATIONS,
    "search_organizations": ToolCategory.ORGANIZATIONS,
    "create_organization": ToolCategory.ORGANIZATIONS,
    "update_organization": ToolCategory.ORGANIZATIONS,
    "delete_organization": ToolCategory.ORGANIZATIONS,
    "get_group": ToolCategory.GROUPS,
    "list_groups": ToolCategory.GROUPS,
    "create_group": ToolCategory.GROUPS,
    "get_ticket_states": ToolCategory.ADMIN,
    "get_priorities": ToolCategory.ADMIN,
    "list_tags": ToolCategory.ADMIN,
    "health_check": ToolCategory.SYSTEM,
    "get_server_info": ToolCategory.SYSTEM,
    "get_allowed_tools": ToolCategory.SYSTEM,
}

REGISTERED_TOOLS: frozenset[str] = frozenset(TOOL_CATEGORIES)


class Profile(Enum):
    """Built-in tool profiles (coarse safety presets)."""

    READONLY = "readonly"
    HELPDESK = "helpdesk"
    FULL = "full"


# Permission level each tool demands (must match the check_access() call in server.py;
# tests/test_access_control.py verifies this against the source).
TOOL_REQUIRED_PERMISSION: dict[str, Permission] = {
    **dict.fromkeys(
        (
            "get_ticket",
            "search_tickets",
            "get_ticket_articles",
            "get_ticket_stats",
            "summarize_ticket",
            "list_ticket_tags",
            "get_article_attachment",
            "get_user",
            "search_users",
            "get_current_user",
            "get_organization",
            "search_organizations",
            "get_group",
            "list_groups",
            "get_ticket_states",
            "get_priorities",
            "list_tags",
            "health_check",
            "get_server_info",
            "get_allowed_tools",
        ),
        Permission.READ_ONLY,
    ),
    **dict.fromkeys(
        (
            "create_ticket",
            "update_ticket",
            "create_article",
            "send_ticket_mail",
            "create_ticket_with_mail",
            "link_tickets",
            "add_ticket_tag",
            "remove_ticket_tag",
            "create_user",
            "update_user",
            "create_organization",
            "update_organization",
            "create_group",
        ),
        Permission.WRITE,
    ),
    **dict.fromkeys(
        ("delete_ticket", "delete_user", "delete_organization", "merge_tickets"),
        Permission.ADMIN,
    ),
}

# Irreversible or destructive operations. Blocked in the readonly and helpdesk profiles.
DESTRUCTIVE_TOOLS: frozenset[str] = frozenset(
    {"delete_ticket", "delete_user", "delete_organization", "merge_tickets"}
)

# Tools that send e-mail to arbitrary external recipients. In the helpdesk profile they
# are only available when MCP_OUTBOUND_MAIL=on; readonly never has them (they write).
MAIL_TOOLS: frozenset[str] = frozenset({"send_ticket_mail", "create_ticket_with_mail"})

# Operations that change who/what exists in Zammad (accounts, organizations, groups).
# With an on-behalf-of service account these are the most sensitive writes, so the
# helpdesk profile blocks them too.
DIRECTORY_MUTATION_TOOLS: frozenset[str] = frozenset(
    {
        "create_user",
        "update_user",
        "create_organization",
        "update_organization",
        "create_group",
    }
)


def _parse_profile(raw: str) -> Profile:
    try:
        return Profile(raw.strip().lower())
    except ValueError as exc:
        valid = ", ".join(p.value for p in Profile)
        raise ValueError(f"Unknown MCP_PROFILE: {raw!r} (valid: {valid})") from exc


def _split_csv(raw: str) -> set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def _parse_permission_name(raw: str) -> Permission:
    mapping = {
        "denied": Permission.DENIED,
        "read_only": Permission.READ_ONLY,
        "read-only": Permission.READ_ONLY,
        "read": Permission.READ_ONLY,
        "write": Permission.WRITE,
        "admin": Permission.ADMIN,
    }
    key = raw.strip().lower()
    if key not in mapping:
        raise ValueError(f"Unknown MCP_DEFAULT_PERMISSION: {raw}")
    return mapping[key]


@dataclass
class AccessPolicy:
    """Access policy configuration."""

    default_permission: Permission = Permission.READ_ONLY
    category_permissions: dict[ToolCategory, Permission] = field(default_factory=dict)
    tool_permissions: dict[str, Permission] = field(default_factory=dict)
    denied_tools: set[str] = field(default_factory=set)
    # Explicit allow-list (names or fnmatch patterns). None = no allow-list.
    # When set, every tool that does not match is denied (default-deny).
    allowed_tools: set[str] | None = None
    profile: Profile = Profile.FULL
    # "any": the model may choose article type/visibility. "internal_only": every
    # article created through the server is forced to be an internal note.
    article_policy: str = "any"
    # Helpdesk profile only: expose the outbound mail tools (MAIL_TOOLS).
    outbound_mail: bool = False
    mail_max_recipients: int = 10
    mail_rate_limit_per_minute: int = 10
    allowed_groups: set[str] | None = None
    allowed_organizations: set[int] | None = None
    rate_limit_per_minute: int = 60
    audit_log_path: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the policy."""
        if ToolCategory.ALL in self.category_permissions:
            all_perm = self.category_permissions[ToolCategory.ALL]
            for cat in ToolCategory:
                if cat != ToolCategory.ALL and cat not in self.category_permissions:
                    self.category_permissions[cat] = all_perm


class AccessController:
    """Controller for managing access permissions to MCP tools."""

    def __init__(self, policy: AccessPolicy | None = None) -> None:
        """Initialize with an access policy."""
        self.policy = policy or AccessPolicy()
        self._access_log: list[dict[str, Any]] = []
        self._call_times: dict[str | None, list[float]] = {}
        self._mail_times: dict[str | None, list[float]] = {}

    def can_execute(self, tool_name: str) -> bool:
        """Check if a tool can be executed."""
        if self._is_denied(tool_name):
            return False
        permission = self._get_permission(tool_name)
        return permission != Permission.DENIED

    def can_read(self, tool_name: str) -> bool:
        """Check if read operations are allowed."""
        if not self.can_execute(tool_name):
            return False
        permission = self._get_permission(tool_name)
        return permission in (Permission.READ_ONLY, Permission.WRITE, Permission.ADMIN)

    def can_write(self, tool_name: str) -> bool:
        """Check if write operations are allowed."""
        if not self.can_execute(tool_name):
            return False
        permission = self._get_permission(tool_name)
        return permission in (Permission.WRITE, Permission.ADMIN)

    def can_admin(self, tool_name: str) -> bool:
        """Check if admin operations are allowed."""
        if not self.can_execute(tool_name):
            return False
        permission = self._get_permission(tool_name)
        return permission == Permission.ADMIN

    def consume_rate_limit(self, user: str | None = None) -> None:
        """Raise PermissionError when the sliding-window limit is exceeded.

        The window is kept per user when an on-behalf-of identity is known, so one
        busy user cannot exhaust the budget of everyone else.
        """
        self._consume(
            self._call_times,
            user,
            self.policy.rate_limit_per_minute,
            "Rate limit exceeded ({limit} calls/minute). Retry after a short wait.",
        )

    def consume_mail_quota(self, user: str | None = None) -> None:
        """Count one outbound mail for ``user``; raise PermissionError over the limit.

        Call this only after the request passed validation, so rejected requests do
        not use up the budget.
        """
        self._consume(
            self._mail_times,
            user,
            self.policy.mail_rate_limit_per_minute,
            "Mail limit exceeded ({limit} mails/minute). Retry after a short wait.",
        )

    @staticmethod
    def _consume(
        store: dict[str | None, list[float]], user: str | None, limit: int, message: str
    ) -> None:
        if limit <= 0:
            return
        now = time.time()
        times = [stamp for stamp in store.get(user, []) if now - stamp < 60.0]
        if len(times) >= limit:
            store[user] = times
            raise PermissionError(message.format(limit=limit))
        times.append(now)
        store[user] = times

    def _is_denied(self, tool_name: str) -> bool:
        """True when the tool is blocked by deny list, allow-list or profile.

        Deny always wins: MCP_DENIED_TOOLS beats MCP_ALLOWED_TOOLS beats the profile.
        Unknown tool names are denied whenever an allow-list or a restrictive profile
        is active (fail closed).
        """
        if any(fnmatch.fnmatchcase(tool_name, p) for p in self.policy.denied_tools):
            return True
        allow = self.policy.allowed_tools
        if allow is not None and not any(fnmatch.fnmatchcase(tool_name, p) for p in allow):
            return True
        profile = self.policy.profile
        if profile is Profile.FULL:
            return False
        if tool_name not in TOOL_REQUIRED_PERMISSION:
            return True
        if tool_name in DESTRUCTIVE_TOOLS or tool_name in DIRECTORY_MUTATION_TOOLS:
            return True
        if tool_name in MAIL_TOOLS and not self.policy.outbound_mail:
            return True
        if profile is Profile.READONLY:
            return TOOL_REQUIRED_PERMISSION[tool_name] is not Permission.READ_ONLY
        return False

    def _get_permission(self, tool_name: str) -> Permission:
        """Get the permission level for a tool."""
        if tool_name in self.policy.tool_permissions:
            return self.policy.tool_permissions[tool_name]
        category = TOOL_CATEGORIES.get(tool_name, ToolCategory.ALL)
        if category in self.policy.category_permissions:
            return self.policy.category_permissions[category]
        return self.policy.default_permission

    def filter_ticket(self, ticket: dict[str, Any]) -> dict[str, Any] | None:
        """Filter ticket data based on policy restrictions."""
        if self.policy.allowed_groups is not None:
            group = ticket.get("group", "")
            if isinstance(group, dict):
                group = group.get("name", "")
            if group not in self.policy.allowed_groups:
                return None

        if self.policy.allowed_organizations is not None:
            org_id = ticket.get("organization_id", ticket.get("organizationId"))
            if org_id is not None and int(org_id) not in self.policy.allowed_organizations:
                return None

        return ticket

    def assert_group_allowed(self, group_name: str) -> None:
        """Deny writes to groups outside MCP_ALLOWED_GROUPS."""
        if self.policy.allowed_groups is None:
            return
        if group_name not in self.policy.allowed_groups:
            raise PermissionError(f"Access denied for group: {group_name}")

    def assert_ticket_allowed(self, ticket: dict[str, Any]) -> None:
        """Raise if the ticket is outside group/org scope."""
        if self.filter_ticket(ticket) is None:
            raise PermissionError("Access denied for this ticket")

    def log_access(
        self,
        tool_name: str,
        allowed: bool,
        client_info: dict[str, Any] | None = None,
    ) -> None:
        """Log an access attempt to memory, stderr, and optional audit file."""
        entry = {
            "timestamp": time.time(),
            "tool": tool_name,
            "allowed": allowed,
            "permission": self._get_permission(tool_name).name,
            "client": client_info or {},
        }
        self._access_log.append(entry)
        logger.info("mcp_access", **entry)
        path = self.policy.audit_log_path
        if path:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")

        if not allowed:
            logger.warning(
                "access_denied",
                tool=tool_name,
                client=client_info,
            )

    def get_access_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent access log entries."""
        return self._access_log[-limit:]

    @classmethod
    def from_env(cls) -> AccessController:
        """Create an access controller from environment variables."""
        allowed_categories_str = os.getenv("MCP_ALLOWED_CATEGORIES", "all")
        allowed_categories = {cat.strip().lower() for cat in allowed_categories_str.split(",")}

        default_raw = os.getenv("MCP_DEFAULT_PERMISSION", "write")
        default_permission = _parse_permission_name(default_raw)

        category_permissions: dict[ToolCategory, Permission] = {}
        if "all" in allowed_categories:
            category_permissions[ToolCategory.ALL] = default_permission
        else:
            for cat in ToolCategory:
                if cat == ToolCategory.ALL:
                    continue
                if cat.value in allowed_categories:
                    category_permissions[cat] = default_permission
                else:
                    category_permissions[cat] = Permission.DENIED

        denied_tools = _split_csv(os.getenv("MCP_DENIED_TOOLS", ""))

        allowed_tools_raw = os.getenv("MCP_ALLOWED_TOOLS", "")
        allowed_tools = _split_csv(allowed_tools_raw) if allowed_tools_raw.strip() else None

        # Secure by default: without MCP_PROFILE the helpdesk profile is used
        # (reads + ticket/article/tag writes; no deletes, merges or directory changes).
        profile = _parse_profile(os.getenv("MCP_PROFILE", "helpdesk"))

        article_policy = os.getenv("MCP_ARTICLE_POLICY", "").strip().lower()
        if not article_policy:
            article_policy = "any" if profile is Profile.FULL else "internal_only"
        if article_policy not in ("any", "internal_only"):
            raise ValueError(
                f"Unknown MCP_ARTICLE_POLICY: {article_policy!r} (valid: any, internal_only)"
            )

        outbound_raw = os.getenv("MCP_OUTBOUND_MAIL", "off").strip().lower() or "off"
        if outbound_raw not in ("on", "off"):
            raise ValueError(f"Unknown MCP_OUTBOUND_MAIL: {outbound_raw!r} (valid: on, off)")
        mail_max_recipients = int(os.getenv("MCP_MAIL_MAX_RECIPIENTS", "10"))
        mail_rate_limit = int(os.getenv("MCP_MAIL_RATE_LIMIT_PER_MINUTE", "10"))

        allowed_groups_str = os.getenv("MCP_ALLOWED_GROUPS", "")
        allowed_groups = None
        if allowed_groups_str:
            allowed_groups = {g.strip() for g in allowed_groups_str.split(",") if g.strip()}

        orgs_str = os.getenv("MCP_ALLOWED_ORGANIZATIONS", "")
        allowed_organizations = None
        if orgs_str:
            allowed_organizations = {
                int(part.strip()) for part in orgs_str.split(",") if part.strip()
            }

        rate_raw = os.getenv("MCP_RATE_LIMIT_PER_MINUTE", "60")
        rate_limit_per_minute = int(rate_raw)

        audit_log_path = os.getenv("MCP_AUDIT_LOG_PATH") or None

        policy = AccessPolicy(
            default_permission=default_permission,
            category_permissions=category_permissions,
            denied_tools=denied_tools,
            allowed_tools=allowed_tools,
            profile=profile,
            article_policy=article_policy,
            outbound_mail=outbound_raw == "on",
            mail_max_recipients=mail_max_recipients,
            mail_rate_limit_per_minute=mail_rate_limit,
            allowed_groups=allowed_groups,
            allowed_organizations=allowed_organizations,
            rate_limit_per_minute=rate_limit_per_minute,
            audit_log_path=audit_log_path,
        )
        return cls(policy)

    def get_allowed_tools(self) -> list[str]:
        """Get list of all allowed registered tools based on current policy."""
        allowed = []
        for tool_name in REGISTERED_TOOLS:
            if self.can_execute(tool_name):
                allowed.append(tool_name)
        return sorted(allowed)

    def get_blocked_tools(self) -> list[str]:
        """Registered tools that cannot be executed under the current policy."""
        return sorted(t for t in REGISTERED_TOOLS if not self.can_execute(t))

    def get_tool_info(self) -> list[dict[str, str]]:
        """Get detailed information about all registered tools and their permissions."""
        info = []
        for tool_name, category in sorted(TOOL_CATEGORIES.items()):
            permission = self._get_permission(tool_name)
            is_denied = self._is_denied(tool_name)
            info.append(
                {
                    "tool": tool_name,
                    "category": category.value,
                    "permission": permission.name,
                    "accessible": str(not is_denied and permission != Permission.DENIED),
                }
            )
        return info
