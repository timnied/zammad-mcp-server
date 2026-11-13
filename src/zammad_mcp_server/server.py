"""Zammad MCP Server implementation using FastMCP."""

from __future__ import annotations

import base64
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import structlog
from fastmcp import FastMCP

from zammad_mcp_server.access_control import REGISTERED_TOOLS, AccessController, Permission
from zammad_mcp_server.cli import parse_server_args, run_oauth_login_cli, run_server
from zammad_mcp_server.client import NotFoundError, ZammadClient
from zammad_mcp_server.formatting import html_to_text, with_body_plain
from zammad_mcp_server.identity import OboConfig, resolve_identity
from zammad_mcp_server.mail import clean_body, clean_subject, parse_addresses, prepare_recipients
from zammad_mcp_server.models import (
    ArticleContentType,
    ArticleCreateRequest,
    ArticleType,
    AttachmentUpload,
    GroupCreateRequest,
    OrganizationCreateRequest,
    TicketCreateRequest,
    TicketPriority,
    TicketState,
    TicketUpdateRequest,
    UserCreateRequest,
)

logger = structlog.get_logger()

# Global state
_client: ZammadClient | None = None
_access_controller: AccessController | None = None


def get_client() -> ZammadClient:
    """Get the global Zammad client."""
    if _client is None:
        raise RuntimeError("Zammad client not initialized")
    return _client


def get_access_controller() -> AccessController:
    """Get the global access controller."""
    if _access_controller is None:
        raise RuntimeError("Access controller not initialized")
    return _access_controller


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Manage application lifecycle."""
    global _client, _access_controller

    # Initialize
    try:
        _client = ZammadClient()
        _access_controller = AccessController.from_env()

        # Blocked tools are not just refused at call time, they disappear from
        # tools/list so the model never sees or tries them. Re-enable first so the
        # result depends only on the current policy (idempotent across restarts).
        blocked = _access_controller.get_blocked_tools()
        server.enable(names=set(REGISTERED_TOOLS), components={"tool"})
        if blocked:
            server.disable(names=set(blocked), components={"tool"})

        logger.info(
            "server_initialized",
            url=_client.url,
            profile=_access_controller.policy.profile.value,
            article_policy=_access_controller.policy.article_policy,
            on_behalf_of=_client.obo.source,
            allowed_tools=len(_access_controller.get_allowed_tools()),
            blocked_tools=blocked,
        )

        yield {"client": _client, "access_controller": _access_controller}

    except Exception as e:
        logger.error("initialization_failed", error=str(e))
        raise

    finally:
        # Cleanup
        if _client:
            _client.close()
            logger.info("client_closed")
        # Reset so a restarted lifespan (or the next test) never sees stale state.
        _client = None
        _access_controller = None


# Create FastMCP instance
mcp = FastMCP(
    "Zammad MCP Server",
    lifespan=app_lifespan,
)


def _current_user() -> str | None:
    """Caller identity for the current request (None when on-behalf-of is off)."""
    config = _client.obo if _client is not None else OboConfig.from_env()
    return resolve_identity(config)


# Helper function to check access
def check_access(tool_name: str, required_permission: Permission) -> None:
    """Check if access is allowed for a tool."""
    controller = get_access_controller()
    try:
        # Fails closed (IdentityError) when on-behalf-of is enabled and the request
        # carries no valid identity - before any rate limit, log entry or API call.
        user = _current_user()
    except PermissionError as exc:
        controller.log_access(tool_name, False, {"user": None, "reason": str(exc)})
        raise
    controller.consume_rate_limit(user)
    allowed = False

    if required_permission == Permission.ADMIN:
        allowed = controller.can_admin(tool_name)
    elif required_permission == Permission.WRITE:
        allowed = controller.can_write(tool_name)
    elif required_permission == Permission.READ_ONLY:
        allowed = controller.can_read(tool_name)

    controller.log_access(tool_name, allowed, {"user": user} if user else None)

    if not allowed:
        raise PermissionError(f"Access denied for tool: {tool_name}")


INTERNAL_NOTE_MESSAGE = (
    "Server policy: articles are always created as internal notes (never sent to customers)."
)


def _enforce_article_policy(article_type: str, internal: bool) -> tuple[str, bool, bool]:
    """Apply MCP_ARTICLE_POLICY. Returns (type, internal, was_changed)."""
    if get_access_controller().policy.article_policy != "internal_only":
        return article_type, internal, False
    return "note", True, (article_type != "note" or not internal)


PENDING_STATES = frozenset({TicketState.PENDING_REMINDER, TicketState.PENDING_CLOSE})


def _parse_state(state: str | None) -> TicketState | None:
    """Parse a state name. Unknown names fail loudly instead of being ignored."""
    if not state:
        return None
    try:
        return TicketState(state.strip().lower())
    except ValueError:
        valid = ", ".join(f"'{item.value}'" for item in TicketState)
        raise ValueError(f"Unknown ticket state {state!r}. Valid states: {valid}.") from None


def _parse_priority(priority: str | None) -> TicketPriority | None:
    """Parse a priority name. Unknown names fail loudly instead of being ignored."""
    if not priority:
        return None
    try:
        return TicketPriority(priority.strip().lower())
    except ValueError:
        valid = ", ".join(f"'{item.value}'" for item in TicketPriority)
        raise ValueError(
            f"Unknown ticket priority {priority!r}. Valid priorities: {valid}."
        ) from None


def _parse_pending_time(raw: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp that carries a UTC offset and lies in the future."""
    if not raw or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            f"pending_time {raw!r} is not a valid ISO 8601 timestamp "
            "(example: '2026-11-12T09:00:00+01:00' or '2026-11-12T08:00:00Z')."
        ) from None
    if value.tzinfo is None:
        raise ValueError(
            f"pending_time {raw!r} has no time zone. Add a UTC offset or 'Z', "
            "e.g. '2026-11-12T09:00:00+01:00'."
        )
    if value <= datetime.now(UTC):
        raise ValueError(f"pending_time {raw!r} is in the past. Use a future point in time.")
    return value.astimezone(UTC)


def _validate_pending(state: TicketState | None, pending_time: datetime | None) -> None:
    """Zammad needs pending_time exactly for the pending states."""
    if state in PENDING_STATES and pending_time is None:
        raise ValueError(
            f"State {state.value!r} requires pending_time (ISO 8601 with time zone, in the "
            "future), e.g. '2026-11-12T09:00:00+01:00'."
        )
    if pending_time is not None and state is not None and state not in PENDING_STATES:
        raise ValueError(
            "pending_time can only be set together with the states "
            f"'pending reminder' or 'pending close', not {state.value!r}."
        )


def _ticket_state_name(ticket: Any) -> str | None:
    state = getattr(ticket, "state", None)
    if state is None:
        return None
    name = getattr(state, "name", state)
    return name.lower() if isinstance(name, str) else None


def _parse_uploads(raw: list[dict[str, str]] | None) -> list[AttachmentUpload] | None:
    if not raw:
        return None
    return [AttachmentUpload.model_validate(item) for item in raw]


def _parse_content_type(value: str | None) -> ArticleContentType | None:
    """Accept Zammad article body formats. None means omit the field."""
    if value is None:
        return None
    try:
        return ArticleContentType(value)
    except ValueError as exc:
        raise ValueError("content_type must be text/plain or text/html") from exc


def _ticket_dict(ticket: Any) -> dict[str, Any]:
    dumped = ticket.model_dump()
    if isinstance(dumped, dict):
        return dumped
    return {}


def _assert_ticket_in_scope(ticket: Any) -> dict[str, Any]:
    ticket_dict = _ticket_dict(ticket)
    get_access_controller().assert_ticket_allowed(ticket_dict)
    group_name = ticket.get_group_name() if hasattr(ticket, "get_group_name") else None
    if group_name:
        get_access_controller().assert_group_allowed(group_name)
    return ticket_dict


# ==================== System Tools ====================


@mcp.tool()
def health_check() -> dict[str, Any]:
    """Check the health of the Zammad MCP Server and its connection to Zammad.

    Returns:
        Health status information including server status and connection details.
    """
    check_access("health_check", Permission.READ_ONLY)
    client = get_client()

    zammad_health = client.health_check()

    return {
        "mcp_server": "healthy",
        "zammad_connection": zammad_health,
        "allowed_tools_count": len(get_access_controller().get_allowed_tools()),
    }


@mcp.tool()
def get_server_info() -> dict[str, Any]:
    """Get information about the Zammad server.

    Returns:
        Server version, configuration, and status information.
    """
    check_access("get_server_info", Permission.READ_ONLY)
    client = get_client()
    return client.get_server_info()


@mcp.tool()
def get_allowed_tools() -> list[dict[str, str]]:
    """Get a list of all tools accessible to the current session.

    Returns:
        List of tools with their categories and permission levels.
    """
    check_access("get_allowed_tools", Permission.READ_ONLY)
    controller = get_access_controller()
    return controller.get_tool_info()


# ==================== Ticket Tools ====================


@mcp.tool()
def get_ticket(
    ticket_id: int,
    include_articles: bool = False,
) -> dict[str, Any]:
    """Get a specific ticket by ID.

    Args:
        ticket_id: The ID of the ticket to retrieve
        include_articles: Whether to include all articles/messages in the ticket

    Returns:
        Ticket details including metadata and optionally articles.
    """
    check_access("get_ticket", Permission.READ_ONLY)
    client = get_client()

    try:
        ticket = client.get_ticket(ticket_id, include_articles=include_articles)

        # Apply access control filtering
        ticket_dict = ticket.model_dump()
        filtered = get_access_controller().filter_ticket(ticket_dict)

        if filtered is None:
            return {"error": "Access denied for this ticket"}

        return with_body_plain(filtered)
    except NotFoundError:
        return {"error": f"Ticket {ticket_id} not found"}


@mcp.tool()
def search_tickets(
    query: str | None = None,
    state: str | None = None,
    priority: str | None = None,
    group: str | None = None,
    owner: str | None = None,
    customer: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """Search tickets. Example query: ``state.name:open AND group.name:Support``.

    Args:
        query: Zammad search syntax or free text
        state: Ticket state (new, open, closed, pending reminder, pending close, merged)
        priority: Priority name (1 low, 2 normal, 3 high)
        group: Filter by group name
        owner: Filter by owner email
        customer: Filter by customer email
        page: Page number for pagination
        per_page: Number of results per page (max 100)
    """
    check_access("search_tickets", Permission.READ_ONLY)
    client = get_client()
    controller = get_access_controller()

    result = client.search_tickets(
        query=query,
        state=state,
        priority=priority,
        group=group,
        owner=owner,
        customer=customer,
        page=page,
        per_page=min(per_page, 100),
    )

    # Apply access control filtering
    filtered_items = []
    for item in result.items:
        ticket_dict = item.model_dump() if hasattr(item, "model_dump") else item
        filtered = controller.filter_ticket(ticket_dict)
        if filtered:
            filtered_items.append(filtered)

    return {
        "tickets": filtered_items,
        "total_count": len(filtered_items),
        "page": page,
        "per_page": per_page,
        "total_pages": (len(filtered_items) + per_page - 1) // per_page,
    }


@mcp.tool()
def create_ticket(
    title: str,
    group: str,
    customer: str | None = None,
    state: str | None = None,
    priority: str | None = None,
    article_subject: str | None = None,
    article_body: str | None = None,
    article_type: str = "note",
    article_internal: bool = False,
    article_content_type: str | None = None,
    attachments: list[dict[str, str]] | None = None,
    pending_time: str | None = None,
) -> dict[str, Any]:
    """Create a ticket. States: new, open, closed, pending reminder, pending close.

    Priorities: '1 low', '2 normal', '3 high'. The pending states require pending_time
    (ISO 8601 with time zone, in the future, e.g. '2026-11-12T09:00:00+01:00').

    article_content_type is text/plain or text/html. Omit it and Zammad stores text/plain.
    Attachments are objects with filename, data (base64), and mime-type or mime_type.
    """
    check_access("create_ticket", Permission.WRITE)
    get_access_controller().assert_group_allowed(group)
    client = get_client()
    article_type, article_internal, _ = _enforce_article_policy(article_type, article_internal)

    state_enum = _parse_state(state)
    priority_enum = _parse_priority(priority)
    pending_dt = _parse_pending_time(pending_time)
    _validate_pending(state_enum, pending_dt)

    try:
        article_type_enum = ArticleType(article_type)
    except ValueError:
        article_type_enum = ArticleType.NOTE

    try:
        article_content_type_value = _parse_content_type(article_content_type)
    except ValueError as exc:
        return {"error": str(exc)}

    request = TicketCreateRequest(
        title=title,
        group=group,
        customer=customer,
        state=state_enum,
        priority=priority_enum,
        pending_time=pending_dt,
        article_subject=article_subject,
        article_body=article_body,
        article_type=article_type_enum,
        article_internal=article_internal,
        article_content_type=article_content_type_value,
        attachments=_parse_uploads(attachments),
    )

    ticket = client.create_ticket(request)
    return ticket.model_dump()


@mcp.tool()
def update_ticket(
    ticket_id: int,
    title: str | None = None,
    group: str | None = None,
    owner: str | None = None,
    state: str | None = None,
    priority: str | None = None,
    pending_time: str | None = None,
) -> dict[str, Any]:
    """Update an existing ticket.

    Args:
        ticket_id: The ID of the ticket to update
        title: New title for the ticket
        group: New group to assign the ticket to
        owner: New owner (email or login)
        state: New state: 'new', 'open', 'closed', 'pending reminder' or 'pending close'
        priority: New priority level ('1 low', '2 normal', '3 high')
        pending_time: Required for 'pending reminder' / 'pending close': when the ticket
            becomes due again, as ISO 8601 with time zone and in the future
            (e.g. '2026-11-12T09:00:00+01:00'). May also be passed alone to reschedule a
            ticket that is already pending.

    Returns:
        The updated ticket details.
    """
    check_access("update_ticket", Permission.WRITE)
    client = get_client()
    existing = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(existing)
    if group:
        get_access_controller().assert_group_allowed(group)

    state_enum = _parse_state(state)
    priority_enum = _parse_priority(priority)
    pending_dt = _parse_pending_time(pending_time)
    _validate_pending(state_enum, pending_dt)
    if state_enum is None and pending_dt is not None:
        current = _ticket_state_name(existing)
        if current not in {item.value for item in PENDING_STATES}:
            raise ValueError(
                "pending_time can only be set for a ticket in a pending state; "
                "also pass state='pending reminder' or 'pending close'."
            )

    request = TicketUpdateRequest(
        title=title,
        group=group,
        owner=owner,
        state=state_enum,
        priority=priority_enum,
        pending_time=pending_dt,
    )

    ticket = client.update_ticket(ticket_id, request)
    return ticket.model_dump()


@mcp.tool()
def delete_ticket(ticket_id: int) -> dict[str, Any]:
    """Delete a ticket.

    Args:
        ticket_id: The ID of the ticket to delete

    Returns:
        Success status.
    """
    check_access("delete_ticket", Permission.ADMIN)
    client = get_client()

    try:
        client.delete_ticket(ticket_id)
        return {"success": True, "message": f"Ticket {ticket_id} deleted"}
    except NotFoundError:
        return {"success": False, "error": f"Ticket {ticket_id} not found"}


@mcp.tool()
def get_ticket_articles(ticket_id: int) -> dict[str, Any]:
    """Get all articles (messages) for a ticket.

    Args:
        ticket_id: The ID of the ticket

    Returns:
        List of articles in the ticket.
    """
    check_access("get_ticket_articles", Permission.READ_ONLY)
    client = get_client()

    try:
        articles = client.get_ticket_articles(ticket_id)
        ticket = client.get_ticket(ticket_id)
        _assert_ticket_in_scope(ticket)
        return {
            "ticket_id": ticket_id,
            "articles": [with_body_plain(a.model_dump()) for a in articles],
            "count": len(articles),
        }
    except NotFoundError:
        return {"error": f"Ticket {ticket_id} not found"}


@mcp.tool()
def create_article(
    ticket_id: int,
    body: str,
    subject: str | None = None,
    type: str = "note",
    internal: bool = False,
    to: str | None = None,
    cc: str | None = None,
    content_type: str | None = None,
    attachments: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Add an article (default: note) to a ticket. internal=True keeps it staff-only.

    Server policy may force every article to be an internal note. content_type is
    text/plain or text/html (omit it and Zammad stores text/plain). Attachments:
    filename, data (base64), mime-type.
    """
    check_access("create_article", Permission.WRITE)
    client = get_client()
    ticket = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(ticket)

    type, internal, coerced = _enforce_article_policy(type, internal)
    if coerced:
        to = cc = None  # an internal note has no recipients

    try:
        article_type_enum = ArticleType(type)
    except ValueError:
        article_type_enum = ArticleType.NOTE

    try:
        content_type_value = _parse_content_type(content_type)
    except ValueError as exc:
        return {"error": str(exc)}

    request = ArticleCreateRequest(
        ticket_id=ticket_id,
        body=body,
        subject=subject,
        type=article_type_enum,
        internal=internal,
        to=to,
        cc=cc,
        content_type=content_type_value,
        attachments=_parse_uploads(attachments),
    )

    article = client.create_article(request)
    result = with_body_plain(article.model_dump())
    if coerced:
        result["policy_note"] = INTERNAL_NOTE_MESSAGE
    return result


MAIL_DELIVERY_NOTE = (
    "The mail was handed to Zammad for delivery through the group's mail channel. "
    "Delivery to the recipient is not confirmed here."
)


def _log_outbound_mail(
    tool: str, ticket_id: int | None, to: list[str], cc: list[str], subject: str
) -> None:
    logger.info(
        "outbound_mail",
        tool=tool,
        user=_current_user(),
        ticket_id=ticket_id,
        to=to,
        cc=cc,
        subject=subject[:120],
    )


@mcp.tool()
def send_ticket_mail(
    ticket_id: int,
    to: str,
    body: str,
    subject: str | None = None,
    cc: str | None = None,
) -> dict[str, Any]:
    """Send an e-mail from within an existing ticket (reply or any other mail).

    The mail is sent through the ticket's group mail channel and appears as an e-mail
    article in the ticket. Recipients are plain addresses, comma separated ('to', 'cc');
    there is no BCC and no attachment support. Plain-text body. The subject defaults
    to the ticket title. The server limits recipients and mails per minute and logs
    every mail with the acting user. The mail goes out to external recipients.

    Args:
        ticket_id: Internal ticket ID (not the ticket number)
        to: Recipient address(es), e.g. 'a@example.com, b@example.com'
        body: Plain-text message
        subject: Subject (default: ticket title)
        cc: Optional CC address(es)
    """
    check_access("send_ticket_mail", Permission.WRITE)
    controller = get_access_controller()
    to_list, cc_list = prepare_recipients(to, cc, controller.policy.mail_max_recipients)
    body = clean_body(body)
    subject_clean = clean_subject(subject, "x") if subject and subject.strip() else None
    client = get_client()
    ticket = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(ticket)
    if subject_clean is None:
        subject_clean = clean_subject(None, str(getattr(ticket, "title", "")))

    controller.consume_mail_quota(_current_user())
    article = client.create_article(
        ArticleCreateRequest(
            ticket_id=ticket_id,
            subject=subject_clean,
            body=body,
            type=ArticleType.EMAIL,
            internal=False,
            to=", ".join(to_list),
            cc=", ".join(cc_list) or None,
            sender="Agent",
            content_type=ArticleContentType.PLAIN,
        )
    )
    _log_outbound_mail("send_ticket_mail", ticket_id, to_list, cc_list, subject_clean)
    return {
        "ticket_id": ticket_id,
        "article_id": article.id,
        "to": to_list,
        "cc": cc_list,
        "subject": subject_clean,
        "note": MAIL_DELIVERY_NOTE,
    }


@mcp.tool()
def create_ticket_with_mail(
    title: str,
    group: str,
    to: str,
    body: str,
    subject: str | None = None,
    cc: str | None = None,
    customer: str | None = None,
    state: str | None = None,
    priority: str | None = None,
    pending_time: str | None = None,
) -> dict[str, Any]:
    """Create a ticket and send an e-mail with it (the first article is the sent mail).

    Recipients are plain addresses, comma separated ('to', 'cc'); no BCC, no
    attachments, plain-text body. The customer defaults to the first 'to' address. The
    server limits recipients and mails per minute and logs every mail with the acting
    user. The mail goes out to external recipients.

    Args:
        title: Ticket title
        group: Group name (its mail channel is used for sending)
        to: Recipient address(es)
        body: Plain-text message
        subject: Mail subject (default: ticket title)
        cc: Optional CC address(es)
        customer: Customer e-mail address (default: first 'to' address)
        state: 'new', 'open', 'closed', 'pending reminder' or 'pending close'
        priority: '1 low', '2 normal' or '3 high'
        pending_time: Required for the pending states (ISO 8601 with time zone)
    """
    check_access("create_ticket_with_mail", Permission.WRITE)
    controller = get_access_controller()
    controller.assert_group_allowed(group)
    to_list, cc_list = prepare_recipients(to, cc, controller.policy.mail_max_recipients)
    body = clean_body(body)
    title = title.strip()
    if not title:
        raise ValueError("The ticket title must not be empty.")
    subject_clean = clean_subject(subject, title)
    customer_list = parse_addresses(customer, "customer") if customer else [to_list[0]]
    if len(customer_list) != 1:
        raise ValueError("'customer' must be exactly one e-mail address.")
    state_enum = _parse_state(state)
    priority_enum = _parse_priority(priority)
    pending_dt = _parse_pending_time(pending_time)
    _validate_pending(state_enum, pending_dt)
    client = get_client()

    controller.consume_mail_quota(_current_user())
    ticket = client.create_ticket(
        TicketCreateRequest(
            title=title,
            group=group,
            customer=customer_list[0],
            state=state_enum,
            priority=priority_enum,
            pending_time=pending_dt,
            article_subject=subject_clean,
            article_body=body,
            article_type=ArticleType.EMAIL,
            article_internal=False,
            article_content_type=ArticleContentType.PLAIN,
            article_to=", ".join(to_list),
            article_cc=", ".join(cc_list) or None,
        )
    )
    _log_outbound_mail("create_ticket_with_mail", ticket.id, to_list, cc_list, subject_clean)
    result = ticket.model_dump()
    result["mail"] = {"to": to_list, "cc": cc_list, "subject": subject_clean}
    result["note"] = MAIL_DELIVERY_NOTE
    return result


@mcp.tool()
def get_ticket_stats(
    group: str | None = None,
    max_scan_pages: int = 10,
) -> dict[str, Any]:
    """Get ticket statistics.

    Args:
        group: Filter by specific group (optional)
        max_scan_pages: Maximum pages to scan for large datasets

    Returns:
        Ticket statistics including counts by state, group, and priority.
    """
    check_access("get_ticket_stats", Permission.READ_ONLY)
    client = get_client()

    stats = client.get_ticket_stats(group=group, max_scan_pages=max_scan_pages)
    return stats.model_dump()


@mcp.tool()
def get_ticket_states() -> list[dict[str, Any]]:
    """Get all available ticket states.

    Returns:
        List of available ticket states with their properties.
    """
    check_access("get_ticket_states", Permission.READ_ONLY)
    client = get_client()
    return client.get_ticket_states()


@mcp.tool()
def get_priorities() -> list[dict[str, Any]]:
    """Get all available ticket priorities.

    Returns:
        List of available priority levels.
    """
    check_access("get_priorities", Permission.READ_ONLY)
    client = get_client()
    return client.get_priorities()


# ==================== User Tools ====================


@mcp.tool()
def get_user(user_id: int) -> dict[str, Any]:
    """Get a user by ID.

    Args:
        user_id: The ID of the user

    Returns:
        User details.
    """
    check_access("get_user", Permission.READ_ONLY)
    client = get_client()

    try:
        user = client.get_user(user_id)
        return user.model_dump()
    except NotFoundError:
        return {"error": f"User {user_id} not found"}


@mcp.tool()
def search_users(
    query: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """Search for users.

    Args:
        query: Search query (email, name, etc.)
        page: Page number
        per_page: Results per page (max 100)

    Returns:
        Search results with users.
    """
    check_access("search_users", Permission.READ_ONLY)
    client = get_client()

    result = client.search_users(
        query=query,
        page=page,
        per_page=min(per_page, 100),
    )

    return {
        "users": [u.model_dump() for u in result.items],
        "total_count": result.total_count,
        "page": page,
        "per_page": per_page,
    }


@mcp.tool()
def create_user(
    email: str | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    login: str | None = None,
    phone: str | None = None,
    mobile: str | None = None,
    organization: str | None = None,
    password: str | None = None,
    active: bool = True,
) -> dict[str, Any]:
    """Create a new user.

    Args:
        email: User's email address
        firstname: First name
        lastname: Last name
        login: Login username (defaults to email if not provided)
        phone: Phone number
        mobile: Mobile number
        organization: Organization name
        password: Initial password
        active: Whether the user is active

    Returns:
        The created user details.
    """
    check_access("create_user", Permission.WRITE)
    client = get_client()

    request = UserCreateRequest(
        email=email,
        firstname=firstname,
        lastname=lastname,
        login=login,
        phone=phone,
        mobile=mobile,
        organization=organization,
        password=password,
        active=active,
    )

    user = client.create_user(request)
    return user.model_dump()


@mcp.tool()
def update_user(
    user_id: int,
    login: str | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    mobile: str | None = None,
    organization: str | None = None,
    active: bool | None = None,
) -> dict[str, Any]:
    """Update a user.

    Args:
        user_id: The ID of the user to update
        login: New login name
        firstname: New first name
        lastname: New last name
        email: New email address
        phone: New phone number
        mobile: New mobile number
        organization: New organization name
        active: Whether the user is active

    Returns:
        The updated user details.
    """
    check_access("update_user", Permission.WRITE)
    client = get_client()

    updates = {
        k: v
        for k, v in {
            "login": login,
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "phone": phone,
            "mobile": mobile,
            "organization": organization,
            "active": active,
        }.items()
        if v is not None
    }

    user = client.update_user(user_id, **updates)
    return user.model_dump()


@mcp.tool()
def delete_user(user_id: int) -> dict[str, Any]:
    """Delete a user.

    Args:
        user_id: The ID of the user to delete

    Returns:
        Success status.
    """
    check_access("delete_user", Permission.ADMIN)
    client = get_client()

    try:
        client.delete_user(user_id)
        return {"success": True, "message": f"User {user_id} deleted"}
    except NotFoundError:
        return {"success": False, "error": f"User {user_id} not found"}


@mcp.tool()
def get_current_user() -> dict[str, Any]:
    """Get the currently authenticated user.

    Returns:
        Current user details.
    """
    check_access("get_current_user", Permission.READ_ONLY)
    client = get_client()

    user = client.get_current_user()
    return user.model_dump()


# ==================== Organization Tools ====================


@mcp.tool()
def get_organization(org_id: int) -> dict[str, Any]:
    """Get an organization by ID.

    Args:
        org_id: The ID of the organization

    Returns:
        Organization details.
    """
    check_access("get_organization", Permission.READ_ONLY)
    client = get_client()

    try:
        org = client.get_organization(org_id)
        return org.model_dump()
    except NotFoundError:
        return {"error": f"Organization {org_id} not found"}


@mcp.tool()
def search_organizations(
    query: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """Search for organizations.

    Args:
        query: Search query
        page: Page number
        per_page: Results per page (max 100)

    Returns:
        Search results with organizations.
    """
    check_access("search_organizations", Permission.READ_ONLY)
    client = get_client()

    result = client.search_organizations(
        query=query,
        page=page,
        per_page=min(per_page, 100),
    )

    return {
        "organizations": [o.model_dump() for o in result.items],
        "total_count": result.total_count,
        "page": page,
        "per_page": per_page,
    }


@mcp.tool()
def create_organization(
    name: str,
    shared: bool = True,
    note: str | None = None,
    domain: str | None = None,
    active: bool = True,
) -> dict[str, Any]:
    """Create a new organization.

    Args:
        name: Organization name
        shared: Whether tickets are shared within the organization
        note: Internal note about the organization
        domain: Email domain for automatic assignment
        active: Whether the organization is active

    Returns:
        The created organization details.
    """
    check_access("create_organization", Permission.WRITE)
    client = get_client()

    request = OrganizationCreateRequest(
        name=name,
        shared=shared,
        note=note,
        domain=domain,
        active=active,
    )

    org = client.create_organization(request)
    return org.model_dump()


@mcp.tool()
def update_organization(
    org_id: int,
    name: str | None = None,
    shared: bool | None = None,
    note: str | None = None,
    domain: str | None = None,
    active: bool | None = None,
) -> dict[str, Any]:
    """Update an organization.

    Args:
        org_id: The ID of the organization to update
        name: New organization name
        shared: Whether the organization is shared
        note: New note text
        domain: New domain
        active: Whether the organization is active

    Returns:
        The updated organization details.
    """
    check_access("update_organization", Permission.WRITE)
    client = get_client()

    updates = {
        k: v
        for k, v in {
            "name": name,
            "shared": shared,
            "note": note,
            "domain": domain,
            "active": active,
        }.items()
        if v is not None
    }

    org = client.update_organization(org_id, **updates)
    return org.model_dump()


@mcp.tool()
def delete_organization(org_id: int) -> dict[str, Any]:
    """Delete an organization.

    Args:
        org_id: The ID of the organization to delete

    Returns:
        Success status.
    """
    check_access("delete_organization", Permission.ADMIN)
    client = get_client()

    try:
        client.delete_organization(org_id)
        return {"success": True, "message": f"Organization {org_id} deleted"}
    except NotFoundError:
        return {"success": False, "error": f"Organization {org_id} not found"}


# ==================== Group Tools ====================


@mcp.tool()
def get_group(group_id: int) -> dict[str, Any]:
    """Get a group by ID.

    Args:
        group_id: The ID of the group

    Returns:
        Group details.
    """
    check_access("get_group", Permission.READ_ONLY)
    client = get_client()

    try:
        group = client.get_group(group_id)
        return group.model_dump()
    except NotFoundError:
        return {"error": f"Group {group_id} not found"}


@mcp.tool()
def list_groups() -> dict[str, Any]:
    """List all groups.

    Returns:
        List of all groups.
    """
    check_access("list_groups", Permission.READ_ONLY)
    client = get_client()

    groups = client.list_groups()
    return {
        "groups": [g.model_dump() for g in groups],
        "count": len(groups),
    }


@mcp.tool()
def create_group(
    name: str,
    active: bool = True,
    note: str | None = None,
) -> dict[str, Any]:
    """Create a new group.

    Args:
        name: Group name
        active: Whether the group is active
        note: Internal note about the group

    Returns:
        The created group details.
    """
    check_access("create_group", Permission.WRITE)
    client = get_client()

    request = GroupCreateRequest(name=name, active=active, note=note)
    group = client.create_group(request)
    return group.model_dump()


@mcp.tool()
def list_ticket_tags(ticket_id: int) -> dict[str, Any]:
    """List tags on a ticket."""
    check_access("list_ticket_tags", Permission.READ_ONLY)
    client = get_client()
    ticket = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(ticket)
    tags = client.list_ticket_tags(ticket_id)
    return {"ticket_id": ticket_id, "tags": tags}


@mcp.tool()
def add_ticket_tag(ticket_id: int, tag: str) -> dict[str, Any]:
    """Add a tag to a ticket (creates the tag if permitted)."""
    check_access("add_ticket_tag", Permission.WRITE)
    client = get_client()
    ticket = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(ticket)
    client.add_ticket_tag(ticket_id, tag)
    return {"ticket_id": ticket_id, "tag": tag, "success": True}


@mcp.tool()
def remove_ticket_tag(ticket_id: int, tag: str) -> dict[str, Any]:
    """Remove a tag from a ticket."""
    check_access("remove_ticket_tag", Permission.WRITE)
    client = get_client()
    ticket = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(ticket)
    client.remove_ticket_tag(ticket_id, tag)
    return {"ticket_id": ticket_id, "tag": tag, "success": True}


@mcp.tool()
def list_tags() -> dict[str, Any]:
    """List the Zammad tag catalog (admin tag list)."""
    check_access("list_tags", Permission.READ_ONLY)
    client = get_client()
    tags = client.list_tags()
    return {"tags": tags, "count": len(tags)}


@mcp.tool()
def get_article_attachment(
    ticket_id: int,
    article_id: int,
    attachment_id: int,
    as_text: bool = False,
) -> dict[str, Any]:
    """Download an article attachment as base64 (or UTF-8 text when as_text is true)."""
    check_access("get_article_attachment", Permission.READ_ONLY)
    client = get_client()
    ticket = client.get_ticket(ticket_id)
    _assert_ticket_in_scope(ticket)
    payload = client.get_article_attachment(ticket_id, article_id, attachment_id)
    encoded = base64.b64encode(payload).decode("ascii")
    result: dict[str, Any] = {
        "ticket_id": ticket_id,
        "article_id": article_id,
        "attachment_id": attachment_id,
        "size": len(payload),
        "data": encoded,
    }
    if as_text:
        result["text"] = payload.decode("utf-8", errors="replace")
    return result


@mcp.tool()
def link_tickets(
    source_id: int,
    target_id: int,
    link_type: str = "normal",
) -> dict[str, Any]:
    """Link two tickets (link_type: normal, parent, child)."""
    check_access("link_tickets", Permission.WRITE)
    client = get_client()
    _assert_ticket_in_scope(client.get_ticket(source_id))
    _assert_ticket_in_scope(client.get_ticket(target_id))
    linked = client.link_tickets(source_id, target_id, link_type=link_type)
    return {
        "source_id": source_id,
        "target_id": target_id,
        "link_type": link_type,
        "result": linked,
    }


@mcp.tool()
def merge_tickets(source_id: int, target_id: int) -> dict[str, Any]:
    """Merge source ticket into target (admin). Customer sees one remaining ticket."""
    check_access("merge_tickets", Permission.ADMIN)
    client = get_client()
    _assert_ticket_in_scope(client.get_ticket(source_id))
    _assert_ticket_in_scope(client.get_ticket(target_id))
    merged = client.merge_tickets(source_id, target_id)
    return {"source_id": source_id, "target_id": target_id, "result": merged}


@mcp.tool()
def summarize_ticket(ticket_id: int) -> dict[str, Any]:
    """Return ticket metadata, tags, and a chronological plain-text thread for agents."""
    check_access("summarize_ticket", Permission.READ_ONLY)
    client = get_client()
    ticket = client.get_ticket(ticket_id, include_articles=True)
    ticket_dict = _assert_ticket_in_scope(ticket)
    tags = client.list_ticket_tags(ticket_id)
    articles = ticket.articles or client.get_ticket_articles(ticket_id)
    sorted_articles = sorted(
        articles,
        key=lambda article: article.created_at or article.updated_at or article.id,
    )
    thread_parts: list[str] = []
    last_customer: str | None = None
    last_agent: str | None = None
    for article in sorted_articles:
        body = html_to_text(article.body or "")
        sender = (article.sender or "").lower()
        stamp = article.created_at.isoformat() if article.created_at else ""
        thread_parts.append(
            f"[{stamp}] {article.sender or 'unknown'} "
            f"({article.type or 'note'}, internal={article.internal}): {body}"
        )
        if "customer" in sender:
            last_customer = body
        elif "agent" in sender:
            last_agent = body
    return {
        "ticket": with_body_plain(ticket_dict),
        "tags": tags,
        "article_count": len(sorted_articles),
        "thread_plain": "\n\n".join(thread_parts),
        "last_customer_message": last_customer,
        "last_agent_message": last_agent,
    }


# ==================== Resources ====================


@mcp.resource("zammad://ticket/{ticket_id}")
def get_ticket_resource(ticket_id: str) -> str:
    """Get ticket details as a formatted resource."""
    check_access("get_ticket", Permission.READ_ONLY)
    client = get_client()

    try:
        ticket = client.get_ticket(int(ticket_id), include_articles=True)

        lines = [
            f"# Ticket #{ticket.number or ticket.id}: {ticket.title}",
            "",
            f"**State:** {ticket.get_state_name() or 'Unknown'}",
            f"**Priority:** {ticket.get_priority_name() or 'Unknown'}",
            f"**Group:** {ticket.get_group_name() or 'Unknown'}",
            f"**Created:** {ticket.created_at}",
            "",
            "## Articles",
            "",
        ]

        if ticket.articles:
            for article in ticket.articles:
                lines.extend(
                    [
                        f"### {article.subject or 'No subject'} ({article.type or 'unknown'})",
                        f"*From: {article.from_address or 'Unknown'} | Internal: {article.internal}*",
                        "",
                        html_to_text(article.body or "") if article.body else "No content",
                        "",
                        "---",
                        "",
                    ]
                )
        else:
            lines.append("No articles available.")

        return "\n".join(lines)
    except NotFoundError:
        return f"Ticket {ticket_id} not found."


@mcp.resource("zammad://user/{user_id}")
def get_user_resource(user_id: str) -> str:
    """Get user details as a formatted resource."""
    check_access("get_user", Permission.READ_ONLY)
    client = get_client()

    try:
        user = client.get_user(int(user_id))

        return f"""# User: {user.get_full_name()}

**Email:** {user.email or "N/A"}
**Login:** {user.login or "N/A"}
**Phone:** {user.phone or "N/A"}
**Mobile:** {user.mobile or "N/A"}
**Active:** {user.active}
**Created:** {user.created_at}
"""
    except NotFoundError:
        return f"User {user_id} not found."


@mcp.resource("zammad://config/states")
def get_states_resource() -> str:
    """Get available ticket states as a resource."""
    check_access("get_ticket_states", Permission.READ_ONLY)
    client = get_client()

    states = client.get_ticket_states()

    lines = ["# Available Ticket States", ""]
    for state in states:
        name = state.get("name", "Unknown")
        state_type = state.get("stateType", state.get("state_type", "Unknown"))
        lines.append(f"- **{name}** (Type: {state_type})")

    return "\n".join(lines)


@mcp.resource("zammad://config/priorities")
def get_priorities_resource() -> str:
    """Get available ticket priorities as a resource."""
    check_access("get_priorities", Permission.READ_ONLY)
    client = get_client()
    priorities = client.get_priorities()
    lines = ["# Available Ticket Priorities", ""]
    for priority in priorities:
        name = priority.get("name", "Unknown")
        lines.append(f"- **{name}**")
    return "\n".join(lines)


@mcp.resource("zammad://organization/{org_id}")
def get_organization_resource(org_id: str) -> str:
    """Get organization details as a formatted resource."""
    check_access("get_organization", Permission.READ_ONLY)
    client = get_client()
    try:
        org = client.get_organization(int(org_id))
        return (
            f"# Organization: {org.name}\n\n"
            f"**Shared:** {org.shared}\n"
            f"**Active:** {org.active}\n"
            f"**Domain:** {org.domain or 'N/A'}\n"
            f"**Note:** {org.note or 'N/A'}\n"
        )
    except NotFoundError:
        return f"Organization {org_id} not found."


@mcp.prompt()
def ticket_summary_prompt(ticket_id: str) -> str:
    """Generate a summary of a ticket."""
    return f"""Please analyze ticket #{ticket_id} and provide a comprehensive summary including:

1. What is the main issue or request?
2. What is the current status?
3. What actions have been taken so far?
4. Who are the key participants?
5. What are the next steps or recommendations?

Use the available tools to fetch the ticket details and articles."""


@mcp.prompt()
def customer_communication_prompt(
    ticket_id: str,
    tone: str = "professional",
) -> str:
    """Generate a customer communication draft."""
    return f"""Draft a {tone} response for ticket #{ticket_id}.

Please:
1. Review the ticket history and understand the context
2. Address all customer questions or concerns
3. Provide clear next steps or resolution
4. Maintain a {tone} tone throughout

Use the ticket tools to gather information before drafting the response."""


@mcp.prompt()
def escalation_analysis_prompt(ticket_id: str) -> str:
    """Analyze if a ticket needs escalation."""
    return f"""Analyze ticket #{ticket_id} for escalation potential:

1. How long has the ticket been open?
2. How many interactions have occurred?
3. Is the customer showing signs of frustration?
4. Does this issue require specialized expertise?
5. What is the business impact?

Call summarize_ticket first, then recommend whether to escalate, to whom, and why."""


@mcp.prompt()
def analyze_ticket(ticket_id: str, locale: str) -> str:
    """Structured ticket analysis with history, tags, and SLA hints."""
    return f"""Analyze ticket #{ticket_id} in locale {locale}.

1. Call summarize_ticket and list_ticket_tags.
2. Summarize the issue, timeline, and current state.
3. Note SLA risk (age, pending close, customer waiting).
4. Recommend next action (reply, escalate, close, wait)."""


@mcp.prompt()
def draft_response(ticket_id: str, locale: str, tone: str, visibility: str) -> str:
    """Draft a customer or internal reply using ticket context."""
    return f"""Draft a {tone} {visibility} reply for ticket #{ticket_id} in {locale}.

1. Call summarize_ticket.
2. Address every open customer question.
3. If visibility is internal, write an agent note; if public, write a customer-facing article.
4. Do not invent facts that are not in the thread."""


@mcp.prompt()
def triage_queue(group: str, locale: str) -> str:
    """Prioritize open tickets in a Zammad group."""
    return f"""Triage open tickets in group {group}. Locale: {locale}.

1. Call search_tickets with state=open and group={group}.
2. Rank by urgency (priority, age, customer waiting).
3. Suggest owner/next step for the top items.
4. Stay inside allowed groups."""


@mcp.prompt()
def escalation_summary(group: str, locale: str) -> str:
    """Summarize overdue or pending-close tickets in a group."""
    return f"""Find escalation candidates in group {group}. Locale: {locale}.

1. Search tickets with query `group.name:{group} AND (state.name:"pending close" OR state.name:open)`.
2. Flag tickets that look overdue, looping, or high priority.
3. Produce a short briefing for a team lead."""


# ==================== Main Entry Point ====================


def main() -> None:
    """Run the MCP server, or `login` to complete a Zammad OAuth callback."""
    if len(sys.argv) > 1 and sys.argv[1] == "login":
        run_oauth_login_cli(sys.argv[2:])
        return
    args = parse_server_args()

    # structlog's stdlib filter drops everything below the root logger level (WARNING by
    # default), which silently discarded the info-level audit trail ("mcp_access").
    logging.basicConfig(
        stream=sys.stderr,
        level=os.getenv("MCP_LOG_LEVEL", "INFO").upper(),
        format="%(message)s",
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    logger.info(
        "starting_mcp_server",
        transport=args.transport,
        host=args.host,
        port=args.port,
    )
    run_server(mcp, args)


if __name__ == "__main__":
    main()
