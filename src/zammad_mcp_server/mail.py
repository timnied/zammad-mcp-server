"""Validation for outbound mail sent through Zammad articles.

Only plain addresses are accepted (no display names, no quotes, no line breaks), so
nothing a model writes can smuggle extra recipients or headers into a message.
"""

from __future__ import annotations

import re

# local@domain.tld; deliberately stricter than RFC 5322. Control characters, spaces,
# quotes, angle brackets, commas and semicolons cannot match.
_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_SPLIT_RE = re.compile(r"[;,]")

MAX_SUBJECT_CHARS = 300
MAX_BODY_CHARS = 100_000


class MailError(ValueError):
    """The mail request violates the server's outbound mail policy."""


def parse_addresses(raw: str | list[str] | None, field: str) -> list[str]:
    """Return the distinct, lower-cased addresses in ``raw`` (comma/semicolon separated)."""
    if raw is None:
        return []
    items = _SPLIT_RE.split(raw) if isinstance(raw, str) else list(raw)
    result: list[str] = []
    for item in items:
        address = item.strip()
        if not address:
            continue
        if len(address) > 254 or not _ADDRESS_RE.fullmatch(address):
            raise MailError(
                f"Invalid address in '{field}': {address[:80]!r}. Use plain addresses such as "
                "'name@example.com' without display names."
            )
        address = address.lower()
        if address not in result:
            result.append(address)
    return result


def prepare_recipients(
    to: str | list[str] | None,
    cc: str | list[str] | None,
    max_recipients: int,
) -> tuple[list[str], list[str]]:
    """Parse and check recipients. ``cc`` addresses already in ``to`` are dropped."""
    to_list = parse_addresses(to, "to")
    cc_list = [a for a in parse_addresses(cc, "cc") if a not in to_list]
    if not to_list:
        raise MailError("At least one recipient in 'to' is required.")
    total = len(to_list) + len(cc_list)
    if max_recipients > 0 and total > max_recipients:
        raise MailError(
            f"Too many recipients ({total}); the server allows at most {max_recipients}."
        )
    return to_list, cc_list


def clean_subject(subject: str | None, default: str) -> str:
    """Single-line subject, falling back to ``default``."""
    value = (subject or "").strip() or default.strip()
    if any(char in value for char in "\r\n\x00"):
        raise MailError("The subject must be a single line.")
    if not value:
        raise MailError("A subject is required.")
    if len(value) > MAX_SUBJECT_CHARS:
        raise MailError(f"The subject is too long (max {MAX_SUBJECT_CHARS} characters).")
    return value


def clean_body(body: str) -> str:
    """Non-empty body within the size limit."""
    if not body or not body.strip():
        raise MailError("The mail body must not be empty.")
    if "\x00" in body:
        raise MailError("The mail body contains invalid characters.")
    if len(body) > MAX_BODY_CHARS:
        raise MailError(f"The mail body is too long (max {MAX_BODY_CHARS} characters).")
    return body
