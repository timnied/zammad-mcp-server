"""Unit tests for outbound mail validation."""

from __future__ import annotations

import pytest

from zammad_mcp_server.mail import (
    MAX_BODY_CHARS,
    MailError,
    clean_body,
    clean_subject,
    parse_addresses,
    prepare_recipients,
)


def test_addresses_are_split_lowercased_and_deduplicated() -> None:
    assert parse_addresses("A@Example.org; b@example.org,a@example.org ,", "to") == [
        "a@example.org",
        "b@example.org",
    ]
    assert parse_addresses(None, "to") == []
    assert parse_addresses(["x@example.org"], "to") == ["x@example.org"]


@pytest.mark.parametrize(
    "bad",
    [
        "Name <a@example.org>",
        '"a b"@example.org',
        "a@example.org\r\nBcc: e@example.org",
        "a@example.org\nb@example.org",
        "no-at-sign",
        "a@localhost",
        "a b@example.org",
        "a@exa mple.org",
        "x" * 300 + "@example.org",
        "a@example.org>",
    ],
)
def test_malformed_or_dangerous_addresses_are_rejected(bad: str) -> None:
    with pytest.raises(MailError):
        parse_addresses(bad, "to")


def test_any_domain_is_accepted() -> None:
    assert parse_addresses("x@kunde.de, y@irgendwo.co.uk, z@sub.domain.example", "to")


def test_prepare_recipients_requires_to_and_drops_cc_duplicates() -> None:
    to, cc = prepare_recipients("a@example.org", "a@example.org, b@example.org", 10)
    assert (to, cc) == (["a@example.org"], ["b@example.org"])
    with pytest.raises(MailError, match="At least one"):
        prepare_recipients("", "b@example.org", 10)


def test_recipient_limit_counts_to_and_cc() -> None:
    prepare_recipients("a@example.org,b@example.org", "c@example.org", 3)
    with pytest.raises(MailError, match="Too many"):
        prepare_recipients("a@example.org,b@example.org", "c@example.org,d@example.org", 3)
    prepare_recipients("a@example.org", None, 0)  # 0 disables the limit


def test_subject_rules() -> None:
    assert clean_subject(None, "Ticket title") == "Ticket title"
    assert clean_subject("  Hallo  ", "x") == "Hallo"
    with pytest.raises(MailError):
        clean_subject("a\nBcc: x@example.org", "x")
    with pytest.raises(MailError):
        clean_subject("x" * 301, "x")
    with pytest.raises(MailError):
        clean_subject(None, "  ")


def test_body_rules() -> None:
    assert clean_body("Hallo") == "Hallo"
    for bad in ("", "   \n", "a\x00b", "x" * (MAX_BODY_CHARS + 1)):
        with pytest.raises(MailError):
            clean_body(bad)
