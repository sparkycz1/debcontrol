"""`app.web.flash` — redirect-carried status messages are signed, so a
crafted link can't make a trusted page display arbitrary text."""

from __future__ import annotations

from starlette.requests import Request

from app.web.flash import MAX_MESSAGE_LENGTH, read_flash, sign_flash


def _request(query: str) -> Request:
    return Request({"type": "http", "query_string": query.encode(), "headers": []})


def test_signed_message_round_trips() -> None:
    token = sign_flash("Select at least one machine.")
    assert read_flash(_request(f"bulk_error={token}"), "bulk_error") == (
        "Select at least one machine."
    )


def test_unsigned_or_tampered_value_is_ignored() -> None:
    assert read_flash(_request("bulk_error=Your+session+expired"), "bulk_error") is None
    token = sign_flash("ok")
    assert read_flash(_request(f"bulk_error={token}x"), "bulk_error") is None


def test_missing_param_is_none() -> None:
    assert read_flash(_request(""), "bulk_error") is None


def test_long_messages_are_truncated_before_signing() -> None:
    token = sign_flash("x" * (MAX_MESSAGE_LENGTH + 50))
    message = read_flash(_request(f"e={token}"), "e")
    assert message is not None
    assert len(message) == MAX_MESSAGE_LENGTH


async def test_forged_bulk_error_is_not_rendered(client):
    response = await client.get("/users?bulk_error=Call+support+at+evil.example")
    assert response.status_code == 200
    assert "evil.example" not in response.text
