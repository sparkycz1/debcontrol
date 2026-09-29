"""Saved audit-log views — app.services.saved_audit_views (build_query_string,
create/list/delete, the duplicate-name guard), the web UI ("Save this
view" on the audit log), and the REST API self-service endpoints. Mirrors
tests/test_saved_views.py, the machine-list equivalent.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.db.models.user import User
from app.services.saved_audit_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from tests.conftest import ADMIN_USERNAME
from tests.test_api_v1_extended import _api_token


def test_build_query_string_only_includes_known_params_in_order():
    assert build_query_string({"outcome": "failure", "q": "reboot"}) == "q=reboot&outcome=failure"


def test_build_query_string_drops_blank_values():
    assert build_query_string({"q": "", "outcome": "failure"}) == "outcome=failure"


def test_build_query_string_empty_when_nothing_set():
    assert build_query_string({"q": "", "outcome": ""}) == ""


async def _admin_user(db_session_factory: Any) -> User:
    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        user: User = result.scalar_one()
        return user


async def test_create_and_list_saved_audit_views(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        await create_saved_view(db, user.id, "Failures", "outcome=failure")

    async with db_session_factory() as db:
        views = await list_saved_views(db, user.id)
        assert [v.name for v in views] == ["Failures"]
        assert views[0].query_string == "outcome=failure"


async def test_create_saved_audit_view_rejects_a_duplicate_name(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        await create_saved_view(db, user.id, "Failures", "outcome=failure")

    async with db_session_factory() as db:
        try:
            await create_saved_view(db, user.id, "Failures", "outcome=denied")
            raised = False
        except DuplicateViewNameError:
            raised = True
        assert raised


async def test_delete_saved_audit_view_is_scoped_to_its_owner(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        view = await create_saved_view(db, user.id, "Failures", "outcome=failure")
        view_id = view.id

    async with db_session_factory() as db:
        deleted_for_someone_else = await delete_saved_view(db, uuid.uuid4(), view_id)
        assert deleted_for_someone_else is False

    async with db_session_factory() as db:
        deleted = await delete_saved_view(db, user.id, view_id)
        assert deleted is True

    async with db_session_factory() as db:
        assert await list_saved_views(db, user.id) == []


async def test_audit_log_offers_save_this_view_when_filtered(client):
    response = await client.get("/audit", params={"outcome": "failure"})
    assert 'action="/audit/saved-views"' in response.text


async def test_audit_log_does_not_offer_save_when_unfiltered(client):
    response = await client.get("/audit")
    assert 'action="/audit/saved-views"' not in response.text


async def test_saving_an_audit_view_from_the_web_and_using_it(client):
    await client.get("/audit")
    csrf_token = client.cookies.get("csrftoken")
    save_resp = await client.post(
        "/audit/saved-views",
        data={"name": "Failures", "q": "", "outcome": "failure", "csrf_token": csrf_token},
    )
    assert save_resp.status_code == 303

    list_resp = await client.get("/audit")
    assert "Failures" in list_resp.text
    assert 'href="/audit?outcome=failure"' in list_resp.text


async def test_saving_an_audit_view_with_a_duplicate_name_shows_an_error(client):
    await client.get("/audit")
    csrf_token = client.cookies.get("csrftoken")
    data = {"name": "Failures", "q": "", "outcome": "failure", "csrf_token": csrf_token}
    await client.post("/audit/saved-views", data=data)

    csrf_token = client.cookies.get("csrftoken")
    data["csrf_token"] = csrf_token
    response = await client.post("/audit/saved-views", data=data, follow_redirects=True)
    assert "already have a saved view with that name" in response.text


async def test_deleting_a_saved_audit_view_via_the_web(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        view = await create_saved_view(db, user.id, "Failures", "outcome=failure")
        view_id = view.id

    await client.get("/audit")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/audit/saved-views/{view_id}/delete", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await list_saved_views(db, user.id) == []


async def test_saved_audit_views_api_round_trip(client):
    headers = await _api_token(client)

    create_resp = await client.post(
        "/api/v1/account/saved-audit-views",
        json={"name": "Failures", "outcome": "failure"},
        headers=headers,
    )
    assert create_resp.status_code == 201, create_resp.text
    view_id = create_resp.json()["id"]
    assert create_resp.json()["query_string"] == "outcome=failure"

    list_resp = await client.get("/api/v1/account/saved-audit-views", headers=headers)
    assert list_resp.status_code == 200
    assert [v["name"] for v in list_resp.json()] == ["Failures"]

    delete_resp = await client.delete(
        f"/api/v1/account/saved-audit-views/{view_id}", headers=headers
    )
    assert delete_resp.status_code == 204

    list_after = await client.get("/api/v1/account/saved-audit-views", headers=headers)
    assert list_after.json() == []


async def test_saved_audit_views_api_rejects_duplicate_name(client):
    headers = await _api_token(client)
    await client.post(
        "/api/v1/account/saved-audit-views",
        json={"name": "Failures", "outcome": "failure"},
        headers=headers,
    )
    response = await client.post(
        "/api/v1/account/saved-audit-views",
        json={"name": "Failures", "outcome": "denied"},
        headers=headers,
    )
    assert response.status_code == 409
