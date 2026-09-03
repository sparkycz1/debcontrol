"""Saved machine-list views — app.services.saved_views (build_query_string,
create/list/delete, the duplicate-name guard), the web UI ("Save this
view" on the machine list), and the REST API self-service endpoints.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.db.models.user import User
from app.services.saved_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from tests.conftest import ADMIN_USERNAME
from tests.test_api_v1_extended import _api_token
from tests.test_web import _create_machine


def test_build_query_string_only_includes_known_params_in_order():
    assert build_query_string({"tag": "prod", "q": "web"}) == "q=web&tag=prod"


def test_build_query_string_drops_blank_values():
    assert build_query_string({"q": "", "tag": "prod"}) == "tag=prod"


def test_build_query_string_empty_when_nothing_set():
    assert build_query_string({"q": "", "tag": ""}) == ""


async def _admin_user(db_session_factory: Any) -> User:
    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        user: User = result.scalar_one()
        return user


async def test_create_and_list_saved_views(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        await create_saved_view(db, user.id, "Prod boxes", "tag=prod")

    async with db_session_factory() as db:
        views = await list_saved_views(db, user.id)
        assert [v.name for v in views] == ["Prod boxes"]
        assert views[0].query_string == "tag=prod"


async def test_create_saved_view_rejects_a_duplicate_name(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        await create_saved_view(db, user.id, "Prod boxes", "tag=prod")

    async with db_session_factory() as db:
        try:
            await create_saved_view(db, user.id, "Prod boxes", "tag=web")
            raised = False
        except DuplicateViewNameError:
            raised = True
        assert raised


async def test_delete_saved_view_is_scoped_to_its_owner(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        view = await create_saved_view(db, user.id, "Prod boxes", "tag=prod")
        view_id = view.id

    async with db_session_factory() as db:
        deleted_for_someone_else = await delete_saved_view(db, uuid.uuid4(), view_id)
        assert deleted_for_someone_else is False

    async with db_session_factory() as db:
        deleted = await delete_saved_view(db, user.id, view_id)
        assert deleted is True

    async with db_session_factory() as db:
        assert await list_saved_views(db, user.id) == []


async def test_machine_list_offers_save_this_view_when_filtered(client):
    response = await client.get("/machines", params={"tag": "prod"})
    assert 'action="/machines/views"' in response.text


async def test_machine_list_does_not_offer_save_when_unfiltered(client):
    response = await client.get("/machines")
    assert 'action="/machines/views"' not in response.text


async def test_saving_a_view_from_the_web_and_using_it(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="prod-box", tags="prod")

    save_resp = await client.post(
        "/machines/views",
        data={"name": "Prod boxes", "q": "", "tag": "prod", "csrf_token": csrf_token},
    )
    assert save_resp.status_code == 303

    list_resp = await client.get("/machines")
    assert "Prod boxes" in list_resp.text
    assert 'href="/machines?tag=prod"' in list_resp.text

    filtered_resp = await client.get("/machines", params={"tag": "prod"})
    assert "prod-box" in filtered_resp.text


async def test_deleting_a_saved_view_via_the_web(client, db_session_factory):
    user = await _admin_user(db_session_factory)
    async with db_session_factory() as db:
        view = await create_saved_view(db, user.id, "Prod boxes", "tag=prod")
        view_id = view.id

    await client.get("/machines")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/views/{view_id}/delete", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await list_saved_views(db, user.id) == []


async def test_saved_views_api_round_trip(client):
    headers = await _api_token(client)

    create_resp = await client.post(
        "/api/v1/account/saved-views",
        json={"name": "Prod boxes", "q": "", "tag": "prod"},
        headers=headers,
    )
    assert create_resp.status_code == 201, create_resp.text
    view_id = create_resp.json()["id"]
    assert create_resp.json()["query_string"] == "tag=prod"

    list_resp = await client.get("/api/v1/account/saved-views", headers=headers)
    assert list_resp.status_code == 200
    assert [v["name"] for v in list_resp.json()] == ["Prod boxes"]

    delete_resp = await client.delete(f"/api/v1/account/saved-views/{view_id}", headers=headers)
    assert delete_resp.status_code == 204

    list_after = await client.get("/api/v1/account/saved-views", headers=headers)
    assert list_after.json() == []


async def test_saved_views_api_rejects_duplicate_name(client):
    headers = await _api_token(client)
    await client.post(
        "/api/v1/account/saved-views",
        json={"name": "Prod boxes", "q": "", "tag": "prod"},
        headers=headers,
    )
    response = await client.post(
        "/api/v1/account/saved-views",
        json={"name": "Prod boxes", "q": "", "tag": "web"},
        headers=headers,
    )
    assert response.status_code == 409
