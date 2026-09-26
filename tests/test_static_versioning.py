"""Static assets are linked with a content-hash query string and cached
accordingly, so an upgrade never pairs new HTML with a stale stylesheet."""

from __future__ import annotations

import re

from app.web.templating import static_url


def test_static_url_carries_a_content_hash() -> None:
    url = static_url("css/style.css")
    assert re.fullmatch(r"/static/css/style\.css\?v=[0-9a-f]{12}", url)
    assert static_url("css/style.css") == url


async def test_pages_link_versioned_assets_and_headers_match(client):
    page = await client.get("/dashboard")
    match = re.search(r'href="(/static/css/style\.css\?v=[0-9a-f]{12})"', page.text)
    assert match is not None

    versioned = await client.get(match.group(1))
    assert versioned.status_code == 200
    assert "immutable" in versioned.headers["cache-control"]

    bare = await client.get("/static/css/style.css")
    assert bare.headers["cache-control"] == "no-cache"
