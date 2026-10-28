"""Links for a container (`app.services.container_links`) and the
containers page's state groups (`app.services.docker_overview`): every
value comes from a label on a managed machine, so only safe http(s)
links may come out."""

from __future__ import annotations

from typing import Any

import pytest

from app.services.container_links import image_links, is_hostname, safe_url, web_links
from app.services.docker_overview import row_state, state_counts


def _urls(container: dict[str, Any], address: str = "10.0.0.5") -> list[str]:
    return [link.url for link in web_links(container, address)]


def test_published_ports_become_links_on_the_machines_address():
    container = {
        "ports": "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 0.0.0.0:8443->443/tcp, 5432/tcp"
    }

    assert _urls(container) == ["http://10.0.0.5:8080", "https://10.0.0.5:8443"]


def test_loopback_udp_and_ranges_are_not_links():
    container = {
        "ports": "127.0.0.1:9000->9000/tcp, 0.0.0.0:53->53/udp, 0.0.0.0:7000-7002->7000-7002/tcp"
    }

    assert _urls(container) == []


def test_a_port_bound_to_one_address_links_there():
    container = {"ports": "192.168.1.9:3000->3000/tcp"}

    assert _urls(container) == ["http://192.168.1.9:3000"]


def test_ipv6_machine_address_is_bracketed():
    container = {"ports": "0.0.0.0:80->80/tcp"}

    assert _urls(container, "fd00::5") == ["http://[fd00::5]:80"]


def test_https_label_and_hide_ports_label():
    https = {"ports": "0.0.0.0:9443->9443/tcp", "link_labels": {"debcontrol.https": "9443"}}
    hidden = {"ports": "0.0.0.0:80->80/tcp", "link_labels": {"debcontrol.hide-ports": "true"}}

    assert _urls(https) == ["https://10.0.0.5:9443"]
    assert _urls(hidden) == []


def test_traefik_router_hosts_come_first():
    container = {
        "ports": "0.0.0.0:8080->80/tcp",
        "link_labels": {
            "traefik.http.routers.app.rule": "Host(`app.example.com`) && PathPrefix(`/ui`)",
            "traefik.http.routers.app.tls.certresolver": "le",
            "traefik.http.routers.plain.rule": "Host(`a.lan`, `b.lan`)",
            "traefik.http.routers.plain.entrypoints": "web",
        },
    }

    assert _urls(container) == [
        "https://app.example.com/ui",
        "http://a.lan",
        "http://b.lan",
        "http://10.0.0.5:8080",
    ]


def test_traefik_disabled_and_bad_hosts_are_ignored():
    disabled = {
        "link_labels": {
            "traefik.enable": "false",
            "traefik.http.routers.app.rule": "Host(`app.example.com`)",
        }
    }
    bad = {"link_labels": {"traefik.http.routers.app.rule": "Host(`evil.com/@x`, `-bad.lan`)"}}

    assert _urls(disabled) == []
    assert _urls(bad) == []


def test_caddy_labels():
    container = {
        "link_labels": {
            "caddy": "photos.example.com, www.photos.example.com",
            "caddy_1": "http://intranet.lan",
            "caddy.reverse_proxy": "{{upstreams 80}}",
        }
    }

    assert _urls(container) == [
        "https://photos.example.com",
        "https://www.photos.example.com",
        "http://intranet.lan",
    ]


def test_debcontrol_url_label_replaces_everything_else():
    container = {
        "ports": "0.0.0.0:8080->80/tcp",
        "link_labels": {
            "debcontrol.url": "https://grafana.example.com/d/home, javascript:alert(1)",
            "traefik.http.routers.app.rule": "Host(`app.example.com`)",
        },
    }

    [link] = web_links(container, "10.0.0.5")
    assert link.url == "https://grafana.example.com/d/home"
    assert link.label == "grafana.example.com"
    assert link.kind == "custom"


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "data:text/html,x",
        "https://user:pass@example.com",
        "https://example.com:notaport",
        "https://exa mple.com",
        "//example.com",
        "https://" + "a" * 500 + ".com",
    ],
)
def test_unsafe_urls_are_refused(value):
    assert safe_url(value) is None


def test_hostname_check():
    assert is_hostname("app.example.com")
    assert is_hostname("localhost")
    assert not is_hostname("-x.com")
    assert not is_hostname("a_b.com")
    assert not is_hostname("a..b")
    assert not is_hostname("x" * 64 + ".com")


def test_image_links_for_registries_and_source():
    assert image_links("postgres:18").registry_url == "https://hub.docker.com/_/postgres"
    assert image_links("grafana/grafana:11").registry_url == (
        "https://hub.docker.com/r/grafana/grafana"
    )
    assert image_links("ghcr.io/immich-app/immich-server:release").registry_url == (
        "https://ghcr.io/immich-app/immich-server"
    )
    assert image_links("quay.io/prometheus/node-exporter").registry_url == (
        "https://quay.io/repository/prometheus/node-exporter"
    )
    assert image_links("registry.lan/app:1").registry_url is None
    assert image_links("debcontrol:local").registry_url == "https://hub.docker.com/_/debcontrol"

    links = image_links(
        "nginx:1.27",
        {"link_labels": {"org.opencontainers.image.source": "https://github.com/nginx/docker-nginx.git"}},
    )
    assert links.source_url == "https://github.com/nginx/docker-nginx"
    assert links.releases_url == "https://github.com/nginx/docker-nginx/releases"


def test_image_source_on_another_host_has_no_release_link_and_http_is_dropped():
    other = image_links("x:1", {"link_labels": {"org.opencontainers.image.source": "https://git.lan/a/b"}})
    plain = image_links("x:1", {"link_labels": {"org.opencontainers.image.source": "http://github.com/a/b"}})

    assert (other.source_url, other.releases_url) == ("https://git.lan/a/b", None)
    assert (plain.source_url, plain.releases_url) == (None, None)


def test_row_state_and_counts():
    containers = [
        {"state": "running", "health": "healthy"},
        {"state": "running", "health": "unhealthy"},
        {"state": "exited"},
        {"state": "dead"},
        {"state": "paused"},
        {"state": "restarting"},
        {"state": "created"},
    ]

    assert [row_state(c) for c in containers] == [
        "running",
        "unhealthy",
        "exited",
        "exited",
        "paused",
        "restarting",
        "created",
    ]
    assert state_counts(containers) == {
        "running": 1,
        "unhealthy": 1,
        "restarting": 1,
        "paused": 1,
        "exited": 2,
        "created": 1,
    }
