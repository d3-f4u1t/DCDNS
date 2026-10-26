"""Tests for the portal's gated DNS demonstration controls."""

from __future__ import annotations

from fastapi.testclient import TestClient

from dcdns.portal import create_app


class FakeResponse:
    status_code = 200
    text = "{}"

    def __init__(self, body: dict | None = None) -> None:
        self.body = body or {"ok": True, "paused": True}

    def json(self) -> dict:
        return self.body


class FakeHTTP:
    def __init__(self, calls: list) -> None:
        self.calls = calls

    def post(self, url, json, timeout):
        self.calls.append((url, json))
        return FakeResponse()

    def get(self, url, **kwargs):
        raise RuntimeError("not used in these tests")


def make_app(tmp_path, demo_controls: bool, http_client=None):
    return create_app(
        node_urls=["http://127.0.0.1:9"],
        identities_dir=str(tmp_path),
        demo_controls=demo_controls,
        node_apis={"n1": "http://127.0.0.1:9", "n2": "http://127.0.0.1:9"},
        dns_nodes={"n1": ("127.0.0.1", 9), "n2": ("127.0.0.1", 9)},
        http_client=http_client,
    )


def test_demo_controls_are_hidden_and_rejected_by_default(tmp_path):
    app = make_app(tmp_path, demo_controls=False)
    with TestClient(app) as client:
        response = client.post(
            "/demo/fault/pause",
            data={"node": "n1", "paused": "1"},
            follow_redirects=False,
        )
    assert response.status_code == 404


def test_demo_pause_route_calls_the_node_control(tmp_path):
    calls = []
    app = make_app(tmp_path, demo_controls=True, http_client=FakeHTTP(calls))
    with TestClient(app) as client:
        calls.clear()
        response = client.post(
            "/demo/fault/pause",
            data={"node": "n1,n2", "paused": "1", "q": "techfest.cs.test"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "ok=" in response.headers["location"]
    assert calls == [
        ("http://127.0.0.1:9/internal/dns/pause", {"paused": True}),
        ("http://127.0.0.1:9/internal/dns/pause", {"paused": True}),
    ]


def test_demo_reset_reports_unreachable_nodes(tmp_path):
    class FailingHTTP:
        def post(self, url, json, timeout):
            raise RuntimeError("node unreachable")

    app = make_app(tmp_path, demo_controls=True, http_client=FailingHTTP())
    with TestClient(app) as client:
        response = client.post(
            "/demo/fault/reset",
            data={"q": "techfest.cs.test"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    location = response.headers["location"]
    assert "err=" in location
    assert "reset+incomplete" in location or "reset%20incomplete" in location


def test_demo_reset_clears_override_and_pause_on_every_node(tmp_path):
    calls = []
    app = make_app(tmp_path, demo_controls=True, http_client=FakeHTTP(calls))
    with TestClient(app) as client:
        calls.clear()
        response = client.post(
            "/demo/fault/reset",
            data={"q": "techfest.cs.test"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "ok=" in response.headers["location"]
    assert {url for url, _payload in calls} == {
        "http://127.0.0.1:9/internal/chaos",
        "http://127.0.0.1:9/internal/dns/pause",
    }
    assert {tuple(sorted(payload.items())) for _url, payload in calls} == {
        (("clear", True),),
        (("paused", False),),
    }
