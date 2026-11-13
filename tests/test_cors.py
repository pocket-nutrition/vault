from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ORIGIN = "https://me.example.org"


def make(cors_origins: str) -> TestClient:
    return TestClient(create_app(Settings(database_url="sqlite:///:memory:", cors_origins=cors_origins)))


def preflight(client: TestClient, origin: str):
    return client.options(
        "/v1/login",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )


def test_a_listed_origin_may_call_the_api():
    resp = preflight(make(ORIGIN), ORIGIN)
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == ORIGIN
    assert "access-control-allow-credentials" not in resp.headers


def test_another_origin_is_not_allowed():
    resp = preflight(make(ORIGIN), "https://evil.example")
    assert "access-control-allow-origin" not in resp.headers


def test_no_cors_at_all_by_default():
    resp = preflight(make(""), ORIGIN)
    assert "access-control-allow-origin" not in resp.headers


def test_a_lockout_wait_is_readable_by_the_page():
    client = make(ORIGIN)
    for _ in range(6):
        resp = client.post(
            "/v1/login",
            json={"username": "nobody-here", "auth_hash": "A" * 43 + "=", "device_label": "web"},
            headers={"Origin": ORIGIN},
        )
    assert resp.status_code == 429
    assert int(resp.headers["retry-after"]) > 0
    assert "retry-after" in resp.headers["access-control-expose-headers"].lower()
