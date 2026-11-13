from fastapi.testclient import TestClient

from tests.conftest import auth, b64, record_body


def _grant(client: TestClient, owner, scope_id: str = "meals") -> tuple[dict, dict[str, str]]:
    body = {
        "scope_id": scope_id,
        "label": "home-assistant",
        "recipient_public_key": b64(32),
        "wrapped_scope_key": b64(80),
    }
    resp = client.post("/v1/grants", json=body, headers=owner)
    assert resp.status_code == 201
    return body, auth(resp.json()["api_key"])


def test_reader_sees_only_its_scope(client: TestClient, owner):
    client.put("/v1/records/private", json=record_body(1), headers=owner)
    client.put("/v1/records/meal-1", json=record_body(1, scope_id="meals"), headers=owner)
    client.put("/v1/records/weight-1", json=record_body(1, scope_id="weight"), headers=owner)
    _, reader = _grant(client, owner, "meals")

    records = client.get("/v1/sync", headers=reader).json()["records"]
    assert [r["id"] for r in records] == ["meal-1"]


def test_reader_receives_its_wrapped_key(client: TestClient, owner):
    body, reader = _grant(client, owner)
    me = client.get("/v1/grants/me", headers=reader).json()
    assert me["scope_id"] == "meals"
    assert me["wrapped_scope_key"] == body["wrapped_scope_key"]
    assert me["recipient_public_key"] == body["recipient_public_key"]


def test_reader_is_read_only(client: TestClient, owner):
    _, reader = _grant(client, owner)
    assert client.put("/v1/records/x", json=record_body(1, "meals"), headers=reader).status_code == 403
    assert client.delete("/v1/records/x?revision=1", headers=reader).status_code == 403
    assert client.get("/v1/keyring", headers=reader).status_code == 403
    assert client.get("/v1/grants", headers=reader).status_code == 403
    assert client.post("/v1/keys", json={"label": "x"}, headers=reader).status_code == 403


def test_owner_cannot_use_grants_me(client: TestClient, owner):
    assert client.get("/v1/grants/me", headers=owner).status_code == 403


def test_reader_sees_tombstones_in_scope(client: TestClient, owner):
    client.put("/v1/records/m1", json=record_body(1, scope_id="meals"), headers=owner)
    _, reader = _grant(client, owner)
    client.delete("/v1/records/m1?revision=2", headers=owner)
    records = client.get("/v1/sync", headers=reader).json()["records"]
    assert [(r["id"], r["deleted"]) for r in records] == [("m1", True)]


def test_revoked_grant_stops_working(client: TestClient, owner):
    _, reader = _grant(client, owner)
    grant_id = client.get("/v1/grants", headers=owner).json()[0]["id"]

    assert client.delete(f"/v1/grants/{grant_id}", headers=owner).status_code == 204
    assert client.get("/v1/sync", headers=reader).status_code == 401
    assert client.get("/v1/grants", headers=owner).json()[0]["revoked_at"] is not None


def test_grant_listing_never_exposes_secrets(client: TestClient, owner):
    _grant(client, owner)
    listed = client.get("/v1/grants", headers=owner).json()[0]
    assert "wrapped_scope_key" not in listed and "api_key" not in listed


def test_cannot_revoke_another_accounts_grant(client: TestClient, owner):
    from tests.conftest import ADMIN_TOKEN

    _grant(client, owner)
    grant_id = client.get("/v1/grants", headers=owner).json()[0]["id"]
    other = auth(client.post("/admin/accounts", headers=auth(ADMIN_TOKEN)).json()["api_key"])
    assert client.delete(f"/v1/grants/{grant_id}", headers=other).status_code == 404
