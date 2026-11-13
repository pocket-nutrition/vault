from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import ADMIN_TOKEN, auth


def test_missing_key_is_rejected(client: TestClient):
    assert client.get("/v1/me").status_code == 401


def test_unknown_key_is_rejected(client: TestClient):
    assert client.get("/v1/me", headers=auth("pnv_nope")).status_code == 401


def test_owner_identity(client: TestClient, owner):
    body = client.get("/v1/me", headers=owner).json()
    assert body["role"] == "owner"
    assert body["scope_id"] is None


def test_admin_creation_requires_token(client: TestClient):
    assert client.post("/admin/accounts").status_code == 401
    assert client.post("/admin/accounts", headers=auth("wrong")).status_code == 401


def test_admin_creation_disabled_without_token():
    app = create_app(Settings(database_url="sqlite:///:memory:", admin_token=""))
    resp = TestClient(app).post("/admin/accounts", headers=auth(""))
    assert resp.status_code == 503


def test_accounts_are_isolated(client: TestClient, owner):
    other = auth(client.post("/admin/accounts", headers=auth(ADMIN_TOKEN)).json()["api_key"])
    from tests.conftest import record_body

    client.put("/v1/records/r1", json=record_body(), headers=owner)
    assert client.get("/v1/sync", headers=other).json()["records"] == []


def test_device_key_lifecycle(client: TestClient, owner):
    created = client.post("/v1/keys", json={"label": "ipad"}, headers=owner).json()
    device = auth(created["api_key"])
    assert client.get("/v1/me", headers=device).status_code == 200

    assert client.delete(f"/v1/keys/{created['id']}", headers=owner).status_code == 204
    assert client.get("/v1/me", headers=device).status_code == 401
    assert client.get("/v1/me", headers=owner).status_code == 200
