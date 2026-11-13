import base64
import os

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ADMIN_TOKEN = "test-admin-token"


def b64(size: int = 64) -> str:
    return base64.b64encode(os.urandom(size)).decode()


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture
def client() -> TestClient:
    settings = Settings(database_url="sqlite:///:memory:", admin_token=ADMIN_TOKEN, max_record_bytes=1024)
    return TestClient(create_app(settings))


@pytest.fixture
def owner(client: TestClient) -> dict[str, str]:
    resp = client.post("/admin/accounts", headers=auth(ADMIN_TOKEN))
    assert resp.status_code == 201
    return auth(resp.json()["api_key"])


def record_body(revision: int = 1, scope_id: str | None = None, **overrides) -> dict:
    body = {"type": "meal", "scope_id": scope_id, "revision": revision, "key_id": "user", "ciphertext": b64()}
    return {**body, **overrides}
