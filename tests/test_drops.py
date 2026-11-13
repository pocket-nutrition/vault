from datetime import timedelta

from fastapi.testclient import TestClient

from app.models import Drop, utcnow
from tests.conftest import auth, b64, record_body


def _mint(client: TestClient, owner, record_id: str = "capture-1", **overrides) -> dict[str, str]:
    body = {"record_id": record_id, "type": "capture", "key_id": "inbox", **overrides}
    resp = client.post("/v1/drops", json=body, headers=owner)
    assert resp.status_code == 201, resp.text
    return auth(resp.json()["token"])


def _drop(client: TestClient, dropper, size: int = 96):
    return client.put("/v1/drop", json={"ciphertext": b64(size)}, headers=dropper)


def test_dropped_record_reaches_the_owner_with_owner_chosen_labels(client: TestClient, owner):
    dropper = _mint(client, owner)
    resp = _drop(client, dropper)
    assert resp.status_code == 200 and resp.json() == {"remaining_writes": 0}

    (record,) = client.get("/v1/sync", headers=owner).json()["records"]
    assert (record["id"], record["type"], record["key_id"], record["revision"]) == ("capture-1", "capture", "inbox", 1)


def test_dropper_cannot_read_anything(client: TestClient, owner):
    client.put("/v1/records/secret", json=record_body(1), headers=owner)
    dropper = _mint(client, owner)

    assert client.get("/v1/sync", headers=dropper).status_code == 403
    assert client.get("/v1/keyring", headers=dropper).status_code == 403
    assert client.get("/v1/grants", headers=dropper).status_code == 403
    assert client.get("/v1/grants/me", headers=dropper).status_code == 403
    assert client.put("/v1/records/x", json=record_body(1), headers=dropper).status_code == 403
    assert client.post("/v1/drops", json={"record_id": "y", "type": "t", "key_id": "k"}, headers=dropper).status_code == 403


def test_owner_and_reader_cannot_use_the_drop_endpoint(client: TestClient, owner):
    assert _drop(client, owner).status_code == 403


def test_write_limit_is_enforced(client: TestClient, owner):
    dropper = _mint(client, owner, max_writes=2)
    assert _drop(client, dropper).json() == {"remaining_writes": 1}
    assert _drop(client, dropper).json() == {"remaining_writes": 0}
    assert _drop(client, dropper).status_code == 403

    (record,) = client.get("/v1/sync", headers=owner).json()["records"]
    assert record["revision"] == 2


def test_expired_token_is_rejected(client: TestClient, owner):
    dropper = _mint(client, owner)
    with client.app.state.session_factory() as db:
        drop = db.query(Drop).one()
        drop.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert _drop(client, dropper).status_code == 401


def test_ttl_bounds(client: TestClient, owner):
    body = {"record_id": "r", "type": "capture", "key_id": "inbox"}
    assert client.post("/v1/drops", json={**body, "ttl_s": 5}, headers=owner).status_code == 422
    assert client.post("/v1/drops", json={**body, "ttl_s": 8 * 24 * 3600}, headers=owner).status_code == 422
    assert client.post("/v1/drops", json={**body, "max_writes": 11}, headers=owner).status_code == 422


def test_cannot_mint_over_an_existing_record_or_drop(client: TestClient, owner):
    client.put("/v1/records/mine", json=record_body(1), headers=owner)
    existing = {"record_id": "mine", "type": "capture", "key_id": "inbox"}
    assert client.post("/v1/drops", json=existing, headers=owner).status_code == 409

    _mint(client, owner, "fresh")
    again = {"record_id": "fresh", "type": "capture", "key_id": "inbox"}
    assert client.post("/v1/drops", json=again, headers=owner).status_code == 409


def test_owner_takeover_locks_the_dropper_out(client: TestClient, owner):
    dropper = _mint(client, owner, max_writes=3)
    _drop(client, dropper)
    client.put("/v1/records/capture-1", json=record_body(2), headers=owner)

    resp = _drop(client, dropper)
    assert resp.status_code == 409
    assert resp.json()["detail"] == {"error": "record_not_droppable"}


def test_rejects_malformed_payloads(client: TestClient, owner):
    dropper = _mint(client, owner)
    assert _drop(client, dropper, size=10).status_code == 422
    assert client.put("/v1/drop", json={"ciphertext": "!!"}, headers=dropper).status_code == 422
    assert _drop(client, dropper, size=4096).status_code == 413


def test_drops_are_isolated_per_account(client: TestClient, owner):
    from tests.conftest import ADMIN_TOKEN

    other = auth(client.post("/admin/accounts", headers=auth(ADMIN_TOKEN)).json()["api_key"])
    dropper = _mint(client, owner)
    _drop(client, dropper)
    assert client.get("/v1/sync", headers=other).json()["records"] == []
