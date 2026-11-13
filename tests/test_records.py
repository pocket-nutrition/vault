from fastapi.testclient import TestClient

from tests.conftest import b64, record_body


def test_create_then_update_advances_revision_and_seq(client: TestClient, owner):
    first = client.put("/v1/records/r1", json=record_body(1), headers=owner)
    second = client.put("/v1/records/r1", json=record_body(2), headers=owner)
    assert first.status_code == second.status_code == 200
    assert second.json()["revision"] == 2
    assert second.json()["seq"] > first.json()["seq"]


def test_stale_revision_conflicts(client: TestClient, owner):
    client.put("/v1/records/r1", json=record_body(1), headers=owner)
    client.put("/v1/records/r1", json=record_body(2), headers=owner)

    resp = client.put("/v1/records/r1", json=record_body(2), headers=owner)
    assert resp.status_code == 409
    assert resp.json()["detail"] == {"error": "revision_conflict", "current_revision": 2}


def test_new_record_must_start_at_revision_one(client: TestClient, owner):
    assert client.put("/v1/records/r1", json=record_body(5), headers=owner).status_code == 409


def test_scope_cannot_change_after_creation(client: TestClient, owner):
    client.put("/v1/records/r1", json=record_body(1, scope_id="meals"), headers=owner)
    resp = client.put("/v1/records/r1", json=record_body(2, scope_id=None), headers=owner)
    assert resp.status_code == 409
    assert resp.json()["detail"] == {"error": "scope_immutable"}


def test_rejects_malformed_payloads(client: TestClient, owner):
    assert client.put("/v1/records/r1", json=record_body(ciphertext="not base64!"), headers=owner).status_code == 422
    assert client.put("/v1/records/r1", json=record_body(ciphertext=b64(8)), headers=owner).status_code == 422
    assert client.put("/v1/records/bad id", json=record_body(), headers=owner).status_code == 422
    assert client.put("/v1/records/r1", json=record_body(type="Meal!"), headers=owner).status_code == 422


def test_rejects_oversized_record(client: TestClient, owner):
    assert client.put("/v1/records/r1", json=record_body(ciphertext=b64(2048)), headers=owner).status_code == 413


def test_delete_leaves_a_tombstone_in_sync(client: TestClient, owner):
    client.put("/v1/records/r1", json=record_body(1), headers=owner)
    deleted = client.delete("/v1/records/r1?revision=2", headers=owner)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert deleted.json()["ciphertext"] == ""

    records = client.get("/v1/sync", headers=owner).json()["records"]
    assert [(r["id"], r["deleted"]) for r in records] == [("r1", True)]


def test_delete_unknown_record_is_404(client: TestClient, owner):
    assert client.delete("/v1/records/nope?revision=1", headers=owner).status_code == 404


def test_recreating_a_deleted_record_resurrects_it(client: TestClient, owner):
    client.put("/v1/records/r1", json=record_body(1), headers=owner)
    client.delete("/v1/records/r1?revision=2", headers=owner)
    resp = client.put("/v1/records/r1", json=record_body(3), headers=owner)
    assert resp.status_code == 200
    assert resp.json()["deleted"] is False


def test_sync_paginates_by_cursor(client: TestClient, owner):
    for i in range(5):
        client.put(f"/v1/records/r{i}", json=record_body(1), headers=owner)

    page1 = client.get("/v1/sync?limit=2", headers=owner).json()
    assert len(page1["records"]) == 2 and page1["has_more"] is True

    page2 = client.get(f"/v1/sync?limit=2&since={page1['cursor']}", headers=owner).json()
    page3 = client.get(f"/v1/sync?limit=2&since={page2['cursor']}", headers=owner).json()
    ids = [r["id"] for p in (page1, page2, page3) for r in p["records"]]
    assert ids == [f"r{i}" for i in range(5)]
    assert page3["has_more"] is False

    empty = client.get(f"/v1/sync?since={page3['cursor']}", headers=owner).json()
    assert empty == {"records": [], "cursor": page3["cursor"], "has_more": False}


def test_updated_record_reappears_after_cursor(client: TestClient, owner):
    client.put("/v1/records/r1", json=record_body(1), headers=owner)
    cursor = client.get("/v1/sync", headers=owner).json()["cursor"]
    client.put("/v1/records/r1", json=record_body(2), headers=owner)
    records = client.get(f"/v1/sync?since={cursor}", headers=owner).json()["records"]
    assert [r["revision"] for r in records] == [2]


def test_keyring_compare_and_swap(client: TestClient, owner):
    assert client.get("/v1/keyring", headers=owner).json() == {"blob": None, "version": 0}

    ok = client.put("/v1/keyring", json={"blob": "{}", "base_version": 0}, headers=owner)
    assert ok.json() == {"blob": "{}", "version": 1}

    stale = client.put("/v1/keyring", json={"blob": "{\"x\":1}", "base_version": 0}, headers=owner)
    assert stale.status_code == 409
