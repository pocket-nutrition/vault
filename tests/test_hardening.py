import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import accounts, ratelimit
from app.accounts import _ArgonSlots, configure_argon
from app.models import Drop, Record, utcnow
from app.ratelimit import RateLimiter, UnknownLoginGuard
from tests.conftest import ADMIN_TOKEN, auth, b64, record_body
from tests.test_accounts import OTHER_HASH, kdf, login, make_client, register


@pytest.fixture(autouse=True)
def _restore_argon_slots():
    yield
    configure_argon(2, 5)


# --- Argon2 concurrency ------------------------------------------------------


def test_argon_slots_reject_when_saturated_instead_of_queueing_forever():
    slots = _ArgonSlots()
    slots.configure(concurrency=1, wait_s=0.05)
    holding, release = threading.Event(), threading.Event()

    def occupy():
        holding.set()
        release.wait(2)

    blocker = slots._pool.submit(occupy)  # takes the only worker
    assert holding.wait(2)
    try:
        with pytest.raises(Exception) as busy:
            slots.run(lambda: None)
        assert getattr(busy.value, "status_code", None) == 503
        assert busy.value.headers == {"Retry-After": "5"}
    finally:
        release.set()
        blocker.result(timeout=2)
    assert slots.run(lambda: "free again") == "free again"


def test_hashing_always_runs_on_the_same_few_threads():
    """The reason for the pool: a burst must not spread hashes over many threads, each of which would
    keep its own retained allocation (that was the production out-of-memory kill)."""
    slots = _ArgonSlots()
    slots.configure(concurrency=2, wait_s=5)
    names = {slots.run(lambda: threading.current_thread().name) for _ in range(40)}
    assert len(names) <= 2 and all(name.startswith("argon") for name in names)


def test_saturated_server_answers_503_not_a_crash():
    client = make_client()
    register(client)
    configure_argon(1, 0.05)
    holding, release = threading.Event(), threading.Event()

    def occupy():
        holding.set()
        release.wait(2)

    blocker = accounts._slots._pool.submit(occupy)
    assert holding.wait(2)
    try:
        resp = login(client)
        assert resp.status_code == 503
        assert resp.headers["retry-after"] == "5"
    finally:
        release.set()
        blocker.result(timeout=2)


# --- Lockout -----------------------------------------------------------------


def test_unknown_usernames_lock_exactly_like_real_ones():
    client = make_client(login_max_failures=3, login_per_10min_per_ip=100)
    for _ in range(3):
        assert login(client, "ghost-user", OTHER_HASH).status_code == 401
    locked = login(client, "ghost-user", OTHER_HASH)
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0

    register(client, "real-user")
    for _ in range(3):
        login(client, "real-user", OTHER_HASH)
    real = login(client, "real-user")
    # Same status and body: the response no longer tells a registered username from an unknown one.
    assert real.status_code == locked.status_code == 429
    assert real.json() == locked.json()


def test_unknown_login_guard_is_bounded(monkeypatch):
    monkeypatch.setattr(ratelimit, "_MAX_TRACKED_KEYS", 50)
    guard = UnknownLoginGuard()
    for i in range(500):
        guard.record_failure(f"name-{i}", 3, 60)
    assert len(guard._state) <= 50


def test_rate_limiter_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(ratelimit, "_MAX_TRACKED_KEYS", 50)
    limiter = RateLimiter()
    for i in range(500):
        limiter.check("login", f"10.0.{i // 250}.{i % 250}", 100, 600)
    assert len(limiter._hits) <= 50


# --- Request size ------------------------------------------------------------


def test_oversized_declared_body_is_refused_before_parsing():
    client = make_client(max_body_bytes=4096)
    resp = client.post("/v1/accounts", content=b"x" * 10_000, headers={"content-type": "application/json"})
    assert resp.status_code == 413
    assert resp.json()["detail"] == {"error": "body_too_large"}


def test_oversized_streamed_body_without_content_length_is_refused():
    client = make_client(max_body_bytes=4096)

    def chunks():
        for _ in range(20):
            yield b"x" * 1024

    resp = client.post("/v1/accounts", content=chunks(), headers={"content-type": "application/json"})
    assert resp.status_code in (400, 413)


def test_normal_requests_still_pass_the_body_limit():
    assert register(make_client(max_body_bytes=8192)).status_code == 201


def test_absurd_field_lengths_are_rejected_by_the_schema(client: TestClient, owner):
    assert client.put("/v1/keyring", json={"blob": "x" * 40_000, "base_version": 0}, headers=owner).status_code == 422


# --- KDF floor ---------------------------------------------------------------


@pytest.mark.parametrize("weak", [kdf(opslimit=2), kdf(memlimit=32 * 1024 * 1024)])
def test_registration_requires_the_apps_default_cost_or_more(client: TestClient, weak):
    assert register(client, kdf=weak).status_code == 422


# --- Storage growth ----------------------------------------------------------


def test_tombstones_keep_costing_quota_so_churn_cannot_grow_the_table_for_free():
    client = make_client(quota_bytes=2000, row_overhead_bytes=256, max_record_bytes=1024)
    key = auth(register(client).json()["api_key"])
    small = lambda rev: record_body(rev, ciphertext=b64(48))  # noqa: E731
    created = 0
    for i in range(20):
        if client.put(f"/v1/records/r{i}", json=small(1), headers=key).status_code != 200:
            break
        client.delete(f"/v1/records/r{i}?revision=2", headers=key)
        created += 1
    assert 1 <= created < 20, "churn must eventually hit the quota"
    assert client.put("/v1/records/one-more", json=small(1), headers=key).status_code == 413


def test_old_tombstones_are_purged_when_records_are_deleted():
    client = make_client(tombstone_retention_days=30)
    key = auth(register(client).json()["api_key"])
    client.put("/v1/records/old", json=record_body(1), headers=key)
    client.delete("/v1/records/old?revision=2", headers=key)
    with client.app.state.session_factory() as db:
        db.query(Record).filter(Record.id == "old").one().updated_at = utcnow() - timedelta(days=31)
        db.commit()

    client.put("/v1/records/other", json=record_body(1), headers=key)
    client.delete("/v1/records/other?revision=2", headers=key)

    with client.app.state.session_factory() as db:
        assert {r.id for r in db.query(Record)} == {"other"}


def test_a_recent_tombstone_is_kept_for_devices_that_have_not_synced_yet():
    client = make_client(tombstone_retention_days=30)
    key = auth(register(client).json()["api_key"])
    for name in ("a", "b"):
        client.put(f"/v1/records/{name}", json=record_body(1), headers=key)
        client.delete(f"/v1/records/{name}?revision=2", headers=key)
    ids = [r["id"] for r in client.get("/v1/sync", headers=key).json()["records"]]
    assert sorted(ids) == ["a", "b"]


# --- Caps --------------------------------------------------------------------


def test_device_cap_applies_to_login_and_to_extra_keys():
    client = make_client(max_devices=2, login_per_10min_per_ip=100)
    first = auth(register(client).json()["api_key"])
    assert login(client).status_code == 200
    capped = login(client)
    assert capped.status_code == 409 and capped.json()["detail"] == {"error": "too_many_devices"}
    assert client.post("/v1/keys", json={"label": "x"}, headers=first).status_code == 409

    keys = client.get("/v1/keys", headers=first).json()
    client.delete(f"/v1/keys/{keys[1]['id']}", headers=first)
    assert login(client).status_code == 200


def test_grant_cap():
    client = make_client(max_grants=1)
    key = auth(register(client).json()["api_key"])
    body = {"scope_id": "meals", "label": "r", "recipient_public_key": b64(32), "wrapped_scope_key": b64(80)}
    assert client.post("/v1/grants", json=body, headers=key).status_code == 201
    assert client.post("/v1/grants", json=body, headers=key).status_code == 409


def test_pending_drops_are_capped_and_expired_ones_are_purged():
    client = make_client(max_pending_drops=2)
    key = auth(register(client).json()["api_key"])

    def mint(record_id: str):
        return client.post(
            "/v1/drops",
            json={"record_id": record_id, "type": "capture", "key_id": "inbox", "ttl_s": 60},
            headers=key,
        )

    assert mint("d1").status_code == 201 and mint("d2").status_code == 201
    assert mint("d3").status_code == 409

    with client.app.state.session_factory() as db:
        for drop in db.query(Drop):
            drop.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert mint("d3").status_code == 201
    with client.app.state.session_factory() as db:
        assert {d.record_id for d in db.query(Drop)} == {"d3"}


def test_revoking_a_drop_kills_its_token_at_once(client: TestClient, owner):
    minted = client.post(
        "/v1/drops", json={"record_id": "cap-1", "type": "capture", "key_id": "inbox"}, headers=owner
    ).json()
    token = auth(minted["token"])
    assert client.delete(f"/v1/drops/{minted['drop_id']}", headers=owner).status_code == 204
    assert client.put("/v1/drop", json={"ciphertext": b64(96)}, headers=token).status_code == 401


def test_a_drop_cannot_be_revoked_by_another_account_or_by_the_dropper(client: TestClient, owner):
    minted = client.post(
        "/v1/drops", json={"record_id": "cap-1", "type": "capture", "key_id": "inbox"}, headers=owner
    ).json()
    other = auth(client.post("/admin/accounts", headers=auth(ADMIN_TOKEN)).json()["api_key"])
    assert client.delete(f"/v1/drops/{minted['drop_id']}", headers=other).status_code == 404
    assert client.delete(f"/v1/drops/{minted['drop_id']}", headers=auth(minted["token"])).status_code == 403
