import base64
import os

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import ADMIN_TOKEN, auth, b64, record_body

AUTH_HASH = base64.b64encode(b"a" * 32).decode()
OTHER_HASH = base64.b64encode(b"b" * 32).decode()


def kdf(**overrides) -> dict:
    return {"alg": "argon2id", "salt": b64(16), "opslimit": 3, "memlimit": 64 * 1024 * 1024, **overrides}


def register(client: TestClient, username: str = "alice", auth_hash: str = AUTH_HASH, **overrides):
    body = {
        "username": username,
        "kdf": kdf(),
        "auth_hash": auth_hash,
        "keyring": '{"v":1}',
        "device_label": "iphone",
        **overrides,
    }
    return client.post("/v1/accounts", json=body)


def login(client: TestClient, username: str = "alice", auth_hash: str = AUTH_HASH, label: str = "ipad"):
    return client.post("/v1/login", json={"username": username, "auth_hash": auth_hash, "device_label": label})


def make_client(**settings) -> TestClient:
    base = {"database_url": "sqlite:///:memory:", "admin_token": ADMIN_TOKEN}
    return TestClient(create_app(Settings(**{**base, **settings})))


def test_server_info_is_public_and_advertises_registration(client: TestClient):
    info = client.get("/v1/server-info").json()
    assert info["registration"] == "open"
    assert info["kdf_defaults"]["alg"] == "argon2id"


def test_register_returns_a_working_device_key_and_the_keyring(client: TestClient):
    resp = register(client)
    assert resp.status_code == 201
    session = resp.json()
    assert session["keyring"] == {"blob": '{"v":1}', "version": 1}
    assert client.get("/v1/me", headers=auth(session["api_key"])).json()["role"] == "owner"


def test_login_on_a_second_device_gets_its_own_key_and_the_same_keyring(client: TestClient):
    first = register(client).json()
    second = login(client).json()
    assert second["api_key"] != first["api_key"] and second["account_id"] == first["account_id"]
    assert second["keyring"] == first["keyring"]

    labels = [k["label"] for k in client.get("/v1/keys", headers=auth(second["api_key"])).json()]
    assert sorted(labels) == ["ipad", "iphone"]


def test_usernames_are_case_insensitive_and_unique(client: TestClient):
    assert register(client, "Alice").status_code == 201
    assert register(client, "alice").status_code == 409
    assert login(client, "ALICE").status_code == 200


@pytest.mark.parametrize("username", ["ab", "has space", "-leading", "x" * 65, "a@b.c"])
def test_rejects_bad_usernames(client: TestClient, username):
    assert register(client, username).status_code == 422


@pytest.mark.parametrize(
    "bad_kdf",
    [
        kdf(opslimit=1),
        kdf(memlimit=1024),
        kdf(memlimit=4 * 1024**3),
        kdf(alg="pbkdf2"),
        kdf(salt=b64(8)),
    ],
)
def test_rejects_weak_or_malformed_kdf_settings(client: TestClient, bad_kdf):
    assert register(client, kdf=bad_kdf).status_code == 422


def test_rejects_malformed_auth_hash(client: TestClient):
    assert register(client, auth_hash=b64(8)).status_code == 422


def test_wrong_password_is_rejected_without_saying_why(client: TestClient):
    register(client)
    wrong = login(client, auth_hash=OTHER_HASH)
    unknown = login(client, "nobody")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_prelogin_returns_the_registered_kdf(client: TestClient):
    settings = kdf()
    register(client, kdf=settings)
    assert client.post("/v1/accounts/prelogin", json={"username": "alice"}).json() == settings


def test_prelogin_for_unknown_users_is_stable_and_looks_real(client: TestClient):
    first = client.post("/v1/accounts/prelogin", json={"username": "ghost"}).json()
    again = client.post("/v1/accounts/prelogin", json={"username": "ghost"}).json()
    other = client.post("/v1/accounts/prelogin", json={"username": "phantom"}).json()
    assert first == again and first["salt"] != other["salt"] and first["alg"] == "argon2id"


def test_account_locks_after_repeated_failures_even_with_the_right_password():
    client = make_client(login_max_failures=3, login_per_10min_per_ip=100)
    register(client)
    for _ in range(3):
        assert login(client, auth_hash=OTHER_HASH).status_code == 401

    locked = login(client)
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0


def test_lock_expires():
    client = make_client(login_max_failures=1, login_lock_s=60, login_per_10min_per_ip=100)
    register(client)
    login(client, auth_hash=OTHER_HASH)
    assert login(client).status_code == 429

    from datetime import timedelta

    from app.models import Account, utcnow

    with client.app.state.session_factory() as db:
        db.query(Account).one().locked_until = utcnow() - timedelta(seconds=1)
        db.commit()
    assert login(client).status_code == 200


def test_successful_login_resets_the_failure_counter():
    client = make_client(login_max_failures=3, login_per_10min_per_ip=100)
    register(client)
    login(client, auth_hash=OTHER_HASH)
    login(client, auth_hash=OTHER_HASH)
    assert login(client).status_code == 200
    login(client, auth_hash=OTHER_HASH)
    login(client, auth_hash=OTHER_HASH)
    assert login(client).status_code == 200


def test_registration_is_rate_limited_per_ip():
    client = make_client(register_per_hour_per_ip=2)
    assert register(client, "user-one").status_code == 201
    assert register(client, "user-two").status_code == 201
    limited = register(client, "user-three")
    assert limited.status_code == 429 and "retry-after" in limited.headers


def test_rate_limit_keys_on_the_forwarded_client_not_the_proxy():
    client = make_client(register_per_hour_per_ip=1, trusted_proxy_hops=1)
    body = lambda name: {  # noqa: E731
        "username": name, "kdf": kdf(), "auth_hash": AUTH_HASH, "keyring": "{}", "device_label": "d",
    }
    # XFF is "<client>, <proxy-appended>": the client is the second to last entry.
    assert client.post("/v1/accounts", json=body("aaa"), headers={"X-Forwarded-For": "1.1.1.1, 9.9.9.9"}).status_code == 201
    assert client.post("/v1/accounts", json=body("bbb"), headers={"X-Forwarded-For": "2.2.2.2, 9.9.9.9"}).status_code == 201
    assert client.post("/v1/accounts", json=body("ccc"), headers={"X-Forwarded-For": "1.1.1.1, 9.9.9.9"}).status_code == 429


def test_spoofed_forwarded_prefix_does_not_dodge_the_limit():
    client = make_client(register_per_hour_per_ip=1, trusted_proxy_hops=1)
    body = lambda name: {  # noqa: E731
        "username": name, "kdf": kdf(), "auth_hash": AUTH_HASH, "keyring": "{}", "device_label": "d",
    }
    client.post("/v1/accounts", json=body("aaa"), headers={"X-Forwarded-For": "1.1.1.1, 9.9.9.9"})
    # The attacker prepends fake entries; only the last trusted hop counts.
    spoof = {"X-Forwarded-For": "6.6.6.6, 1.1.1.1, 9.9.9.9"}
    assert client.post("/v1/accounts", json=body("bbb"), headers=spoof).status_code == 429


def test_registration_can_be_closed():
    client = make_client(registration="closed")
    assert client.get("/v1/server-info").json()["registration"] == "closed"
    assert register(client).status_code == 403


def test_logout_revokes_only_this_device(client: TestClient):
    phone = register(client).json()["api_key"]
    tablet = login(client).json()["api_key"]
    assert client.post("/v1/logout", headers=auth(tablet)).status_code == 204
    assert client.get("/v1/me", headers=auth(tablet)).status_code == 401
    assert client.get("/v1/me", headers=auth(phone)).status_code == 200


def test_delete_account_requires_the_password_and_erases_everything(client: TestClient):
    key = auth(register(client).json()["api_key"])
    client.put("/v1/records/r1", json=record_body(1), headers=key)

    assert client.request("DELETE", "/v1/account", json={}, headers=key).status_code == 401
    assert client.request("DELETE", "/v1/account", json={"auth_hash": OTHER_HASH}, headers=key).status_code == 401
    assert client.request("DELETE", "/v1/account", json={"auth_hash": AUTH_HASH}, headers=key).status_code == 204

    assert client.get("/v1/me", headers=key).status_code == 401
    assert login(client).status_code == 401
    assert register(client).status_code == 201  # the username is free again

    from app.models import Record

    with client.app.state.session_factory() as db:
        assert db.query(Record).count() == 0


def test_deleting_one_account_leaves_others_alone(client: TestClient):
    mine = auth(register(client, "alice").json()["api_key"])
    other = auth(register(client, "bobby", OTHER_HASH).json()["api_key"])
    client.put("/v1/records/r1", json=record_body(1), headers=other)
    client.request("DELETE", "/v1/account", json={"auth_hash": AUTH_HASH}, headers=mine)
    assert len(client.get("/v1/sync", headers=other).json()["records"]) == 1


def test_admin_created_accounts_can_delete_with_their_key_alone(client: TestClient, owner):
    assert client.request("DELETE", "/v1/account", json={}, headers=owner).status_code == 204


def test_quota_blocks_writes_beyond_the_limit_but_allows_shrinking():
    client = make_client(quota_bytes=4000, max_record_bytes=1024)
    key = auth(register(client).json()["api_key"])
    big = lambda rev: record_body(rev, ciphertext=b64(1000))  # noqa: E731  (~1336 chars each)

    assert client.put("/v1/records/a", json=big(1), headers=key).status_code == 200
    assert client.put("/v1/records/b", json=big(1), headers=key).status_code == 200
    over = client.put("/v1/records/c", json=big(1), headers=key)
    assert over.status_code == 413 and over.json()["detail"] == {"error": "quota_exceeded"}

    # Replacing a record with a smaller one frees space, and deleting is always allowed.
    assert client.put("/v1/records/a", json=record_body(2), headers=key).status_code == 200
    assert client.delete("/v1/records/b?revision=2", headers=key).status_code == 200
    assert client.put("/v1/records/c", json=big(1), headers=key).status_code == 200


def test_quota_applies_to_drops_too():
    from tests.test_drops import _mint

    client = make_client(quota_bytes=200, max_record_bytes=1024)
    key = auth(register(client).json()["api_key"])
    dropper = _mint(client, key)
    resp = client.put("/v1/drop", json={"ciphertext": b64(300)}, headers=dropper)
    assert resp.status_code == 413
