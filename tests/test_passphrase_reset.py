import base64

from fastapi.testclient import TestClient

from tests.conftest import auth
from tests.test_accounts import AUTH_HASH, kdf, login, make_client, register
from tests.test_two_factor import code_for, enabled_account, _frozen_clock  # noqa: F401  (autouse fixture)

NEW_HASH = base64.b64encode(b"n" * 32).decode()


def reset(client: TestClient, key: dict, **overrides):
    body = {"new_auth_hash": NEW_HASH, "kdf": kdf(), "keyring": '{"v":1,"reset":true}', "base_version": 1, **overrides}
    return client.post("/v1/account/passphrase/reset", json=body, headers=key)


def fresh() -> TestClient:
    return make_client(login_per_10min_per_ip=100, two_factor_per_10min_per_ip=100)


def test_a_linked_device_replaces_a_forgotten_passphrase_without_the_old_one():
    client = fresh()
    phone = auth(register(client).json()["api_key"])
    tablet = auth(login(client, label="tablet").json()["api_key"])
    new_kdf = kdf()

    resp = reset(client, phone, kdf=new_kdf)

    assert resp.status_code == 200 and resp.json() == {"version": 2, "revoked_devices": 1}
    assert login(client).status_code == 401  # the forgotten passphrase is dead
    session = login(client, auth_hash=NEW_HASH).json()
    assert session["keyring"] == {"blob": '{"v":1,"reset":true}', "version": 2}
    assert client.post("/v1/accounts/prelogin", json={"username": "alice"}).json() == new_kdf
    assert client.get("/v1/me", headers=phone).status_code == 200
    assert client.get("/v1/me", headers=tablet).status_code == 401  # holds the old KDF: must log in again


def test_reset_needs_a_linked_owner_device():
    client = fresh()
    register(client)
    assert client.post("/v1/account/passphrase/reset", json={}).status_code in (401, 403, 422)
    assert reset(client, auth("not-a-real-key")).status_code == 401


def test_reset_still_requires_two_factor_when_it_is_on(_frozen_clock):
    client = fresh()
    key, secret, codes = enabled_account(client)

    missing = reset(client, key)
    assert missing.status_code == 401 and missing.json()["detail"]["error"] == "two_factor_required"
    wrong = reset(client, key, totp_code="000000")
    assert wrong.status_code == 401 and wrong.json()["detail"]["error"] == "invalid_two_factor"

    _frozen_clock["t"] += 30  # the enabling code's step is spent: replays are refused
    assert reset(client, key, totp_code=code_for(secret, _frozen_clock["t"])).status_code == 200
    assert login(client, auth_hash=NEW_HASH).status_code == 401  # 2FA still on for logins
    assert client.post(
        "/v1/login", json={"username": "alice", "auth_hash": NEW_HASH, "device_label": "x", "recovery_code": codes[0]}
    ).status_code == 200


def test_wrong_codes_count_toward_the_lockout():
    client = make_client(login_per_10min_per_ip=100, two_factor_per_10min_per_ip=100, login_max_failures=3)
    key, _, _ = enabled_account(client)
    for _ in range(3):
        reset(client, key, totp_code="000000")
    assert reset(client, key, totp_code="000000").status_code == 429


def test_a_stale_keyring_version_is_a_conflict():
    client = fresh()
    key = auth(register(client).json()["api_key"])
    resp = reset(client, key, base_version=7)
    assert resp.status_code == 409 and resp.json()["detail"] == {"error": "keyring_conflict", "current_version": 1}
