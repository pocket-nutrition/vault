import base64

from fastapi.testclient import TestClient

from tests.conftest import ADMIN_TOKEN, auth, b64
from tests.test_accounts import AUTH_HASH, OTHER_HASH, kdf, login, make_client, register

NEW_HASH = base64.b64encode(b"n" * 32).decode()


def change(client: TestClient, key: dict, **overrides):
    body = {
        "auth_hash": AUTH_HASH,
        "new_auth_hash": NEW_HASH,
        "kdf": kdf(),
        "keyring": '{"v":1,"rewrapped":true}',
        "base_version": 1,
        **overrides,
    }
    return client.post("/v1/account/passphrase", json=body, headers=key)


def fresh() -> TestClient:
    return make_client(login_per_10min_per_ip=100)


def test_change_swaps_credentials_keyring_and_kdf_atomically():
    client = fresh()
    key = auth(register(client).json()["api_key"])
    new_kdf = kdf()
    resp = change(client, key, kdf=new_kdf)
    assert resp.status_code == 200 and resp.json() == {"version": 2, "revoked_devices": 0}

    assert login(client).status_code == 401  # old passphrase is dead
    session = login(client, auth_hash=NEW_HASH).json()
    assert session["keyring"] == {"blob": '{"v":1,"rewrapped":true}', "version": 2}
    assert client.post("/v1/accounts/prelogin", json={"username": "alice"}).json() == new_kdf


def test_change_revokes_other_devices_but_not_the_caller_grants_or_drops():
    client = fresh()
    phone = auth(register(client).json()["api_key"])
    tablet = auth(login(client, label="tablet").json()["api_key"])
    laptop = auth(login(client, label="laptop").json()["api_key"])
    grant = client.post(
        "/v1/grants",
        json={"scope_id": "meals", "label": "coach", "recipient_public_key": b64(32), "wrapped_scope_key": b64(80)},
        headers=phone,
    ).json()
    drop = client.post("/v1/drops", json={"record_id": "cap-1", "type": "capture", "key_id": "inbox"}, headers=phone)
    client.post("/v1/logout", headers=laptop)  # already revoked: not counted again

    resp = change(client, phone)
    assert resp.json() == {"version": 2, "revoked_devices": 1}
    assert client.get("/v1/me", headers=phone).status_code == 200
    assert client.get("/v1/me", headers=tablet).status_code == 401
    assert client.get("/v1/me", headers=auth(grant["api_key"])).json()["role"] == "reader"
    assert client.put("/v1/drop", json={"ciphertext": b64(96)}, headers=auth(drop.json()["token"])).status_code == 200


def test_wrong_current_passphrase_is_401_and_counts_toward_the_lockout():
    client = make_client(login_max_failures=2, login_per_10min_per_ip=100)
    key = auth(register(client).json()["api_key"])
    first = change(client, key, auth_hash=OTHER_HASH)
    assert first.status_code == 401 and first.json()["detail"] == {"error": "invalid_credentials"}
    change(client, key, auth_hash=OTHER_HASH)

    locked = change(client, key)
    assert locked.status_code == 429 and locked.json()["detail"] == {"error": "account_locked"}
    assert int(locked.headers["retry-after"]) > 0
    assert login(client).status_code == 429


def test_stale_base_version_is_a_keyring_conflict():
    client = fresh()
    key = auth(register(client).json()["api_key"])
    client.put("/v1/keyring", json={"blob": "{}", "base_version": 1}, headers=key)
    resp = change(client, key, base_version=1)
    assert resp.status_code == 409
    assert resp.json()["detail"] == {"error": "keyring_conflict", "current_version": 2}
    assert login(client).status_code == 200  # nothing changed


def test_accounts_without_a_passphrase_cannot_change_it(client: TestClient):
    owner = auth(client.post("/admin/accounts", headers=auth(ADMIN_TOKEN)).json()["api_key"])
    resp = change(client, owner, base_version=0)
    assert resp.status_code == 409 and resp.json()["detail"] == {"error": "no_passphrase"}


def test_new_kdf_and_keyring_are_validated_like_registration():
    client = make_client(max_keyring_bytes=64, login_per_10min_per_ip=100)
    key = auth(register(client).json()["api_key"])
    assert change(client, key, kdf=kdf(opslimit=1)).status_code == 422
    assert change(client, key, new_auth_hash=b64(8)).status_code == 422
    assert change(client, key, keyring="x" * 100).status_code == 413


def test_change_needs_an_owner_key(client: TestClient):
    assert client.post("/v1/account/passphrase", json={}).status_code == 401
