import base64
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app import totp
from app.models import Account
from tests.conftest import auth
from tests.test_accounts import AUTH_HASH, OTHER_HASH, login, make_client, register

NOW = 1_800_000_000.0  # fixed clock, so codes and steps are deterministic


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    clock = {"t": NOW}
    monkeypatch.setattr(totp, "_now", lambda: clock["t"])
    return clock


def code_for(secret: str, at: float = NOW) -> str:
    return totp.totp(totp._decode_secret(secret), at)


def setup(client: TestClient, key: dict, auth_hash: str = AUTH_HASH):
    return client.post("/v1/account/two-factor/setup", json={"auth_hash": auth_hash}, headers=key)


def enable(client: TestClient, key: dict, code: str):
    return client.post("/v1/account/two-factor/enable", json={"code": code}, headers=key)


def disable(client: TestClient, key: dict, code: str, auth_hash: str = AUTH_HASH):
    return client.post("/v1/account/two-factor/disable", json={"auth_hash": auth_hash, "code": code}, headers=key)


def status(client: TestClient, key: dict) -> dict:
    return client.get("/v1/account/two-factor", headers=key).json()


def login_2fa(client: TestClient, **extra):
    body = {"username": "alice", "auth_hash": AUTH_HASH, "device_label": "ipad", **extra}
    return client.post("/v1/login", json=body)


def enabled_account(client: TestClient) -> tuple[dict, str, list[str]]:
    key = auth(register(client).json()["api_key"])
    secret = setup(client, key).json()["secret"]
    codes = enable(client, key, code_for(secret)).json()["recovery_codes"]
    return key, secret, codes


@pytest.fixture
def client() -> TestClient:
    return make_client(login_per_10min_per_ip=100, two_factor_per_10min_per_ip=100)


def detail(resp) -> dict:
    return resp.json()["detail"]


# --- status & setup ----------------------------------------------------------


def test_status_starts_disabled(client):
    key = auth(register(client).json()["api_key"])
    assert status(client, key) == {"enabled": False, "recovery_codes_left": 0}


def test_setup_returns_a_base32_secret_and_an_otpauth_uri_with_the_server_name(client):
    key = auth(register(client).json()["api_key"])
    resp = setup(client, key)
    assert resp.status_code == 200
    body = resp.json()
    assert "=" not in body["secret"] and len(base64.b32decode(body["secret"])) == 20
    assert body["otpauth_uri"] == (
        f"otpauth://totp/Pocket%20Nutrition%20Vault:alice?secret={body['secret']}"
        "&issuer=Pocket%20Nutrition%20Vault&algorithm=SHA1&digits=6&period=30"
    )
    query = parse_qs(urlparse(body["otpauth_uri"]).query)
    assert query["issuer"] == ["Pocket Nutrition Vault"]
    # Setup alone does not turn anything on.
    assert status(client, key)["enabled"] is False
    assert login(client).status_code == 200


def test_setup_url_encodes_a_custom_server_name():
    client = make_client(server_name="Café & Co")
    key = auth(register(client).json()["api_key"])
    uri = setup(client, key).json()["otpauth_uri"]
    assert uri.startswith("otpauth://totp/Caf%C3%A9%20%26%20Co:alice?")
    assert "&issuer=Caf%C3%A9%20%26%20Co&" in uri


def test_setup_with_a_wrong_passphrase_is_401_and_counts_toward_the_lockout():
    client = make_client(login_max_failures=2, two_factor_per_10min_per_ip=100, login_per_10min_per_ip=100)
    key = auth(register(client).json()["api_key"])
    first = setup(client, key, OTHER_HASH)
    assert first.status_code == 401 and detail(first) == {"error": "invalid_credentials"}
    setup(client, key, OTHER_HASH)
    locked = setup(client, key)
    assert locked.status_code == 429 and detail(locked) == {"error": "account_locked"}
    assert int(locked.headers["retry-after"]) > 0
    assert login(client).status_code == 429


def test_setup_refused_when_already_enabled(client):
    key, _, _ = enabled_account(client)
    resp = setup(client, key)
    assert resp.status_code == 409 and detail(resp) == {"error": "two_factor_enabled"}


def test_setup_is_refused_for_accounts_without_a_passphrase(client, owner):
    resp = setup(client, owner)
    assert resp.status_code == 409 and detail(resp) == {"error": "no_passphrase"}


def test_a_second_setup_replaces_the_pending_secret(client):
    key = auth(register(client).json()["api_key"])
    first = setup(client, key).json()["secret"]
    second = setup(client, key).json()["secret"]
    assert first != second
    assert enable(client, key, code_for(first)).status_code == 400
    assert enable(client, key, code_for(second)).status_code == 200


# --- enable ------------------------------------------------------------------


def test_enable_without_setup_is_409(client):
    key = auth(register(client).json()["api_key"])
    resp = enable(client, key, "123456")
    assert resp.status_code == 409 and detail(resp) == {"error": "no_pending_setup"}


def test_enable_with_a_wrong_code_is_400_and_keeps_the_pending_secret(client):
    key = auth(register(client).json()["api_key"])
    secret = setup(client, key).json()["secret"]
    wrong = enable(client, key, "000000" if code_for(secret) != "000000" else "111111")
    assert wrong.status_code == 400 and detail(wrong) == {"error": "invalid_code"}
    assert enable(client, key, code_for(secret)).status_code == 200


def test_enable_returns_ten_recovery_codes_once_and_stores_only_hashes(client):
    key, secret, codes = enabled_account(client)
    assert len(codes) == 10 and all(len(c) == 14 and c.count("-") == 2 for c in codes)
    assert status(client, key) == {"enabled": True, "recovery_codes_left": 10}
    with client.app.state.session_factory() as db:
        account = db.query(Account).one()
        assert account.totp_secret == secret and account.totp_pending_secret is None
        assert account.totp_last_step == int(NOW // 30)
        stored = account.totp_recovery_hashes
    assert all(code not in stored and code.replace("-", "") not in stored for code in codes)
    # Pending secret is gone, so enable cannot be called again to mint fresh codes.
    assert enable(client, key, code_for(secret, NOW + 30)).status_code == 409


# --- login -------------------------------------------------------------------


def test_login_without_a_code_asks_for_one_and_is_not_counted():
    client = make_client(login_max_failures=1, login_per_10min_per_ip=100, two_factor_per_10min_per_ip=100)
    enabled_account(client)
    for _ in range(3):
        resp = login(client)
        assert resp.status_code == 401 and detail(resp) == {"error": "two_factor_required"}
    with client.app.state.session_factory() as db:
        assert db.query(Account).one().failed_logins == 0


def test_wrong_passphrase_is_still_invalid_credentials_when_two_factor_is_on(client):
    enabled_account(client)
    resp = client.post(
        "/v1/login", json={"username": "alice", "auth_hash": OTHER_HASH, "device_label": "x", "totp_code": "123456"}
    )
    assert resp.status_code == 401 and detail(resp) == {"error": "invalid_credentials"}


def test_login_with_a_valid_totp_issues_a_key_and_resets_failures(client, _frozen_clock):
    key, secret, _ = enabled_account(client)
    login(client, auth_hash=OTHER_HASH)  # one failure on the counter
    _frozen_clock["t"] = NOW + 30  # the enable code's step is already used
    resp = login_2fa(client, totp_code=code_for(secret, NOW + 30))
    assert resp.status_code == 200 and resp.json()["api_key"].startswith("pnv_")
    with client.app.state.session_factory() as db:
        assert db.query(Account).one().failed_logins == 0


def test_a_totp_code_cannot_be_replayed(client, _frozen_clock):
    _, secret, _ = enabled_account(client)
    _frozen_clock["t"] = NOW + 60
    code = code_for(secret, NOW + 60)
    assert login_2fa(client, totp_code=code).status_code == 200
    replay = login_2fa(client, totp_code=code)
    assert replay.status_code == 401 and detail(replay) == {"error": "invalid_two_factor"}
    # An older code still inside the drift window is refused too: its step is before the last one.
    older = login_2fa(client, totp_code=code_for(secret, NOW + 30))
    assert detail(older) == {"error": "invalid_two_factor"}


def test_the_code_used_to_enable_cannot_log_in(client):
    _, secret, _ = enabled_account(client)
    resp = login_2fa(client, totp_code=code_for(secret))
    assert resp.status_code == 401 and detail(resp) == {"error": "invalid_two_factor"}


def test_wrong_two_factor_codes_count_toward_the_lockout(_frozen_clock):
    client = make_client(login_max_failures=2, login_per_10min_per_ip=100, two_factor_per_10min_per_ip=100)
    _, secret, _ = enabled_account(client)
    for _ in range(2):
        assert detail(login_2fa(client, totp_code="000000", recovery_code="aaaa-aaaa-aaaa"))["error"] == (
            "invalid_two_factor"
        )
    _frozen_clock["t"] = NOW + 30
    locked = login_2fa(client, totp_code=code_for(secret, NOW + 30))
    assert locked.status_code == 429 and detail(locked) == {"error": "account_locked"}


def test_a_recovery_code_logs_in_once_and_two_factor_stays_on(client):
    key, _, codes = enabled_account(client)
    assert login_2fa(client, recovery_code=codes[0].upper().replace("-", " ")).status_code == 200
    again = login_2fa(client, recovery_code=codes[0])
    assert again.status_code == 401 and detail(again) == {"error": "invalid_two_factor"}
    assert status(client, key) == {"enabled": True, "recovery_codes_left": 9}
    assert detail(login(client)) == {"error": "two_factor_required"}


def test_linked_devices_keep_working_without_a_code(client):
    key, _, _ = enabled_account(client)
    assert client.get("/v1/me", headers=key).status_code == 200


# --- disable -----------------------------------------------------------------


def test_disable_when_not_enabled_is_409(client):
    key = auth(register(client).json()["api_key"])
    resp = disable(client, key, "123456")
    assert resp.status_code == 409 and detail(resp) == {"error": "two_factor_disabled"}


def test_disable_with_a_wrong_passphrase_is_401_and_counted():
    client = make_client(login_max_failures=1, login_per_10min_per_ip=100, two_factor_per_10min_per_ip=100)
    key, _, codes = enabled_account(client)
    resp = disable(client, key, codes[0], OTHER_HASH)
    assert resp.status_code == 401 and detail(resp) == {"error": "invalid_credentials"}
    assert disable(client, key, codes[0]).status_code == 429


def test_disable_with_a_wrong_code_is_400(client):
    key, _, _ = enabled_account(client)
    resp = disable(client, key, "not-a-code")
    assert resp.status_code == 400 and detail(resp) == {"error": "invalid_code"}
    assert status(client, key)["enabled"] is True


def test_disable_with_a_totp_clears_everything(client, _frozen_clock):
    key, secret, _ = enabled_account(client)
    _frozen_clock["t"] = NOW + 30
    assert disable(client, key, code_for(secret, NOW + 30)).status_code == 204
    assert status(client, key) == {"enabled": False, "recovery_codes_left": 0}
    with client.app.state.session_factory() as db:
        account = db.query(Account).one()
        assert (account.totp_secret, account.totp_pending_secret, account.totp_last_step,
                account.totp_recovery_hashes) == (None, None, None, None)
    assert login(client).status_code == 200


def test_disable_with_a_recovery_code(client):
    key, _, codes = enabled_account(client)
    assert disable(client, key, codes[3]).status_code == 204
    assert status(client, key)["enabled"] is False


def test_two_factor_settings_are_rate_limited_per_ip():
    client = make_client(two_factor_per_10min_per_ip=2)
    key = auth(register(client).json()["api_key"])
    assert enable(client, key, "123456").status_code == 409
    assert enable(client, key, "123456").status_code == 409
    limited = setup(client, key)
    assert limited.status_code == 429 and detail(limited) == {"error": "rate_limited"}


def test_two_factor_endpoints_need_an_owner_key(client):
    assert client.get("/v1/account/two-factor").status_code == 401
