import base64
import hashlib
import hmac
import json
import logging
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app import totp
from app.models import Account, ApiKey, Drop, Grant, Record, utcnow
from app.ratelimit import client_ip
from app.schemas import (
    DEFAULT_KDF_MEMLIMIT,
    DEFAULT_KDF_OPSLIMIT,
    ChangePassphraseIn,
    ChangePassphraseOut,
    DeleteAccountIn,
    Kdf,
    KeyringOut,
    LoginIn,
    PreloginIn,
    RegisterIn,
    ResetPassphraseIn,
    ServerInfo,
    Session,
    TwoFactorDisableIn,
    TwoFactorEnableIn,
    TwoFactorEnableOut,
    TwoFactorSetupIn,
    TwoFactorSetupOut,
    TwoFactorStatus,
)
from app.security import Principal, generate_api_key, get_db, require_owner

router = APIRouter(prefix="/v1")

# The client's auth hash is already a 256-bit Argon2id-derived value; this second hash only protects
# it at rest. OWASP minimum parameters keep it cheap enough for a small instance.
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
log = logging.getLogger(__name__)


class _ArgonSlots:
    """Runs every Argon2 hash on a small FIXED set of worker threads.

    Two reasons it is a dedicated pool and not just a semaphore around the request threads:
    each hash allocates ~19 MiB, and glibc keeps freed memory in a per-thread arena. If hashes ran on
    whichever of the ~40 request threads happened to serve them, every thread would end up holding its own
    retained 19 MiB and a burst of 25 logins used ~475 MiB (an out-of-memory kill, seen in production).
    With a fixed pool the same few arenas are reused. Requests that cannot get a worker within a few
    seconds are refused with 503 rather than queueing without bound.
    """

    def __init__(self) -> None:
        self._pool: ThreadPoolExecutor | None = None
        self._wait_s = 5.0

    def configure(self, concurrency: int, wait_s: float) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
        self._pool = ThreadPoolExecutor(max_workers=max(1, concurrency), thread_name_prefix="argon")
        self._wait_s = wait_s

    def run(self, work, *args):
        if self._pool is None:
            self.configure(2, 5.0)
        future = self._pool.submit(work, *args)
        try:
            return future.result(timeout=self._wait_s)
        except FutureTimeout:
            future.cancel()  # not started yet: it never will; already running: it finishes and is dropped
            raise HTTPException(503, {"error": "busy"}, {"Retry-After": "5"}) from None


_slots = _ArgonSlots()
_DUMMY_DIGEST = _hasher.hash("pnv-dummy")


def configure_argon(concurrency: int, wait_s: float) -> None:
    _slots.configure(concurrency, wait_s)


def _hash(auth_hash: str) -> str:
    return _slots.run(_hasher.hash, auth_hash)


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:  # SQLite hands back naive datetimes
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)  # Postgres returns aware ones, in the session time zone


def _is_past(moment: datetime) -> bool:
    return _as_utc(moment) <= datetime.now(timezone.utc)


def _prelogin_secret(request: Request) -> bytes:
    state = request.app.state
    if not hasattr(state, "_prelogin_key"):
        settings = state.settings
        configured = settings.prelogin_secret or settings.admin_token
        if not configured:
            log.warning(
                "Neither VAULT_PRELOGIN_SECRET nor VAULT_ADMIN_TOKEN is set: fake KDF salts change on every "
                "restart, which lets a client tell unknown usernames from real ones. Set VAULT_PRELOGIN_SECRET."
            )
        state._prelogin_key = (configured or secrets.token_hex(32)).encode()
    return state._prelogin_key


def _fake_kdf(request: Request, username: str) -> Kdf:
    """Deterministic settings for unknown usernames, so prelogin does not reveal which accounts exist."""
    salt = hmac.new(_prelogin_secret(request), f"prelogin:{username}".encode(), hashlib.sha256).digest()[:16]
    return Kdf(salt=base64.b64encode(salt).decode(), opslimit=DEFAULT_KDF_OPSLIMIT, memlimit=DEFAULT_KDF_MEMLIMIT)


def _limit(request: Request, bucket: str, limit: int, window_s: int) -> None:
    ip = client_ip(request, request.app.state.settings.trusted_proxy_hops)
    request.app.state.rate_limiter.check(bucket, ip, limit, window_s)


def _new_device_key(db: DbSession, request: Request, account_id: str, label: str) -> tuple[str, str]:
    active = db.scalar(
        select(func.count()).select_from(ApiKey).where(
            ApiKey.account_id == account_id, ApiKey.role == "owner", ApiKey.revoked_at.is_(None)
        )
    )
    if active >= request.app.state.settings.max_devices:
        raise HTTPException(409, {"error": "too_many_devices"})
    plaintext, key_hash = generate_api_key()
    key = ApiKey(id=str(uuid.uuid4()), account_id=account_id, key_hash=key_hash, role="owner", label=label)
    db.add(key)
    return key.id, plaintext


@router.get("/server-info", response_model=ServerInfo)
def server_info(request: Request) -> ServerInfo:
    settings = request.app.state.settings
    return ServerInfo(
        name=settings.server_name,
        version=request.app.version,
        registration=settings.registration,
        quota_bytes=settings.quota_bytes,
        kdf_defaults={"alg": "argon2id", "opslimit": DEFAULT_KDF_OPSLIMIT, "memlimit": DEFAULT_KDF_MEMLIMIT},
    )


@router.post("/accounts/prelogin", response_model=Kdf)
def prelogin(body: PreloginIn, request: Request, db: DbSession = Depends(get_db)) -> Kdf:
    _limit(request, "login", request.app.state.settings.login_per_10min_per_ip, 600)
    account = db.scalar(select(Account).where(Account.username == body.username))
    if account is None or account.kdf is None:
        return _fake_kdf(request, body.username)
    return Kdf(**json.loads(account.kdf))


@router.post("/accounts", status_code=201, response_model=Session)
def register(body: RegisterIn, request: Request, db: DbSession = Depends(get_db)) -> Session:
    settings = request.app.state.settings
    if settings.registration != "open":
        raise HTTPException(403, {"error": "registration_closed"})
    _limit(request, "register", settings.register_per_hour_per_ip, 3600)
    if len(body.keyring.encode()) > settings.max_keyring_bytes:
        raise HTTPException(413, "Keyring too large")

    account = Account(
        id=str(uuid.uuid4()),
        username=body.username,
        kdf=body.kdf.model_dump_json(),
        auth_digest=_hash(body.auth_hash),
        keyring=body.keyring,
        keyring_version=1,
    )
    db.add(account)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, {"error": "username_taken"}) from None
    key_id, api_key = _new_device_key(db, request, account.id, body.device_label)
    db.commit()
    return Session(
        account_id=account.id,
        api_key=api_key,
        key_id=key_id,
        keyring=KeyringOut(blob=account.keyring, version=account.keyring_version),
    )


def _verify(digest: str, auth_hash: str) -> bool:
    def check() -> bool:
        try:
            return _hasher.verify(digest, auth_hash)
        except (VerifyMismatchError, InvalidHashError):
            return False

    return _slots.run(check)


def _locked(retry_after: int) -> HTTPException:
    return HTTPException(429, {"error": "account_locked"}, {"Retry-After": str(max(retry_after, 1))})


def _check_not_locked(account: Account) -> None:
    if account.locked_until is not None and not _is_past(account.locked_until):
        remaining = int((_as_utc(account.locked_until) - utcnow()).total_seconds()) + 1
        raise _locked(remaining)


def _count_failure(db: DbSession, request: Request, account: Account, error: HTTPException) -> HTTPException:
    """Count one failed credential check toward the account lockout, commit it, and return `error` to raise.

    Login, passphrase change and the two-factor settings share one counter, so an attacker holding a
    device key cannot use the settings endpoints as a lockout-free passphrase oracle.
    """
    settings = request.app.state.settings
    account.failed_logins += 1
    if account.failed_logins >= settings.login_max_failures:
        account.locked_until = utcnow() + timedelta(seconds=settings.login_lock_s)
        account.failed_logins = 0
    db.commit()
    return error


def _invalid_credentials() -> HTTPException:
    return HTTPException(401, {"error": "invalid_credentials"})


def _verify_owner_passphrase(db: DbSession, request: Request, account: Account, auth_hash: str) -> None:
    """For owner endpoints that re-ask the passphrase. `account` must already be row-locked."""
    if account.auth_digest is None:
        raise HTTPException(409, {"error": "no_passphrase"})
    _check_not_locked(account)
    if not _verify(account.auth_digest, auth_hash):
        raise _count_failure(db, request, account, _invalid_credentials())


def _second_factor_ok(account: Account, body: LoginIn | ResetPassphraseIn) -> bool:
    """Check the code given at login; on success record the TOTP step or burn the recovery code."""
    if body.totp_code is not None:
        step = totp.matching_step(account.totp_secret, body.totp_code, account.totp_last_step)
        if step is not None:
            account.totp_last_step = step
            return True
    if body.recovery_code is not None:
        remaining = totp.consume_recovery_code(account.totp_recovery_hashes, body.recovery_code)
        if remaining is not None:
            account.totp_recovery_hashes = remaining
            return True
    return False


@router.post("/login", response_model=Session)
def login(body: LoginIn, request: Request, db: DbSession = Depends(get_db)) -> Session:
    settings = request.app.state.settings
    _limit(request, "login", settings.login_per_10min_per_ip, 600)
    guard = request.app.state.unknown_logins

    # Row lock before any check, so parallel guesses are counted one by one instead of all reading the
    # same counter (which would let a burst of N guesses count as one failure).
    account = db.scalar(select(Account).where(Account.username == body.username).with_for_update())
    if account is None or account.auth_digest is None:
        remaining = guard.locked_for(body.username)
        if remaining:
            raise _locked(remaining)
        _verify(_DUMMY_DIGEST, body.auth_hash)  # spend the same time as a real check
        guard.record_failure(body.username, settings.login_max_failures, settings.login_lock_s)
        raise _invalid_credentials()
    _check_not_locked(account)

    if not _verify(account.auth_digest, body.auth_hash):
        raise _count_failure(db, request, account, _invalid_credentials())

    if account.totp_secret is not None:
        if body.totp_code is None and body.recovery_code is None:
            # Not a failure: this is the normal first round-trip of a two-factor login. Only reachable
            # with the right passphrase, and wrong passphrases are already counted above.
            raise HTTPException(401, {"error": "two_factor_required"})
        if not _second_factor_ok(account, body):
            raise _count_failure(db, request, account, HTTPException(401, {"error": "invalid_two_factor"}))

    account.failed_logins = 0
    account.locked_until = None
    key_id, api_key = _new_device_key(db, request, account.id, body.device_label)
    db.commit()
    return Session(
        account_id=account.id,
        api_key=api_key,
        key_id=key_id,
        keyring=KeyringOut(blob=account.keyring, version=account.keyring_version),
    )


@router.post("/logout", status_code=204)
def logout(principal: Principal = Depends(require_owner), db: DbSession = Depends(get_db)) -> None:
    """Revoke the API key used for this request (unlink this device)."""
    key = db.get(ApiKey, principal.key_id)
    key.revoked_at = key.revoked_at or utcnow()
    db.commit()


@router.delete("/account", status_code=204)
def delete_account(
    body: DeleteAccountIn,
    principal: Principal = Depends(require_owner),
    db: DbSession = Depends(get_db),
) -> None:
    """Erase the account and every byte stored for it (GDPR erasure)."""
    account = db.get(Account, principal.account_id, with_for_update=True)
    if account.auth_digest is not None and (body.auth_hash is None or not _verify(account.auth_digest, body.auth_hash)):
        raise HTTPException(401, {"error": "invalid_credentials"})
    for model in (Record, ApiKey, Drop, Grant):
        db.execute(delete(model).where(model.account_id == account.id))
    db.delete(account)
    db.commit()


# --- passphrase change -------------------------------------------------------


@router.post("/account/passphrase", response_model=ChangePassphraseOut)
def change_passphrase(
    body: ChangePassphraseIn,
    request: Request,
    principal: Principal = Depends(require_owner),
    db: DbSession = Depends(get_db),
) -> ChangePassphraseOut:
    """Swap auth digest, KDF and keyring in one transaction, then unlink every other device.

    Other devices hold the old KDF and would derive the wrong keys at their next unlock, so they must
    log in again with the new passphrase. Reader grants and drops do not depend on the passphrase.
    """
    settings = request.app.state.settings
    _limit(request, "login", settings.login_per_10min_per_ip, 600)
    if len(body.keyring.encode()) > settings.max_keyring_bytes:
        raise HTTPException(413, "Keyring too large")
    account = db.get(Account, principal.account_id, with_for_update=True)
    _verify_owner_passphrase(db, request, account, body.auth_hash)
    if body.base_version != account.keyring_version:
        # Same shape as PUT /v1/keyring: another device re-wrapped the keyring first; refetch and retry.
        raise HTTPException(409, {"error": "keyring_conflict", "current_version": account.keyring_version})

    revoked = _replace_passphrase(db, account, principal, body.new_auth_hash, body.kdf, body.keyring)
    db.commit()
    return ChangePassphraseOut(version=account.keyring_version, revoked_devices=revoked)


def _replace_passphrase(db: DbSession, account: Account, principal: Principal, new_auth_hash: str, kdf: Kdf, keyring: str) -> int:
    """Swap auth digest, KDF and keyring, bump the keyring version and revoke every other owner key.

    Returns how many devices were unlinked. The caller commits.
    """
    account.auth_digest = _hash(new_auth_hash)
    account.kdf = kdf.model_dump_json()
    account.keyring = keyring
    account.keyring_version += 1
    account.failed_logins = 0
    others = db.scalars(
        select(ApiKey).where(
            ApiKey.account_id == account.id,
            ApiKey.role == "owner",
            ApiKey.revoked_at.is_(None),
            ApiKey.id != principal.key_id,
        )
    ).all()
    now = utcnow()
    for key in others:
        key.revoked_at = now
    return len(others)


@router.post("/account/passphrase/reset", response_model=ChangePassphraseOut)
def reset_passphrase(
    body: ResetPassphraseIn,
    request: Request,
    principal: Principal = Depends(require_owner),
    db: DbSession = Depends(get_db),
) -> ChangePassphraseOut:
    """Replace a forgotten passphrase from a device that is still linked, without the old one.

    The linked device holds the user key, so it can wrap it under a new passphrase and a new recovery
    key. Nothing readable is exposed: the records stay encrypted under the unchanged user key, and a
    device key can already delete every record, so this adds no power a stolen key did not have beyond
    locking other devices out. Two-factor, when on, is still required, and a wrong code is counted
    toward the lockout like a wrong passphrase.
    """
    settings = request.app.state.settings
    _limit(request, "login", settings.login_per_10min_per_ip, 600)
    if len(body.keyring.encode()) > settings.max_keyring_bytes:
        raise HTTPException(413, "Keyring too large")
    account = db.get(Account, principal.account_id, with_for_update=True)
    _check_not_locked(account)
    if account.totp_secret is not None:
        if body.totp_code is None and body.recovery_code is None:
            raise HTTPException(401, {"error": "two_factor_required"})
        if not _second_factor_ok(account, body):
            raise _count_failure(db, request, account, HTTPException(401, {"error": "invalid_two_factor"}))
    if body.base_version != account.keyring_version:
        raise HTTPException(409, {"error": "keyring_conflict", "current_version": account.keyring_version})

    revoked = _replace_passphrase(db, account, principal, body.new_auth_hash, body.kdf, body.keyring)
    db.commit()
    return ChangePassphraseOut(version=account.keyring_version, revoked_devices=revoked)


# --- two-factor (TOTP) -------------------------------------------------------
# Guards linking a NEW device only: devices already linked authenticate with their device key and never
# see a code prompt. It does nothing against offline guessing of a stolen database (see PROTOCOL.md).


def _limit_two_factor(request: Request) -> None:
    _limit(request, "two_factor", request.app.state.settings.two_factor_per_10min_per_ip, 600)


@router.get("/account/two-factor", response_model=TwoFactorStatus)
def two_factor_status(principal: Principal = Depends(require_owner), db: DbSession = Depends(get_db)) -> TwoFactorStatus:
    account = db.get(Account, principal.account_id)
    enabled = account.totp_secret is not None
    left = len(totp.load_hashes(account.totp_recovery_hashes)) if enabled else 0
    return TwoFactorStatus(enabled=enabled, recovery_codes_left=left)


@router.post("/account/two-factor/setup", response_model=TwoFactorSetupOut)
def two_factor_setup(
    body: TwoFactorSetupIn,
    request: Request,
    principal: Principal = Depends(require_owner),
    db: DbSession = Depends(get_db),
) -> TwoFactorSetupOut:
    _limit_two_factor(request)
    account = db.get(Account, principal.account_id, with_for_update=True)
    if account.totp_secret is not None:
        raise HTTPException(409, {"error": "two_factor_enabled"})
    _verify_owner_passphrase(db, request, account, body.auth_hash)

    # Pending until /enable proves the authenticator app reads it correctly, so a half-finished setup
    # can never lock the user out. A new setup overwrites any earlier pending secret.
    secret = totp.new_secret()
    account.totp_pending_secret = secret
    account.failed_logins = 0
    db.commit()
    issuer = quote(request.app.state.settings.server_name, safe="")
    return TwoFactorSetupOut(
        secret=secret, otpauth_uri=totp.otpauth_uri(issuer, quote(account.username, safe=""), secret)
    )


@router.post("/account/two-factor/enable", response_model=TwoFactorEnableOut)
def two_factor_enable(
    body: TwoFactorEnableIn,
    request: Request,
    principal: Principal = Depends(require_owner),
    db: DbSession = Depends(get_db),
) -> TwoFactorEnableOut:
    _limit_two_factor(request)
    account = db.get(Account, principal.account_id, with_for_update=True)
    if account.totp_pending_secret is None:
        raise HTTPException(409, {"error": "no_pending_setup"})
    step = totp.matching_step(account.totp_pending_secret, body.code, None)
    if step is None:
        raise HTTPException(400, {"error": "invalid_code"})

    codes = totp.new_recovery_codes()
    account.totp_secret = account.totp_pending_secret
    account.totp_pending_secret = None
    account.totp_last_step = step  # the code just typed cannot be replayed to log in
    account.totp_recovery_hashes = totp.dump_hashes([totp.hash_recovery_code(c) for c in codes])
    db.commit()
    return TwoFactorEnableOut(recovery_codes=codes)  # the only time they are ever shown


@router.post("/account/two-factor/disable", status_code=204)
def two_factor_disable(
    body: TwoFactorDisableIn,
    request: Request,
    principal: Principal = Depends(require_owner),
    db: DbSession = Depends(get_db),
) -> None:
    _limit_two_factor(request)
    account = db.get(Account, principal.account_id, with_for_update=True)
    if account.totp_secret is None:
        raise HTTPException(409, {"error": "two_factor_disabled"})
    _verify_owner_passphrase(db, request, account, body.auth_hash)
    valid = totp.matching_step(account.totp_secret, body.code, account.totp_last_step) is not None
    if not valid:
        valid = totp.consume_recovery_code(account.totp_recovery_hashes, body.code) is not None
    if not valid:
        raise HTTPException(400, {"error": "invalid_code"})

    account.totp_secret = None
    account.totp_pending_secret = None
    account.totp_last_step = None
    account.totp_recovery_hashes = None
    account.failed_logins = 0
    db.commit()
