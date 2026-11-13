import base64
import binascii
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, Field, StringConstraints

ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
TYPE_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}$"

# nonce (24) + Poly1305 tag (16): the smallest well-formed XChaCha20-Poly1305 payload.
MIN_CIPHERTEXT_BYTES = 40
# Sealed box overhead: ephemeral public key (32) + MAC (16).
MIN_SEALED_BYTES = 48

Id = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
RecordType = Annotated[str, StringConstraints(pattern=TYPE_PATTERN)]
KeyId = Annotated[str, StringConstraints(min_length=1, max_length=128)]
Label = Annotated[str, StringConstraints(min_length=1, max_length=128)]


def _check_b64(value: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("must be standard base64") from exc
    return value


Base64 = Annotated[str, BeforeValidator(_check_b64)]
# Generous upper bounds; the real limits are settings. They stop absurd values before any decoding work.
Base64Record = Annotated[str, BeforeValidator(_check_b64), StringConstraints(max_length=1_000_000)]
KeyringText = Annotated[str, StringConstraints(max_length=32_768)]


class RecordIn(BaseModel):
    type: RecordType
    scope_id: Id | None = None
    # New revision: the current revision + 1 (1 for a new record).
    revision: int
    key_id: KeyId
    ciphertext: Base64Record


class RecordOut(BaseModel):
    id: str
    type: str
    scope_id: str | None
    revision: int
    key_id: str
    ciphertext: str
    deleted: bool
    seq: int
    updated_at: datetime


class SyncOut(BaseModel):
    records: list[RecordOut]
    cursor: int
    has_more: bool


class KeyringIn(BaseModel):
    # Opaque to the server. Must be a JSON-serialised string built by the client.
    blob: KeyringText
    # Compare-and-swap: the version the client last read (0 when none was stored yet).
    base_version: int


class KeyringOut(BaseModel):
    blob: str | None
    version: int


class GrantIn(BaseModel):
    scope_id: Id
    label: Label
    recipient_public_key: Annotated[Base64, StringConstraints(max_length=128)]
    wrapped_scope_key: Annotated[Base64, StringConstraints(max_length=2048)]


class GrantOut(BaseModel):
    id: str
    scope_id: str
    label: str
    recipient_public_key: str
    created_at: datetime
    revoked_at: datetime | None


class GrantCreated(BaseModel):
    grant_id: str
    api_key: str


class GrantMe(BaseModel):
    grant_id: str
    scope_id: str
    recipient_public_key: str
    wrapped_scope_key: str


class KeyIn(BaseModel):
    label: Label


class KeyOut(BaseModel):
    id: str
    role: str
    label: str
    created_at: datetime
    revoked_at: datetime | None


class KeyCreated(BaseModel):
    id: str
    api_key: str


class AccountCreated(BaseModel):
    account_id: str
    api_key: str


class MeOut(BaseModel):
    account_id: str
    role: str
    scope_id: str | None


class DropIn(BaseModel):
    record_id: Id
    type: RecordType
    scope_id: Id | None = None
    # Fixed by the owner so the depositor cannot mislabel which key the payload is sealed to.
    key_id: KeyId
    ttl_s: Annotated[int, Field(ge=60, le=7 * 24 * 3600)] = 3600
    max_writes: Annotated[int, Field(ge=1, le=10)] = 1


class DropCreated(BaseModel):
    drop_id: str
    token: str
    expires_at: datetime


class DropWriteIn(BaseModel):
    ciphertext: Base64Record


class DropWriteOut(BaseModel):
    remaining_writes: int


# --- accounts ----------------------------------------------------------------

MIN_KDF_OPSLIMIT = 3
MAX_KDF_OPSLIMIT = 10
MIN_KDF_MEMLIMIT = 64 * 1024 * 1024
MAX_KDF_MEMLIMIT = 1024 * 1024 * 1024
KDF_SALT_BYTES = 16
AUTH_HASH_BYTES = 32

DEFAULT_KDF_OPSLIMIT = 3
DEFAULT_KDF_MEMLIMIT = 64 * 1024 * 1024

Username = Annotated[
    str,
    BeforeValidator(lambda v: v.strip().lower() if isinstance(v, str) else v),
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.-]{2,63}$"),
]


def _check_exact_length(size: int):
    def check(value: str) -> str:
        _check_b64(value)
        if len(base64.b64decode(value)) != size:
            raise ValueError(f"must decode to exactly {size} bytes")
        return value

    return check


AuthHash = Annotated[str, BeforeValidator(_check_exact_length(AUTH_HASH_BYTES))]


class Kdf(BaseModel):
    """Client-chosen key derivation settings, stored so any device can derive the same keys."""

    alg: Literal["argon2id"] = "argon2id"
    salt: Annotated[str, BeforeValidator(_check_exact_length(KDF_SALT_BYTES))]
    opslimit: Annotated[int, Field(ge=MIN_KDF_OPSLIMIT, le=MAX_KDF_OPSLIMIT)]
    memlimit: Annotated[int, Field(ge=MIN_KDF_MEMLIMIT, le=MAX_KDF_MEMLIMIT)]


class ServerInfo(BaseModel):
    name: str
    version: str
    registration: str
    quota_bytes: int
    kdf_defaults: dict[str, int | str]


class PreloginIn(BaseModel):
    username: Username


class RegisterIn(BaseModel):
    username: Username
    kdf: Kdf
    auth_hash: AuthHash
    keyring: KeyringText
    device_label: Label


# Loose on purpose: a malformed code is answered like a wrong one (invalid_two_factor / invalid_code), not 422.
OneTimeCode = Annotated[str, StringConstraints(max_length=64)]


class LoginIn(BaseModel):
    username: Username
    auth_hash: AuthHash
    device_label: Label
    # Required only when the account has two-factor on; checked after auth_hash. Either one is enough.
    totp_code: OneTimeCode | None = None
    recovery_code: OneTimeCode | None = None


class Session(BaseModel):
    account_id: str
    api_key: str
    key_id: str
    keyring: KeyringOut


class DeleteAccountIn(BaseModel):
    # Required for password accounts; ignored for admin-created, API-key-only accounts.
    auth_hash: AuthHash | None = None


class ChangePassphraseIn(BaseModel):
    auth_hash: AuthHash
    new_auth_hash: AuthHash
    kdf: Kdf
    # The user key re-wrapped under the new passphrase; same rules as PUT /v1/keyring.
    keyring: KeyringText
    base_version: int


class ResetPassphraseIn(BaseModel):
    """A forgotten passphrase, replaced from a device that is still linked (it holds the user key)."""

    new_auth_hash: AuthHash
    kdf: Kdf
    # The same user key wrapped under the new passphrase AND a new recovery key; same rules as PUT /v1/keyring.
    keyring: KeyringText
    base_version: int
    # Required only when the account has two-factor on. Either one is enough.
    totp_code: OneTimeCode | None = None
    recovery_code: OneTimeCode | None = None


class ChangePassphraseOut(BaseModel):
    version: int
    revoked_devices: int


class TwoFactorStatus(BaseModel):
    enabled: bool
    recovery_codes_left: int


class TwoFactorSetupIn(BaseModel):
    auth_hash: AuthHash


class TwoFactorSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TwoFactorEnableIn(BaseModel):
    code: OneTimeCode


class TwoFactorEnableOut(BaseModel):
    recovery_codes: list[str]


class TwoFactorDisableIn(BaseModel):
    auth_hash: AuthHash
    # A current TOTP code or an unused recovery code.
    code: OneTimeCode
