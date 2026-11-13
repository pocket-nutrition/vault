"""TOTP (RFC 6238) and single-use recovery codes for two-factor login.

Hand-rolled on hmac + struct rather than a dependency: the whole algorithm is a dozen lines, and the
fixed parameters (SHA1, 6 digits, 30 s) are the only ones every authenticator app supports.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time

SECRET_BYTES = 20  # RFC 4226 recommends 160 bits, the SHA1 block it is fed to
DIGITS = 6
PERIOD_S = 30
# Accept the previous and next step too, so a phone clock a few seconds off still works.
DRIFT_STEPS = 1

RECOVERY_CODE_COUNT = 10
# Lowercase RFC 4648 base32: no 0/1/8/9, so nothing reads as O/l/B/g when copied from paper.
_RECOVERY_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_RECOVERY_GROUPS, _RECOVERY_GROUP_LEN = 3, 4  # 12 characters x 5 bits = 60 bits


def _now() -> float:
    # Indirection so tests can move the clock without patching time.time for the whole process.
    return time.time()


def new_secret() -> str:
    """A fresh secret, as unpadded base32 (the form authenticator apps and otpauth URIs expect)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _decode_secret(secret_b32: str) -> bytes:
    return base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP with dynamic truncation."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def totp(key: bytes, at: float, digits: int = DIGITS) -> str:
    return hotp(key, int(at // PERIOD_S), digits)


def matching_step(secret_b32: str, code: str, last_step: int | None) -> int | None:
    """The time step `code` is valid for, or None.

    Steps at or before `last_step` are refused, so a code seen once (shoulder-surfed, phished, or
    replayed from a log) cannot be used again, even within its 30 s window.
    """
    code = code.replace(" ", "")
    if not re.fullmatch(rf"\d{{{DIGITS}}}", code):
        return None
    key = _decode_secret(secret_b32)
    current = int(_now() // PERIOD_S)
    floor = -1 if last_step is None else last_step
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if step > floor and hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def otpauth_uri(issuer_quoted: str, username_quoted: str, secret_b32: str) -> str:
    return (
        f"otpauth://totp/{issuer_quoted}:{username_quoted}?secret={secret_b32}&issuer={issuer_quoted}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD_S}"
    )


# --- recovery codes ----------------------------------------------------------


def new_recovery_codes() -> list[str]:
    return [
        "-".join(
            "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP_LEN))
            for _ in range(_RECOVERY_GROUPS)
        )
        for _ in range(RECOVERY_CODE_COUNT)
    ]


def hash_recovery_code(code: str) -> str:
    # 60 random bits per code, so a plain SHA-256 is enough at rest (no password to slow down);
    # normalised first so case, dashes and spaces typed by the user do not matter.
    normalised = code.lower().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalised.encode()).hexdigest()


def load_hashes(stored: str | None) -> list[str]:
    return json.loads(stored) if stored else []


def dump_hashes(hashes: list[str]) -> str:
    return json.dumps(hashes)


def consume_recovery_code(stored: str | None, code: str) -> str | None:
    """The stored list without `code`, or None when `code` is not one of the unused codes."""
    candidate = hash_recovery_code(code)
    hashes = load_hashes(stored)
    match = next((h for h in hashes if hmac.compare_digest(h, candidate)), None)
    if match is None:
        return None
    return dump_hashes([h for h in hashes if h != match])
