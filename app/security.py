import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApiKey, Drop, Grant

KEY_PREFIX = "pnv_"

_bearer = HTTPBearer(auto_error=False)


def generate_api_key() -> tuple[str, str]:
    """Return (plaintext, sha256 hex). The plaintext is shown once and never stored."""
    plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
    return plaintext, hash_api_key(plaintext)


def hash_api_key(plaintext: str) -> str:
    # 256 bits of entropy, so a plain SHA-256 is enough (no brute-force surface to slow down).
    return hashlib.sha256(plaintext.encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    account_id: str
    role: str  # "owner" | "reader" | "dropper"
    grant: Grant | None
    drop: Drop | None = None
    key_id: str = ""


def _is_past(moment: datetime) -> bool:
    if moment.tzinfo is None:  # SQLite hands back naive datetimes
        moment = moment.replace(tzinfo=timezone.utc)
    return moment <= datetime.now(timezone.utc)


def get_db(request: Request):
    with request.app.state.session_factory() as db:
        yield db


def get_principal(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Principal:
    unauthorized = HTTPException(401, "Invalid or missing API key", {"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(creds.credentials)))
    if key is None or key.revoked_at is not None:
        raise unauthorized
    grant = db.get(Grant, key.grant_id) if key.grant_id else None
    if grant is not None and grant.revoked_at is not None:
        raise unauthorized
    drop = db.get(Drop, key.drop_id) if key.drop_id else None
    if drop is not None and _is_past(drop.expires_at):
        raise unauthorized
    return Principal(key.account_id, key.role, grant, drop, key.id)


def require_owner(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.role != "owner":
        raise HTTPException(403, "Owner API key required")
    return principal


def require_dropper(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.role != "dropper":
        raise HTTPException(403, "Drop token required")
    return principal
