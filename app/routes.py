import base64
import hmac
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import Account, ApiKey, Drop, Grant, Record, utcnow
from app.schemas import (
    ID_PATTERN,
    MIN_CIPHERTEXT_BYTES,
    MIN_SEALED_BYTES,
    AccountCreated,
    DropCreated,
    DropIn,
    DropWriteIn,
    DropWriteOut,
    GrantCreated,
    GrantIn,
    GrantMe,
    GrantOut,
    KeyCreated,
    KeyIn,
    KeyOut,
    KeyringIn,
    KeyringOut,
    MeOut,
    RecordIn,
    RecordOut,
    SyncOut,
)
from app.security import Principal, generate_api_key, get_db, get_principal, require_dropper, require_owner

admin_router = APIRouter(prefix="/admin", tags=["admin"])
router = APIRouter(prefix="/v1")

RecordId = Path(pattern=ID_PATTERN)


def _lock_account(db: Session, account_id: str) -> Account:
    """Load the account under a row lock so concurrent writes get distinct, ordered seq values."""
    account = db.get(Account, account_id, with_for_update=True)
    if account is None:
        raise HTTPException(401, "Account no longer exists")
    return account


def _record_out(record: Record) -> RecordOut:
    return RecordOut(
        id=record.id,
        type=record.type,
        scope_id=record.scope_id,
        revision=record.revision,
        key_id=record.key_id,
        ciphertext=record.ciphertext,
        deleted=record.deleted,
        seq=record.seq,
        updated_at=record.updated_at,
    )


def _check_quota(request: Request, db: Session, account_id: str, delta: int) -> None:
    """Quota counts stored ciphertext plus a fixed overhead per row, tombstones included, so creating and
    deleting records under fresh ids cannot grow the table for free."""
    settings = request.app.state.settings
    rows, size = db.execute(
        select(func.count(), func.coalesce(func.sum(func.length(Record.ciphertext)), 0)).where(
            Record.account_id == account_id
        )
    ).one()
    used = size + rows * settings.row_overhead_bytes
    if delta > 0 and used + delta > settings.quota_bytes:
        raise HTTPException(413, {"error": "quota_exceeded"})


def _purge_old_tombstones(request: Request, db: Session, account_id: str) -> None:
    """A deleted record only needs its tombstone until every device has synced past it. Devices offline
    longer than the retention must resync from scratch (see PROTOCOL.md)."""
    cutoff = utcnow() - timedelta(days=request.app.state.settings.tombstone_retention_days)
    db.execute(
        delete(Record).where(Record.account_id == account_id, Record.deleted.is_(True), Record.updated_at < cutoff)
    )


def _check_revision(current: int, requested: int) -> None:
    if requested != current + 1:
        raise HTTPException(409, {"error": "revision_conflict", "current_revision": current})


# --- admin -------------------------------------------------------------------


@admin_router.post("/accounts", status_code=201, response_model=AccountCreated)
def create_account(request: Request, db: Session = Depends(get_db)) -> AccountCreated:
    admin_token = request.app.state.settings.admin_token
    if not admin_token:
        raise HTTPException(503, "Account creation is disabled (VAULT_ADMIN_TOKEN is unset)")
    provided = request.headers.get("authorization", "").removeprefix("Bearer ")
    if not hmac.compare_digest(provided.encode(), admin_token.encode()):
        raise HTTPException(401, "Invalid admin token")

    account = Account(id=str(uuid.uuid4()))
    plaintext, key_hash = generate_api_key()
    db.add(account)
    db.flush()
    db.add(ApiKey(id=str(uuid.uuid4()), account_id=account.id, key_hash=key_hash, role="owner", label="initial"))
    db.commit()
    return AccountCreated(account_id=account.id, api_key=plaintext)


# --- identity ----------------------------------------------------------------


@router.get("/me", response_model=MeOut)
def me(principal: Principal = Depends(get_principal)) -> MeOut:
    return MeOut(
        account_id=principal.account_id,
        role=principal.role,
        scope_id=principal.grant.scope_id if principal.grant else None,
    )


# --- keyring -----------------------------------------------------------------


@router.get("/keyring", response_model=KeyringOut)
def get_keyring(principal: Principal = Depends(require_owner), db: Session = Depends(get_db)) -> KeyringOut:
    account = db.get(Account, principal.account_id)
    return KeyringOut(blob=account.keyring, version=account.keyring_version)


@router.put("/keyring", response_model=KeyringOut)
def put_keyring(
    body: KeyringIn,
    request: Request,
    principal: Principal = Depends(require_owner),
    db: Session = Depends(get_db),
) -> KeyringOut:
    if len(body.blob.encode()) > request.app.state.settings.max_keyring_bytes:
        raise HTTPException(413, "Keyring too large")
    account = _lock_account(db, principal.account_id)
    if body.base_version != account.keyring_version:
        raise HTTPException(409, {"error": "keyring_conflict", "current_version": account.keyring_version})
    account.keyring = body.blob
    account.keyring_version += 1
    db.commit()
    return KeyringOut(blob=account.keyring, version=account.keyring_version)


# --- records & sync ----------------------------------------------------------


@router.put("/records/{record_id}", response_model=RecordOut)
def put_record(
    body: RecordIn,
    request: Request,
    record_id: str = RecordId,
    principal: Principal = Depends(require_owner),
    db: Session = Depends(get_db),
) -> RecordOut:
    ciphertext_len = len(base64.b64decode(body.ciphertext))
    if ciphertext_len < MIN_CIPHERTEXT_BYTES:
        raise HTTPException(422, "Ciphertext too short to be a valid payload")
    if ciphertext_len > request.app.state.settings.max_record_bytes:
        raise HTTPException(413, "Record too large")

    account = _lock_account(db, principal.account_id)
    record = db.get(Record, (account.id, record_id))
    _check_revision(record.revision if record else 0, body.revision)
    if record and record.scope_id != body.scope_id:
        raise HTTPException(409, {"error": "scope_immutable"})
    row_cost = 0 if record else request.app.state.settings.row_overhead_bytes
    _check_quota(request, db, account.id, row_cost + len(body.ciphertext) - len(record.ciphertext if record else ""))

    account.seq += 1
    if record is None:
        record = Record(account_id=account.id, id=record_id)
        db.add(record)
    record.type = body.type
    record.scope_id = body.scope_id
    record.revision = body.revision
    record.key_id = body.key_id
    record.ciphertext = body.ciphertext
    record.deleted = False
    record.drop_id = None
    record.seq = account.seq
    record.updated_at = utcnow()
    db.commit()
    return _record_out(record)


@router.delete("/records/{record_id}", response_model=RecordOut)
def delete_record(
    request: Request,
    record_id: str = RecordId,
    revision: int = Query(),
    principal: Principal = Depends(require_owner),
    db: Session = Depends(get_db),
) -> RecordOut:
    account = _lock_account(db, principal.account_id)
    record = db.get(Record, (account.id, record_id))
    if record is None:
        raise HTTPException(404, "Record not found")
    _check_revision(record.revision, revision)
    _purge_old_tombstones(request, db, account.id)

    account.seq += 1
    record.revision = revision
    record.ciphertext = ""
    record.deleted = True
    record.drop_id = None
    record.seq = account.seq
    record.updated_at = utcnow()
    db.commit()
    return _record_out(record)


@router.get("/sync", response_model=SyncOut)
def sync(
    request: Request,
    since: int = Query(0, ge=0),
    limit: int = Query(200, ge=1),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> SyncOut:
    if principal.role == "dropper":
        raise HTTPException(403, "Drop tokens cannot read")
    limit = min(limit, request.app.state.settings.max_page_size)
    query = select(Record).where(Record.account_id == principal.account_id, Record.seq > since)
    if principal.grant is not None:
        # Readers only ever see their own scope; the server enforces it, the scope key enforces the rest.
        query = query.where(Record.scope_id == principal.grant.scope_id)
    rows = db.scalars(query.order_by(Record.seq).limit(limit + 1)).all()
    page = rows[:limit]
    return SyncOut(
        records=[_record_out(r) for r in page],
        cursor=page[-1].seq if page else since,
        has_more=len(rows) > limit,
    )


# --- drops (write-only deposit slots) ----------------------------------------


@router.post("/drops", status_code=201, response_model=DropCreated)
def create_drop(
    body: DropIn, request: Request, principal: Principal = Depends(require_owner), db: Session = Depends(get_db)
) -> DropCreated:
    account = _lock_account(db, principal.account_id)
    _purge_expired_drops(db, account.id)
    pending = db.scalar(select(func.count()).select_from(Drop).where(Drop.account_id == account.id))
    if pending >= request.app.state.settings.max_pending_drops:
        raise HTTPException(409, {"error": "too_many_drops"})
    taken = db.get(Record, (account.id, body.record_id)) or db.scalar(
        select(Drop).where(Drop.account_id == account.id, Drop.record_id == body.record_id)
    )
    if taken is not None:
        raise HTTPException(409, {"error": "record_id_taken"})

    drop = Drop(
        id=str(uuid.uuid4()),
        account_id=account.id,
        record_id=body.record_id,
        type=body.type,
        scope_id=body.scope_id,
        key_id=body.key_id,
        expires_at=utcnow() + timedelta(seconds=body.ttl_s),
        max_writes=body.max_writes,
    )
    plaintext, key_hash = generate_api_key()
    db.add(drop)
    db.flush()
    db.add(
        ApiKey(
            id=str(uuid.uuid4()),
            account_id=account.id,
            key_hash=key_hash,
            role="dropper",
            drop_id=drop.id,
            label=f"drop:{body.record_id}",
        )
    )
    db.commit()
    return DropCreated(drop_id=drop.id, token=plaintext, expires_at=drop.expires_at)


def _purge_expired_drops(db: Session, account_id: str) -> None:
    """Expired drops are dead weight: remove them (and their tokens) so they cannot pile up."""
    expired = [
        d.id for d in db.scalars(select(Drop).where(Drop.account_id == account_id, Drop.expires_at < utcnow()))
    ]
    if expired:
        db.execute(delete(ApiKey).where(ApiKey.drop_id.in_(expired)))
        db.execute(delete(Drop).where(Drop.id.in_(expired)))


@router.delete("/drops/{drop_id}", status_code=204)
def revoke_drop(drop_id: str, principal: Principal = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    """Kill a drop token before it expires (for example when the request it was minted for is cancelled)."""
    drop = db.get(Drop, drop_id)
    if drop is None or drop.account_id != principal.account_id:
        raise HTTPException(404, "Drop not found")
    now = utcnow()
    for key in db.scalars(select(ApiKey).where(ApiKey.drop_id == drop.id, ApiKey.revoked_at.is_(None))):
        key.revoked_at = now
    drop.writes = drop.max_writes
    db.commit()


@router.put("/drop", response_model=DropWriteOut)
def write_drop(
    body: DropWriteIn,
    request: Request,
    principal: Principal = Depends(require_dropper),
    db: Session = Depends(get_db),
) -> DropWriteOut:
    ciphertext_len = len(base64.b64decode(body.ciphertext))
    if ciphertext_len < MIN_SEALED_BYTES:
        raise HTTPException(422, "Payload too short to be a sealed box")
    if ciphertext_len > request.app.state.settings.max_record_bytes:
        raise HTTPException(413, "Record too large")

    account = _lock_account(db, principal.account_id)
    drop = db.get(Drop, principal.drop.id)
    if drop.writes >= drop.max_writes:
        raise HTTPException(403, {"error": "drop_exhausted"})
    record = db.get(Record, (account.id, drop.record_id))
    if record is not None and record.drop_id != drop.id:
        # The owner took the record over (or it never belonged to this drop): hands off.
        raise HTTPException(409, {"error": "record_not_droppable"})
    row_cost = 0 if record else request.app.state.settings.row_overhead_bytes
    _check_quota(request, db, account.id, row_cost + len(body.ciphertext) - len(record.ciphertext if record else ""))

    account.seq += 1
    if record is None:
        record = Record(account_id=account.id, id=drop.record_id, revision=0)
        db.add(record)
    record.type = drop.type
    record.scope_id = drop.scope_id
    record.revision += 1
    record.key_id = drop.key_id
    record.ciphertext = body.ciphertext
    record.deleted = False
    record.drop_id = drop.id
    record.seq = account.seq
    record.updated_at = utcnow()
    drop.writes += 1
    db.commit()
    return DropWriteOut(remaining_writes=drop.max_writes - drop.writes)


# --- grants (external readers) -----------------------------------------------


@router.post("/grants", status_code=201, response_model=GrantCreated)
def create_grant(
    body: GrantIn, request: Request, principal: Principal = Depends(require_owner), db: Session = Depends(get_db)
) -> GrantCreated:
    _lock_account(db, principal.account_id)
    active = db.scalar(
        select(func.count()).select_from(Grant).where(Grant.account_id == principal.account_id, Grant.revoked_at.is_(None))
    )
    if active >= request.app.state.settings.max_grants:
        raise HTTPException(409, {"error": "too_many_grants"})
    grant = Grant(
        id=str(uuid.uuid4()),
        account_id=principal.account_id,
        scope_id=body.scope_id,
        label=body.label,
        recipient_public_key=body.recipient_public_key,
        wrapped_scope_key=body.wrapped_scope_key,
    )
    plaintext, key_hash = generate_api_key()
    db.add(grant)
    db.flush()
    db.add(
        ApiKey(
            id=str(uuid.uuid4()),
            account_id=principal.account_id,
            key_hash=key_hash,
            role="reader",
            grant_id=grant.id,
            label=body.label,
        )
    )
    db.commit()
    return GrantCreated(grant_id=grant.id, api_key=plaintext)


@router.get("/grants", response_model=list[GrantOut])
def list_grants(principal: Principal = Depends(require_owner), db: Session = Depends(get_db)) -> list[Grant]:
    return list(db.scalars(select(Grant).where(Grant.account_id == principal.account_id).order_by(Grant.created_at)))


@router.get("/grants/me", response_model=GrantMe)
def my_grant(principal: Principal = Depends(get_principal)) -> GrantMe:
    if principal.grant is None:
        raise HTTPException(403, "Reader API key required")
    grant = principal.grant
    return GrantMe(
        grant_id=grant.id,
        scope_id=grant.scope_id,
        recipient_public_key=grant.recipient_public_key,
        wrapped_scope_key=grant.wrapped_scope_key,
    )


@router.delete("/grants/{grant_id}", status_code=204)
def revoke_grant(
    grant_id: str, principal: Principal = Depends(require_owner), db: Session = Depends(get_db)
) -> None:
    grant = db.get(Grant, grant_id)
    if grant is None or grant.account_id != principal.account_id:
        raise HTTPException(404, "Grant not found")
    now: datetime = utcnow()
    grant.revoked_at = grant.revoked_at or now
    for key in db.scalars(select(ApiKey).where(ApiKey.grant_id == grant.id, ApiKey.revoked_at.is_(None))):
        key.revoked_at = now
    db.commit()


# --- owner API keys (one per device) -----------------------------------------


@router.post("/keys", status_code=201, response_model=KeyCreated)
def create_key(
    body: KeyIn, request: Request, principal: Principal = Depends(require_owner), db: Session = Depends(get_db)
) -> KeyCreated:
    _lock_account(db, principal.account_id)
    active = db.scalar(
        select(func.count()).select_from(ApiKey).where(
            ApiKey.account_id == principal.account_id, ApiKey.role == "owner", ApiKey.revoked_at.is_(None)
        )
    )
    if active >= request.app.state.settings.max_devices:
        raise HTTPException(409, {"error": "too_many_devices"})
    plaintext, key_hash = generate_api_key()
    key = ApiKey(
        id=str(uuid.uuid4()),
        account_id=principal.account_id,
        key_hash=key_hash,
        role="owner",
        label=body.label,
    )
    db.add(key)
    db.commit()
    return KeyCreated(id=key.id, api_key=plaintext)


@router.get("/keys", response_model=list[KeyOut])
def list_keys(principal: Principal = Depends(require_owner), db: Session = Depends(get_db)) -> list[ApiKey]:
    return list(
        db.scalars(
            select(ApiKey)
            .where(ApiKey.account_id == principal.account_id, ApiKey.role == "owner")
            .order_by(ApiKey.created_at)
        )
    )


@router.delete("/keys/{key_id}", status_code=204)
def revoke_key(key_id: str, principal: Principal = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    key = db.get(ApiKey, key_id)
    if key is None or key.account_id != principal.account_id or key.role != "owner":
        raise HTTPException(404, "Key not found")
    key.revoked_at = key.revoked_at or utcnow()
    db.commit()
