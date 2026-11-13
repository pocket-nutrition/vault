from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Per-account change counter; the sync cursor. Bumped under a row lock on every write.
    seq: Mapped[int] = mapped_column(BigInteger, default=0)
    # Opaque client-built blob (wrapped user key + KDF params). The server never parses it.
    keyring: Mapped[str | None] = mapped_column(Text, nullable=True)
    keyring_version: Mapped[int] = mapped_column(Integer, default=0)
    # Password login (NULL for accounts created by the admin endpoint, which use an API key only).
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # JSON {alg, salt, opslimit, memlimit}: the client's KDF settings, served back at prelogin.
    kdf: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Argon2id of the client-derived auth hash. The server never sees the password or the wrap key.
    auth_digest: Mapped[str | None] = mapped_column(String(256), nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Two-factor login (TOTP). Authentication material, not an encryption key: it only gates linking a
    # new device and decrypts nothing. Base32 secrets; NULL totp_secret means 2FA is off.
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Set by /two-factor/setup, promoted to totp_secret once the user proves the app shows valid codes.
    totp_pending_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Last accepted time step: codes for this step or earlier are refused (replay protection).
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # JSON list of SHA-256 hex digests of the unused recovery codes.
    totp_recovery_hashes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ux_accounts_username", "username", unique=True),)


class Grant(Base):
    __tablename__ = "grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(128))
    recipient_public_key: Mapped[str] = mapped_column(String(128))
    wrapped_scope_key: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Drop(Base):
    """A write-only, short-lived slot: lets a third party deposit one sealed record and nothing else."""

    __tablename__ = "drops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    record_id: Mapped[str] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(64))
    scope_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_id: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_writes: Mapped[int] = mapped_column(Integer)
    writes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ux_drops_account_record", "account_id", "record_id", unique=True),)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    # SHA-256 of the key; the key itself is shown once at creation and never stored.
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(16))  # "owner" | "reader" | "dropper"
    grant_id: Mapped[str | None] = mapped_column(ForeignKey("grants.id"), nullable=True)
    drop_id: Mapped[str | None] = mapped_column(ForeignKey("drops.id"), nullable=True)
    label: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Record(Base):
    __tablename__ = "records"

    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), primary_key=True)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str] = mapped_column(String(64))
    scope_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revision: Mapped[int] = mapped_column(Integer)
    key_id: Mapped[str] = mapped_column(String(128))
    # base64(nonce || AEAD ciphertext); empty for tombstones.
    ciphertext: Mapped[str] = mapped_column(Text, default="")
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Set while the record is still owned by a drop; any owner write clears it.
    drop_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_records_account_seq", "account_id", "seq"),)
