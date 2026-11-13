"""TOTP two-factor login: secret, pending secret, replay step and recovery code hashes."""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    with op.batch_alter_table("accounts") as batch:
        batch.add_column(sa.Column("totp_secret", sa.String(64)))
        batch.add_column(sa.Column("totp_pending_secret", sa.String(64)))
        batch.add_column(sa.Column("totp_last_step", sa.BigInteger()))
        batch.add_column(sa.Column("totp_recovery_hashes", sa.Text()))


def downgrade() -> None:
    raise NotImplementedError("Forward-only: restore from backup instead")
