"""Username + password login, KDF settings and brute-force lockout."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"


def upgrade() -> None:
    with op.batch_alter_table("accounts") as batch:
        batch.add_column(sa.Column("username", sa.String(64)))
        batch.add_column(sa.Column("kdf", sa.Text()))
        batch.add_column(sa.Column("auth_digest", sa.String(256)))
        batch.add_column(sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("locked_until", sa.DateTime(timezone=True)))
    op.create_index("ux_accounts_username", "accounts", ["username"], unique=True)


def downgrade() -> None:
    raise NotImplementedError("Forward-only: restore from backup instead")
