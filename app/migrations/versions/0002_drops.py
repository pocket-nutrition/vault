"""Write-only drop tokens.

Idempotent on purpose: one deployed database already has the `drops` table (an earlier build
created it with create_all) but not the two drop_id columns.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"


def _columns(inspector: sa.Inspector, table: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())

    if "drops" not in inspector.get_table_names():
        op.create_table(
            "drops",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("account_id", sa.String(36), sa.ForeignKey("accounts.id"), nullable=False),
            sa.Column("record_id", sa.String(64), nullable=False),
            sa.Column("type", sa.String(64), nullable=False),
            sa.Column("scope_id", sa.String(64)),
            sa.Column("key_id", sa.String(128), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("max_writes", sa.Integer(), nullable=False),
            sa.Column("writes", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_drops_account_id", "drops", ["account_id"])
        op.create_index("ux_drops_account_record", "drops", ["account_id", "record_id"], unique=True)

    if "drop_id" not in _columns(inspector, "api_keys"):
        with op.batch_alter_table("api_keys") as batch:
            batch.add_column(sa.Column("drop_id", sa.String(36)))
            batch.create_foreign_key("fk_api_keys_drop_id", "drops", ["drop_id"], ["id"])
    if "drop_id" not in _columns(inspector, "records"):
        op.add_column("records", sa.Column("drop_id", sa.String(36)))


def downgrade() -> None:
    raise NotImplementedError("Forward-only: restore from backup instead")
