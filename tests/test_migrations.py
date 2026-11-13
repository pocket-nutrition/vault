import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic import command
from alembic.config import Config

from app.db import make_engine, run_migrations
from app.models import Base


def test_migrations_match_the_models():
    """Fails when someone edits models.py without writing a migration (how prod broke once)."""
    engine = make_engine("sqlite:///:memory:")
    run_migrations(engine)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_database_deployed_before_alembic_is_adopted_in_place(tmp_path):
    """Production was created from the 0001 schema by create_all; it must upgrade without data loss."""
    engine = make_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    config = Config()
    config.set_main_option("script_location", "app/migrations")
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, "0001")
        conn.execute(sa.text("DROP TABLE alembic_version"))  # as if Alembic never ran
        conn.execute(sa.text("INSERT INTO accounts (id, created_at, seq, keyring_version) VALUES ('acc-1', '2026-10-21 00:00:00', 7, 0)"))

    run_migrations(engine)

    with engine.connect() as conn:
        columns = {c["name"] for c in sa.inspect(conn).get_columns("accounts")}
        assert {"username", "auth_digest", "locked_until"} <= columns
        assert conn.execute(sa.text("SELECT seq FROM accounts WHERE id='acc-1'")).scalar_one() == 7
        assert "drops" in sa.inspect(conn).get_table_names()


def test_running_migrations_twice_is_a_no_op():
    engine = make_engine("sqlite:///:memory:")
    run_migrations(engine)
    run_migrations(engine)


def test_database_that_already_has_the_drops_table_is_upgraded(tmp_path):
    """The exact state of the deployed database: 0001 plus a drops table from an old create_all."""
    engine = make_engine(f"sqlite:///{tmp_path / 'hybrid.db'}")
    config = Config()
    config.set_main_option("script_location", "app/migrations")
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, "0001")
        Base.metadata.tables["drops"].create(conn)
        conn.execute(sa.text("DROP TABLE alembic_version"))

    run_migrations(engine)

    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert "drop_id" in {c["name"] for c in inspector.get_columns("api_keys")}
        assert "drop_id" in {c["name"] for c in inspector.get_columns("records")}
