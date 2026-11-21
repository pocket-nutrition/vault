from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, make_url, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

BASELINE_REVISION = "0001"
# Arbitrary constant: serialises migrations across instances that start at the same time (a rolling update).
_MIGRATION_LOCK_ID = 727_274_001


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite") and ":memory:" in database_url:
        # One shared connection, otherwise every session would see its own empty database.
        return create_engine(database_url, poolclass=StaticPool, connect_args={"check_same_thread": False})
    url = make_url(database_url)
    if url.drivername == "postgresql":
        # SQLAlchemy 2.1 maps a bare postgresql:// URL to psycopg 3; the image ships psycopg2.
        url = url.set(drivername="postgresql+psycopg2")
    return create_engine(url, pool_pre_ping=True)


def run_migrations(engine: Engine) -> None:
    """Bring the database to the latest schema. Runs at startup; keep replicas at 1 or run it as a one-off step."""
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            # Held until this transaction ends: a second instance starting at the same time waits here, then
            # finds the schema already current instead of racing on the same ALTER TABLE.
            connection.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _MIGRATION_LOCK_ID})
        config.attributes["connection"] = connection
        tables = inspect(connection).get_table_names()
        if "accounts" in tables and "alembic_version" not in tables:
            # The one database that predates Alembic is exactly the 0001 schema: adopt it in place.
            command.stamp(config, BASELINE_REVISION)
        command.upgrade(config, "head")
