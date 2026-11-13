from alembic import context

from app.models import Base

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Migrations are run by app.db.run_migrations(), which supplies the connection")

context.configure(connection=connection, target_metadata=Base.metadata, render_as_batch=True)
with context.begin_transaction():
    context.run_migrations()
