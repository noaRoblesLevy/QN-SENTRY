"""Bring the database schema up to date with the Alembic migrations.

Run by the "migrate" service in docker-compose.yml before the API and worker start:

    python -m qnsentry.db.migrate

Databases created before Alembic (by create_all) already have the tables of the first
migration but no alembic_version table. Those are stamped at the first migration
instead of creating the tables again, so their data is kept.
"""

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

log = logging.getLogger(__name__)

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
# The migration that matches the schema create_all used to make
INITIAL_REVISION = "0001"


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    return config


def migrate() -> None:
    # Imported here so alembic_config() works without database settings (tests)
    from qnsentry.db.session import engine

    config = alembic_config()
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())

    if "alembic_version" not in tables and "scans" in tables:
        log.info("Existing database without migrations: marking it as revision %s", INITIAL_REVISION)
        command.stamp(config, INITIAL_REVISION)

    command.upgrade(config, "head")
    log.info("Database schema is up to date")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    migrate()
