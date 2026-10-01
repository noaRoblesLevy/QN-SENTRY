"""Bring the database schema up to date with the Alembic migrations.

Run by the "migrate" service in docker-compose.yml before the API and worker start:

    python -m qnsentry.db.migrate

Databases created before Alembic (by create_all) already have the tables of the first
migration but no alembic_version table. Those are stamped at the first migration
instead of creating the tables again, so their data is kept.

Run it before starting the API or worker outside Docker as well: they no longer create
tables themselves.
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
# The tables of that migration
INITIAL_TABLES = frozenset({"clients", "domains", "scans", "module_runs", "findings"})


def needs_stamp(tables: set[str]) -> bool:
    """True for a database created by create_all before Alembic: it has all the tables of
    the first migration but no alembic_version table.

    A database with only some of those tables is not something create_all made: stamping
    it would make the next upgrade fail on the missing tables, so it is refused instead.
    """
    if "alembic_version" in tables:
        return False
    existing = tables & INITIAL_TABLES
    if not existing:
        return False
    if existing != INITIAL_TABLES:
        missing = ", ".join(sorted(INITIAL_TABLES - existing))
        raise RuntimeError(
            f"The database has only some of the QN-Sentry tables (missing: {missing}) and no "
            "migration history. Restore it from a backup or start with an empty database."
        )
    return True


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

    if needs_stamp(tables):
        log.info("Existing database without migrations: marking it as revision %s", INITIAL_REVISION)
        command.stamp(config, INITIAL_REVISION)

    command.upgrade(config, "head")
    log.info("Database schema is up to date")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    migrate()
