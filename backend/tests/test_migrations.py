import pytest
from alembic.script import ScriptDirectory

from qnsentry.db.migrate import INITIAL_REVISION, INITIAL_TABLES, alembic_config, needs_stamp


def test_migrations_form_one_line():
    """Two branches that both add a migration after the same one give two heads,
    and `alembic upgrade head` then fails: renumber one of them before merging."""
    script = ScriptDirectory.from_config(alembic_config())
    assert len(script.get_heads()) == 1


def test_initial_revision_exists():
    script = ScriptDirectory.from_config(alembic_config())
    assert script.get_revision(INITIAL_REVISION).down_revision is None


def test_initial_tables_match_the_first_migration():
    # If the first migration ever changes, needs_stamp must follow
    source = ScriptDirectory.from_config(alembic_config()).get_revision(INITIAL_REVISION).path
    with open(source, encoding="utf-8") as migration:
        created = {line.split("'")[1] for line in migration if "op.create_table(" in line}
    assert created == INITIAL_TABLES


def test_empty_database_is_upgraded_not_stamped():
    assert needs_stamp(set()) is False


def test_database_made_by_create_all_is_stamped():
    assert needs_stamp(set(INITIAL_TABLES)) is True


def test_database_with_migration_history_is_not_stamped():
    assert needs_stamp(set(INITIAL_TABLES) | {"alembic_version"}) is False


def test_other_tables_do_not_count():
    # e.g. a table someone created by hand in the same database
    assert needs_stamp({"notes"}) is False


def test_database_with_only_some_tables_is_refused():
    with pytest.raises(RuntimeError, match="missing: findings, module_runs"):
        needs_stamp({"clients", "domains", "scans"})
