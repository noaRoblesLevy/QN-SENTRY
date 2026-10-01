from alembic.script import ScriptDirectory

from qnsentry.db.migrate import INITIAL_REVISION, alembic_config


def test_migrations_form_one_line():
    """Two branches that both add a migration after the same one give two heads,
    and `alembic upgrade head` then fails: renumber one of them before merging."""
    script = ScriptDirectory.from_config(alembic_config())
    assert len(script.get_heads()) == 1


def test_initial_revision_exists():
    script = ScriptDirectory.from_config(alembic_config())
    assert script.get_revision(INITIAL_REVISION).down_revision is None
