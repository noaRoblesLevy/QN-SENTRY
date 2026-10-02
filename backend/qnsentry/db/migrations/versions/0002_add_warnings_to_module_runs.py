"""Add warnings to module runs (#32): parts of a module that failed while it still had results.

Existing module runs get an empty list through the server default.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-01 12:54:58.640609
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'module_runs',
        sa.Column('warnings', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column('module_runs', 'warnings')
