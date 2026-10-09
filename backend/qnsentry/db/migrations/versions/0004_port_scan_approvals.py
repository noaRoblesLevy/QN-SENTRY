"""Port scan approvals (#81): the addresses of a domain the user confirmed may be port-scanned.

New table, so existing domains start without approvals: no address is scanned until it is confirmed.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-08 12:22:02.269723
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('port_scan_approvals',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('domain_id', sa.Integer(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('approved_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('domain_id', 'ip')
    )


def downgrade() -> None:
    op.drop_table('port_scan_approvals')
