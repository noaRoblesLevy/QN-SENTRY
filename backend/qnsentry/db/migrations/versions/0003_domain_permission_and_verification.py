"""Permission (#3) and ownership verification (#48) of domains.

Existing domains get no exception: both columns start empty, so after the upgrade a
domain added earlier (e.g. badsecurityinc.be) can only be scanned again once the user has
confirmed permission in the dashboard and the TXT record has been verified. Marking them
as confirmed or verified here would skip exactly the checks this migration introduces.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-01 16:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('domains', sa.Column('permission_confirmed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('domains', sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('domains', 'verified_at')
    op.drop_column('domains', 'permission_confirmed_at')
