"""Initial schema: the tables create_all made before Alembic was introduced.

The status and severity columns get their CHECK constraint from sa.Enum(create_constraint=True).

Revision ID: 0001
Revises:
Create Date: 2026-10-01 12:07:35.430398
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('clients',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('domains',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('client_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=253), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('scans',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('domain_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('queued', 'running', 'completed', 'partial', 'failed', name='scanstatus', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('context', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('module', sa.String(length=50), nullable=False),
    sa.Column('type', sa.String(length=50), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', sa.Enum('info', 'low', 'medium', 'high', 'critical', name='severity', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('asset', sa.Text(), nullable=False),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('module_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('module', sa.String(length=50), nullable=False),
    sa.Column('status', sa.Enum('pending', 'running', 'completed', 'failed', name='modulestatus', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('finding_count', sa.Integer(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('module_runs')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('domains')
    op.drop_table('clients')
