"""Store the risk score per scan (#59) instead of computing it from the findings on every request.

Existing finished scans (completed or partial) get their score here, with the rules of
Scan.computed_risk(): a partial scan, a module run with warnings or a placeholder finding
makes the score incomplete. Running, queued and failed scans keep null, as before.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-12 10:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from qnsentry.risk import METHOD, compute_risk

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('risk_score', sa.Integer(), nullable=True))
    op.add_column('scans', sa.Column('risk_level', sa.String(length=16), nullable=True))
    op.add_column('scans', sa.Column('risk_complete', sa.Boolean(), nullable=True))
    op.add_column('scans', sa.Column('risk_points', sa.Integer(), nullable=True))
    op.add_column('scans', sa.Column('risk_method', sa.Integer(), nullable=True))

    connection = op.get_bind()
    scans = connection.execute(sa.text(
        "SELECT id, status = 'completed' AS completed,"
        " EXISTS (SELECT 1 FROM module_runs r WHERE r.scan_id = s.id AND jsonb_array_length(r.warnings) > 0) AS warned,"
        " EXISTS (SELECT 1 FROM findings f WHERE f.scan_id = s.id AND f.type = 'placeholder') AS placeholder"
        " FROM scans s WHERE status IN ('completed', 'partial')"
    )).all()
    for scan in scans:
        severities = connection.execute(
            sa.text("SELECT severity FROM findings WHERE scan_id = :id"), {"id": scan.id}
        ).scalars()
        risk = compute_risk(severities, complete=scan.completed and not scan.warned and not scan.placeholder)
        connection.execute(
            sa.text(
                "UPDATE scans SET risk_score = :score, risk_level = :level, risk_complete = :complete,"
                " risk_points = :points, risk_method = :method WHERE id = :id"
            ),
            {"score": risk.score, "level": risk.level, "complete": risk.complete,
             "points": risk.points, "method": METHOD, "id": scan.id},
        )


def downgrade() -> None:
    op.drop_column('scans', 'risk_method')
    op.drop_column('scans', 'risk_points')
    op.drop_column('scans', 'risk_complete')
    op.drop_column('scans', 'risk_level')
    op.drop_column('scans', 'risk_score')
