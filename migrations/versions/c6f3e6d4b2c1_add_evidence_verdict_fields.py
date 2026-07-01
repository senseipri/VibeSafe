"""add_evidence_verdict_fields

Revision ID: c6f3e6d4b2c1
Revises: a433f3a7ad37
Create Date: 2026-06-13 18:30:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c6f3e6d4b2c1"
down_revision: Union[str, None] = "a433f3a7ad37"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_findings",
        sa.Column("status", sa.String(length=20), nullable=False, server_default="candidate"),
    )
    op.add_column(
        "scan_findings",
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_findings",
        sa.Column("evidence_refs", postgresql.JSON(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("proof", postgresql.JSON(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("validator", sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_findings", "validator")
    op.drop_column("scan_findings", "cvss_vector")
    op.drop_column("scan_findings", "proof")
    op.drop_column("scan_findings", "evidence_refs")
    op.drop_column("scan_findings", "confidence")
    op.drop_column("scan_findings", "status")
