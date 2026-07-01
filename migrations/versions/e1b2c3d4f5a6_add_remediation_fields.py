"""add_remediation_fields_to_scan_findings

Revision ID: e1b2c3d4f5a6
Revises: d4a7c1b9e2f0
Create Date: 2026-06-29 17:00:00.000000

Adds three new columns to scan_findings:
  - recommendation  TEXT NOT NULL DEFAULT ''
  - fix             TEXT NOT NULL DEFAULT ''
  - fix_source      VARCHAR(30) NOT NULL DEFAULT ''

These carry actionable remediation guidance for every non-rejected finding.
fix_source records the provenance of the content:
  'static_table'  — built-in category lookup (always available)
  'llm_kimi'      — Kimi K2 LLM returned recommendation/explanation
  'llm_fallback'  — LLM was available but static table was used as fallback
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e1b2c3d4f5a6"
down_revision: Union[str, None] = "d4a7c1b9e2f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_findings",
        sa.Column(
            "recommendation",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
    )
    op.add_column(
        "scan_findings",
        sa.Column(
            "fix",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
    )
    op.add_column(
        "scan_findings",
        sa.Column(
            "fix_source",
            sa.String(length=30),
            nullable=False,
            server_default="",
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_findings", "fix_source")
    op.drop_column("scan_findings", "fix")
    op.drop_column("scan_findings", "recommendation")
