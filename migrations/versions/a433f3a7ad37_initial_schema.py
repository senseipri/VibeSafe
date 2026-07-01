"""initial_schema

Revision ID: a433f3a7ad37
Revises:
Create Date: 2026-05-25 18:10:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a433f3a7ad37"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- scans table -------------------------------------------------------
    op.create_table(
        "scans",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("repo_url", sa.String(500), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("files_scanned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scan_ms", sa.Integer(), nullable=True),
        sa.Column("frameworks", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("models_used", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- scan_findings table -----------------------------------------------
    op.create_table(
        "scan_findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("file_path", sa.String(1000), nullable=False, server_default=""),
        sa.Column("line_number", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("attack_chain", sa.Text(), nullable=False, server_default=""),
        sa.Column("fix_code", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column(
            "confirmed_by",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("owasp_cat", sa.String(100), nullable=True),
        sa.Column(
            "false_positive_risk",
            sa.String(20),
            nullable=False,
            server_default="low",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Index on scan_findings.scan_id for fast lookups by scan
    op.create_index(
        op.f("ix_scan_findings_scan_id"),
        "scan_findings",
        ["scan_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_findings_scan_id"), table_name="scan_findings")
    op.drop_table("scan_findings")
    op.drop_table("scans")
