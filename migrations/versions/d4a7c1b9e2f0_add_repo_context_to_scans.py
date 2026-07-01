"""add_repo_context_to_scans

Revision ID: d4a7c1b9e2f0
Revises: c6f3e6d4b2c1
Create Date: 2026-06-20 16:40:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4a7c1b9e2f0"
down_revision: Union[str, None] = "a8fbb027b070"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "repo_context",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "repo_context")
