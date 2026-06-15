"""Add member_label to access_log for member activity tracking.

Revision ID: 006
Revises: 005
Create Date: 2026-06-15
"""
from typing import Sequence, Union
from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE access_log ADD COLUMN member_label TEXT
    """)


def downgrade() -> None:
    pass  # SQLite cannot drop columns
