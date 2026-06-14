"""Add must_change_password flag to members.

Revision ID: 005
Revises: 004
Create Date: 2026-06-14
"""
from typing import Sequence, Union
from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE members ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1
    """)


def downgrade() -> None:
    pass  # SQLite cannot drop columns
