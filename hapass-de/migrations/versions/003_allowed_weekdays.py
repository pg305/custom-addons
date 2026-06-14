"""Add allowed_weekdays to tokens.

Revision ID: 003
Revises: 002
Create Date: 2026-06-14
"""
from typing import Sequence, Union
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # NULL means all days are allowed; JSON array of ints (0=Mo ... 6=So) otherwise.
    op.execute("ALTER TABLE tokens ADD COLUMN allowed_weekdays TEXT")


def downgrade() -> None:
    # SQLite does not support DROP COLUMN in older versions; recreate is the safe path.
    op.execute("""
        CREATE TABLE tokens_backup AS
        SELECT id, slug, label, created_at, expires_at, revoked,
               last_accessed, rate_limit_rpm, ip_allowlist
        FROM tokens
    """)
    op.execute("DROP TABLE tokens")
    op.execute("ALTER TABLE tokens_backup RENAME TO tokens")
