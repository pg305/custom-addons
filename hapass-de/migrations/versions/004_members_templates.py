"""Add templates, members, and member_sessions tables.

Revision ID: 004
Revises: 003
Create Date: 2026-06-14
"""
from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS templates (
            id               TEXT PRIMARY KEY,
            name             TEXT UNIQUE NOT NULL,
            entity_ids       TEXT NOT NULL DEFAULT '[]',
            allowed_weekdays TEXT
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id            TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            template_id   TEXT REFERENCES templates(id) ON DELETE SET NULL,
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    INTEGER NOT NULL
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS member_sessions (
            id          TEXT PRIMARY KEY,
            member_id   TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_members_username ON members(username)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_member_sessions_member ON member_sessions(member_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_member_sessions_expires ON member_sessions(expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS member_sessions")
    op.execute("DROP TABLE IF EXISTS members")
    op.execute("DROP TABLE IF EXISTS templates")
