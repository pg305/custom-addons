"""SQLite database setup and CRUD operations.

Note: Uses a single aiosqlite connection for all operations. This serializes
all DB access (reads block writes and vice versa), which is acceptable at
homelab scale with low concurrent users. For higher concurrency, consider
connection pooling or switching to PostgreSQL.
"""
import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import aiosqlite

from app.config import settings
logger = logging.getLogger(__name__)

_db: aiosqlite.Connection | None = None
_lock = asyncio.Lock()


def run_migrations() -> None:
    """Run Alembic migrations synchronously (called before the async event loop)."""
    from alembic.config import Config
    from alembic import command

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{settings.db_path}")
    command.upgrade(cfg, "head")


async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        async with _lock:
            if _db is None:
                _db = await aiosqlite.connect(settings.db_path)
                _db.row_factory = aiosqlite.Row
                await _db.execute("PRAGMA journal_mode=WAL")
                await _db.execute("PRAGMA foreign_keys=ON")
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        try:
            await _db.close()
        except Exception as exc:
            logger.warning("Error closing database: %s", exc)
        _db = None


# ---------------------------------------------------------------------------
# Admin sessions
# ---------------------------------------------------------------------------

async def create_admin_session(ttl_seconds: int) -> str:
    db = await get_db()
    session_id = uuid.uuid4().hex + uuid.uuid4().hex  # 64-char hex
    now = int(time.time())
    await db.execute(
        "INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)",
        (session_id, now, now + ttl_seconds),
    )
    await db.commit()
    return session_id


async def get_admin_session(session_id: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM admin_sessions WHERE id = ? AND expires_at > ?",
        (session_id, int(time.time())),
    ) as cur:
        return await cur.fetchone()


async def delete_admin_session(session_id: str) -> None:
    db = await get_db()
    await db.execute("DELETE FROM admin_sessions WHERE id = ?", (session_id,))
    await db.commit()


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

async def create_token(
    label: str,
    slug: str,
    entity_ids: list[str],
    expires_at: int,
    ip_allowlist: list[str] | None,
    allowed_weekdays: list[int] | None = None,
) -> dict[str, Any]:
    db = await get_db()
    token_id = str(uuid.uuid4())
    now = int(time.time())
    ip_json = json.dumps(ip_allowlist) if ip_allowlist else None
    weekdays_json = json.dumps(sorted(set(allowed_weekdays))) if allowed_weekdays else None

    # Deduplicate entity IDs
    entity_ids = list(dict.fromkeys(entity_ids))

    try:
        await db.execute("BEGIN IMMEDIATE")
        await db.execute(
            """INSERT INTO tokens
               (id, slug, label, created_at, expires_at, ip_allowlist, allowed_weekdays)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (token_id, slug, label, now, expires_at, ip_json, weekdays_json),
        )
        if entity_ids:
            await db.executemany(
                "INSERT INTO token_entities (token_id, entity_id) VALUES (?, ?)",
                [(token_id, eid) for eid in entity_ids],
            )
        await db.execute("COMMIT")
    except Exception:
        await db.execute("ROLLBACK")
        raise
    return await get_token_by_id(token_id)  # type: ignore[return-value]


async def get_token_by_slug(slug: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM tokens WHERE slug = ?", (slug,)) as cur:
        return await cur.fetchone()


async def get_token_by_id(token_id: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM tokens WHERE id = ?", (token_id,)) as cur:
        return await cur.fetchone()


async def list_tokens() -> list[aiosqlite.Row]:
    db = await get_db()
    async with db.execute(
        """SELECT t.*, COUNT(te.entity_id) AS entity_count
           FROM tokens t
           LEFT JOIN token_entities te ON te.token_id = t.id
           GROUP BY t.id
           ORDER BY t.created_at DESC"""
    ) as cur:
        return await cur.fetchall()


async def get_token_entities(token_id: str) -> list[str]:
    db = await get_db()
    async with db.execute(
        "SELECT entity_id FROM token_entities WHERE token_id = ?", (token_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [r["entity_id"] for r in rows]


async def update_token_entities(token_id: str, entity_ids: list[str]) -> None:
    db = await get_db()
    # Deduplicate entity IDs
    entity_ids = list(dict.fromkeys(entity_ids))
    try:
        await db.execute("BEGIN IMMEDIATE")
        await db.execute("DELETE FROM token_entities WHERE token_id = ?", (token_id,))
        await db.executemany(
            "INSERT INTO token_entities (token_id, entity_id) VALUES (?, ?)",
            [(token_id, eid) for eid in entity_ids],
        )
        await db.execute("COMMIT")
    except Exception:
        await db.execute("ROLLBACK")
        raise


async def update_token_weekdays(token_id: str, allowed_weekdays: list[int] | None) -> None:
    db = await get_db()
    weekdays_json = json.dumps(sorted(set(allowed_weekdays))) if allowed_weekdays else None
    await db.execute(
        "UPDATE tokens SET allowed_weekdays = ? WHERE id = ?",
        (weekdays_json, token_id),
    )
    await db.commit()


async def update_token_expiry(token_id: str, expires_at: int) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE tokens SET expires_at = ? WHERE id = ?",
        (expires_at, token_id),
    )
    await db.commit()


async def revoke_token(token_id: str) -> None:
    db = await get_db()
    await db.execute("UPDATE tokens SET revoked = 1 WHERE id = ?", (token_id,))
    await db.commit()


async def unrevoke_token(token_id: str) -> None:
    db = await get_db()
    await db.execute("UPDATE tokens SET revoked = 0 WHERE id = ?", (token_id,))
    await db.commit()


async def delete_token(token_id: str) -> None:
    db = await get_db()
    # Nullify access_log references before deleting to avoid FK constraint
    # failures on databases where the ON DELETE SET NULL clause is missing.
    await db.execute("UPDATE access_log SET token_id = NULL WHERE token_id = ?", (token_id,))
    await db.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
    await db.commit()


async def touch_token(token_id: str) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE tokens SET last_accessed = ? WHERE id = ?",
        (int(time.time()), token_id),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Access log
# ---------------------------------------------------------------------------

async def log_access(
    token_id: str,
    event_type: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    entity_id: str | None = None,
    service: str | None = None,
) -> None:
    db = await get_db()
    await db.execute(
        """INSERT INTO access_log
           (token_id, timestamp, event_type, entity_id, service, ip_address, user_agent)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (token_id, int(time.time()), event_type, entity_id, service, ip_address, user_agent),
    )
    # Single-write commit is acceptable at homelab scale; batch for high throughput
    await db.commit()


async def list_access_logs(limit: int = 50) -> list[aiosqlite.Row]:
    db = await get_db()
    async with db.execute(
        """SELECT al.timestamp, al.event_type, al.entity_id, al.service,
                  al.ip_address, t.label AS token_label
           FROM access_log al
           LEFT JOIN tokens t ON t.id = al.token_id
           ORDER BY al.timestamp DESC, al.id DESC
           LIMIT ?""",
        (limit,),
    ) as cur:
        return await cur.fetchall()


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

async def create_template(name: str, entity_ids: list[str], allowed_weekdays: list[int] | None) -> dict:
    db = await get_db()
    template_id = str(uuid.uuid4())
    entity_ids = list(dict.fromkeys(entity_ids))
    wd_json = json.dumps(sorted(set(allowed_weekdays))) if allowed_weekdays else None
    await db.execute(
        "INSERT INTO templates (id, name, entity_ids, allowed_weekdays) VALUES (?, ?, ?, ?)",
        (template_id, name, json.dumps(entity_ids), wd_json),
    )
    await db.commit()
    return await get_template_by_id(template_id)  # type: ignore[return-value]


async def get_template_by_id(template_id: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM templates WHERE id = ?", (template_id,)) as cur:
        return await cur.fetchone()


async def list_templates() -> list[aiosqlite.Row]:
    db = await get_db()
    async with db.execute("SELECT * FROM templates ORDER BY name") as cur:
        return await cur.fetchall()


async def update_template(template_id: str, name: str, entity_ids: list[str], allowed_weekdays: list[int] | None) -> None:
    db = await get_db()
    entity_ids = list(dict.fromkeys(entity_ids))
    wd_json = json.dumps(sorted(set(allowed_weekdays))) if allowed_weekdays else None
    await db.execute(
        "UPDATE templates SET name = ?, entity_ids = ?, allowed_weekdays = ? WHERE id = ?",
        (name, json.dumps(entity_ids), wd_json, template_id),
    )
    await db.commit()


async def delete_template(template_id: str) -> None:
    db = await get_db()
    await db.execute("DELETE FROM templates WHERE id = ?", (template_id,))
    await db.commit()


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

async def create_member(username: str, password_hash: str, template_id: str | None) -> aiosqlite.Row:
    db = await get_db()
    member_id = str(uuid.uuid4())
    now = int(time.time())
    await db.execute(
        "INSERT INTO members (id, username, password_hash, template_id, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
        (member_id, username, password_hash, template_id, now),
    )
    await db.commit()
    return await get_member_by_id(member_id)  # type: ignore[return-value]


async def get_member_by_id(member_id: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM members WHERE id = ?", (member_id,)) as cur:
        return await cur.fetchone()


async def get_member_by_username(username: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM members WHERE username = ?", (username,)) as cur:
        return await cur.fetchone()


async def list_members() -> list[aiosqlite.Row]:
    db = await get_db()
    async with db.execute(
        """SELECT m.*, t.name AS template_name
           FROM members m
           LEFT JOIN templates t ON t.id = m.template_id
           ORDER BY m.username"""
    ) as cur:
        return await cur.fetchall()


async def update_member(
    member_id: str,
    *,
    username: str | None = None,
    password_hash: str | None = None,
    template_id: str | None | type[...] = ...,
    active: bool | None = None,
) -> None:
    db = await get_db()
    fields: list[str] = []
    params: list[Any] = []
    if username is not None:
        fields.append("username = ?")
        params.append(username)
    if password_hash is not None:
        fields.append("password_hash = ?")
        params.append(password_hash)
    if template_id is not ...:
        fields.append("template_id = ?")
        params.append(template_id)
    if active is not None:
        fields.append("active = ?")
        params.append(1 if active else 0)
    if not fields:
        return
    params.append(member_id)
    await db.execute(f"UPDATE members SET {', '.join(fields)} WHERE id = ?", params)
    await db.commit()


async def delete_member(member_id: str) -> None:
    db = await get_db()
    await db.execute("DELETE FROM members WHERE id = ?", (member_id,))
    await db.commit()


# ---------------------------------------------------------------------------
# Member sessions
# ---------------------------------------------------------------------------

MEMBER_SESSION_TTL = 86400 * 30  # 30 days


async def create_member_session(member_id: str) -> str:
    db = await get_db()
    session_id = uuid.uuid4().hex + uuid.uuid4().hex
    now = int(time.time())
    await db.execute(
        "INSERT INTO member_sessions (id, member_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (session_id, member_id, now, now + MEMBER_SESSION_TTL),
    )
    await db.commit()
    return session_id


async def get_member_session(session_id: str) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute(
        """SELECT ms.*, m.id AS member_id, m.username, m.template_id, m.active
           FROM member_sessions ms
           JOIN members m ON m.id = ms.member_id
           WHERE ms.id = ? AND ms.expires_at > ?""",
        (session_id, int(time.time())),
    ) as cur:
        return await cur.fetchone()


async def delete_member_session(session_id: str) -> None:
    db = await get_db()
    await db.execute("DELETE FROM member_sessions WHERE id = ?", (session_id,))
    await db.commit()


async def cleanup_old_data(retention_days: int) -> None:
    """Delete old access_log rows and expired admin sessions.

    Guest tokens are intentionally retained until an admin deletes them so
    expired or revoked links can be renewed with the same entities and slug.
    """
    db = await get_db()
    now = int(time.time())
    cutoff = now - (retention_days * 86400)
    await db.execute("DELETE FROM access_log WHERE timestamp < ?", (cutoff,))
    await db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now,))
    await db.execute("DELETE FROM member_sessions WHERE expires_at < ?", (now,))
    await db.commit()
