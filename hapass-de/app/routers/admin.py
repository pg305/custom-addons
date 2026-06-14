"""Admin API router."""
import asyncio
import ipaddress
import json
import secrets
import time
from typing import Any

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app import database as db
from app.auth import INGRESS_SENTINEL, SESSION_COOKIE, require_admin, verify_password
from app.config import settings
from app import ha_client
from app.models import (
    AdminLoginRequest,
    MemberCreateRequest,
    MemberUpdateRequest,
    NEVER_EXPIRES_SECONDS,
    SUPPORTED_DOMAINS,
    TemplateCreateRequest,
    TemplateUpdateRequest,
    TokenCreateRequest,
    TokenUpdateEntitiesRequest,
    TokenUpdateExpiryRequest,
    TokenUpdateWeekdaysRequest,
)
from app.rate_limiter import RateLimiter

router = APIRouter(prefix="/admin")

# Admin session lifetime — 24 hours, hardcoded like Uptime Kuma / Dockge.
ADMIN_SESSION_TTL = 86400

# CSRF: Admin routes are protected by SameSite=strict cookie. The slug-based
# guest auth acts as a bearer token — no additional CSRF token needed.

# M-24: Rate limiting on admin login (5 failed attempts/min/IP)
_login_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post("/login")
async def login(body: AdminLoginRequest, request: Request, response: Response) -> dict:
    if not settings.admin_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Login disabled — use HA sidebar")

    # Rate limit login attempts by IP
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    allowed = await _login_limiter.check(f"login:{client_ip}", 5)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    if body.username != settings.admin_username or not await verify_password(body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    is_https = (
        request.url.scheme == "https"
        or forwarded_proto == "https"
    )
    session_id = await db.create_admin_session(ttl_seconds=ADMIN_SESSION_TTL)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        secure=is_https,
        max_age=ADMIN_SESSION_TTL,
    )
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response, session_id: str = Depends(require_admin)) -> dict:
    if session_id == INGRESS_SENTINEL:
        return {"ok": True}
    await db.delete_admin_session(session_id)
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

def _row_to_response(row: Any, entity_ids: list[str] | None = None) -> dict:
    ip_raw = row["ip_allowlist"]
    ip_list = json.loads(ip_raw) if ip_raw else None
    wd_raw = row["allowed_weekdays"] if "allowed_weekdays" in row.keys() else None
    wd_list = json.loads(wd_raw) if wd_raw else None
    if entity_ids is not None:
        count = len(entity_ids)
    elif "entity_count" in row.keys():
        count = row["entity_count"]
    else:
        count = 0
    return {
        "id": row["id"],
        "slug": row["slug"],
        "label": row["label"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "revoked": bool(row["revoked"]),
        "last_accessed": row["last_accessed"],
        "ip_allowlist": ip_list,
        "allowed_weekdays": wd_list,
        "entity_count": count,
        "entity_ids": entity_ids,
    }


def _activity_row_to_response(row: Any) -> dict:
    return {
        "timestamp": row["timestamp"],
        "activity": row["event_type"],
        "token_label": row["token_label"],
        "target_entity_id": row["entity_id"],
        "service": row["service"],
        "ip_address": row["ip_address"],
    }


@router.get("/tokens")
async def list_tokens(_: str = Depends(require_admin)) -> list[dict]:
    rows = await db.list_tokens()
    return [_row_to_response(r) for r in rows]


@router.get("/activity")
async def list_activity(
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(require_admin),
) -> list[dict]:
    rows = await db.list_access_logs(limit=limit)
    return [_activity_row_to_response(r) for r in rows]


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def create_token(
    body: TokenCreateRequest,
    request: Request,
    _: str = Depends(require_admin),
) -> dict:
    # Validate IP CIDR list if provided
    if body.ip_allowlist:
        for cidr in body.ip_allowlist:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Invalid CIDR: {cidr}",
                )

    slug = body.slug or secrets.token_hex(16)
    if body.expires_in_seconds == NEVER_EXPIRES_SECONDS:
        expires_at = NEVER_EXPIRES_SECONDS
    else:
        expires_at = int(time.time()) + body.expires_in_seconds

    # Ensure slug uniqueness
    existing = await db.get_token_by_slug(slug)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Slug '{slug}' already exists",
        )

    row = await db.create_token(
        label=body.label,
        slug=slug,
        entity_ids=body.entity_ids,
        expires_at=expires_at,
        ip_allowlist=body.ip_allowlist,
        allowed_weekdays=body.allowed_weekdays,
    )
    entity_ids = await db.get_token_entities(row["id"])
    return _row_to_response(row, entity_ids)


@router.get("/tokens/{token_id}")
async def get_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    entity_ids = await db.get_token_entities(token_id)
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/entities")
async def update_token_entities(
    token_id: str,
    body: TokenUpdateEntitiesRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if row["revoked"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot edit entities on a revoked token",
        )
    await db.update_token_entities(token_id, body.entity_ids)
    await ha_client.invalidate_entity_cache(token_id)
    entity_ids = await db.get_token_entities(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/weekdays")
async def update_token_weekdays(
    token_id: str,
    body: TokenUpdateWeekdaysRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if body.allowed_weekdays is not None:
        for d in body.allowed_weekdays:
            if d < 0 or d > 6:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Wochentage müssen zwischen 0 (Mo) und 6 (So) liegen",
                )
    await db.update_token_weekdays(token_id, body.allowed_weekdays)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row)


@router.patch("/tokens/{token_id}/expiry")
async def update_token_expiry(
    token_id: str,
    body: TokenUpdateExpiryRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if body.expires_in_seconds == NEVER_EXPIRES_SECONDS:
        new_expires = NEVER_EXPIRES_SECONDS
    else:
        new_expires = int(time.time()) + body.expires_in_seconds
    await db.update_token_expiry(token_id, new_expires)
    # Un-revoke if the token was revoked (admin is explicitly renewing it)
    if row["revoked"]:
        await db.unrevoke_token(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.revoke_token(token_id)
    # Notify connected SSE clients
    if not row["revoked"]:
        await ha_client.broadcast_token_expired(token_id)
    return {"ok": True}


@router.delete("/tokens/{token_id}")
async def delete_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await ha_client.broadcast_token_expired(token_id)
    await db.delete_token(token_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Template management
# ---------------------------------------------------------------------------

def _template_to_response(row: Any) -> dict:
    wd_raw = row["allowed_weekdays"]
    wd_list = json.loads(wd_raw) if wd_raw else None
    ei_raw = row["entity_ids"]
    ei_list = json.loads(ei_raw) if ei_raw else []
    return {
        "id": row["id"],
        "name": row["name"],
        "entity_ids": ei_list,
        "allowed_weekdays": wd_list,
    }


def _validate_weekdays(days: list[int] | None) -> None:
    if days is None:
        return
    for d in days:
        if d < 0 or d > 6:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Wochentage müssen zwischen 0 (Mo) und 6 (So) liegen",
            )


@router.get("/templates")
async def list_templates(_: str = Depends(require_admin)) -> list[dict]:
    rows = await db.list_templates()
    return [_template_to_response(r) for r in rows]


@router.post("/templates", status_code=status.HTTP_201_CREATED)
async def create_template(body: TemplateCreateRequest, _: str = Depends(require_admin)) -> dict:
    _validate_weekdays(body.allowed_weekdays)
    row = await db.create_template(body.name, body.entity_ids, body.allowed_weekdays)
    return _template_to_response(row)


@router.get("/templates/{template_id}")
async def get_template(template_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_template_by_id(template_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _template_to_response(row)


@router.put("/templates/{template_id}")
async def update_template(
    template_id: str, body: TemplateUpdateRequest, _: str = Depends(require_admin)
) -> dict:
    row = await db.get_template_by_id(template_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    _validate_weekdays(body.allowed_weekdays)
    await db.update_template(template_id, body.name, body.entity_ids, body.allowed_weekdays)
    row = await db.get_template_by_id(template_id)
    return _template_to_response(row)


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_template_by_id(template_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.delete_template(template_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Member management
# ---------------------------------------------------------------------------

def _member_to_response(row: Any) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "template_id": row["template_id"],
        "template_name": row["template_name"] if "template_name" in row.keys() else None,
        "active": bool(row["active"]),
        "created_at": row["created_at"],
    }


def _hash_password(plain: str) -> str:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.get_event_loop().run_in_executor(
                None, lambda: bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
            )
        )
    finally:
        loop.close()


async def _async_hash_password(plain: str) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
    )


@router.get("/members")
async def list_members(_: str = Depends(require_admin)) -> list[dict]:
    rows = await db.list_members()
    return [_member_to_response(r) for r in rows]


@router.post("/members", status_code=status.HTTP_201_CREATED)
async def create_member(body: MemberCreateRequest, _: str = Depends(require_admin)) -> dict:
    if body.template_id:
        tpl = await db.get_template_by_id(body.template_id)
        if not tpl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template nicht gefunden")

    existing = await db.get_member_by_username(body.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Benutzername '{body.username}' bereits vergeben")

    pw_hash = await _async_hash_password(body.password)
    row = await db.create_member(body.username, pw_hash, body.template_id)
    # fetch with template name
    rows = await db.list_members()
    for r in rows:
        if r["id"] == row["id"]:
            return _member_to_response(r)
    return _member_to_response(row)


@router.get("/members/{member_id}")
async def get_member(member_id: str, _: str = Depends(require_admin)) -> dict:
    rows = await db.list_members()
    for r in rows:
        if r["id"] == member_id:
            return _member_to_response(r)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.patch("/members/{member_id}")
async def update_member(
    member_id: str, body: MemberUpdateRequest, _: str = Depends(require_admin)
) -> dict:
    row = await db.get_member_by_id(member_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    if body.template_id is not None:
        tpl = await db.get_template_by_id(body.template_id)
        if not tpl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template nicht gefunden")

    if body.username is not None:
        existing = await db.get_member_by_username(body.username)
        if existing and existing["id"] != member_id:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Benutzername bereits vergeben")

    pw_hash = await _async_hash_password(body.password) if body.password else None

    # Distinguish "not provided" from "set to None" for template_id
    template_id_sentinel = ... if body.template_id is None and "template_id" not in body.model_fields_set else body.template_id

    await db.update_member(
        member_id,
        username=body.username,
        password_hash=pw_hash,
        template_id=template_id_sentinel,
        active=body.active,
    )
    rows = await db.list_members()
    for r in rows:
        if r["id"] == member_id:
            return _member_to_response(r)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.delete("/members/{member_id}")
async def delete_member(member_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_member_by_id(member_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.delete_member(member_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# HA entity list proxy
# ---------------------------------------------------------------------------

@router.get("/ha/entities")
async def ha_entities(_: str = Depends(require_admin)) -> list[dict]:
    try:
        states = await ha_client.get_states()
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Home Assistant unreachable")
    # Only return entities whose domain guests can either control or view.
    return [
        {
            "entity_id": s["entity_id"],
            "friendly_name": s.get("attributes", {}).get("friendly_name", s["entity_id"]),
            "domain": domain,
            "state": s["state"],
        }
        for s in states
        if (domain := s["entity_id"].split(".")[0]) in SUPPORTED_DOMAINS
    ]
