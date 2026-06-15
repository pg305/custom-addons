"""Member (Vereinsmitglied) router: login, logout, and member PWA."""
import asyncio
import datetime
import json
import logging
import re
import time
from typing import AsyncIterator

import bcrypt
import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import database as db
from app import ha_client
from app.config import settings
from app.context import base_context
from pydantic import BaseModel
from app.models import (
    ALLOWED_SERVICES,
    CommandRequest,
    FORBIDDEN_DATA_KEYS,
    MemberLoginRequest,
    NEVER_EXPIRES_SECONDS,
)
from app.ingress import is_ingress_request
from app.rate_limiter import RateLimiter, rate_limiter
from app.routers.guest import (
    _get_cached_states,
    _client_ip,
    _fire_activity_event,
    _activity_payload,
    SSE_KEEPALIVE_SECONDS,
    _ALLOWED_SSE_EVENTS,
    COMMAND_RPM,
)

MEMBER_SUB_PREFIX = "member:"

router = APIRouter()
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory="templates")

MEMBER_SESSION_COOKIE = "ha_member_session"

_member_login_limiter = RateLimiter()


def _hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


async def _verify_member_password(plain: str, hashed: str) -> bool:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, bcrypt.checkpw, plain.encode(), hashed.encode())


async def _get_member_from_request(request: Request):
    """Return the member row from the session cookie, or None."""
    session_id = request.cookies.get(MEMBER_SESSION_COOKIE)
    if not session_id:
        return None, None
    row = await db.get_member_session(session_id)
    if not row:
        return None, None
    if not row["active"]:
        return None, None
    return row, session_id


async def _require_member(request: Request):
    """Raise 401 if no valid member session."""
    row, _ = await _get_member_from_request(request)
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Nicht eingeloggt")
    return row


async def _get_member_entities(member_row) -> list[str]:
    """Return entity list from the member's assigned template."""
    template_id = member_row["template_id"]
    if not template_id:
        return []
    tpl = await db.get_template_by_id(template_id)
    if not tpl:
        return []
    return json.loads(tpl["entity_ids"])


def _check_member_weekday(member_row) -> bool:
    """Return False if today is not in the template's allowed weekdays."""
    if not member_row["template_id"]:
        return True  # no template = no restriction
    # We need the template to check weekdays; caller must fetch it
    return True


async def _validate_member_access(member_row) -> list[str]:
    """Validate weekday access from template and return entity list."""
    template_id = member_row["template_id"]
    if not template_id:
        return []
    tpl = await db.get_template_by_id(template_id)
    if not tpl:
        return []
    if tpl["allowed_weekdays"]:
        allowed = json.loads(tpl["allowed_weekdays"])
        today = datetime.datetime.now().weekday()
        if today not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Heute kein Zugang")
    return json.loads(tpl["entity_ids"])


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def member_login_page(request: Request):
    # Via HA Ingress: Admin-Panel direkt ohne Login (wie vorher)
    if is_ingress_request(request):
        return RedirectResponse(url=f"{request.state.ingress_path}/admin/dashboard", status_code=302)
    row, _ = await _get_member_from_request(request)
    if row:
        return RedirectResponse(url="/me", status_code=302)
    ctx = base_context(request)
    ctx["contact_message"] = settings.contact_message
    return templates.TemplateResponse(request, "member_login.html", ctx)


@router.post("/member/login")
async def member_login(body: MemberLoginRequest, request: Request, response: Response) -> dict:
    client_ip = _client_ip(request)
    allowed = await _member_login_limiter.check(f"mlogin:{client_ip}", 5)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Zu viele Versuche")

    member = await db.get_member_by_username(body.username)
    if not member or not await _verify_member_password(body.password, member["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültige Anmeldedaten")
    if not member["active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Konto deaktiviert")

    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    is_https = request.url.scheme == "https" or forwarded_proto == "https"

    session_id = await db.create_member_session(member["id"])
    response.set_cookie(
        MEMBER_SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        secure=is_https,
        max_age=db.MEMBER_SESSION_TTL,
    )
    return {"ok": True, "username": member["username"], "must_change_password": bool(member["must_change_password"])}


@router.post("/member/logout")
async def member_logout(request: Request, response: Response) -> dict:
    _, session_id = await _get_member_from_request(request)
    if session_id:
        await db.delete_member_session(session_id)
    response.delete_cookie(MEMBER_SESSION_COOKIE)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Passwort ändern (Pflicht beim ersten Login)
# ---------------------------------------------------------------------------

class ChangePasswordRequest(BaseModel):
    password: str
    password_confirm: str


@router.get("/me/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    row, _ = await _get_member_from_request(request)
    if not row:
        return RedirectResponse(url="/", status_code=302)
    ctx = base_context(request)
    ctx.update({"username": row["username"], "contact_message": settings.contact_message})
    return templates.TemplateResponse(request, "member_change_password.html", ctx)


@router.post("/me/change-password")
async def change_password(request: Request) -> dict:
    row, _ = await _get_member_from_request(request)
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    body = await request.json()
    password = body.get("password", "")
    password_confirm = body.get("password_confirm", "")

    if len(password) < 6:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Passwort muss mindestens 6 Zeichen haben")
    if not any(c.isupper() for c in password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Passwort muss mindestens einen Großbuchstaben enthalten")
    if not any(c.islower() for c in password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Passwort muss mindestens einen Kleinbuchstaben enthalten")
    if password != password_confirm:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Passwörter stimmen nicht überein")

    pw_hash = await _hash_bcrypt(password)
    await db.set_member_password(row["member_id"], pw_hash)
    return {"ok": True}


@router.post("/me/skip-password-change")
async def skip_password_change(request: Request) -> dict:
    """Member keeps the current password — just clear the must_change flag."""
    row, _ = await _get_member_from_request(request)
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    await db.clear_must_change_password(row["member_id"])
    return {"ok": True}


async def _hash_bcrypt(plain: str) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode())


# ---------------------------------------------------------------------------
# Member PWA — same UX as guest PWA, label = username
# ---------------------------------------------------------------------------

@router.get("/me", response_class=HTMLResponse)
async def member_pwa(request: Request):
    row, _ = await _get_member_from_request(request)
    if not row:
        return RedirectResponse(url="/", status_code=302)

    ctx = base_context(request)
    ctx.update({
        "slug": "",
        "label": row["username"],
        "expires_at": NEVER_EXPIRES_SECONDS,
        "contact_message": settings.contact_message,
        "never_expires": NEVER_EXPIRES_SECONDS,
        "api_base": "/me",
        "is_member": True,
        "must_change_password": bool(row["must_change_password"]),
    })
    return templates.TemplateResponse(request, "guest_pwa.html", ctx)


@router.get("/me/manifest.json")
async def member_manifest(request: Request):
    bp = request.state.ingress_path
    manifest = {
        "name": settings.app_name,
        "short_name": settings.app_name[:12],
        "description": "Vereins-Steuerung",
        "start_url": f"{bp}/me",
        "scope": f"{bp}/me",
        "display": "standalone",
        "background_color": settings.brand_bg,
        "theme_color": settings.brand_primary,
        "orientation": "portrait",
        "icons": [
            {"src": f"{bp}/static/icons/icon-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "any"},
            {"src": f"{bp}/static/icons/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any"},
            {"src": f"{bp}/static/icons/icon-maskable-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "maskable"},
            {"src": f"{bp}/static/icons/icon-maskable-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "maskable"},
        ],
    }
    return JSONResponse(manifest)


@router.get("/me/state")
async def member_state(request: Request):
    row = await _require_member(request)
    entity_ids = await _validate_member_access(row)

    allowed = set(entity_ids)
    all_states = await _get_cached_states()
    states = {}
    for s in all_states:
        eid = s.get("entity_id", "")
        if eid in allowed:
            states[eid] = s
    for eid in entity_ids:
        if eid not in states:
            states[eid] = {"entity_id": eid, "state": "unavailable", "attributes": {}}

    return {"entities": entity_ids, "states": states}


async def _member_event_generator(member_id: str, entity_ids: list[str], request: Request) -> AsyncIterator[str]:
    sub_id = f"{MEMBER_SUB_PREFIX}{member_id}"
    q = await ha_client.subscribe_with_entities(sub_id, entity_ids)
    try:
        yield f"event: connected\ndata: {{\"ws_healthy\": {str(ha_client.is_ws_healthy()).lower()}}}\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(q.get(), timeout=SSE_KEEPALIVE_SECONDS)
                if event["type"] not in _ALLOWED_SSE_EVENTS:
                    continue
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                if event["type"] == "token_expired":
                    break
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
    finally:
        await ha_client.unsubscribe(sub_id, q)


@router.get("/me/stream")
async def member_stream(request: Request):
    row = await _require_member(request)
    entity_ids = await _validate_member_access(row)
    return StreamingResponse(
        _member_event_generator(row["member_id"], entity_ids, request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/me/command")
async def member_command(body: CommandRequest, background_tasks: BackgroundTasks, request: Request):
    row = await _require_member(request)
    member_id = row["member_id"]

    entity_ids = await _validate_member_access(row)

    allowed = await rate_limiter.check(member_id, COMMAND_RPM)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit überschritten")

    if not re.match(r'^[a-z_]+\.[a-z_]+$', body.service) and not re.match(r'^[a-z_]+$', body.service):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Ungültiges Service-Format")

    if body.entity_id not in entity_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Gerät nicht freigegeben")

    entity_domain = body.entity_id.split(".")[0]

    if "." in body.service:
        svc_domain, svc_name = body.service.split(".", 1)
        if svc_domain != entity_domain:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Service-Domain stimmt nicht überein")
    else:
        svc_name = body.service

    allowed_svc = ALLOWED_SERVICES.get(entity_domain)
    if not allowed_svc or svc_name not in allowed_svc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Service '{svc_name}' nicht erlaubt")

    clean_data = {k: v for k, v in body.data.items() if k not in FORBIDDEN_DATA_KEYS}
    service_data = {**clean_data, "entity_id": body.entity_id}

    try:
        await ha_client.call_service(entity_domain, svc_name, service_data)
    except (httpx.HTTPStatusError, Exception):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Service-Aufruf fehlgeschlagen")

    await db.log_access(
        token_id=None,
        event_type="command",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        entity_id=body.entity_id,
        service=body.service,
        member_label=row["username"],
    )
    background_tasks.add_task(
        _fire_activity_event,
        {
            "schema_version": 1,
            "activity": "command",
            "token_label": row["username"],
            "target_entity_id": body.entity_id,
            "service": f"{entity_domain}.{svc_name}",
        },
    )

    return {"ok": True}
