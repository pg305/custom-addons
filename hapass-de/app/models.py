"""Pydantic request/response models."""
from typing import Any
from pydantic import BaseModel, Field

NEVER_EXPIRES_SECONDS = 4102444800  # 2099-12-31T00:00:00Z

# Services guests are permitted to call, keyed by entity domain.
# Script/scene/automation domains are intentionally excluded —
# they execute arbitrary automations and bypass entity scoping.
ALLOWED_SERVICES: dict[str, set[str]] = {
    "light":         {"turn_on", "turn_off", "toggle"},
    "switch":        {"turn_on", "turn_off", "toggle"},
    "input_boolean": {"turn_on", "turn_off", "toggle"},
    "climate":       {"set_temperature", "set_hvac_mode", "turn_on", "turn_off"},
    "lock":          {"lock", "unlock", "open"},
    "media_player":  {"media_play", "media_pause", "media_stop", "volume_set",
                      "media_play_pause", "turn_on", "turn_off"},
    "cover":         {"open_cover", "close_cover", "stop_cover"},
    "fan":           {"turn_on", "turn_off", "toggle", "set_percentage"},
}

READ_ONLY_DOMAINS: set[str] = {"sensor", "binary_sensor"}
SUPPORTED_DOMAINS: set[str] = set(ALLOWED_SERVICES) | READ_ONLY_DOMAINS

# Keys that could bypass the entity allowlist if forwarded to HA
FORBIDDEN_DATA_KEYS = {"entity_id", "device_id", "area_id", "floor_id", "label_id"}


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class TokenCreateRequest(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    slug: str | None = Field(default=None, pattern=r"^[a-z0-9_-]{1,64}$")
    entity_ids: list[str] = Field(..., min_length=1)
    expires_in_seconds: int = Field(..., gt=0)
    ip_allowlist: list[str] | None = None
    allowed_weekdays: list[int] | None = Field(default=None, description="0=Mo,1=Di,...,6=So — None means all days")


class TokenUpdateEntitiesRequest(BaseModel):
    entity_ids: list[str] = Field(..., min_length=1)


class TokenUpdateExpiryRequest(BaseModel):
    expires_in_seconds: int = Field(..., gt=0)


class TokenUpdateWeekdaysRequest(BaseModel):
    allowed_weekdays: list[int] | None = None


class CommandRequest(BaseModel):
    entity_id: str
    service: str  # e.g. "light.turn_on"
    data: dict[str, Any] = Field(default_factory=dict)


class TokenResponse(BaseModel):
    id: str
    slug: str
    label: str
    created_at: int
    expires_at: int
    revoked: bool
    last_accessed: int | None
    ip_allowlist: list[str] | None
    entity_count: int
    entity_ids: list[str] | None = None


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

class TemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    entity_ids: list[str] = Field(default_factory=list)
    allowed_weekdays: list[int] | None = Field(default=None, description="0=Mo,1=Di,...,6=So — None means all days")


class TemplateUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    entity_ids: list[str] = Field(default_factory=list)
    allowed_weekdays: list[int] | None = None


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

class MemberCreateRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100, pattern=r"^[^\s]+$")
    password: str = Field(..., min_length=6)
    template_id: str | None = None


class MemberUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100, pattern=r"^[^\s]+$")
    password: str | None = Field(default=None, min_length=6)
    template_id: str | None | str = None
    active: bool | None = None


class MemberLoginRequest(BaseModel):
    username: str
    password: str
