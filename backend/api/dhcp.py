"""
SentinelDNS DHCP Management API.

This router is intentionally read-only for the first DHCP web stage.
It exposes only DHCP configuration already loaded by SentinelDNS and
sanitized persistent lease information already stored in the database.

Security properties:
- Every page/API endpoint requires the existing authentication dependency.
- No DHCP packet data or secrets are exposed.
- No configuration mutation is performed by this router.
- Responses are explicitly bounded and sanitized.
- Management responses are marked no-store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from backend.core.config import settings
from backend.security.dependencies import get_current_user
from database.models.user import User
from dhcp.storage import DHCPLeaseStorage, StoredLease


TEMPLATES_DIRECTORY = (
    Path(__file__).resolve().parents[1]
    / "templates"
)

templates = Jinja2Templates(
    directory=TEMPLATES_DIRECTORY,
)

router = APIRouter(
    tags=["DHCP"],
)

MAX_LEASES_RETURNED = 500


class DHCPLeaseResponse(BaseModel):
    """Sanitized DHCP lease representation."""

    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=7, max_length=15)
    hostname: str | None = Field(default=None, max_length=255)
    lease_start: datetime
    lease_end: datetime
    state: str = Field(pattern=r"^(ACTIVE|EXPIRED)$")
    remaining_seconds: int = Field(ge=0)


class DHCPResponse(BaseModel):
    """Complete sanitized DHCP management response."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    listen_host: str = Field(min_length=1, max_length=255)
    listen_port: int = Field(ge=1, le=65535)
    interface: str = Field(max_length=255)
    server_ip: str = Field(min_length=7, max_length=15)
    subnet_mask: str = Field(min_length=7, max_length=15)
    gateway: str = Field(min_length=7, max_length=15)
    dns_server: str = Field(min_length=7, max_length=15)
    lease_time: int = Field(ge=1)
    pool_start: str = Field(min_length=7, max_length=15)
    pool_end: str = Field(min_length=7, max_length=15)
    pool_size: int = Field(ge=1)
    active_leases: int = Field(ge=0)
    expired_leases: int = Field(ge=0)
    leases: list[DHCPLeaseResponse]


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def _pool_size(start: str, end: str) -> int:
    start_ip = IPv4Address(start)
    end_ip = IPv4Address(end)
    if int(end_ip) < int(start_ip):
        raise ValueError("Invalid DHCP pool range.")
    return int(end_ip) - int(start_ip) + 1


def _serialize_lease(lease: StoredLease, now: float) -> DHCPLeaseResponse:
    remaining = max(0, int(lease.lease_end - now))
    state = "ACTIVE" if lease.lease_end > now else "EXPIRED"

    return DHCPLeaseResponse(
        client_id=lease.client_id,
        ip_address=lease.ip_address,
        hostname=lease.hostname,
        lease_start=datetime.fromtimestamp(
            lease.lease_start,
            tz=timezone.utc,
        ),
        lease_end=datetime.fromtimestamp(
            lease.lease_end,
            tz=timezone.utc,
        ),
        state=state,
        remaining_seconds=remaining,
    )


def _build_response() -> DHCPResponse:
    """Read configured DHCP state and persistent leases without mutation."""
    now = datetime.now(timezone.utc).timestamp()
    storage = DHCPLeaseStorage()
    stored_leases = storage.all()

    # Count the complete persistent set first so the summary remains
    # accurate even when the response is bounded for safety.
    active_leases = sum(
        1 for lease in stored_leases if lease.lease_end > now
    )
    expired_leases = len(stored_leases) - active_leases

    # The API is bounded so an unexpectedly large database cannot
    # produce an unbounded management response.
    stored_leases = stored_leases[:MAX_LEASES_RETURNED]

    leases = [
        _serialize_lease(lease, now)
        for lease in stored_leases
    ]

    config = settings.dhcp

    return DHCPResponse(
        enabled=config.enabled,
        listen_host=config.listen.host,
        listen_port=config.listen.port,
        interface=config.interface,
        server_ip=config.server_ip,
        subnet_mask=config.subnet_mask,
        gateway=config.gateway,
        dns_server=config.dns_server,
        lease_time=config.lease_time,
        pool_start=config.pool.start,
        pool_end=config.pool.end,
        pool_size=_pool_size(
            config.pool.start,
            config.pool.end,
        ),
        active_leases=active_leases,
        expired_leases=expired_leases,
        leases=leases,
    )


@router.get(
    "/dhcp",
    response_class=Response,
)
async def dhcp_page(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Render the authenticated DHCP management page."""
    response = templates.TemplateResponse(
        request=request,
        name="dhcp/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
        },
    )
    return _no_store(response)


@router.get(
    "/api/dhcp",
    response_model=DHCPResponse,
)
async def dhcp_api(
    current_user: User = Depends(get_current_user),
):
    """Return authenticated, read-only DHCP configuration and lease data."""
    data = _build_response()
    response = JSONResponse(
        content=data.model_dump(mode="json"),
    )
    return _no_store(response)
