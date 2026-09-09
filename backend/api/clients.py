"""Authenticated DHCP client inventory and safe client controls."""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from backend.core.config import settings
from backend.security.dependencies import get_current_user
from database.database import SessionLocal
from database.models.dhcp_control import DHCPExclusionRecord, DHCPReservationRecord
from database.models.dhcp_lease import DHCPLease
from database.models.user import User

TEMPLATES_DIRECTORY = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIRECTORY)
router = APIRouter(tags=["Clients"])
MAX_CLIENTS_RETURNED = 500
MAX_SELECTED_CLIENTS = 50


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


class ClientResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=7, max_length=15)
    hostname: str | None = Field(default=None, max_length=255)
    lease_start: datetime
    lease_end: datetime
    state: str = Field(pattern=r"^(ACTIVE|EXPIRED)$")
    remaining_seconds: int = Field(ge=0)
    reserved: bool = False
    excluded: bool = False


class ClientsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_matching: int = Field(ge=0)
    returned: int = Field(ge=0, le=MAX_CLIENTS_RETURNED)
    active: int = Field(ge=0)
    expired: int = Field(ge=0)
    reservations: int = Field(ge=0)
    exclusions: int = Field(ge=0)
    clients: list[ClientResponse]


class SelectedClientsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_ids: list[str] = Field(min_length=1, max_length=MAX_SELECTED_CLIENTS)


class ControlResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requested: int = Field(ge=1, le=MAX_SELECTED_CLIENTS)
    succeeded: int = Field(ge=0, le=MAX_SELECTED_CLIENTS)
    failed: int = Field(ge=0, le=MAX_SELECTED_CLIENTS)
    details: list[str] = Field(max_length=MAX_SELECTED_CLIENTS)


def _normalize_client_id(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 255:
        raise ValueError("Invalid client identifier.")
    return value


def _validate_pool_ip(value: str) -> str:
    try:
        ip = IPv4Address(value.strip())
    except ValueError as exc:
        raise ValueError("Invalid IPv4 address.") from exc
    pool = settings.dhcp.pool
    start, end = IPv4Address(pool.start), IPv4Address(pool.end)
    if not (int(start) <= int(ip) <= int(end)):
        raise ValueError("IP address is outside the configured DHCP pool.")
    return str(ip)


def _serialize(model: DHCPLease, now: datetime, reserved: set[str], excluded: set[str]) -> ClientResponse:
    end = model.lease_end.replace(tzinfo=timezone.utc) if model.lease_end.tzinfo is None else model.lease_end.astimezone(timezone.utc)
    start = model.lease_start.replace(tzinfo=timezone.utc) if model.lease_start.tzinfo is None else model.lease_start.astimezone(timezone.utc)
    return ClientResponse(
        client_id=model.client_id,
        ip_address=model.ip_address,
        hostname=model.hostname,
        lease_start=start,
        lease_end=end,
        state="ACTIVE" if end > now else "EXPIRED",
        remaining_seconds=max(0, int((end - now).total_seconds())),
        reserved=model.client_id in reserved,
        excluded=model.ip_address in excluded,
    )


def _load_clients(search: str) -> ClientsResponse:
    term = search.strip()
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        query = select(DHCPLease)
        if term:
            pattern = f"%{term}%"
            query = query.where(or_(DHCPLease.client_id.ilike(pattern), DHCPLease.ip_address.ilike(pattern), DHCPLease.hostname.ilike(pattern)))
        total = int(db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0)
        active = int(db.scalar(select(func.count()).select_from(query.where(DHCPLease.lease_end > now.replace(tzinfo=None)).order_by(None).subquery())) or 0)
        reservations = set(db.scalars(select(DHCPReservationRecord.client_id)).all())
        exclusions = set(db.scalars(select(DHCPExclusionRecord.ip_address)).all())
        models = db.scalars(query.order_by(DHCPLease.lease_end.desc(), DHCPLease.ip_address.asc()).limit(MAX_CLIENTS_RETURNED)).all()
        clients = [_serialize(m, now, reservations, exclusions) for m in models]
        return ClientsResponse(total_matching=total, returned=len(clients), active=active, expired=max(0, total-active), reservations=len(reservations), exclusions=len(exclusions), clients=clients)
    except SQLAlchemyError as exc:
        raise RuntimeError("Unable to read client records.") from exc
    finally:
        db.close()


def _live_server(request: Request):
    server = getattr(request.app.state, "dns_server", None)
    if server is None:
        raise RuntimeError("DHCP server unavailable.")
    return server


def _reserve_one(server, db, client_id: str) -> str:
    client_id = _normalize_client_id(client_id)
    lease = db.scalar(select(DHCPLease).where(DHCPLease.client_id == client_id))
    if lease is None:
        raise ValueError("Client record was not found.")
    ip = _validate_pool_ip(lease.ip_address)
    existing = db.scalar(select(DHCPReservationRecord).where(DHCPReservationRecord.client_id == client_id))
    if existing is not None:
        raise ValueError("Client already has a reservation.")
    excluded = db.scalar(select(DHCPExclusionRecord).where(DHCPExclusionRecord.ip_address == ip))
    if excluded is not None:
        raise ValueError("This IP is already excluded.")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active_other = db.scalar(select(DHCPLease).where(DHCPLease.ip_address == ip, DHCPLease.client_id != client_id, DHCPLease.lease_end > now))
    if active_other is not None:
        raise ValueError("IP is currently leased to another client.")
    reservation = None
    try:
        reservation = server.reservations.add(client_id=client_id, ip_address=ip, hostname=lease.hostname)
        db.add(DHCPReservationRecord(client_id=client_id, ip_address=ip, hostname=lease.hostname))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if reservation is not None:
            server.reservations.remove_by_client(client_id)
        raise ValueError("Reservation already exists or conflicts with another record.") from exc
    except Exception:
        db.rollback()
        if reservation is not None:
            server.reservations.remove_by_client(client_id)
        raise
    return f"Reserved {client_id} → {ip}."


def _exclude_one(server, db, client_id: str) -> str:
    client_id = _normalize_client_id(client_id)
    lease = db.scalar(select(DHCPLease).where(DHCPLease.client_id == client_id))
    if lease is None:
        raise ValueError("Client record was not found.")
    ip = _validate_pool_ip(lease.ip_address)
    if db.scalar(select(DHCPExclusionRecord).where(DHCPExclusionRecord.ip_address == ip)) is not None:
        raise ValueError("This IP is already excluded.")
    if db.scalar(select(DHCPReservationRecord).where(DHCPReservationRecord.ip_address == ip)) is not None:
        raise ValueError("This IP is reserved and cannot also be excluded.")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active = db.scalar(select(DHCPLease).where(DHCPLease.ip_address == ip, DHCPLease.lease_end > now))
    if active is not None:
        raise ValueError("An active lease currently uses this IP. Wait for it to expire before excluding it.")
    if server.pool.is_reserved(ip):
        raise ValueError("This IP is already reserved by the DHCP runtime.")
    try:
        server.pool.reserve(ip)
        db.add(DHCPExclusionRecord(ip_address=ip))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        server.pool.unreserve(ip)
        raise ValueError("Exclusion already exists.") from exc
    except Exception:
        db.rollback()
        server.pool.unreserve(ip)
        raise
    return f"Excluded {ip} from dynamic allocation."


@router.get("/clients", response_class=Response)
async def clients_page(request: Request, current_user: User = Depends(get_current_user)):
    response = templates.TemplateResponse(request=request, name="clients/index.html", context={"application": "SentinelDNS", "version": "1.0.0", "user": current_user})
    return _no_store(response)


@router.get("/api/clients", response_model=ClientsResponse)
async def clients_api(search: str = Query(default="", max_length=100), current_user: User = Depends(get_current_user)):
    try:
        data = _load_clients(search)
    except RuntimeError:
        return JSONResponse(status_code=503, content={"detail": "Client information is temporarily unavailable."}, headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"})
    return _no_store(JSONResponse(content=data.model_dump(mode="json")))


@router.post("/api/clients/reservations", response_model=ControlResult)
async def reserve_clients(payload: SelectedClientsRequest, request: Request, current_user: User = Depends(get_current_user)):
    db = SessionLocal(); server = _live_server(request); details = []; succeeded = 0
    try:
        for raw_id in payload.client_ids:
            try:
                details.append(_reserve_one(server, db, raw_id)); succeeded += 1
            except ValueError as exc:
                db.rollback(); details.append(f"{raw_id.strip()}: {exc}")
        result = ControlResult(requested=len(payload.client_ids), succeeded=succeeded, failed=len(payload.client_ids)-succeeded, details=details)
        return _no_store(JSONResponse(status_code=200 if result.failed == 0 else 207, content=result.model_dump()))
    finally:
        db.close()


@router.post("/api/clients/exclusions", response_model=ControlResult)
async def exclude_clients(payload: SelectedClientsRequest, request: Request, current_user: User = Depends(get_current_user)):
    db = SessionLocal(); server = _live_server(request); details = []; succeeded = 0
    try:
        for raw_id in payload.client_ids:
            try:
                details.append(_exclude_one(server, db, raw_id)); succeeded += 1
            except ValueError as exc:
                db.rollback(); details.append(f"{raw_id.strip()}: {exc}")
        result = ControlResult(requested=len(payload.client_ids), succeeded=succeeded, failed=len(payload.client_ids)-succeeded, details=details)
        return _no_store(JSONResponse(status_code=200 if result.failed == 0 else 207, content=result.model_dump()))
    finally:
        db.close()


@router.delete("/api/clients/reservations/{client_id}")
async def remove_reservation(client_id: str, request: Request, current_user: User = Depends(get_current_user)):
    client_id = _normalize_client_id(client_id)
    db = SessionLocal(); server = _live_server(request)
    try:
        record = db.scalar(select(DHCPReservationRecord).where(DHCPReservationRecord.client_id == client_id))
        if record is None:
            return _no_store(JSONResponse(status_code=404, content={"detail": "Reservation not found."}))
        db.delete(record); db.commit(); server.reservations.remove_by_client(client_id)
        return _no_store(JSONResponse(content={"status": "removed"}))
    finally:
        db.close()


@router.delete("/api/clients/exclusions/{ip_address}")
async def remove_exclusion(ip_address: str, request: Request, current_user: User = Depends(get_current_user)):
    ip = _validate_pool_ip(ip_address)
    db = SessionLocal(); server = _live_server(request)
    try:
        record = db.scalar(select(DHCPExclusionRecord).where(DHCPExclusionRecord.ip_address == ip))
        if record is None:
            return _no_store(JSONResponse(status_code=404, content={"detail": "Exclusion not found."}))
        db.delete(record); db.commit(); server.pool.unreserve(ip)
        return _no_store(JSONResponse(content={"status": "removed"}))
    finally:
        db.close()
