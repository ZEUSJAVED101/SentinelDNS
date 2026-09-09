"""Load persistent DHCP reservations/exclusions into the live server."""
from __future__ import annotations

import logging

from sqlalchemy import select

from database.database import SessionLocal
from database.models.dhcp_control import DHCPExclusionRecord, DHCPReservationRecord

LOGGER = logging.getLogger(__name__)


def load_persistent_controls(server) -> None:
    """Restore persisted controls before the DHCP socket starts.

    Invalid/conflicting records are skipped rather than preventing SentinelDNS
    from starting. The database remains the source of truth and the UI can
    surface the configured records on the next refresh.
    """
    db = SessionLocal()
    try:
        for record in db.scalars(select(DHCPExclusionRecord).order_by(DHCPExclusionRecord.ip_address)).all():
            try:
                server.pool.reserve(record.ip_address)
            except Exception as exc:
                LOGGER.warning("Skipping DHCP exclusion %s: %s", record.ip_address, exc)

        for record in db.scalars(select(DHCPReservationRecord).order_by(DHCPReservationRecord.client_id)).all():
            try:
                server.reservations.add(record.client_id, record.ip_address, record.hostname)
            except Exception as exc:
                LOGGER.warning("Skipping DHCP reservation for %s: %s", record.client_id, exc)
    finally:
        db.close()
