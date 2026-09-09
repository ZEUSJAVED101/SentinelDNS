"""Persistent DHCP reservations and address exclusions."""
from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base
from database.mixins import TimestampMixin


class DHCPReservationRecord(TimestampMixin, Base):
    """Persistent static DHCP reservation."""

    __tablename__ = "dhcp_reservations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(15), unique=True, nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)


class DHCPExclusionRecord(TimestampMixin, Base):
    """Persistent IPv4 address excluded from dynamic DHCP allocation."""

    __tablename__ = "dhcp_exclusions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(15), unique=True, nullable=False, index=True)


__all__ = ["DHCPReservationRecord", "DHCPExclusionRecord"]
