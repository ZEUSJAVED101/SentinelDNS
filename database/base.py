"""
SentinelDNS Database Base

This module defines the single declarative base class
used by every SQLAlchemy model in the project.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models.

    Every database model should inherit from this class.
    """

    pass