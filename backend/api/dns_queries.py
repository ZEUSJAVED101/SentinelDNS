"""
SentinelDNS DNS Queries API

Responsibilities:

- Expose recent sanitized DNS query events
- Require authentication
- Enforce a strict maximum response size
- Never expose raw DNS packets
- Never expose client addresses
- Never expose authentication data

Security model:

- Read-only endpoint
- Authenticated users only
- Bounded in-memory source
- Bounded API limit
- Response schema validation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from backend.security.dependencies import get_current_user
from database.models.user import User
from dns_engine.query_log import query_log


router = APIRouter(
    prefix="/api/queries",
    tags=["DNS Queries"],
)


# ==========================================================
# RESPONSE SCHEMA
# ==========================================================


class DNSQueryResponse(BaseModel):
    """
    Sanitized DNS query record returned to the dashboard.

    Only fields explicitly defined here can leave the API.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    timestamp: datetime

    domain: str = Field(
        min_length=1,
        max_length=253,
    )

    query_type: int = Field(
        ge=0,
        le=65535,
    )

    query_class: int = Field(
        ge=0,
        le=65535,
    )

    status: Literal[
        "ALLOWED",
        "BLOCKED",
        "ERROR",
    ]

    cache: Literal[
        "HIT",
        "MISS",
        "NOT_USED",
    ]

    upstream: Literal[
        "SUCCESS",
        "FAILED",
        "NOT_USED",
    ]

    rcode: int | None = Field(
        default=None,
        ge=0,
        le=15,
    )

    latency_ms: float = Field(
        ge=0,
        le=300_000,
    )


class DNSQueriesResponse(BaseModel):
    """
    Complete API response.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    count: int = Field(
        ge=0,
    )

    limit: int = Field(
        ge=1,
    )

    queries: list[DNSQueryResponse]


# ==========================================================
# CONSTANTS
# ==========================================================

MAX_API_LIMIT = 100


# ==========================================================
# HELPERS
# ==========================================================


def _timestamp_to_datetime(
    timestamp: float,
) -> datetime:
    """
    Convert a Unix timestamp to an explicit UTC datetime.
    """

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    )


def _serialize_query(
    entry,
) -> DNSQueryResponse:
    """
    Convert an internal audit entry into the strict
    public API schema.

    The explicit mapping prevents accidental exposure of
    future internal fields.
    """

    return DNSQueryResponse(
        timestamp=_timestamp_to_datetime(
            entry.timestamp,
        ),
        domain=entry.domain,
        query_type=entry.query_type,
        query_class=entry.query_class,
        status=entry.status,
        cache=entry.cache,
        upstream=entry.upstream,
        rcode=entry.rcode,
        latency_ms=entry.latency_ms,
    )


# ==========================================================
# RECENT QUERIES
# ==========================================================


@router.get(
    "/recent",
    response_model=DNSQueriesResponse,
)
def recent_queries(
    limit: int = Query(
        default=50,
        ge=1,
        le=MAX_API_LIMIT,
    ),
    current_user: User = Depends(
        get_current_user,
    ),
) -> DNSQueriesResponse:
    """
    Return recent sanitized DNS query events.

    Authentication is mandatory.

    The current user is intentionally not included in the
    response because authorization is the purpose of the
    dependency, not query metadata.
    """

    # ------------------------------------------------------
    # Retrieve only the requested bounded number of entries.
    # ------------------------------------------------------

    entries = query_log.recent(
        limit=limit,
    )

    queries = [
        _serialize_query(
            entry,
        )
        for entry in entries
    ]

    return DNSQueriesResponse(
        count=len(queries),
        limit=limit,
        queries=queries,
    )