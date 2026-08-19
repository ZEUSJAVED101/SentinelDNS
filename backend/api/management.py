"""
SentinelDNS Management Pages

Responsibilities:
- Render authenticated management pages.
- Expose safe runtime configuration.
- Reload blocklists.
- Enable and disable DNS filters.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
)
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from backend.security.dependencies import get_current_user
from database.models.user import User
from dns_engine.blocklist_registry import BlocklistRegistry


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

TEMPLATES_DIRECTORY = (
    PROJECT_ROOT
    / "backend"
    / "templates"
)

BLOCKLIST_DIRECTORY = (
    PROJECT_ROOT
    / "data"
    / "blocklists"
)

templates = Jinja2Templates(
    directory=TEMPLATES_DIRECTORY,
)

router = APIRouter(
    tags=["Management"],
)


def _dashboard_service(
    request: Request,
):
    """
    Return the shared DashboardService instance.
    """

    return getattr(
        request.app.state,
        "dashboard_service",
        None,
    )


def _no_store(
    response: Response,
) -> Response:
    """
    Prevent management pages from being cached.
    """

    response.headers["Cache-Control"] = (
        "no-store, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"

    return response


# ==========================================================
# UPSTREAM DNS
# ==========================================================


@router.get(
    "/upstream",
    response_class=Response,
)
async def upstream_page(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Render the authenticated Upstream DNS page.
    """

    service = _dashboard_service(
        request,
    )

    if service is None:
        return Response(
            content=(
                "Dashboard service unavailable."
            ),
            status_code=503,
            media_type="text/plain",
        )

    transport = service.transport()

    response = templates.TemplateResponse(
        request=request,
        name="upstream/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
            "transport": transport,
        },
    )

    return _no_store(
        response,
    )


# ==========================================================
# CACHE
# ==========================================================


@router.get(
    "/cache",
    response_class=Response,
)
async def cache_page(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Render the authenticated DNS Cache page.
    """

    service = _dashboard_service(
        request,
    )

    if service is None:
        return Response(
            content=(
                "Dashboard service unavailable."
            ),
            status_code=503,
            media_type="text/plain",
        )

    cache = service.cache()

    response = templates.TemplateResponse(
        request=request,
        name="cache/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
            "cache": cache,
        },
    )

    return _no_store(
        response,
    )


# ==========================================================
# BLOCKLISTS
# ==========================================================


@router.get(
    "/blocklists",
    response_class=Response,
)
async def blocklists_page(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Render the authenticated Blocklists page.
    """

    if not BLOCKLIST_DIRECTORY.is_dir():
        return Response(
            content=(
                "Blocklist directory unavailable."
            ),
            status_code=503,
            media_type="text/plain",
        )

    files = sorted(
        BLOCKLIST_DIRECTORY.glob(
            "*.txt",
        ),
    )

    blocklists = []

    for path in files:

        loader = BlocklistRegistry.get(
            path.name,
        )

        blocklists.append(
            {
                "filename": path.name,
                "size": loader.size,
                "exists": path.exists(),
            }
        )

    total_domains = sum(
        item["size"]
        for item in blocklists
    )

    response = templates.TemplateResponse(
        request=request,
        name="blocklists/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
            "blocklists": blocklists,
            "total_blocklists": len(
                blocklists,
            ),
            "total_domains": total_domains,
        },
    )

    return _no_store(
        response,
    )


@router.post(
    "/blocklists/{filename}/reload",
)
async def reload_blocklist(
    filename: str,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Reload one blocklist from disk.
    """

    if (
        not filename.endswith(".txt")
        or Path(filename).name != filename
    ):
        return Response(
            content="Invalid blocklist filename.",
            status_code=400,
            media_type="text/plain",
        )

    path = (
        BLOCKLIST_DIRECTORY
        / filename
    )

    if not path.is_file():
        return Response(
            content="Blocklist not found.",
            status_code=404,
            media_type="text/plain",
        )

    BlocklistRegistry.reload(
        filename,
    )

    return RedirectResponse(
        url="/blocklists",
        status_code=303,
    )


@router.post(
    "/blocklists/reload-all",
)
async def reload_all_blocklists(
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Reload all blocklists.
    """

    if BLOCKLIST_DIRECTORY.is_dir():

        for path in BLOCKLIST_DIRECTORY.glob(
            "*.txt",
        ):
            BlocklistRegistry.get(
                path.name,
            )

    BlocklistRegistry.reload_all()

    return RedirectResponse(
        url="/blocklists",
        status_code=303,
    )


# ==========================================================
# FILTERS
# ==========================================================


@router.get(
    "/filters",
    response_class=Response,
)
async def filters_page(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Render the authenticated Filters page.
    """

    service = _dashboard_service(
        request,
    )

    if service is None:
        return Response(
            content=(
                "Dashboard service unavailable."
            ),
            status_code=503,
            media_type="text/plain",
        )

    filters = service.filters()

    response = templates.TemplateResponse(
        request=request,
        name="filters/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
            "filters": filters,
        },
    )

    return _no_store(
        response,
    )


@router.post(
    "/filters/{filter_name}/toggle",
)
async def toggle_filter(
    filter_name: str,
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Enable or disable a DNS filter.

    The change is applied directly to the live
    FilterManager used by DNSResolver.
    """

    service = _dashboard_service(
        request,
    )

    if service is None:
        return Response(
            content=(
                "Dashboard service unavailable."
            ),
            status_code=503,
            media_type="text/plain",
        )

    resolver = getattr(
        service,
        "resolver",
        None,
    )

    if resolver is None:
        return Response(
            content="DNS resolver unavailable.",
            status_code=503,
            media_type="text/plain",
        )

    manager = getattr(
        resolver,
        "filter_manager",
        None,
    )

    if manager is None:
        return Response(
            content="Filter manager unavailable.",
            status_code=503,
            media_type="text/plain",
        )

    try:

        current_state = manager.is_enabled(
            filter_name,
        )

        manager.set_enabled(
            filter_name,
            not current_state,
        )

    except ValueError:

        return Response(
            content="Unknown DNS filter.",
            status_code=404,
            media_type="text/plain",
        )

    return RedirectResponse(
        url="/filters",
        status_code=303,
    )