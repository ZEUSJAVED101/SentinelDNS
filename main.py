"""
SentinelDNS Entry Point

Responsibilities:

- Initialize the database
- Start/stop the DNS engine
- Create the FastAPI application
- Register API routers
- Register exception handlers
- Serve the SentinelDNS dashboard
- Serve static frontend assets
- Share one DNSResolver instance
- Share the same resolver with DashboardService
"""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.auth import router as auth_router
from backend.exceptions.handlers import (
    register_exception_handlers,
)
from backend.services.dashboard_service import (
    DashboardService,
)
from database.database import init_database
from dns_engine.resolver import DNSResolver
from dns_engine.server import DNSServer


# ==========================================================
# PROJECT PATHS
# ==========================================================

PROJECT_ROOT = Path(__file__).resolve().parent

TEMPLATES_DIRECTORY = (
    PROJECT_ROOT
    / "backend"
    / "templates"
)

STATIC_DIRECTORY = (
    PROJECT_ROOT
    / "backend"
    / "static"
)


# ==========================================================
# DATABASE
# ==========================================================

init_database()


# ==========================================================
# SECURITY HEADERS
# ==========================================================

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",

    "X-Frame-Options": "DENY",

    "Referrer-Policy": "no-referrer",

    "Permissions-Policy": (
        "camera=(), "
        "microphone=(), "
        "geolocation=(), "
        "payment=()"
    ),

    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:;"
    ),
}


# ==========================================================
# FASTAPI LIFESPAN
# ==========================================================

@asynccontextmanager
async def lifespan(
    app: FastAPI,
):
    """
    Start and stop SentinelDNS runtime services.

    IMPORTANT:

    Exactly ONE DNSResolver is created.

    The same resolver is shared by:

        DNS server
             +
        Dashboard service

    This ensures dashboard metrics represent the
    actual DNS engine.
    """

    print()
    print("========================================")
    print(" SentinelDNS Starting")
    print("========================================")

    # ------------------------------------------------------
    # Create ONE DNS resolver.
    # ------------------------------------------------------

    dns_resolver = DNSResolver()

    app.state.dns_resolver = dns_resolver

    print(
        "✓ DNS Resolver created"
    )

    # ------------------------------------------------------
    # Create dashboard service using SAME resolver.
    # ------------------------------------------------------

    dashboard_service = DashboardService(
        resolver=dns_resolver,
    )

    app.state.dashboard_service = (
        dashboard_service
    )

    print(
        "✓ Dashboard service connected"
    )

    # ------------------------------------------------------
    # Create DNS server using SAME resolver.
    # ------------------------------------------------------

    dns_server = DNSServer(
        host="127.0.0.1",
        port=53,
        resolver=dns_resolver,
    )

    app.state.dns_server = dns_server

    print(
        "✓ DNS Server starting"
    )

    # ------------------------------------------------------
    # Start DNS server in background.
    # ------------------------------------------------------

    dns_thread = threading.Thread(
        target=dns_server.start,
        daemon=True,
        name="sentineldns-dns",
    )

    app.state.dns_thread = dns_thread

    dns_thread.start()

    print(
        "✓ DNS listening on 127.0.0.1:53"
    )

    print(
        "========================================"
    )

    try:

        yield

    finally:

        print()
        print(
            "========================================"
        )
        print(
            " SentinelDNS Shutting Down"
        )
        print(
            "========================================"
        )

        # --------------------------------------------------
        # Stop DNS server.
        # --------------------------------------------------

        try:

            dns_server.stop()

        except Exception:

            pass

        # --------------------------------------------------
        # Wait briefly for DNS thread.
        # --------------------------------------------------

        try:

            dns_thread.join(
                timeout=2.0,
            )

        except Exception:

            pass

        print(
            "✓ SentinelDNS stopped"
        )


# ==========================================================
# FASTAPI APPLICATION
# ==========================================================

app = FastAPI(
    title="SentinelDNS API",
    version="1.0.0",
    description=(
        "DNS Filtering and Management System"
    ),
    lifespan=lifespan,
)


# ==========================================================
# SECURITY MIDDLEWARE
# ==========================================================

@app.middleware("http")
async def security_headers(
    request: Request,
    call_next,
):
    """
    Add security headers to every HTTP response.
    """

    response = await call_next(
        request,
    )

    for name, value in SECURITY_HEADERS.items():

        response.headers[
            name
        ] = value

    return response


# ==========================================================
# STATIC FILES
# ==========================================================

if not STATIC_DIRECTORY.is_dir():

    raise RuntimeError(
        "Static directory not found: "
        f"{STATIC_DIRECTORY}"
    )

app.mount(
    "/static",
    StaticFiles(
        directory=STATIC_DIRECTORY,
    ),
    name="static",
)


# ==========================================================
# TEMPLATES
# ==========================================================

if not TEMPLATES_DIRECTORY.is_dir():

    raise RuntimeError(
        "Templates directory not found: "
        f"{TEMPLATES_DIRECTORY}"
    )

templates = Jinja2Templates(
    directory=TEMPLATES_DIRECTORY,
)


# ==========================================================
# EXCEPTION HANDLERS
# ==========================================================

register_exception_handlers(
    app,
)


# ==========================================================
# API ROUTERS
# ==========================================================

app.include_router(
    auth_router,
)


# ==========================================================
# ROOT
# ==========================================================

@app.get(
    "/",
    tags=["Root"],
)
async def root():
    """
    Basic SentinelDNS health endpoint.
    """

    return {
        "application": "SentinelDNS",
        "status": "running",
        "dns_engine": "running",
        "version": "1.0.0",
    }


# ==========================================================
# DASHBOARD PAGE
# ==========================================================

@app.get(
    "/dashboard",
    tags=["Dashboard"],
    response_class=Response,
)
async def dashboard(
    request: Request,
):
    """
    Render the SentinelDNS dashboard.

    Dashboard data is generated from the SAME
    DNSResolver used by the DNS server.
    """

    dashboard_service = getattr(
        request.app.state,
        "dashboard_service",
        None,
    )

    if dashboard_service is None:

        return Response(
            content=(
                "Dashboard service unavailable."
            ),
            status_code=503,
            media_type="text/plain",
        )

    # ------------------------------------------------------
    # Generate dashboard data.
    # ------------------------------------------------------

    dashboard_data = (
        dashboard_service.get_dashboard_data()
    )

    # ------------------------------------------------------
    # Render dashboard.
    #
    # IMPORTANT:
    # The Jinja template expects:
    #
    #     dashboard.dns
    #     dashboard.cache
    #     dashboard.transport
    #     dashboard.filters
    #     dashboard.blocklists
    #
    # Therefore "dashboard" MUST be supplied here.
    # ------------------------------------------------------

    response = templates.TemplateResponse(
        request=request,
        name="dashboard/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "dashboard": dashboard_data,
        },
    )

    # ------------------------------------------------------
    # Dashboard data should not be cached.
    # ------------------------------------------------------

    response.headers[
        "Cache-Control"
    ] = "no-store, max-age=0"

    response.headers[
        "Pragma"
    ] = "no-cache"

    return response


# ==========================================================
# DASHBOARD API
# ==========================================================

@app.get(
    "/api/dashboard/",
    tags=["Dashboard"],
)
async def dashboard_api(
    request: Request,
):
    """
    Return read-only dashboard runtime information.

    The DashboardService reads from the SAME resolver
    that processes DNS queries.
    """

    dashboard_service = getattr(
        request.app.state,
        "dashboard_service",
        None,
    )

    if dashboard_service is None:

        return Response(
            content="Dashboard service unavailable.",
            status_code=503,
            media_type="text/plain",
        )

    try:

        dashboard_data = (
            dashboard_service.get_dashboard_data()
        )

    except Exception:

        return Response(
            content="Dashboard data unavailable.",
            status_code=503,
            media_type="text/plain",
        )

    return dashboard_data