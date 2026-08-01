"""
SentinelDNS Entry Point

Responsibilities:
- Initialize the database
- Start/Stop the DNS Engine
- Create the FastAPI application
- Register API routers
- Register global exception handlers
"""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.api.auth import router as auth_router
from backend.exceptions.handlers import register_exception_handlers
from database.database import init_database
from dns_engine.server import DNSServer


# ==========================================================
# Initialize Database
# ==========================================================

init_database()


# ==========================================================
# FastAPI Lifespan
# ==========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Start background services when FastAPI starts.
    """

    dns_server = DNSServer()

    dns_thread = threading.Thread(
        target=dns_server.start,
        daemon=True,
    )

    dns_thread.start()

    print("✓ DNS Engine Started")

    yield

    print("✓ SentinelDNS Shutting Down")


# ==========================================================
# FastAPI Application
# ==========================================================

app = FastAPI(
    title="SentinelDNS API",
    version="1.0.0",
    description="DNS Filtering and Management System",
    lifespan=lifespan,
)


# ==========================================================
# Exception Handlers
# ==========================================================

register_exception_handlers(app)


# ==========================================================
# API Routers
# ==========================================================

app.include_router(auth_router)


# ==========================================================
# Root Endpoint
# ==========================================================

@app.get("/", tags=["Root"])
def root():
    return {
        "application": "SentinelDNS",
        "status": "running",
        "dns_engine": "running",
        "version": "1.0.0",
    }