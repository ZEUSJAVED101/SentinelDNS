"""
SentinelDNS Entry Point

Responsibilities:
- Initialize the database
- Create the FastAPI application
- Register API routers
- Register global exception handlers
"""

from fastapi import FastAPI

from backend.api.auth import router as auth_router
from backend.exceptions.handlers import register_exception_handlers
from database.database import init_database

# ==========================================================
# Initialize Database
# ==========================================================

init_database()

# ==========================================================
# Create FastAPI Application
# ==========================================================

app = FastAPI(
    title="SentinelDNS API",
    version="1.0.0",
    description="DNS Filtering and Management System",
)

# ==========================================================
# Register Global Exception Handlers
# ==========================================================

register_exception_handlers(app)

# ==========================================================
# Register API Routers
# ==========================================================

app.include_router(auth_router)

# ==========================================================
# Root Endpoint
# ==========================================================

@app.get("/", tags=["Root"])
def root():
    """
    Root endpoint.
    """
    return {
        "application": "SentinelDNS",
        "status": "running",
        "version": "1.0.0",
    }