"""
SentinelDNS Database Configuration

Responsibilities:
- Create the SQLAlchemy engine
- Enable SQLite foreign key support
- Create database sessions
- Initialize database tables
"""
import database.models
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import settings
from database.base import Base


# ==========================================================
# Database URL
# ==========================================================

DATABASE_URL = f"sqlite:///{settings.database.path}"


# ==========================================================
# Database Engine
# ==========================================================

engine: Engine = create_engine(
    DATABASE_URL,
    echo=settings.application.debug,
    future=True,
)


# ==========================================================
# Enable SQLite Foreign Keys
# ==========================================================

@event.listens_for(engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    """
    Enable SQLite foreign key constraint enforcement.
    """

    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


# ==========================================================
# Session Factory
# ==========================================================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# ==========================================================
# Database Session Dependency
# ==========================================================

def get_db():
    """
    Provide a database session.

    Ensures the session is always closed properly.
    """

    db: Session = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ==========================================================
# Database Initialization
# ==========================================================

def init_database() -> None:
    """
    Create all database tables.
    """

    Base.metadata.create_all(bind=engine)