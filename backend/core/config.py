"""
SentinelDNS Configuration Module

Responsibilities:
- Load environment variables (.env)
- Load YAML configuration (config.yaml)
- Validate configuration using Pydantic
- Expose a single immutable settings object
"""

from pathlib import Path
from typing import List
import os

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict


# ==========================================================
# Project Paths
# ==========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CONFIG_FILE = PROJECT_ROOT / "config" / "config.yaml"
ENV_FILE = PROJECT_ROOT / ".env"


# ==========================================================
# Load Environment Variables
# ==========================================================

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)


# ==========================================================
# Configuration Models
# ==========================================================

class ApplicationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    debug: bool


class ServerConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    port: int


class DatabaseConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str


class DNSConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    upstream_servers: List[str]
    enable_doh: bool
    enable_dot: bool


class LoggingConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    level: str
    file: str


class SecurityConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    secret_key: str


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True)

    application: ApplicationConfig
    server: ServerConfig
    database: DatabaseConfig
    dns: DNSConfig
    logging: LoggingConfig
    security: SecurityConfig


# ==========================================================
# Load YAML
# ==========================================================

if not CONFIG_FILE.exists():
    raise FileNotFoundError(f"Configuration file not found: {CONFIG_FILE}")

with CONFIG_FILE.open("r", encoding="utf-8") as file:
    config = yaml.safe_load(file)


# ==========================================================
# Merge .env values
# ==========================================================

config["security"] = {
    "secret_key": os.getenv(
        "SECRET_KEY",
        "CHANGE_ME_IN_PRODUCTION"
    )
}


# ==========================================================
# Global Settings Object
# ==========================================================

settings = Settings(**config)