"""
SentinelDNS Configuration Module

Responsibilities:
- Load environment variables (.env)
- Load YAML configuration (config.yaml)
- Validate configuration using Pydantic
- Expose a single immutable settings object
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List

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
    algorithm: str
    access_token_expire_minutes: int


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True)

    application: ApplicationConfig
    server: ServerConfig
    database: DatabaseConfig
    dns: DNSConfig
    logging: LoggingConfig
    security: SecurityConfig


# ==========================================================
# Load YAML Configuration
# ==========================================================

if not CONFIG_FILE.exists():

    raise FileNotFoundError(
        f"Configuration file not found: {CONFIG_FILE}"
    )

try:

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        config: Any = yaml.safe_load(file)

except yaml.YAMLError as exc:

    raise RuntimeError(
        f"Invalid YAML configuration: {CONFIG_FILE}"
    ) from exc

if not isinstance(config, dict):

    raise RuntimeError(
        "Configuration file must contain a YAML mapping."
    )


# ==========================================================
# Merge Environment Variables
# ==========================================================

config.setdefault(
    "security",
    {},
)

secret_key = os.getenv("SECRET_KEY")

if not secret_key:

    raise RuntimeError(
        "SECRET_KEY environment variable is not configured."
    )

config["security"]["secret_key"] = secret_key


# ==========================================================
# Global Settings Object
# ==========================================================

settings = Settings(
    **config,
)