"""
SentinelDNS Configuration Module

Responsibilities:
- Load environment variables (.env)
- Load YAML configuration
- Validate configuration using Pydantic
- Expose immutable application settings
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

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


class DNSListenConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    port: int


class DNSUpstreamConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    servers: list[str]
    timeout: float
    retries: int
    max_response_size: int


class DoHConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    provider: str
    endpoint: str
    timeout: float
    http2: bool
    verify_tls: bool


class DoTConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    server: str
    port: int
    timeout: float
    verify_tls: bool


class DNSConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    transport: str
    listen: DNSListenConfig
    upstream: DNSUpstreamConfig
    doh: DoHConfig
    dot: DoTConfig
# ==========================================================
# DHCP
# ==========================================================
class DHCPListenConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    port: int


class DHCPPoolConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    start: str
    end: str


class DHCPConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool

    listen: DHCPListenConfig

    interface: str

    server_ip: str

    subnet_mask: str

    gateway: str

    dns_server: str

    lease_time: int

    pool: DHCPPoolConfig


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

    dhcp: DHCPConfig

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

if not isinstance(
    config,
    dict,
):

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

secret_key = os.getenv(
    "SECRET_KEY",
)

if not secret_key:

    raise RuntimeError(
        "SECRET_KEY environment variable is not configured."
    )

config["security"][
    "secret_key"
] = secret_key


# ==========================================================
# Validate Configuration
# ==========================================================

settings = Settings(
    **config,
)


# ==========================================================
# Export
# ==========================================================

__all__ = [
    "settings",
    "Settings",
]
