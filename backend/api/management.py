"""
SentinelDNS Management API

Responsibilities:
- Render authenticated management pages
- Expose safe runtime configuration
- Configure DNS upstream transport
- Reload blocklists
- Enable and disable DNS filters
- Display security events

Security principles:
- All management operations require authentication.
- Runtime upstream configuration is validated before activation.
- Invalid upstream configuration never replaces the active resolver.
- Configuration changes are persisted to config.yaml.
- Secrets are never returned through the API.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, build_opener, HTTPRedirectHandler

import yaml
from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
)
from fastapi.responses import (
    JSONResponse,
    RedirectResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from backend.core.config import CONFIG_FILE
from backend.security.dependencies import get_current_user, require_admin
from database.models.user import User
from dns_engine.blocklist_registry import BlocklistRegistry
from dns_engine.upstream import DNSUpstream


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

CUSTOM_BLOCKLIST_RE = re.compile(
    r"^custom_[a-z0-9][a-z0-9_-]{0,47}\.txt$"
)
CUSTOM_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,47}$"
)
MAX_BLOCKLIST_BYTES = 2 * 1024 * 1024
MAX_BLOCKLIST_DOMAINS = 100_000
MAX_GITHUB_FETCH_BYTES = 2 * 1024 * 1024
GITHUB_HOSTS = {"github.com", "www.github.com", "raw.githubusercontent.com"}


def _validate_custom_filename(filename: str) -> str:
    if not isinstance(filename, str) or not CUSTOM_BLOCKLIST_RE.fullmatch(filename):
        raise ValueError("Invalid custom blocklist filename.")
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid custom blocklist filename.")
    return filename


def _slug_filename(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Blocklist name must be text.")
    name = name.strip()
    if not name or len(name) > 48 or not CUSTOM_NAME_RE.fullmatch(name):
        raise ValueError("Blocklist name must be 1-48 characters and contain only letters, numbers, spaces, '_' or '-'.")
    slug = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_")
    if not slug:
        raise ValueError("Blocklist name must contain at least one letter or number.")
    return "custom_" + slug[:48] + ".txt"


def _normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        raise ValueError("Invalid domain.")
    if any(ch in value for ch in ("/", "\\", ":", "@")) or " " in value:
        raise ValueError("Only domain names are accepted, one per line.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not valid blocklist domains.")
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name.") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise ValueError("A domain must contain at least one dot.")
    for label in labels:
        if not 1 <= len(label) <= 63 or label[0] == "-" or label[-1] == "-":
            raise ValueError("Invalid domain label.")
        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise ValueError("Invalid domain label.")
    return ascii_name


def _parse_domains(content: str) -> list[str]:
    if not isinstance(content, str):
        raise ValueError("Blocklist content must be text.")
    if len(content.encode("utf-8")) > MAX_BLOCKLIST_BYTES:
        raise ValueError("Blocklist is too large. Maximum size is 2 MiB.")
    domains: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(content.splitlines(), 1):
        if line_number > MAX_BLOCKLIST_DOMAINS + 1:
            raise ValueError("Blocklist contains too many lines.")
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if len(line) > 253:
            raise ValueError(f"Line {line_number} is too long.")
        domain = _normalize_domain(line)
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
            if len(domains) > MAX_BLOCKLIST_DOMAINS:
                raise ValueError("Blocklist contains too many domains.")
    return domains


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirects are not allowed for GitHub blocklist downloads.")


def _github_raw_url(value: str) -> str:
    """Accept only public GitHub repository file URLs over HTTPS."""
    if not isinstance(value, str):
        raise ValueError("GitHub source URL must be text.")

    value = value.strip()
    if len(value) > 2048:
        raise ValueError("GitHub source URL is too long.")

    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("GitHub source must use a public HTTPS URL without credentials.")
    if parsed.port not in (None, 443):
        raise ValueError("GitHub source must use HTTPS on the standard port.")
    if parsed.hostname is None or parsed.hostname.lower() not in GITHUB_HOSTS:
        raise ValueError("Only github.com and raw.githubusercontent.com sources are allowed.")
    if parsed.query or parsed.fragment:
        raise ValueError("GitHub source URL must not contain a query string or fragment.")

    host = parsed.hostname.lower()
    path = parsed.path

    if host == "raw.githubusercontent.com":
        parts = [part for part in path.split("/") if part]
        if len(parts) < 4:
            raise ValueError("Invalid GitHub raw file URL.")
        return f"https://raw.githubusercontent.com/{'/'.join(parts)}"

    parts = [part for part in path.split("/") if part]
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError("Use a GitHub file URL containing /blob/<ref>/<path>.")

    owner, repo, _, ref, *file_parts = parts
    if not owner or not repo or not ref or not file_parts:
        raise ValueError("Invalid GitHub repository file URL.")
    return (
        "https://raw.githubusercontent.com/"
        f"{owner}/{repo}/{ref}/{'/'.join(file_parts)}"
    )


def _fetch_github_content(source_url: str) -> str:
    """Fetch a bounded public GitHub text file without redirects or proxy targets."""
    raw_url = _github_raw_url(source_url)
    request = URLRequest(
        raw_url,
        headers={
            "Accept": "text/plain, */*;q=0.1",
            "User-Agent": "SentinelDNS/1.0 blocklist-importer",
        },
        method="GET",
    )

    opener = build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=10) as response:
            content_type = (response.headers.get("Content-Type") or "").lower()
            if content_type and not any(
                value in content_type
                for value in ("text/", "application/octet-stream")
            ):
                raise ValueError("GitHub source is not a text file.")

            declared = response.headers.get("Content-Length")
            if declared:
                try:
                    if int(declared) > MAX_GITHUB_FETCH_BYTES:
                        raise ValueError("GitHub blocklist is larger than 2 MiB.")
                except ValueError as exc:
                    if str(exc).startswith("GitHub blocklist"):
                        raise

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_GITHUB_FETCH_BYTES:
                    raise ValueError("GitHub blocklist is larger than 2 MiB.")
                chunks.append(chunk)
    except HTTPError as exc:
        raise ValueError(f"GitHub download failed with HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError("GitHub blocklist could not be downloaded.") from exc

    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("GitHub blocklist must be UTF-8 text.") from exc


def _write_blocklist(filename: str, domains: list[str]) -> None:
    _validate_custom_filename(filename)
    BLOCKLIST_DIRECTORY.mkdir(parents=True, exist_ok=True)
    target = BLOCKLIST_DIRECTORY / filename
    payload = ("\n".join(domains) + "\n") if domains else ""
    fd, temp_name = tempfile.mkstemp(prefix=".blocklist_", suffix=".tmp", dir=BLOCKLIST_DIRECTORY)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _custom_blocklist_records() -> list[dict[str, object]]:
    records = []
    if not BLOCKLIST_DIRECTORY.is_dir():
        return records
    for path in sorted(BLOCKLIST_DIRECTORY.glob("*.txt")):
        if path.name.startswith("custom_"):
            try:
                _validate_custom_filename(path.name)
            except ValueError:
                continue
        loader = BlocklistRegistry.get(path.name)
        records.append({"filename": path.name, "domains": loader.size, "exists": path.is_file(), "custom": path.name.startswith("custom_")})
    return records

templates = Jinja2Templates(
    directory=TEMPLATES_DIRECTORY,
)

router = APIRouter(
    tags=["Management"],
)


# ==========================================================
# UPSTREAM REQUEST MODEL
# ==========================================================


class UpstreamConfiguration(BaseModel):
    """
    Runtime DNS upstream configuration.

    Supported transports:

        udp
        dot
        doh
    """

    transport: str = Field(
        min_length=1,
        max_length=10,
    )

    # ------------------------------------------------------
    # UDP
    # ------------------------------------------------------

    udp_servers: list[str] = Field(
        default_factory=list,
    )

    udp_timeout: float = Field(
        default=5.0,
        gt=0,
        le=60,
    )

    udp_max_response_size: int = Field(
        default=4096,
        ge=512,
        le=65535,
    )

    # ------------------------------------------------------
    # DoT
    # ------------------------------------------------------

    dot_server: str | None = Field(
        default=None,
        max_length=253,
    )

    dot_port: int = Field(
        default=853,
        ge=1,
        le=65535,
    )

    dot_timeout: float = Field(
        default=5.0,
        gt=0,
        le=60,
    )

    dot_max_response_size: int = Field(
        default=4096,
        ge=512,
        le=65535,
    )

    # ------------------------------------------------------
    # DoH
    # ------------------------------------------------------

    doh_provider: str | None = Field(
        default=None,
        max_length=50,
    )

    doh_endpoint: str | None = Field(
        default=None,
        max_length=2048,
    )

    doh_timeout: float = Field(
        default=5.0,
        gt=0,
        le=60,
    )

    doh_max_response_size: int = Field(
        default=4096,
        ge=512,
        le=65535,
    )


class CustomBlocklistCreate(BaseModel):
    name: str = Field(min_length=1, max_length=48)
    content: str = Field(default="", max_length=MAX_BLOCKLIST_BYTES)
    source_url: str | None = Field(default=None, max_length=2048)


class CustomBlocklistUpdate(BaseModel):
    content: str = Field(default="", max_length=MAX_BLOCKLIST_BYTES)


class CustomFilterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=48)
    blocklist_filename: str = Field(min_length=1, max_length=64)
    enabled: bool = True


class CustomFilterUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=48)
    blocklist_filename: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None


# ==========================================================
# HELPERS
# ==========================================================


def _dashboard_service(
    request: Request,
):
    """
    Return the shared DashboardService.
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


def _validate_hostname_or_ip(
    value: str,
) -> str:
    """
    Validate an upstream hostname or IP address.
    """

    value = value.strip()

    if not value:
        raise ValueError(
            "Upstream server must not be empty."
        )

    if len(value) > 253:
        raise ValueError(
            "Upstream server name is too long."
        )

    # ------------------------------------------------------
    # Accept valid IP addresses.
    # ------------------------------------------------------

    try:

        ipaddress.ip_address(
            value,
        )

        return value

    except ValueError:

        pass

    # ------------------------------------------------------
    # Validate hostname.
    # ------------------------------------------------------

    if value.endswith("."):
        value = value[:-1]

    labels = value.split(".")

    if not labels:
        raise ValueError(
            "Invalid upstream hostname."
        )

    for label in labels:

        if not label:
            raise ValueError(
                "Invalid upstream hostname."
            )

        if len(label) > 63:
            raise ValueError(
                "Invalid upstream hostname."
            )

        if (
            label.startswith("-")
            or label.endswith("-")
        ):
            raise ValueError(
                "Invalid upstream hostname."
            )

        allowed = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789-"
        )

        if any(
            character not in allowed
            for character in label
        ):
            raise ValueError(
                "Invalid upstream hostname."
            )

    return value


def _validate_doh_endpoint(
    endpoint: str,
) -> str:
    """
    Validate a custom DoH endpoint.

    DoH must use HTTPS.
    """

    endpoint = endpoint.strip()

    if not endpoint:
        raise ValueError(
            "DoH endpoint must not be empty."
        )

    parsed = urlparse(
        endpoint,
    )

    if parsed.scheme.lower() != "https":
        raise ValueError(
            "DoH endpoint must use HTTPS."
        )

    if not parsed.netloc:
        raise ValueError(
            "Invalid DoH endpoint."
        )

    return endpoint


def _build_upstream(
    configuration: UpstreamConfiguration,
) -> DNSUpstream:
    """
    Validate configuration and construct a new
    DNSUpstream instance.

    The returned instance is not activated yet.
    """

    transport = (
        configuration.transport
        .strip()
        .lower()
    )

    if transport not in {
        "udp",
        "dot",
        "doh",
    }:

        raise ValueError(
            "Unsupported DNS transport. "
            "Use udp, dot or doh."
        )

    # ======================================================
    # UDP
    # ======================================================

    if transport == "udp":

        if not configuration.udp_servers:

            raise ValueError(
                "At least one UDP upstream server "
                "is required."
            )

        servers = []

        for server in configuration.udp_servers:

            servers.append(
                _validate_hostname_or_ip(
                    server,
                )
            )

        return DNSUpstream(
            transport="udp",
            udp_servers=servers,
            udp_timeout=configuration.udp_timeout,
            udp_max_response_size=(
                configuration.udp_max_response_size
            ),
        )

    # ======================================================
    # DoT
    # ======================================================

    if transport == "dot":

        if not configuration.dot_server:

            raise ValueError(
                "DoT server is required."
            )

        server = _validate_hostname_or_ip(
            configuration.dot_server,
        )

        return DNSUpstream(
            transport="dot",
            dot_server=server,
            dot_port=configuration.dot_port,
            dot_timeout=configuration.dot_timeout,
            dot_max_response_size=(
                configuration.dot_max_response_size
            ),
        )

    # ======================================================
    # DoH
    # ======================================================

    provider = (
        configuration.doh_provider
        or ""
    ).strip().lower()

    endpoint = configuration.doh_endpoint

    builtin_providers = {
        "cloudflare",
        "google",
        "quad9",
    }

    if provider == "custom":

        if not endpoint:

            raise ValueError(
                "Custom DoH requires an HTTPS endpoint."
            )

        endpoint = _validate_doh_endpoint(
            endpoint,
        )

    elif provider in builtin_providers:

        # --------------------------------------------------
        # Built-in provider.
        #
        # DNSUpstream resolves the provider using its
        # built-in trusted provider definitions.
        # --------------------------------------------------

        endpoint = None

    else:

        raise ValueError(
            "Unknown DoH provider. "
            "Use cloudflare, google, quad9 or custom."
        )

    return DNSUpstream(
        transport="doh",
        doh_provider=provider,
        doh_endpoint=endpoint,
        doh_timeout=configuration.doh_timeout,
        doh_max_response_size=(
            configuration.doh_max_response_size
        ),
    )


def _save_upstream_configuration(
    configuration: UpstreamConfiguration,
) -> None:
    """
    Persist the upstream configuration to config.yaml.

    Existing unrelated configuration is preserved.
    """

    if not CONFIG_FILE.exists():

        raise RuntimeError(
            f"Configuration file not found: "
            f"{CONFIG_FILE}"
        )

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        data = yaml.safe_load(
            file,
        )

    if not isinstance(
        data,
        dict,
    ):

        raise RuntimeError(
            "Configuration file must contain "
            "a YAML mapping."
        )

    dns = data.setdefault(
        "dns",
        {},
    )

    if not isinstance(
        dns,
        dict,
    ):

        raise RuntimeError(
            "Invalid dns configuration."
        )

    transport = (
        configuration.transport
        .strip()
        .lower()
    )

    dns["transport"] = transport

    # ------------------------------------------------------
    # Common upstream settings.
    # ------------------------------------------------------

    upstream = dns.setdefault(
        "upstream",
        {},
    )

    if not isinstance(
        upstream,
        dict,
    ):

        upstream = {}

        dns["upstream"] = upstream

    upstream["timeout"] = (
        configuration.udp_timeout
    )

    upstream["retries"] = 2

    upstream["max_response_size"] = (
        configuration.udp_max_response_size
    )

    # ------------------------------------------------------
    # UDP servers.
    # ------------------------------------------------------

    upstream["servers"] = list(
        configuration.udp_servers,
    )

    # ------------------------------------------------------
    # DoH.
    # ------------------------------------------------------

    doh = dns.setdefault(
        "doh",
        {},
    )

    if not isinstance(
        doh,
        dict,
    ):

        doh = {}

        dns["doh"] = doh

    doh["enabled"] = (
        transport == "doh"
    )

    doh["provider"] = (
        configuration.doh_provider
        or "cloudflare"
    )

    if (
        configuration.doh_provider
        == "custom"
        and configuration.doh_endpoint
    ):

        doh["endpoint"] = (
            configuration.doh_endpoint
        )

    else:

        builtin_endpoints = {
            "cloudflare": (
                "https://cloudflare-dns.com/dns-query"
            ),
            "google": (
                "https://dns.google/dns-query"
            ),
            "quad9": (
                "https://dns.quad9.net/dns-query"
            ),
        }

        doh["endpoint"] = builtin_endpoints.get(
            (
                configuration.doh_provider
                or "cloudflare"
            ).lower(),
            configuration.doh_endpoint
            or "https://cloudflare-dns.com/dns-query",
        )

    doh["timeout"] = (
        configuration.doh_timeout
    )

    doh["http2"] = True

    doh["verify_tls"] = True

    # ------------------------------------------------------
    # DoT.
    # ------------------------------------------------------

    dot = dns.setdefault(
        "dot",
        {},
    )

    if not isinstance(
        dot,
        dict,
    ):

        dot = {}

        dns["dot"] = dot

    dot["enabled"] = (
        transport == "dot"
    )

    if configuration.dot_server:

        dot["server"] = (
            configuration.dot_server
        )

    dot["port"] = (
        configuration.dot_port
    )

    dot["timeout"] = (
        configuration.dot_timeout
    )

    dot["verify_tls"] = True

    # ------------------------------------------------------
    # Atomic-ish write.
    #
    # Write to a temporary file first and replace the
    # existing configuration only after serialization
    # succeeds.
    # ------------------------------------------------------

    temporary_file = CONFIG_FILE.with_suffix(
        ".yaml.tmp",
    )

    try:

        with temporary_file.open(
            "w",
            encoding="utf-8",
        ) as file:

            yaml.safe_dump(
                data,
                file,
                sort_keys=False,
                default_flow_style=False,
            )

        temporary_file.replace(
            CONFIG_FILE,
        )

    except Exception:

        try:

            temporary_file.unlink(
                missing_ok=True,
            )

        except Exception:

            pass

        raise


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

    return _no_store(response)


@router.get(
    "/api/upstream",
)
async def upstream_api(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Return the currently active upstream configuration.

    Only safe configuration information is returned.
    """

    service = _dashboard_service(
        request,
    )

    if service is None:

        return JSONResponse(
            content={
                "available": False,
                "error": (
                    "Dashboard service unavailable."
                ),
            },
            status_code=503,
        )

    resolver = getattr(
        service,
        "resolver",
        None,
    )

    if resolver is None:

        return JSONResponse(
            content={
                "available": False,
                "error": (
                    "DNS resolver unavailable."
                ),
            },
            status_code=503,
        )

    try:

        info = resolver.upstream_info()

    except Exception as exc:

        return JSONResponse(
            content={
                "available": False,
                "error": str(exc),
            },
            status_code=503,
        )

    return JSONResponse(
        content={
            "available": True,
            "upstream": info,
        },
        headers={
            "Cache-Control": (
                "no-store, max-age=0"
            ),
            "Pragma": "no-cache",
        },
    )


@router.post(
    "/upstream/apply",
)
async def apply_upstream(
    configuration: UpstreamConfiguration,
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):
    """
    Validate, persist and activate a new upstream.

    The new DNSUpstream is constructed first.

    Only after successful construction is the live resolver
    changed.

    This prevents an invalid configuration from replacing
    the working DNS transport.
    """

    service = _dashboard_service(
        request,
    )

    if service is None:

        return JSONResponse(
            content={
                "success": False,
                "error": (
                    "Dashboard service unavailable."
                ),
            },
            status_code=503,
        )

    resolver = getattr(
        service,
        "resolver",
        None,
    )

    if resolver is None:

        return JSONResponse(
            content={
                "success": False,
                "error": (
                    "DNS resolver unavailable."
                ),
            },
            status_code=503,
        )

    # ------------------------------------------------------
    # Build and validate the new upstream first.
    # ------------------------------------------------------

    try:

        new_upstream = _build_upstream(
            configuration,
        )

    except Exception as exc:

        return JSONResponse(
            content={
                "success": False,
                "error": str(exc),
                "active_upstream": (
                    resolver.upstream_info()
                ),
            },
            status_code=400,
        )

    # ------------------------------------------------------
    # Persist configuration before activation.
    #
    # If persistence fails, the new upstream is closed and
    # the currently active upstream remains untouched.
    # ------------------------------------------------------

    try:

        _save_upstream_configuration(
            configuration,
        )

    except Exception as exc:

        try:

            new_upstream.close()

        except Exception:

            pass

        return JSONResponse(
            content={
                "success": False,
                "error": (
                    "Failed to save configuration: "
                    f"{exc}"
                ),
                "active_upstream": (
                    resolver.upstream_info()
                ),
            },
            status_code=500,
        )

    # ------------------------------------------------------
    # Activate the already validated upstream.
    # ------------------------------------------------------

    try:

        resolver.replace_upstream(
            new_upstream,
        )

    except Exception as exc:

        try:

            new_upstream.close()

        except Exception:

            pass

        return JSONResponse(
            content={
                "success": False,
                "error": (
                    "Failed to activate upstream: "
                    f"{exc}"
                ),
                "active_upstream": (
                    resolver.upstream_info()
                ),
            },
            status_code=500,
        )

    active = resolver.upstream_info()

    return JSONResponse(
        content={
            "success": True,
            "message": (
                "DNS upstream updated successfully."
            ),
            "active_upstream": active,
        },
        headers={
            "Cache-Control": (
                "no-store, max-age=0"
            ),
            "Pragma": "no-cache",
        },
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

    return _no_store(response)


# ==========================================================
# SECURITY EVENTS
# ==========================================================


@router.get(
    "/security-events",
    response_class=Response,
)
async def security_events_page(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):

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

    events = service.security_events()

    response = templates.TemplateResponse(
        request=request,
        name="security_events/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
            "events": events,
        },
    )

    return _no_store(response)


@router.get(
    "/api/security-events",
)
async def security_events_api(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
):

    service = _dashboard_service(
        request,
    )

    if service is None:

        return {
            "available": False,
            "events": [],
        }

    return {
        "available": True,
        "events": service.security_events(),
    }


# ==========================================================
# CUSTOM BLOCKLIST MANAGEMENT
# ==========================================================


@router.get("/api/blocklists")
async def custom_blocklists_api(
    current_user: User = Depends(get_current_user),
):
    return JSONResponse(
        content={"blocklists": _custom_blocklist_records()},
        headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
    )


@router.get("/api/blocklists/{filename}")
async def custom_blocklist_detail(
    filename: str,
    current_user: User = Depends(get_current_user),
):
    try:
        filename = _validate_custom_filename(filename)
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=400)
    target = BLOCKLIST_DIRECTORY / filename
    if not target.is_file():
        return JSONResponse(content={"detail": "Custom blocklist not found."}, status_code=404)
    try:
        content = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return JSONResponse(content={"detail": "Blocklist could not be read."}, status_code=500)
    return JSONResponse(content={"filename": filename, "domains": content.splitlines()})


@router.post("/api/blocklists", status_code=201)
async def create_custom_blocklist(
    payload: CustomBlocklistCreate,
    current_user: User = Depends(require_admin),
):
    try:
        filename = _slug_filename(payload.name)
        if (BLOCKLIST_DIRECTORY / filename).exists():
            return JSONResponse(content={"detail": "A blocklist with that name already exists."}, status_code=409)
        content = payload.content
        if payload.source_url:
            content = _fetch_github_content(payload.source_url)
        domains = _parse_domains(content)
        _write_blocklist(filename, domains)
        BlocklistRegistry.reload(filename)
        return JSONResponse(content={"filename": filename, "domains": len(domains)}, status_code=201)
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=400)


@router.put("/api/blocklists/{filename}")
async def update_custom_blocklist(
    filename: str,
    payload: CustomBlocklistUpdate,
    current_user: User = Depends(require_admin),
):
    try:
        filename = _validate_custom_filename(filename)
        target = BLOCKLIST_DIRECTORY / filename
        if not target.is_file():
            return JSONResponse(content={"detail": "Custom blocklist not found."}, status_code=404)
        domains = _parse_domains(payload.content)
        _write_blocklist(filename, domains)
        BlocklistRegistry.reload(filename)
        return JSONResponse(content={"filename": filename, "domains": len(domains)})
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=400)


@router.delete("/api/blocklists/{filename}")
async def delete_custom_blocklist(
    filename: str,
    request: Request,
    current_user: User = Depends(require_admin),
):
    try:
        filename = _validate_custom_filename(filename)
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=400)
    target = BLOCKLIST_DIRECTORY / filename
    if not target.is_file():
        return JSONResponse(content={"detail": "Custom blocklist not found."}, status_code=404)
    service = _dashboard_service(request)
    manager = getattr(getattr(service, "resolver", None), "filter_manager", None) if service else None
    if manager is not None:
        for item in manager.custom_definitions.values():
            if item.get("filename") == filename:
                return JSONResponse(content={"detail": "Blocklist is used by a custom filter. Edit or remove that filter first."}, status_code=409)
    try:
        target.unlink()
        loader = BlocklistRegistry.loaded().get(filename)
        if loader is not None:
            loader._domains.clear()
    except OSError:
        return JSONResponse(content={"detail": "Blocklist could not be deleted."}, status_code=500)
    return JSONResponse(content={"deleted": filename})


@router.get("/api/filters")
async def custom_filters_api(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    service = _dashboard_service(request)
    manager = getattr(getattr(service, "resolver", None), "filter_manager", None) if service else None
    if manager is None:
        return JSONResponse(content={"detail": "Filter manager unavailable."}, status_code=503)
    return JSONResponse(
        content={"filters": manager.status()},
        headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
    )


@router.post("/api/filters", status_code=201)
async def create_custom_filter(
    payload: CustomFilterCreate,
    request: Request,
    current_user: User = Depends(require_admin),
):
    service = _dashboard_service(request)
    manager = getattr(getattr(service, "resolver", None), "filter_manager", None) if service else None
    if manager is None:
        return JSONResponse(content={"detail": "Filter manager unavailable."}, status_code=503)
    try:
        manager.add_custom_filter(payload.name, payload.blocklist_filename, payload.enabled)
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=400)
    return JSONResponse(content={"name": payload.name, "enabled": payload.enabled}, status_code=201)


@router.put("/api/filters/{filter_name}")
async def update_custom_filter(
    filter_name: str,
    payload: CustomFilterUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
):
    service = _dashboard_service(request)
    manager = getattr(getattr(service, "resolver", None), "filter_manager", None) if service else None
    if manager is None:
        return JSONResponse(content={"detail": "Filter manager unavailable."}, status_code=503)
    try:
        name = manager.update_custom_filter(filter_name, payload.name, payload.blocklist_filename, payload.enabled)
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=400)
    return JSONResponse(content={"name": name})


@router.delete("/api/filters/{filter_name}")
async def delete_custom_filter(
    filter_name: str,
    request: Request,
    current_user: User = Depends(require_admin),
):
    service = _dashboard_service(request)
    manager = getattr(getattr(service, "resolver", None), "filter_manager", None) if service else None
    if manager is None:
        return JSONResponse(content={"detail": "Filter manager unavailable."}, status_code=503)
    try:
        manager.remove_custom_filter(filter_name)
    except ValueError as exc:
        return JSONResponse(content={"detail": str(exc)}, status_code=404)
    return JSONResponse(content={"deleted": filter_name})


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

    return _no_store(response)


@router.post(
    "/blocklists/{filename}/reload",
)
async def reload_blocklist(
    filename: str,
    current_user: User = Depends(
        get_current_user,
    ),
):

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

    return _no_store(response)


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