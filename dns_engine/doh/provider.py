"""
DNS-over-HTTPS Provider Definitions

Responsibilities:
- Define trusted DoH providers
- Validate custom providers
- Provide immutable provider configuration
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(slots=True, frozen=True)
class DoHProvider:
    """
    Immutable DNS-over-HTTPS provider configuration.
    """

    name: str
    endpoint: str
    timeout: float = 5.0
    max_response_size: int = 4096

    def validate(self) -> None:
        """
        Validate provider configuration.
        """

        parsed = urlparse(self.endpoint)

        if parsed.scheme != "https":
            raise ValueError(
                "DoH endpoint must use HTTPS."
            )

        if not parsed.netloc:
            raise ValueError(
                "Invalid DoH endpoint."
            )

        if self.timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        if self.max_response_size < 512:
            raise ValueError(
                "Maximum response size is too small."
            )


# ==========================================================
# Built-in Providers
# ==========================================================

CLOUDFLARE = DoHProvider(
    name="cloudflare",
    endpoint="https://cloudflare-dns.com/dns-query",
)

GOOGLE = DoHProvider(
    name="google",
    endpoint="https://dns.google/dns-query",
)

QUAD9 = DoHProvider(
    name="quad9",
    endpoint="https://dns.quad9.net/dns-query",
)


_BUILTIN_PROVIDERS = {
    CLOUDFLARE.name: CLOUDFLARE,
    GOOGLE.name: GOOGLE,
    QUAD9.name: QUAD9,
}


def get_provider(
    name: str,
) -> DoHProvider:
    """
    Return a built-in provider by name.
    """

    provider = _BUILTIN_PROVIDERS.get(
        name.lower(),
    )

    if provider is None:
        raise ValueError(
            f"Unknown DoH provider: {name}"
        )

    return provider


def create_custom_provider(
    *,
    endpoint: str,
    timeout: float = 5.0,
    max_response_size: int = 4096,
) -> DoHProvider:
    """
    Create and validate a custom DoH provider.
    """

    provider = DoHProvider(
        name="custom",
        endpoint=endpoint,
        timeout=timeout,
        max_response_size=max_response_size,
    )

    provider.validate()

    return provider