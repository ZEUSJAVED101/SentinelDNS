"""
SentinelDNS DNS-over-HTTPS Client

Responsibilities:
- Send DNS queries using RFC 8484
- Use HTTPS with HTTP/2
- Verify TLS certificates
- Validate DNS responses
"""

from __future__ import annotations

import httpx

from dns_engine.doh.exceptions import (
    DoHConfigurationError,
)
from dns_engine.doh.provider import (
    DoHProvider,
)


class DoHClient:
    """
    Secure DNS-over-HTTPS client.
    """

    DNS_CONTENT_TYPE = "application/dns-message"

    MIN_DNS_PACKET_SIZE = 12

    DEFAULT_MAX_RESPONSE_SIZE = 4096

    def __init__(
        self,
        provider: DoHProvider,
    ) -> None:
        """
        Initialize a DNS-over-HTTPS client.
        """

        if not isinstance(
            provider,
            DoHProvider,
        ):
            raise DoHConfigurationError(
                "Invalid DoH provider."
            )

        provider.validate()

        self._provider = provider

        timeout = httpx.Timeout(
            connect=provider.timeout,
            read=provider.timeout,
            write=provider.timeout,
            pool=provider.timeout,
        )

        limits = httpx.Limits(
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=30,
        )

        self._client = httpx.Client(
            http2=True,
            verify=True,
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            headers={
                "Accept": self.DNS_CONTENT_TYPE,
                "Content-Type": self.DNS_CONTENT_TYPE,
                "User-Agent": "SentinelDNS/1.0",
            },
        )
    def _check_transaction_id(
        self,
        request: bytes,
        response: bytes,
    ) -> None:
        """
        Verify that the DNS transaction IDs match.
        """

        if request[:2] != response[:2]:
            raise ValueError(
                "DNS transaction ID mismatch."
            )

    def _validate_response(
        self,
        request: bytes,
        response: bytes,
    ) -> None:
        """
        Validate a DNS response received from a DoH server.
        """

        if len(response) < self.MIN_DNS_PACKET_SIZE:
            raise ValueError(
                "Incomplete DNS response."
            )

        if (
            len(response)
            > self._provider.max_response_size
        ):
            raise ValueError(
                "DNS response exceeds configured limit."
            )

        self._check_transaction_id(
            request,
            response,
        )
    def query(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Send a DNS query over HTTPS (RFC 8484).
        """

        if (
            len(packet)
            < self.MIN_DNS_PACKET_SIZE
        ):
            raise ValueError(
                "Invalid DNS request packet."
            )

        try:

            response = self._client.post(
                self._provider.endpoint,
                content=packet,
            )

        except httpx.TimeoutException as exc:

            from dns_engine.doh.exceptions import (
                DoHTimeoutError,
            )

            raise DoHTimeoutError(
                "DNS-over-HTTPS request timed out."
            ) from exc

        except httpx.ConnectError as exc:

            from dns_engine.doh.exceptions import (
                DoHConnectionError,
            )

            raise DoHConnectionError(
                "Unable to connect to DoH server."
            ) from exc

        except httpx.HTTPError as exc:

            from dns_engine.doh.exceptions import (
                DoHProtocolError,
            )

            raise DoHProtocolError(
                str(exc),
            ) from exc

        if (
            response.status_code
            != httpx.codes.OK
        ):
            from dns_engine.doh.exceptions import (
                DoHProtocolError,
            )

            raise DoHProtocolError(
                f"Unexpected HTTP status: "
                f"{response.status_code}"
            )

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        if (
            self.DNS_CONTENT_TYPE
            not in content_type.lower()
        ):
            from dns_engine.doh.exceptions import (
                DoHProtocolError,
            )

            raise DoHProtocolError(
                "Invalid DoH Content-Type."
            )

        dns_response = response.content

        self._validate_response(
            packet,
            dns_response,
        )

        return dns_response
    def close(
        self,
    ) -> None:
        """
        Close the underlying HTTP client.
        """

        self._client.close()

    def __enter__(
        self,
    ) -> "DoHClient":
        """
        Enter the runtime context.
        """

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        """
        Exit the runtime context.
        """

        self.close()