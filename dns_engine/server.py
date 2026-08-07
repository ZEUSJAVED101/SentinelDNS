"""
SentinelDNS DNS Server

Responsibilities:
- Listen for DNS queries
- Delegate queries to the DNS resolver
- Return DNS responses
- Read server configuration from config.yaml
"""

from __future__ import annotations

import logging
import socket

from backend.core.config import settings
from dns_engine.resolver import DNSResolver

LOGGER = logging.getLogger(__name__)


class DNSServer:
    """
    UDP DNS Server.
    """

    MAX_DNS_PACKET_SIZE = 512

    def __init__(
        self,
    ) -> None:
        """
        Initialize the DNS server.
        """

        self.host = settings.dns.listen.host
        self.port = settings.dns.listen.port
        self.resolver = DNSResolver()

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        #
        # Allow quick restart after shutdown.
        #
        self.socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

    def start(
        self,
    ) -> None:
        """
        Start the DNS server.
        """

        try:

            self.socket.bind(
                (
                    self.host,
                    self.port,
                )
            )

        except OSError as exc:

            LOGGER.exception(
                "Unable to bind DNS socket."
            )

            raise RuntimeError(
                f"Cannot bind UDP {self.host}:{self.port}"
            ) from exc

        LOGGER.info(
            "SentinelDNS listening on %s:%s",
            self.host,
            self.port,
        )

        print(
            "\n"
            "========================================\n"
            " SentinelDNS DNS Engine Started\n"
            f" Listening on UDP {self.host}:{self.port}\n"
            "========================================\n"
        )

        try:

            while True:

                data, address = self.socket.recvfrom(
                    self.MAX_DNS_PACKET_SIZE,
                )

                try:

                    response = self.resolver.resolve(
                        data,
                    )

                    self.socket.sendto(
                        response,
                        address,
                    )

                except Exception:

                    LOGGER.exception(
                        "Failed to process DNS request."
                    )

        except KeyboardInterrupt:

            LOGGER.info(
                "Stopping SentinelDNS..."
            )

            print(
                "\nStopping SentinelDNS..."
            )

        finally:

            try:

                self.socket.close()

            except OSError:
                pass

            LOGGER.info(
                "DNS socket closed."
            )