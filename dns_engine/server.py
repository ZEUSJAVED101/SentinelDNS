"""
SentinelDNS DNS Server

Responsibilities:
- Listen for DNS queries
- Delegate query processing to the resolver
- Return DNS responses
"""

from __future__ import annotations

import logging
import socket

from dns_engine.resolver import DNSResolver

LOGGER = logging.getLogger(__name__)


class DNSServer:
    """
    Simple UDP DNS server.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5300,
    ) -> None:

        self.host = host
        self.port = port

        self.resolver = DNSResolver()

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

    def start(self) -> None:
        """
        Start the DNS server.
        """

        self.socket.bind(
            (
                self.host,
                self.port,
            )
        )

        LOGGER.info(
            "SentinelDNS listening on %s:%s",
            self.host,
            self.port,
        )

        print(
            f"\n"
            f"=====================================\n"
            f" SentinelDNS DNS Engine Started\n"
            f" Listening on UDP {self.host}:{self.port}\n"
            f"=====================================\n"
        )

        try:

            while True:

                try:

                    data, address = self.socket.recvfrom(
                        512,
                    )

                    LOGGER.info(
                        "Received %d bytes from %s",
                        len(data),
                        address,
                    )

                    response = self.resolver.resolve(
                        data,
                    )

                    self.socket.sendto(
                        response,
                        address,
                    )

                except KeyboardInterrupt:

                    raise

                except Exception:

                    LOGGER.exception(
                        "Unhandled exception while processing DNS request."
                    )

                    #
                    # Continue serving other clients.
                    #
                    continue

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