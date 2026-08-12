"""
SentinelDNS DNS Server

Responsibilities:

- Listen for DNS queries
- Delegate query processing to DNSResolver
- Return DNS responses
- Allow the application to share one resolver instance
- Support clean startup and shutdown
"""

from __future__ import annotations

import logging
import socket

from dns_engine.resolver import DNSResolver


LOGGER = logging.getLogger(__name__)


class DNSServer:
    """
    UDP DNS server.

    The resolver can be injected so the DNS engine,
    dashboard, cache and metrics all use the same
    runtime resolver instance.
    """

    # ------------------------------------------------------
    # Maximum UDP DNS packet size.
    # ------------------------------------------------------

    MAX_PACKET_SIZE = 4096

    # ------------------------------------------------------
    # Socket receive timeout.
    #
    # This allows the server to periodically check
    # whether shutdown has been requested.
    # ------------------------------------------------------

    SOCKET_TIMEOUT = 1.0

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 53,
        resolver: DNSResolver | None = None,
    ) -> None:
        """
        Initialize the DNS server.

        Parameters
        ----------
        host:
            Local address on which the DNS server listens.

        port:
            UDP DNS port.

        resolver:
            Optional shared DNSResolver instance.
        """

        if not host:
            raise ValueError(
                "DNS server host cannot be empty."
            )

        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or port < 1
            or port > 65535
        ):
            raise ValueError(
                "Invalid DNS server port."
            )

        self.host = host
        self.port = port

        # --------------------------------------------------
        # IMPORTANT:
        # Use the injected resolver when supplied.
        #
        # This is what allows main.py and the dashboard
        # to observe the exact same DNS runtime state.
        # --------------------------------------------------

        self.resolver = (
            resolver
            if resolver is not None
            else DNSResolver()
        )

        self.socket: socket.socket | None = None

        self._running = False

    # ======================================================
    # SOCKET
    # ======================================================

    def _create_socket(self) -> socket.socket:
        """
        Create and bind the UDP DNS socket.
        """

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        try:

            # --------------------------------------------------
            # Allow safe address reuse during development and
            # clean restarts.
            # --------------------------------------------------

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )

            # --------------------------------------------------
            # Timeout allows stop() to be detected promptly.
            # --------------------------------------------------

            sock.settimeout(
                self.SOCKET_TIMEOUT,
            )

            # --------------------------------------------------
            # Bind only to the configured local address.
            # --------------------------------------------------

            sock.bind(
                (
                    self.host,
                    self.port,
                )
            )

            return sock

        except Exception:

            try:
                sock.close()
            except OSError:
                pass

            raise

    # ======================================================
    # START
    # ======================================================

    def start(self) -> None:
        """
        Start the DNS server.

        This method blocks until stop() is called or
        an unrecoverable socket error occurs.
        """

        if self._running:
            raise RuntimeError(
                "DNS server is already running."
            )

        sock = self._create_socket()

        self.socket = sock
        self._running = True

        LOGGER.info(
            "SentinelDNS listening on UDP %s:%s",
            self.host,
            self.port,
        )

        print(
            "\n"
            "=====================================\n"
            " SentinelDNS DNS Engine Started\n"
            f" Listening on UDP "
            f"{self.host}:{self.port}\n"
            "=====================================\n"
        )

        try:

            self.serve_forever()

        finally:

            self.stop()

    # ======================================================
    # SERVE
    # ======================================================

    def serve_forever(self) -> None:
        """
        Process DNS packets until stop() is called.
        """

        if self.socket is None:
            raise RuntimeError(
                "DNS socket is not initialized."
            )

        while self._running:

            try:

                data, address = (
                    self.socket.recvfrom(
                        self.MAX_PACKET_SIZE,
                    )
                )

            except socket.timeout:

                # --------------------------------------------------
                # Normal timeout.
                #
                # This lets the loop notice stop().
                # --------------------------------------------------

                continue

            except OSError:

                # --------------------------------------------------
                # Socket may have been closed by stop().
                # --------------------------------------------------

                if not self._running:
                    break

                LOGGER.exception(
                    "DNS socket receive failed."
                )

                continue

            # ------------------------------------------------------
            # Ignore empty packets defensively.
            # ------------------------------------------------------

            if not data:
                continue

            # ------------------------------------------------------
            # Resolve DNS query.
            # ------------------------------------------------------

            try:

                response = self.resolver.resolve(
                    data,
                )

            except Exception:

                LOGGER.exception(
                    "Unhandled DNS request error."
                )

                continue

            # ------------------------------------------------------
            # Do not send an empty response.
            # ------------------------------------------------------

            if not response:
                LOGGER.warning(
                    "Resolver returned an empty DNS response."
                )

                continue

            # ------------------------------------------------------
            # Send response to requesting client.
            # ------------------------------------------------------

            try:

                self.socket.sendto(
                    response,
                    address,
                )

            except OSError:

                if not self._running:
                    break

                LOGGER.exception(
                    "Failed to send DNS response."
                )

    # ======================================================
    # STOP
    # ======================================================

    def stop(self) -> None:
        """
        Stop the DNS server safely.

        This method is intentionally idempotent so it can
        safely be called multiple times during application
        shutdown.
        """

        self._running = False

        sock = self.socket

        self.socket = None

        if sock is not None:

            try:
                sock.close()

            except OSError:
                pass

        LOGGER.info(
            "SentinelDNS DNS server stopped."
        )

    # ======================================================
    # STATUS
    # ======================================================

    @property
    def running(self) -> bool:
        """
        Return whether the DNS server is currently running.
        """

        return self._running