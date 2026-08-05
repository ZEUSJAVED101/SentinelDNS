"""
SentinelDNS DNS-over-TLS Client

Responsibilities:
- Send DNS queries over TLS (RFC 7858)
- Verify TLS certificates
- Validate upstream responses
- Prevent malformed DNS responses
"""

from __future__ import annotations

import socket
import ssl
import struct


class DoTClient:
    """
    Secure DNS-over-TLS client.
    """

    MIN_DNS_PACKET_SIZE = 12

    DEFAULT_BUFFER_SIZE = 4096

    def __init__(
        self,
        server: str,
        port: int = 853,
        timeout: float = 5.0,
        max_response_size: int = DEFAULT_BUFFER_SIZE,
    ) -> None:

        if not server:
            raise ValueError(
                "DNS-over-TLS server cannot be empty."
            )

        if port <= 0 or port > 65535:
            raise ValueError(
                "Invalid DNS-over-TLS port."
            )

        if timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        if (
            max_response_size
            < self.MIN_DNS_PACKET_SIZE
        ):
            raise ValueError(
                "Maximum response size is too small."
            )

        self.server = server

        self.port = port

        self.timeout = timeout

        self.max_response_size = max_response_size

        #
        # Secure TLS Context
        #
        self._context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
        )

        #
        # Require TLS 1.2+
        #
        self._context.minimum_version = (
            ssl.TLSVersion.TLSv1_2
        )

        #
        # Verify certificates
        #
        self._context.check_hostname = True

        self._context.verify_mode = (
            ssl.CERT_REQUIRED
        )

    def _validate_response(
        self,
        request: bytes,
        response: bytes,
    ) -> None:
        """
        Validate DNS response.
        """

        if (
            len(response)
            < self.MIN_DNS_PACKET_SIZE
        ):

            raise ValueError(
                "Incomplete DNS response."
            )

        if (
            len(response)
            > self.max_response_size
        ):

            raise ValueError(
                "DNS response exceeds configured limit."
            )

        #
        # Transaction ID
        #
        if request[:2] != response[:2]:

            raise ValueError(
                "DNS transaction ID mismatch."
            )

    def _recv_exact(
        self,
        tls_socket: ssl.SSLSocket,
        size: int,
    ) -> bytes:
        """
        Read exactly size bytes.
        """

        data = bytearray()

        while len(data) < size:

            chunk = tls_socket.recv(
                size - len(data)
            )

            if not chunk:

                raise ConnectionError(
                    "TLS connection closed unexpectedly."
                )

            data.extend(chunk)

        return bytes(data)
    def query(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Send a DNS query over TLS (RFC 7858).

        Returns
        -------
        bytes
            Raw DNS response.
        """

        if len(packet) < self.MIN_DNS_PACKET_SIZE:
            raise ValueError(
                "Invalid DNS request packet."
            )

        #
        # RFC 7858 requires a 2-byte length prefix.
        #
        framed_packet = struct.pack(
            "!H",
            len(packet),
        ) + packet

        #
        # Establish TCP connection.
        #
        with socket.create_connection(
            (
                self.server,
                self.port,
            ),
            timeout=self.timeout,
        ) as tcp_socket:

            #
            # Wrap TCP socket with TLS.
            #
            with self._context.wrap_socket(
                tcp_socket,
                server_hostname=self.server,
            ) as tls_socket:

                tls_socket.settimeout(
                    self.timeout,
                )

                #
                # Send framed DNS packet.
                #
                tls_socket.sendall(
                    framed_packet,
                )

                #
                # Read RFC 7858 length prefix.
                #
                length_data = self._recv_exact(
                    tls_socket,
                    2,
                )

                response_length = struct.unpack(
                    "!H",
                    length_data,
                )[0]

                if (
                    response_length
                    < self.MIN_DNS_PACKET_SIZE
                ):
                    raise ValueError(
                        "Invalid DNS response length."
                    )

                if (
                    response_length
                    > self.max_response_size
                ):
                    raise ValueError(
                        "DNS response exceeds configured limit."
                    )

                #
                # Read complete DNS response.
                #
                response = self._recv_exact(
                    tls_socket,
                    response_length,
                )

                #
                # Validate DNS response.
                #
                self._validate_response(
                    packet,
                    response,
                )

                return response