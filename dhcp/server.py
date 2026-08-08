"""
SentinelDNS DHCP Server

Responsibilities:
- Receive DHCP/BOOTP UDP packets
- Parse DHCP requests
- Handle DHCPDISCOVER
- Handle DHCPREQUEST
- Handle DHCPDECLINE
- Handle DHCPRELEASE
- Handle DHCPINFORM
- Generate DHCPOFFER
- Generate DHCPACK
- Generate DHCPNAK
- Allocate dynamic addresses
- Respect static reservations
- Persist leases
- Provide graceful socket shutdown

The server uses the existing SentinelDNS DHCP configuration.
"""

from __future__ import annotations

import logging
import socket
import struct
from threading import Event, RLock

from backend.core.config import settings

from dhcp.lease_manager import (
    DHCPLease,
    DHCPLeaseError,
    DHCPLeaseManager,
    DHCPLeaseNotFoundError,
)

from dhcp.options import (
    DHCPOption,
    DHCPOptionCode,
    DHCPOptionError,
    encode_options,
    get_message_type,
    get_option_value,
    parse_options,
)

from dhcp.packet import (
    DHCPPacket,
    DHCPPacketError,
)

from dhcp.pool import (
    DHCPAddressPool,
    DHCPPoolError,
    DHCPPoolExhaustedError,
)

from dhcp.reservation import (
    DHCPReservationManager,
)

from dhcp.storage import (
    DHCPLeaseStorage,
    StoredLease,
)


LOGGER = logging.getLogger(__name__)


class DHCPMessageType:
    """
    DHCP message type values defined by RFC 2132.
    """

    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


class DHCPServerError(RuntimeError):
    """Raised when the DHCP server cannot operate correctly."""


class DHCPServer:
    """
    SentinelDNS DHCP server.

    The server coordinates:

        DHCPPacket
            ↓
        DHCP Options
            ↓
        Reservation / Pool
            ↓
        Lease Manager
            ↓
        Persistent Storage
    """

    MAX_PACKET_SIZE = 4096

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        """
        Initialize the DHCP server.

        When host/port are omitted, the existing SentinelDNS
        DHCP configuration is used.
        """

        dhcp_config = settings.dhcp

        self.enabled = dhcp_config.enabled

        self.host = (
            host
            if host is not None
            else dhcp_config.listen.host
        )

        self.port = (
            port
            if port is not None
            else dhcp_config.listen.port
        )

        self.interface = dhcp_config.interface

        self.server_ip = dhcp_config.server_ip

        self.subnet_mask = dhcp_config.subnet_mask

        self.gateway = dhcp_config.gateway

        self.dns_server = dhcp_config.dns_server

        self.lease_time = dhcp_config.lease_time

        self.pool = DHCPAddressPool(
            start=dhcp_config.pool.start,
            end=dhcp_config.pool.end,
        )

        self.reservations = (
            DHCPReservationManager()
        )

        self.lease_manager = (
            DHCPLeaseManager(
                self.pool
            )
        )

        self.storage = DHCPLeaseStorage()

        self.socket: socket.socket | None = None

        self._stop_event = Event()

        self._lock = RLock()

    # ==========================================================
    # Socket Lifecycle
    # ==========================================================

    def _create_socket(self) -> socket.socket:
        """
        Create and configure the DHCP UDP socket.
        """

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        # DHCP commonly uses broadcast traffic.
        try:

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BROADCAST,
                1,
            )

        except OSError:

            LOGGER.warning(
                "Unable to enable UDP broadcast mode."
            )

        sock.bind(
            (
                self.host,
                self.port,
            )
        )

        # A timeout allows the stop event to be checked.
        sock.settimeout(1.0)

        return sock

    def start(self) -> None:
        """
        Start the DHCP server and process requests.
        """

        if not self.enabled:

            LOGGER.info(
                "SentinelDNS DHCP service is disabled."
            )

            print(
                "DHCP Service : DISABLED"
            )

            return

        with self._lock:

            if self.socket is not None:

                raise DHCPServerError(
                    "DHCP server is already running."
                )

            self._stop_event.clear()

            self.socket = self._create_socket()

        LOGGER.info(
            "SentinelDNS DHCP server listening "
            "on %s:%s",
            self.host,
            self.port,
        )

        print(
            "\n"
            "=====================================\n"
            " SentinelDNS DHCP Server Started\n"
            f" Listening on UDP {self.host}:{self.port}\n"
            f" Server IP : {self.server_ip}\n"
            f" Pool      : {self.pool.start} - "
            f"{self.pool.end}\n"
            "=====================================\n"
        )

        try:

            self.serve_forever()

        except KeyboardInterrupt:

            LOGGER.info(
                "DHCP server interrupted."
            )

        finally:

            self.stop()

    def serve_forever(self) -> None:
        """
        Process DHCP packets until stop() is requested.
        """

        if self.socket is None:

            raise DHCPServerError(
                "DHCP socket is not initialized."
            )

        while not self._stop_event.is_set():

            try:

                data, address = self.socket.recvfrom(
                    self.MAX_PACKET_SIZE
                )

            except socket.timeout:

                continue

            except OSError as exc:

                if self._stop_event.is_set():
                    break

                LOGGER.error(
                    "DHCP socket receive failed: %s",
                    exc,
                )

                continue

            LOGGER.info(
                "Received DHCP packet of %d bytes "
                "from %s",
                len(data),
                address,
            )

            try:

                response = self.handle_packet(
                    data
                )

            except Exception:

                LOGGER.exception(
                    "Unhandled DHCP packet error."
                )

                continue

            if response is None:
                continue

            try:

                self._send_response(
                    response,
                    address,
                )

            except OSError:

                LOGGER.exception(
                    "Failed to send DHCP response."
                )

    def stop(self) -> None:
        """
        Stop the DHCP server and close the socket.
        """

        self._stop_event.set()

        with self._lock:

            if self.socket is not None:

                try:

                    self.socket.close()

                except OSError:

                    pass

                finally:

                    self.socket = None

        LOGGER.info(
            "DHCP server stopped."
        )

    # ==========================================================
    # Packet Processing
    # ==========================================================

    def handle_packet(
        self,
        data: bytes,
    ) -> bytes | None:
        """
        Parse and process one DHCP packet.

        This method is intentionally independent of the UDP
        socket, making it suitable for unit testing.
        """

        try:

            packet = DHCPPacket.from_bytes(
                data
            )

        except DHCPPacketError as exc:

            LOGGER.warning(
                "Invalid DHCP packet: %s",
                exc,
            )

            return None

        try:

            options = parse_options(
                packet.options
            )

        except DHCPOptionError as exc:

            LOGGER.warning(
                "Invalid DHCP options: %s",
                exc,
            )

            return None

        message_type = get_message_type(
            options
        )

        if message_type is None:

            LOGGER.warning(
                "DHCP packet has no message type."
            )

            return None

        LOGGER.info(
            "DHCP message type=%s "
            "client=%s xid=%08x",
            message_type,
            packet.client_mac,
            packet.xid,
        )

        if message_type == DHCPMessageType.DISCOVER:

            return self._handle_discover(
                packet,
                options,
            )

        if message_type == DHCPMessageType.REQUEST:

            return self._handle_request(
                packet,
                options,
            )

        if message_type == DHCPMessageType.DECLINE:

            self._handle_decline(
                packet,
                options,
            )

            return None

        if message_type == DHCPMessageType.RELEASE:

            self._handle_release(
                packet
            )

            return None

        if message_type == DHCPMessageType.INFORM:

            return self._handle_inform(
                packet,
                options,
            )

        LOGGER.info(
            "Ignoring unsupported DHCP message type %s.",
            message_type,
        )

        return None

    # ==========================================================
    # DHCPDISCOVER
    # ==========================================================

    def _handle_discover(
        self,
        packet: DHCPPacket,
        options: list[DHCPOption],
    ) -> bytes | None:
        """
        Handle DHCPDISCOVER and create a DHCPOFFER.
        """

        client_id = self._client_id(
            packet,
            options,
        )

        requested_ip = self._requested_ip(
            options
        )

        LOGGER.info(
            "DHCPDISCOVER from %s requested_ip=%s",
            client_id,
            requested_ip,
        )

        lease = self._obtain_lease(
            client_id=client_id,
            requested_ip=requested_ip,
            hostname=None,
        )

        if lease is None:

            LOGGER.warning(
                "No DHCP address available for %s.",
                client_id,
            )

            return None

        return self._build_response(
            request=packet,
            message_type=DHCPMessageType.OFFER,
            yiaddr=lease.ip_address,
            include_lease=True,
        )

    # ==========================================================
    # DHCPREQUEST
    # ==========================================================

    def _handle_request(
        self,
        packet: DHCPPacket,
        options: list[DHCPOption],
    ) -> bytes | None:
        """
        Handle DHCPREQUEST.

        Supports:
        - Initial address requests
        - Requested IP option
        - Server identifier
        - Existing lease renewal
        """

        client_id = self._client_id(
            packet,
            options,
        )

        requested_ip = self._requested_ip(
            options
        )

        server_identifier = (
            self._server_identifier(
                options
            )
        )

        # If another DHCP server is explicitly selected,
        # this request is not for SentinelDNS.
        if (
            server_identifier is not None
            and server_identifier
            != self.server_ip
        ):

            LOGGER.info(
                "DHCPREQUEST is for another server: %s",
                server_identifier,
            )

            return None

        LOGGER.info(
            "DHCPREQUEST from %s requested_ip=%s",
            client_id,
            requested_ip,
        )

        existing = self.lease_manager.get_by_client(
            client_id
        )

        try:

            if existing is not None:

                lease = self.lease_manager.renew(
                    client_id,
                    self.lease_time,
                )

            else:

                lease = self._obtain_lease(
                    client_id=client_id,
                    requested_ip=requested_ip,
                    hostname=None,
                )

                if lease is None:

                    return self._build_response(
                        request=packet,
                        message_type=DHCPMessageType.NAK,
                        yiaddr="0.0.0.0",
                        include_lease=False,
                    )

            self._persist_lease(
                lease
            )

        except (
            DHCPLeaseError,
            DHCPLeaseNotFoundError,
            DHCPPoolError,
        ) as exc:

            LOGGER.warning(
                "Unable to process DHCPREQUEST "
                "from %s: %s",
                client_id,
                exc,
            )

            return self._build_response(
                request=packet,
                message_type=DHCPMessageType.NAK,
                yiaddr="0.0.0.0",
                include_lease=False,
            )

        return self._build_response(
            request=packet,
            message_type=DHCPMessageType.ACK,
            yiaddr=lease.ip_address,
            include_lease=True,
        )

    # ==========================================================
    # DHCPDECLINE
    # ==========================================================

    def _handle_decline(
        self,
        packet: DHCPPacket,
        options: list[DHCPOption],
    ) -> None:
        """
        Handle DHCPDECLINE.

        The client reports that the offered address appears
        to be in use.

        The address is removed from the active lease manager
        when it belongs to the requesting client.
        """

        client_id = self._client_id(
            packet,
            options,
        )

        declined_ip = self._requested_ip(
            options
        )

        LOGGER.warning(
            "DHCPDECLINE from %s for %s",
            client_id,
            declined_ip,
        )

        lease = self.lease_manager.get_by_client(
            client_id
        )

        if (
            lease is not None
            and (
                declined_ip is None
                or lease.ip_address == declined_ip
            )
        ):

            self.lease_manager.release(
                client_id
            )

            self.storage.delete(
                client_id
            )

    # ==========================================================
    # DHCPRELEASE
    # ==========================================================

    def _handle_release(
        self,
        packet: DHCPPacket,
    ) -> None:
        """
        Handle DHCPRELEASE.
        """

        client_id = packet.client_mac

        LOGGER.info(
            "DHCPRELEASE from %s",
            client_id,
        )

        try:

            released = self.lease_manager.release(
                client_id
            )

            self.storage.delete(
                client_id
            )

            if released:

                LOGGER.info(
                    "Released DHCP lease for %s",
                    client_id,
                )

        except DHCPLeaseError as exc:

            LOGGER.warning(
                "Unable to release DHCP lease: %s",
                exc,
            )

    # ==========================================================
    # DHCPINFORM
    # ==========================================================

    def _handle_inform(
        self,
        packet: DHCPPacket,
        options: list[DHCPOption],
    ) -> bytes:
        """
        Handle DHCPINFORM.

        DHCPINFORM requests configuration information without
        allocating an IP address.
        """

        LOGGER.info(
            "DHCPINFORM from %s",
            packet.client_mac,
        )

        return self._build_response(
            request=packet,
            message_type=DHCPMessageType.ACK,
            yiaddr="0.0.0.0",
            include_lease=False,
        )

    # ==========================================================
    # Lease Allocation
    # ==========================================================

    def _obtain_lease(
        self,
        client_id: str,
        requested_ip: str | None,
        hostname: str | None,
    ) -> DHCPLease | None:
        """
        Obtain a lease using the following priority:

        1. Existing lease
        2. Static reservation
        3. Valid requested IP
        4. Dynamic pool
        """

        existing = self.lease_manager.get_by_client(
            client_id
        )

        if existing is not None:

            self._persist_lease(
                existing
            )

            return existing

        reservation = (
            self.reservations.get_by_client(
                client_id
            )
        )

        if reservation is not None:

            try:

                lease = (
                    self.lease_manager.create_specific(
                        client_id=client_id,
                        ip_address=reservation.ip_address,
                        lease_time=self.lease_time,
                        hostname=(
                            hostname
                            or reservation.hostname
                        ),
                    )
                )

                self._persist_lease(
                    lease
                )

                return lease

            except DHCPLeaseError as exc:

                LOGGER.warning(
                    "Reservation could not be assigned "
                    "to %s: %s",
                    client_id,
                    exc,
                )

                return None

        if requested_ip is not None:

            try:

                lease = (
                    self.lease_manager.create_specific(
                        client_id=client_id,
                        ip_address=requested_ip,
                        lease_time=self.lease_time,
                        hostname=hostname,
                    )
                )

                self._persist_lease(
                    lease
                )

                return lease

            except DHCPLeaseError:

                LOGGER.info(
                    "Requested IP %s is unavailable "
                    "for %s; attempting dynamic allocation.",
                    requested_ip,
                    client_id,
                )

        try:

            lease = self.lease_manager.create(
                client_id=client_id,
                lease_time=self.lease_time,
                hostname=hostname,
            )

        except DHCPPoolExhaustedError:

            LOGGER.warning(
                "DHCP pool exhausted."
            )

            return None

        except DHCPLeaseError as exc:

            LOGGER.warning(
                "Unable to create DHCP lease: %s",
                exc,
            )

            return None

        self._persist_lease(
            lease
        )

        return lease

    def _persist_lease(
        self,
        lease: DHCPLease,
    ) -> None:
        """
        Persist a lease using the existing SentinelDNS
        database layer.
        """

        stored = StoredLease(
            client_id=lease.client_id,
            ip_address=lease.ip_address,
            lease_start=lease.lease_start,
            lease_end=lease.lease_end,
            hostname=lease.hostname,
        )

        self.storage.save(
            stored
        )

    # ==========================================================
    # DHCP Response Construction
    # ==========================================================

    def _build_response(
        self,
        request: DHCPPacket,
        message_type: int,
        yiaddr: str,
        include_lease: bool,
    ) -> bytes:
        """
        Construct a DHCP response packet.
        """

        response = request.copy(
            op=2,
            yiaddr=yiaddr,
            siaddr=self.server_ip,
            options=b"",
        )

        options: list[DHCPOption] = []

        # DHCP message type.
        options.append(
            DHCPOption(
                code=DHCPOptionCode.MESSAGE_TYPE,
                value=bytes(
                    (message_type,)
                ),
            )
        )

        # DHCP server identifier.
        options.append(
            DHCPOption(
                code=DHCPOptionCode.SERVER_IDENTIFIER,
                value=socket.inet_aton(
                    self.server_ip
                ),
            )
        )

        # Network configuration.
        options.append(
            DHCPOption(
                code=DHCPOptionCode.SUBNET_MASK,
                value=socket.inet_aton(
                    self.subnet_mask
                ),
            )
        )

        if self.gateway:

            options.append(
                DHCPOption(
                    code=DHCPOptionCode.ROUTER,
                    value=socket.inet_aton(
                        self.gateway
                    ),
                )
            )

        if self.dns_server:

            options.append(
                DHCPOption(
                    code=DHCPOptionCode.DNS_SERVER,
                    value=socket.inet_aton(
                        self.dns_server
                    ),
                )
            )

        if include_lease:

            options.append(
                DHCPOption(
                    code=DHCPOptionCode.LEASE_TIME,
                    value=struct.pack(
                        "!I",
                        self.lease_time,
                    ),
                )
            )

            # T1 = 50% of lease time.
            renewal_time = max(
                1,
                self.lease_time // 2,
            )

            options.append(
                DHCPOption(
                    code=DHCPOptionCode.RENEWAL_TIME,
                    value=struct.pack(
                        "!I",
                        renewal_time,
                    ),
                )
            )

            # T2 = 87.5% of lease time.
            rebinding_time = max(
                1,
                int(
                    self.lease_time * 0.875
                ),
            )

            options.append(
                DHCPOption(
                    code=DHCPOptionCode.REBINDING_TIME,
                    value=struct.pack(
                        "!I",
                        rebinding_time,
                    ),
                )
            )

        response.options = encode_options(
            options
        )

        return response.to_bytes()

    # ==========================================================
    # DHCP Option Helpers
    # ==========================================================

    @staticmethod
    def _client_id(
        packet: DHCPPacket,
        options: list[DHCPOption],
    ) -> str:
        """
        Determine the client identifier.

        DHCP option 61 is preferred when present.
        Otherwise the client's MAC address is used.
        """

        value = get_option_value(
            options,
            DHCPOptionCode.CLIENT_IDENTIFIER,
        )

        if value:

            # Preserve the complete DHCP client identifier
            # in a deterministic hexadecimal form.
            return value.hex()

        return packet.client_mac

    @staticmethod
    def _requested_ip(
        options: list[DHCPOption],
    ) -> str | None:
        """
        Extract DHCP option 50.
        """

        value = get_option_value(
            options,
            DHCPOptionCode.REQUESTED_IP,
        )

        if value is None:
            return None

        if len(value) != 4:

            raise DHCPOptionError(
                "Invalid requested IP option."
            )

        return socket.inet_ntoa(
            value
        )

    @staticmethod
    def _server_identifier(
        options: list[DHCPOption],
    ) -> str | None:
        """
        Extract DHCP option 54.
        """

        value = get_option_value(
            options,
            DHCPOptionCode.SERVER_IDENTIFIER,
        )

        if value is None:
            return None

        if len(value) != 4:

            raise DHCPOptionError(
                "Invalid server identifier option."
            )

        return socket.inet_ntoa(
            value
        )

    # ==========================================================
    # Response Transmission
    # ==========================================================

    def _send_response(
        self,
        response: bytes,
        client_address: tuple[str, int],
    ) -> None:
        """
        Send a DHCP response.

        Broadcast responses are sent to the DHCP broadcast
        address. Otherwise the originating address is used.
        """

        if self.socket is None:

            raise DHCPServerError(
                "DHCP socket is not available."
            )

        try:

            packet = DHCPPacket.from_bytes(
                response
            )

            destination = client_address

            if packet.broadcast:

                destination = (
                    "255.255.255.255",
                    68,
                )

            elif packet.yiaddr != "0.0.0.0":

                destination = (
                    packet.yiaddr,
                    68,
                )

            self.socket.sendto(
                response,
                destination,
            )

            LOGGER.info(
                "Sent DHCP response to %s",
                destination,
            )

        except DHCPPacketError:

            # This should never happen for a response
            # produced internally, but fail safely.
            self.socket.sendto(
                response,
                client_address,
            )


__all__ = [
    "DHCPMessageType",
    "DHCPServer",
    "DHCPServerError",
]