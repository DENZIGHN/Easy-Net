"""TCP desynchronization for DPI bypass.

Technique: Inject fake data into the TCP stream before the real handshake/data
to desynchronize the DPI's TCP state tracking from the real connection state.

Methods:
1. Fake SYN: Send extra data in the SYN packet that the server ignores
   (data in SYN is technically valid but most servers discard it).
   The DPI may try to parse this fake data, getting confused.

2. Split: Split the first data segment into two, with the first part
   containing garbage that confuses DPI pattern matching.

3. Disorder: Send TCP segments out of order. The server's TCP stack
   reassembles them correctly, but DPI may not handle reordering.

The key principle: DPI systems that do lightweight TCP stream reassembly
can be tricked when the TCP state they observe differs from what the
actual endpoints see.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
from typing import TYPE_CHECKING

from easynet.core.base import BypassMethod, BypassResult, ConnectionContext

if TYPE_CHECKING:
    from easynet.utils.config import Config

logger = logging.getLogger(__name__)


def build_fake_data_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq_num: int,
    fake_payload: bytes,
    ttl: int = 1,
) -> bytes:
    """Build a TCP data packet with fake payload and low TTL.

    Similar to the RST packet builder, but carries actual (garbage) payload.
    The low TTL ensures the server never receives this fake data.
    """
    tcp_header_len = 20
    ip_total_len = 20 + tcp_header_len + len(fake_payload)

    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    # IP Header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0x5678,
        0, ttl, socket.IPPROTO_TCP, 0,
        ip_src, ip_dst,
    )

    # TCP Header with PSH+ACK flags
    tcp_data_offset = 5 << 4
    tcp_flags = 0x18  # PSH + ACK
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq_num, 0,
        tcp_data_offset, tcp_flags,
        65535, 0, 0,
    )

    # TCP checksum
    pseudo = struct.pack("!4s4sBBH", ip_src, ip_dst, 0, socket.IPPROTO_TCP,
                         len(tcp_header) + len(fake_payload))
    chk = _checksum(pseudo + tcp_header + fake_payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq_num, 0,
        tcp_data_offset, tcp_flags,
        65535, chk, 0,
    )

    # IP checksum
    ip_chk = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0x5678,
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        ip_src, ip_dst,
    )

    return ip_header + tcp_header + fake_payload


def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class TcpDesyncBypass(BypassMethod):
    """DPI bypass via TCP stream desynchronization.

    Injects fake data (with low TTL) to confuse DPI state tracking.
    The server never sees the fake data; the DPI gets desynchronized.
    """

    name = "tcp_desync"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.desync_config = config.bypass.tcp_desync
        self._raw_socket: socket.socket | None = None

    async def setup(self) -> None:
        """Create raw socket for packet injection."""
        try:
            self._raw_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
            )
            self._raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.logger.info("Raw socket created for TCP desync")
        except PermissionError:
            self.logger.error("Root privileges required for raw socket (TCP desync)")
            raise

    async def teardown(self) -> None:
        """Close raw socket."""
        if self._raw_socket:
            self._raw_socket.close()
            self._raw_socket = None

    async def is_applicable(self, ctx: ConnectionContext) -> bool:
        """Applicable when enabled and raw socket available."""
        if not self.desync_config.enabled:
            return False
        return self._raw_socket is not None

    async def send_fake_data(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ttl: int = 1,
    ) -> bool:
        """Inject fake data packet into the TCP stream.

        Sends garbage data with the current sequence number but low TTL.
        The DPI thinks this is real data and updates its TCP state;
        the server never receives it (TTL expires en route).
        """
        if not self._raw_socket:
            return False

        # Generate random fake payload that won't match any protocol
        fake_payload = os.urandom(16)

        packet = build_fake_data_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            fake_payload=fake_payload,
            ttl=ttl,
        )

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self._raw_socket.sendto(packet, (dst_ip, 0)),  # type: ignore[union-attr]
            )
            self.logger.debug(
                f"Sent fake data: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"TTL={ttl} payload={len(fake_payload)}B"
            )
            return True
        except OSError as e:
            self.logger.error(f"Failed to send fake data: {e}")
            return False

    async def apply(self, ctx: ConnectionContext, data: bytes) -> tuple[BypassResult, bytes]:
        """Prepare TCP desync for the connection.

        The proxy layer should call send_fake_data() before forwarding
        real data to desynchronize the DPI's TCP state tracking.
        """
        ctx._tcp_desync = self  # type: ignore[attr-defined]
        self.logger.info(f"TCP desync prepared for {ctx.domain} (method={self.desync_config.method})")
        return BypassResult.SUCCESS, data
