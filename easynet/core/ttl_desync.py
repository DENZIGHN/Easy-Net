"""TTL-based desynchronization attack for DPI bypass.

Technique: Send a fake TCP RST (or other disruptive) packet with a very low
TTL value before the real data. The fake packet will be seen by the DPI system
(which sits close to the client) but will expire (TTL=0) before reaching the
actual destination server.

The DPI sees the RST and thinks the connection is closed, so it stops tracking.
Meanwhile, the real data with normal TTL reaches the server successfully.

This exploits the assumption that DPI systems process packets in-line and trust
TCP state signals like RST without verifying they reach the endpoint.

Sequence:
1. Establish TCP connection normally
2. Send fake RST packet with TTL=1 (dies at first router hop)
3. DPI records the connection as closed
4. Send real data with normal TTL=64 — DPI ignores it (connection "closed")
5. Server never saw the RST, processes data normally

Requirements: Raw socket access (root/admin privileges).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from easynet.core.base import BypassMethod, BypassResult, ConnectionContext

if TYPE_CHECKING:
    from easynet.utils.config import Config

logger = logging.getLogger(__name__)


def build_tcp_rst_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq_num: int,
    ttl: int = 1,
) -> bytes:
    """Construct a raw TCP RST packet with specified TTL.

    Builds the packet manually: IP header + TCP header.
    This avoids requiring scapy as a dependency for the core functionality.

    The packet has:
    - IP header with the specified (low) TTL
    - TCP header with RST flag set
    - Matching seq number to look legitimate to DPI
    """
    # IP Header (20 bytes, no options)
    ip_ver_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
    ip_tos = 0
    ip_total_len = 40  # 20 IP + 20 TCP
    ip_id = 0x1234
    ip_frag = 0
    ip_ttl = ttl
    ip_proto = socket.IPPROTO_TCP
    ip_checksum = 0  # Will be filled by kernel or calculated
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_total_len, ip_id,
        ip_frag, ip_ttl, ip_proto, ip_checksum,
        ip_src, ip_dst,
    )

    # TCP Header (20 bytes, no options)
    tcp_data_offset = 5 << 4  # 20 bytes, no options
    tcp_flags = 0x04  # RST flag
    tcp_window = 0
    tcp_checksum = 0  # Will be calculated
    tcp_urgent = 0

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq_num, 0,  # seq, ack
        tcp_data_offset, tcp_flags,
        tcp_window, tcp_checksum, tcp_urgent,
    )

    # Calculate TCP checksum using pseudo-header
    pseudo_header = struct.pack(
        "!4s4sBBH",
        ip_src, ip_dst,
        0, socket.IPPROTO_TCP, len(tcp_header),
    )
    tcp_checksum = _checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq_num, 0,
        tcp_data_offset, tcp_flags,
        tcp_window, tcp_checksum, tcp_urgent,
    )

    # Calculate IP checksum
    ip_checksum = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_total_len, ip_id,
        ip_frag, ip_ttl, ip_proto, ip_checksum,
        ip_src, ip_dst,
    )

    return ip_header + tcp_header


def _checksum(data: bytes) -> int:
    """Calculate Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class TtlDesyncBypass(BypassMethod):
    """DPI bypass via TTL-based desynchronization.

    Sends a fake RST packet with low TTL to trick the DPI into thinking
    the connection is closed, then sends real data with normal TTL.
    """

    name = "ttl_desync"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.ttl_config = config.bypass.ttl_desync
        self._raw_socket: socket.socket | None = None

    async def setup(self) -> None:
        """Create raw socket for sending crafted packets."""
        try:
            self._raw_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
            )
            self._raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.logger.info("Raw socket created for TTL desync")
        except PermissionError:
            self.logger.error("Root privileges required for raw socket (TTL desync)")
            raise

    async def teardown(self) -> None:
        """Close the raw socket."""
        if self._raw_socket:
            self._raw_socket.close()
            self._raw_socket = None

    async def is_applicable(self, ctx: ConnectionContext) -> bool:
        """Applicable to any TCP connection when enabled."""
        if not self.ttl_config.enabled:
            return False
        return self._raw_socket is not None

    async def send_fake_rst(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq_num: int
    ) -> bool:
        """Send a fake RST packet with low TTL.

        The packet will be processed by the local DPI but will not reach
        the destination server (TTL expires at the first router hop).
        """
        if not self._raw_socket:
            return False

        packet = build_tcp_rst_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ttl=self.ttl_config.fake_ttl,
        )

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self._raw_socket.sendto(packet, (dst_ip, 0)),  # type: ignore[union-attr]
            )
            self.logger.debug(
                f"Sent fake RST: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"TTL={self.ttl_config.fake_ttl} seq={seq_num}"
            )
            return True
        except OSError as e:
            self.logger.error(f"Failed to send fake RST: {e}")
            return False

    async def apply(self, ctx: ConnectionContext, data: bytes) -> tuple[BypassResult, bytes]:
        """Apply TTL desync: send fake RST before real data.

        The proxy layer should:
        1. Call send_fake_rst() before sending real data
        2. Send the real data normally (it passes through unmodified)
        """
        # Store reference for proxy layer to call send_fake_rst()
        ctx._ttl_desync = self  # type: ignore[attr-defined]
        self.logger.info(f"TTL desync prepared for {ctx.domain}")
        return BypassResult.SUCCESS, data
