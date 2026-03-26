"""TCP packet fragmentation at TLS ClientHello.

Technique: Split the TCP segment containing the TLS ClientHello so that the
SNI (Server Name Indication) field is divided across multiple TCP segments.
DPI systems that don't reassemble TCP streams will fail to extract the SNI
and thus cannot match it against a blocklist.

The key insight is that TLS ClientHello contains the SNI extension which
carries the plaintext hostname. By fragmenting the TCP segment right at the
SNI boundary, each fragment alone doesn't contain the full hostname.
"""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from easynet.core.base import BypassMethod, BypassResult, ConnectionContext

if TYPE_CHECKING:
    from easynet.utils.config import Config

logger = logging.getLogger(__name__)

# TLS record type for Handshake
TLS_HANDSHAKE = 0x16
# TLS Handshake type for ClientHello
TLS_CLIENT_HELLO = 0x01
# SNI extension type
SNI_EXTENSION_TYPE = 0x0000


def find_sni_offset(data: bytes) -> int | None:
    """Locate the SNI hostname within a TLS ClientHello.

    Walks the TLS record structure:
    1. TLS record header (5 bytes): type(1) + version(2) + length(2)
    2. Handshake header (4 bytes): type(1) + length(3)
    3. ClientHello fields: version(2) + random(32) + session_id(var) +
       cipher_suites(var) + compression(var) + extensions(var)
    4. Extensions are type(2) + length(2) + data, we scan for type 0x0000 (SNI)
    5. Inside SNI: list_length(2) + name_type(1) + name_length(2) + name

    Returns the byte offset within `data` where the SNI hostname string starts,
    or None if no SNI is found.
    """
    if len(data) < 5:
        return None

    # Check TLS record header
    content_type = data[0]
    if content_type != TLS_HANDSHAKE:
        return None

    record_length = struct.unpack("!H", data[3:5])[0]
    pos = 5  # Skip TLS record header

    if pos >= len(data):
        return None

    # Check handshake type
    if data[pos] != TLS_CLIENT_HELLO:
        return None

    # Skip handshake header (type + 3-byte length)
    pos += 4

    # Skip ClientHello version (2 bytes) + random (32 bytes)
    pos += 2 + 32

    if pos >= len(data):
        return None

    # Skip session ID (1-byte length prefix)
    session_id_len = data[pos]
    pos += 1 + session_id_len

    if pos + 2 > len(data):
        return None

    # Skip cipher suites (2-byte length prefix)
    cipher_suites_len = struct.unpack("!H", data[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len

    if pos >= len(data):
        return None

    # Skip compression methods (1-byte length prefix)
    compression_len = data[pos]
    pos += 1 + compression_len

    if pos + 2 > len(data):
        return None

    # Extensions total length
    extensions_len = struct.unpack("!H", data[pos : pos + 2])[0]
    pos += 2

    extensions_end = pos + extensions_len

    # Walk extensions looking for SNI (type 0x0000)
    while pos + 4 <= extensions_end and pos + 4 <= len(data):
        ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
        ext_len = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
        pos += 4

        if ext_type == SNI_EXTENSION_TYPE:
            # SNI extension data: list_length(2) + name_type(1) + name_length(2) + name
            if pos + 5 <= len(data):
                sni_name_offset = pos + 2 + 1 + 2  # Skip list_len + type + name_len
                return sni_name_offset

        pos += ext_len

    return None


def fragment_at_sni(data: bytes, fragment_size: int = 2) -> list[bytes]:
    """Split data into fragments around the SNI field.

    The first fragment contains everything up to the middle of the SNI hostname.
    This ensures no single fragment contains the complete hostname.

    Args:
        data: Full TCP payload containing TLS ClientHello.
        fragment_size: Number of SNI bytes to include in first fragment.

    Returns:
        List of byte fragments. If SNI is not found, returns [data] unchanged.
    """
    sni_offset = find_sni_offset(data)
    if sni_offset is None:
        logger.debug("No SNI found in data, returning unfragmented")
        return [data]

    # Split at `fragment_size` bytes into the SNI hostname
    split_point = sni_offset + fragment_size
    if split_point >= len(data):
        return [data]

    logger.debug(f"Fragmenting at offset {split_point} (SNI starts at {sni_offset})")
    return [data[:split_point], data[split_point:]]


def fragment_fixed_size(data: bytes, size: int = 40) -> list[bytes]:
    """Split data into fixed-size fragments.

    Simple approach: just chop the TCP payload into N-byte chunks.
    Less targeted but works against simpler DPI that expects full payloads.
    """
    if len(data) <= size:
        return [data]
    return [data[i : i + size] for i in range(0, len(data), size)]


class FragmentationBypass(BypassMethod):
    """DPI bypass via TCP segment fragmentation.

    Splits TLS ClientHello across multiple TCP segments so the SNI
    hostname is never fully visible in a single segment.
    """

    name = "fragmentation"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.frag_config = config.bypass.fragmentation

    async def is_applicable(self, ctx: ConnectionContext) -> bool:
        """Applicable to TLS connections (port 443 or detected TLS)."""
        if not self.frag_config.enabled:
            return False
        return ctx.is_tls or ctx.dst_port == 443

    async def apply(self, ctx: ConnectionContext, data: bytes) -> tuple[BypassResult, bytes]:
        """Fragment the TLS ClientHello data.

        Note: This returns the fragments concatenated with a marker.
        The actual TCP segmentation happens at the socket send level
        in the proxy layer, using TCP_NODELAY and small send() calls.
        """
        strategy = self.frag_config.strategy

        if strategy == "sni_split":
            fragments = fragment_at_sni(data, self.frag_config.fragment_size)
        elif strategy == "fixed_size":
            fragments = fragment_fixed_size(data, self.frag_config.fragment_size)
        elif strategy == "random":
            import random

            size = random.randint(1, max(2, len(data) // 3))
            fragments = fragment_fixed_size(data, size)
        else:
            self.logger.warning(f"Unknown strategy {strategy!r}, skipping")
            return BypassResult.SKIPPED, data

        if len(fragments) <= 1:
            return BypassResult.SKIPPED, data

        self.logger.info(
            f"Split {len(data)}B into {len(fragments)} fragments "
            f"(strategy={strategy}, domain={ctx.domain})"
        )

        # Store fragments in context for the proxy layer to send individually
        ctx._fragments = fragments  # type: ignore[attr-defined]
        return BypassResult.SUCCESS, data
