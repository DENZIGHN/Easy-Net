"""HTTP Host header manipulation for DPI bypass.

Technique: DPI systems often inspect the HTTP Host header to determine which
domain is being accessed. By manipulating the Host header in ways that are
still valid HTTP but confuse DPI regex patterns, we can bypass the inspection.

Methods implemented:
1. Case randomization: HTTP spec says Host is case-insensitive, but DPI
   may do case-sensitive matching. "ExAmPlE.cOm" == "example.com" for servers.
2. Space insertion: Extra whitespace after "Host:" is valid per HTTP/1.1
   but may break DPI parsers expecting "Host: domain".
3. Tab insertion: Similar to space insertion, using tab characters.
4. Trailing dot: "example.com." is a valid FQDN (absolute DNS name) that
   resolves identically but may not match DPI patterns.
"""

from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING

from easynet.core.base import BypassMethod, BypassResult, ConnectionContext

if TYPE_CHECKING:
    from easynet.utils.config import Config

# Regex to find the Host header line in raw HTTP request
HOST_HEADER_RE = re.compile(rb"(Host:\s*)([^\r\n]+)", re.IGNORECASE)


def randomize_case(hostname: str) -> str:
    """Randomize the case of each character in the hostname.

    HTTP Host header is case-insensitive per RFC 7230, so
    "ExAmPlE.CoM" is equivalent to "example.com" for the server,
    but a DPI doing case-sensitive string matching will miss it.
    """
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower() for c in hostname
    )


def insert_space(hostname: str) -> tuple[str, str]:
    """Add extra spaces between 'Host:' and the hostname.

    Returns (header_prefix, hostname) where header_prefix has extra spaces.
    Per HTTP/1.1 spec (RFC 7230 Section 3.2), optional whitespace (OWS)
    is allowed between the header name, colon, and value.
    """
    # Random number of spaces (2-5)
    spaces = " " * random.randint(2, 5)
    return f"Host:{spaces}", hostname


def insert_tab(hostname: str) -> tuple[str, str]:
    """Use tab character between 'Host:' and hostname."""
    return "Host:\t", hostname


def add_trailing_dot(hostname: str) -> str:
    """Add trailing dot to make it an absolute FQDN.

    "example.com." is the fully qualified form. DNS resolvers treat it
    identically, but DPI pattern matching may not account for it.
    """
    if not hostname.endswith("."):
        return hostname + "."
    return hostname


def manipulate_host_header(data: bytes, methods: list[str]) -> bytes:
    """Apply Host header manipulation to raw HTTP request data.

    Args:
        data: Raw HTTP request bytes.
        methods: List of manipulation methods to apply (randomly picks one).

    Returns:
        Modified HTTP request bytes.
    """
    match = HOST_HEADER_RE.search(data)
    if not match:
        return data

    original_header = match.group(0)
    hostname = match.group(2).decode("ascii", errors="replace").strip()

    # Pick a random method from the enabled ones
    method = random.choice(methods) if methods else "case_randomize"

    if method == "case_randomize":
        new_hostname = randomize_case(hostname)
        new_header = f"Host: {new_hostname}".encode()
    elif method == "space_prefix":
        prefix, host = insert_space(hostname)
        new_header = f"{prefix}{host}".encode()
    elif method == "tab_insert":
        prefix, host = insert_tab(hostname)
        new_header = f"{prefix}{host}".encode()
    elif method == "dot_trailing":
        new_hostname = add_trailing_dot(hostname)
        new_header = f"Host: {new_hostname}".encode()
    else:
        return data

    return data.replace(original_header, new_header, 1)


class HostManipulationBypass(BypassMethod):
    """DPI bypass via HTTP Host header manipulation."""

    name = "host_manipulation"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.manip_config = config.bypass.host_manipulation

    async def is_applicable(self, ctx: ConnectionContext) -> bool:
        """Applicable to plain HTTP connections."""
        if not self.manip_config.enabled:
            return False
        return ctx.is_http or ctx.dst_port == 80

    async def apply(self, ctx: ConnectionContext, data: bytes) -> tuple[BypassResult, bytes]:
        """Manipulate the Host header in the HTTP request."""
        if not data.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ",
                                b"DELETE ", b"PATCH ", b"OPTIONS ")):
            return BypassResult.SKIPPED, data

        modified = manipulate_host_header(data, self.manip_config.methods)

        if modified == data:
            return BypassResult.SKIPPED, data

        self.logger.info(
            f"Manipulated Host header for {ctx.domain} "
            f"(methods={self.manip_config.methods})"
        )
        return BypassResult.SUCCESS, modified
