"""DNS resolution with DoH, DoT, and system DNS.

Provides encrypted DNS resolution to bypass DNS-based censorship:
- DNS-over-HTTPS (DoH): DNS queries sent as HTTPS requests to trusted resolvers
- DNS-over-TLS (DoT): DNS queries sent over TLS-encrypted TCP connections
- System DNS: Used as a baseline for comparison (block detection)
"""

from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import aiohttp
import dns.message
import dns.query
import dns.rdatatype

if TYPE_CHECKING:
    from easynet.utils.config import Config, DohProvider, DotServer

logger = logging.getLogger(__name__)


@dataclass
class DnsResult:
    """Result of a DNS query."""

    domain: str
    addresses: list[str]
    ttl: int = 0
    source: str = "unknown"  # "doh", "dot", "system"
    provider: str = ""
    query_time_ms: float = 0
    error: str | None = None


@dataclass
class DnsCache:
    """Simple TTL-aware DNS cache."""

    _entries: dict[str, tuple[DnsResult, float]] = field(default_factory=dict)

    def get(self, domain: str) -> DnsResult | None:
        if domain in self._entries:
            result, expire_at = self._entries[domain]
            if time.time() < expire_at:
                return result
            del self._entries[domain]
        return None

    def put(self, domain: str, result: DnsResult, ttl: int = 300) -> None:
        self._entries[domain] = (result, time.time() + ttl)

    def clear(self) -> None:
        self._entries.clear()


class DnsResolver:
    """Multi-provider DNS resolver with DoH, DoT, and system DNS support."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.dns_config = config.dns
        self.cache = DnsCache()
        self._session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        """Initialize HTTP session for DoH queries."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.dns_config.doh_timeout)
        )
        logger.info("DNS resolver initialized")

    async def shutdown(self) -> None:
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def resolve(self, domain: str, use_cache: bool = True) -> DnsResult:
        """Resolve a domain using the best available DNS method.

        Tries DoH first, falls back to DoT, then system DNS.
        Results are cached to avoid repeated lookups.
        """
        if use_cache:
            cached = self.cache.get(domain)
            if cached:
                logger.debug(f"DNS cache hit for {domain}")
                return cached

        # Try DoH first
        if self.dns_config.doh_enabled:
            for provider in sorted(
                self.dns_config.doh_providers, key=lambda p: p.priority
            ):
                result = await self._resolve_doh(domain, provider)
                if result.addresses:
                    self.cache.put(domain, result, self.dns_config.doh_cache_ttl)
                    return result

        # Fall back to DoT
        if self.dns_config.dot_enabled:
            for server in self.dns_config.dot_servers:
                result = await self._resolve_dot(domain, server)
                if result.addresses:
                    self.cache.put(domain, result, self.dns_config.doh_cache_ttl)
                    return result

        # Last resort: system DNS
        result = await self._resolve_system(domain)
        if result.addresses:
            self.cache.put(domain, result, 60)
        return result

    async def resolve_all_providers(self, domain: str) -> list[DnsResult]:
        """Resolve using ALL providers (for block detection comparison).

        Returns results from every configured provider plus system DNS,
        allowing comparison of responses to detect DNS-based blocking.
        """
        tasks = []

        for provider in self.dns_config.doh_providers:
            tasks.append(self._resolve_doh(domain, provider))
        for server in self.dns_config.dot_servers:
            tasks.append(self._resolve_dot(domain, server))
        tasks.append(self._resolve_system(domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, DnsResult)]

    async def _resolve_doh(self, domain: str, provider: "DohProvider") -> DnsResult:
        """Resolve via DNS-over-HTTPS (RFC 8484).

        Sends the DNS query as an HTTP GET/POST to the DoH provider.
        The query is encoded in DNS wire format and sent as application/dns-message.
        """
        start = time.monotonic()
        try:
            # Build DNS query in wire format
            query = dns.message.make_query(domain, dns.rdatatype.A)
            wire = query.to_wire()

            # RFC 8484: GET with base64url-encoded query in ?dns= parameter
            b64_query = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()

            headers = {"Accept": "application/dns-message"}

            async with self._session.get(  # type: ignore[union-attr]
                provider.url,
                params={"dns": b64_query},
                headers=headers,
            ) as resp:
                if resp.status != 200:
                    return DnsResult(
                        domain=domain, addresses=[], source="doh",
                        provider=provider.name,
                        error=f"HTTP {resp.status}",
                    )

                response_wire = await resp.read()
                response = dns.message.from_wire(response_wire)

                addresses = []
                ttl = 0
                for rrset in response.answer:
                    for rdata in rrset:
                        if rrset.rdtype == dns.rdatatype.A:
                            addresses.append(rdata.address)
                    ttl = max(ttl, rrset.ttl)

                elapsed = (time.monotonic() - start) * 1000
                logger.debug(
                    f"DoH ({provider.name}): {domain} -> {addresses} ({elapsed:.1f}ms)"
                )
                return DnsResult(
                    domain=domain, addresses=addresses, ttl=ttl,
                    source="doh", provider=provider.name,
                    query_time_ms=elapsed,
                )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.debug(f"DoH ({provider.name}) failed for {domain}: {e}")
            return DnsResult(
                domain=domain, addresses=[], source="doh",
                provider=provider.name, query_time_ms=elapsed,
                error=str(e),
            )

    async def _resolve_dot(self, domain: str, server: "DotServer") -> DnsResult:
        """Resolve via DNS-over-TLS (RFC 7858).

        Opens a TLS connection to port 853 and sends the DNS query
        in wire format, prefixed with a 2-byte length field.
        """
        start = time.monotonic()
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            wire = query.to_wire()

            # Create TLS context
            ssl_ctx = ssl.create_default_context()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    server.host, server.port, ssl=ssl_ctx
                ),
                timeout=self.dns_config.dot_timeout,
            )

            try:
                # Send length-prefixed DNS query
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()

                # Read response length
                length_data = await asyncio.wait_for(
                    reader.readexactly(2), timeout=self.dns_config.dot_timeout
                )
                resp_length = struct.unpack("!H", length_data)[0]

                # Read response
                resp_data = await asyncio.wait_for(
                    reader.readexactly(resp_length), timeout=self.dns_config.dot_timeout
                )
            finally:
                writer.close()
                await writer.wait_closed()

            response = dns.message.from_wire(resp_data)
            addresses = []
            ttl = 0
            for rrset in response.answer:
                for rdata in rrset:
                    if rrset.rdtype == dns.rdatatype.A:
                        addresses.append(rdata.address)
                ttl = max(ttl, rrset.ttl)

            elapsed = (time.monotonic() - start) * 1000
            logger.debug(
                f"DoT ({server.host}): {domain} -> {addresses} ({elapsed:.1f}ms)"
            )
            return DnsResult(
                domain=domain, addresses=addresses, ttl=ttl,
                source="dot", provider=server.host,
                query_time_ms=elapsed,
            )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.debug(f"DoT ({server.host}) failed for {domain}: {e}")
            return DnsResult(
                domain=domain, addresses=[], source="dot",
                provider=server.host, query_time_ms=elapsed,
                error=str(e),
            )

    async def _resolve_system(self, domain: str) -> DnsResult:
        """Resolve using system DNS (standard UDP query).

        Used as a baseline for comparing against encrypted DNS results
        to detect DNS-based censorship (poisoned responses, NXDOMAIN injection).
        """
        start = time.monotonic()
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(domain, None, type=2)  # SOCK_DGRAM
            addresses = list({info[4][0] for info in infos})

            elapsed = (time.monotonic() - start) * 1000
            logger.debug(f"System DNS: {domain} -> {addresses} ({elapsed:.1f}ms)")
            return DnsResult(
                domain=domain, addresses=addresses,
                source="system", provider="system",
                query_time_ms=elapsed,
            )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.debug(f"System DNS failed for {domain}: {e}")
            return DnsResult(
                domain=domain, addresses=[], source="system",
                provider="system", query_time_ms=elapsed,
                error=str(e),
            )
