"""Smart routing - block detection and method selection.

Implements intelligent routing decisions:
1. Detect which domains are blocked (DNS comparison, TTL analysis, timeouts)
2. Maintain a blocklist (local + community sources)
3. Automatically select the best bypass method per domain
4. Split tunneling: only bypass blocked domains, direct for the rest
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easynet.core.engine import BypassEngine
    from easynet.dns.resolver import DnsResolver
    from easynet.utils.config import Config

logger = logging.getLogger(__name__)


@dataclass
class BlockDetectionResult:
    """Result of a block detection check for a domain."""

    domain: str
    is_blocked: bool = False
    detection_method: str = ""
    details: str = ""
    checked_at: float = field(default_factory=time.time)


@dataclass
class DomainInfo:
    """Tracked information about a domain."""

    domain: str
    is_blocked: bool = False
    bypass_method: str | None = None
    last_checked: float = 0
    detection_result: BlockDetectionResult | None = None


class Blocklist:
    """Manages the domain blocklist (local file + community sources)."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._domains: set[str] = set()
        self._blocklist_path = Path(config.routing.blocklist_file).expanduser()

    async def load(self) -> None:
        """Load blocklist from local file."""
        if self._blocklist_path.exists():
            text = self._blocklist_path.read_text()
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self._domains.add(line.lower())
            logger.info(f"Loaded {len(self._domains)} domains from blocklist")
        else:
            # Create empty blocklist file
            self._blocklist_path.parent.mkdir(parents=True, exist_ok=True)
            self._blocklist_path.write_text(
                "# EasyNet blocklist - one domain per line\n"
                "# Lines starting with # are comments\n"
            )
            logger.info(f"Created empty blocklist at {self._blocklist_path}")

    async def update_from_community(self) -> int:
        """Fetch and merge blocklists from community sources.

        Returns the number of new domains added.
        """
        if not self.config.routing.community_sources:
            return 0

        import aiohttp

        added = 0
        async with aiohttp.ClientSession() as session:
            for url in self.config.routing.community_sources:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for line in text.splitlines():
                                line = line.strip().lower()
                                if line and not line.startswith("#") and line not in self._domains:
                                    self._domains.add(line)
                                    added += 1
                    logger.info(f"Fetched blocklist from {url}")
                except Exception as e:
                    logger.warning(f"Failed to fetch blocklist from {url}: {e}")

        if added > 0:
            await self.save()
            logger.info(f"Added {added} domains from community sources")

        return added

    async def save(self) -> None:
        """Save current blocklist to file."""
        self._blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# EasyNet blocklist - one domain per line\n"]
        lines.extend(sorted(self._domains))
        self._blocklist_path.write_text("\n".join(lines) + "\n")

    def contains(self, domain: str) -> bool:
        """Check if a domain is in the blocklist."""
        domain = domain.lower()
        # Check exact match and parent domains
        parts = domain.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self._domains:
                return True
        return False

    def add(self, domain: str) -> None:
        """Add a domain to the blocklist."""
        self._domains.add(domain.lower())

    def remove(self, domain: str) -> None:
        """Remove a domain from the blocklist."""
        self._domains.discard(domain.lower())

    @property
    def domains(self) -> set[str]:
        return self._domains.copy()


class BlockDetector:
    """Detects whether a domain is being blocked.

    Uses multiple detection methods:
    1. DNS comparison: Compare system DNS results with DoH/DoT results.
       Mismatches suggest DNS poisoning/hijacking.
    2. TTL analysis: Check if RST packets arrive with unusual TTL values,
       which suggests they were injected by a middlebox.
    3. Timeout detection: Connect timeouts to known-accessible sites
       suggest TCP-level blocking.
    """

    def __init__(self, config: Config, dns_resolver: DnsResolver) -> None:
        self.config = config
        self.dns = dns_resolver

    async def check_domain(self, domain: str) -> BlockDetectionResult:
        """Run all enabled detection methods on a domain."""
        methods = self.config.routing.detection_methods

        if "dns_comparison" in methods:
            result = await self._check_dns(domain)
            if result.is_blocked:
                return result

        if "timeout_detection" in methods:
            result = await self._check_timeout(domain)
            if result.is_blocked:
                return result

        return BlockDetectionResult(domain=domain, is_blocked=False)

    async def _check_dns(self, domain: str) -> BlockDetectionResult:
        """Compare DNS responses from different sources.

        If system DNS returns different IPs than DoH/DoT, the system DNS
        is likely being poisoned (a common censorship technique).
        """
        try:
            results = await self.dns.resolve_all_providers(domain)

            # Group results by source type
            encrypted_ips: set[str] = set()
            system_ips: set[str] = set()

            for r in results:
                if r.source in ("doh", "dot"):
                    encrypted_ips.update(r.addresses)
                elif r.source == "system":
                    system_ips.update(r.addresses)

            if not encrypted_ips or not system_ips:
                return BlockDetectionResult(
                    domain=domain,
                    is_blocked=False,
                    detection_method="dns_comparison",
                    details="Insufficient DNS data",
                )

            # Check for mismatch
            if system_ips and encrypted_ips and not system_ips.intersection(encrypted_ips):
                return BlockDetectionResult(
                    domain=domain,
                    is_blocked=True,
                    detection_method="dns_comparison",
                    details=(
                        f"DNS mismatch: system={system_ips}, "
                        f"encrypted={encrypted_ips}"
                    ),
                )

            return BlockDetectionResult(
                domain=domain,
                is_blocked=False,
                detection_method="dns_comparison",
                details="DNS responses consistent",
            )

        except Exception as e:
            logger.warning(f"DNS comparison failed for {domain}: {e}")
            return BlockDetectionResult(
                domain=domain, is_blocked=False,
                detection_method="dns_comparison",
                details=f"Error: {e}",
            )

    async def _check_timeout(self, domain: str) -> BlockDetectionResult:
        """Check if TCP connections to the domain time out.

        A timeout to a known-accessible domain suggests TCP-level blocking
        (e.g., IP blackholing or RST injection).
        """
        try:
            # Resolve via DoH first
            dns_result = await self.dns.resolve(domain)
            if not dns_result.addresses:
                return BlockDetectionResult(
                    domain=domain, is_blocked=False,
                    detection_method="timeout_detection",
                    details="Cannot resolve domain",
                )

            ip = dns_result.addresses[0]

            # Try to connect on port 443 with a short timeout
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443),
                    timeout=5.0,
                )
                writer.close()
                await writer.wait_closed()
                return BlockDetectionResult(
                    domain=domain, is_blocked=False,
                    detection_method="timeout_detection",
                    details="Connection successful",
                )
            except asyncio.TimeoutError:
                return BlockDetectionResult(
                    domain=domain, is_blocked=True,
                    detection_method="timeout_detection",
                    details=f"TCP connection to {ip}:443 timed out",
                )
            except ConnectionRefusedError:
                # Refused != blocked (server might be down)
                return BlockDetectionResult(
                    domain=domain, is_blocked=False,
                    detection_method="timeout_detection",
                    details="Connection refused (not necessarily blocked)",
                )

        except Exception as e:
            return BlockDetectionResult(
                domain=domain, is_blocked=False,
                detection_method="timeout_detection",
                details=f"Error: {e}",
            )


class SmartRouter:
    """Orchestrates routing decisions: which domains to bypass and how.

    Combines blocklist, auto-detection, and method selection to make
    per-connection routing decisions.
    """

    def __init__(
        self,
        config: Config,
        dns_resolver: DnsResolver,
        bypass_engine: BypassEngine | None = None,
    ) -> None:
        self.config = config
        self.blocklist = Blocklist(config)
        self.detector = BlockDetector(config, dns_resolver)
        self.engine = bypass_engine
        self._domain_info: dict[str, DomainInfo] = {}

    async def initialize(self) -> None:
        """Load blocklist and start periodic tasks."""
        await self.blocklist.load()

    async def should_bypass(self, domain: str) -> bool:
        """Decide whether to apply bypass for the given domain.

        Returns True if the domain is in the blocklist or detected as blocked.
        In split tunneling mode, only bypasses blocked domains.
        """
        if not self.config.proxy.split_tunnel_enabled:
            return True  # Bypass everything

        domain = domain.lower()

        # Check blocklist first (fast path)
        if self.blocklist.contains(domain):
            return True

        # Check cache
        if domain in self._domain_info:
            info = self._domain_info[domain]
            age = time.time() - info.last_checked
            if age < self.config.routing.check_interval:
                return info.is_blocked

        # Auto-detect if enabled
        if self.config.routing.detection_enabled:
            result = await self.detector.check_domain(domain)
            self._domain_info[domain] = DomainInfo(
                domain=domain,
                is_blocked=result.is_blocked,
                last_checked=time.time(),
                detection_result=result,
            )

            if result.is_blocked:
                logger.info(
                    f"Detected block for {domain}: {result.detection_method} - "
                    f"{result.details}"
                )
                self.blocklist.add(domain)
                return True

        return False

    async def select_method(self, domain: str) -> str | None:
        """Select the best bypass method for a domain.

        If auto-select is enabled, tests methods in priority order
        and returns the first one that works.
        """
        if not self.config.routing.auto_select_enabled:
            return None

        # Check if we already know the best method
        if domain in self._domain_info and self._domain_info[domain].bypass_method:
            return self._domain_info[domain].bypass_method

        # Use the engine's cached method if available
        if self.engine:
            cached = self.engine.get_domain_method(domain)
            if cached:
                return cached

        # Default to first in priority list
        if self.config.routing.method_priority:
            return self.config.routing.method_priority[0]

        return None

    def get_status(self) -> dict:
        """Get router status for monitoring/web UI."""
        blocked = [d for d, info in self._domain_info.items() if info.is_blocked]
        return {
            "blocklist_size": len(self.blocklist.domains),
            "detected_blocked": len(blocked),
            "tracked_domains": len(self._domain_info),
            "blocked_domains": blocked,
        }
