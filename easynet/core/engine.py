"""Core bypass engine - orchestrates all DPI bypass methods."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from easynet.core.base import BypassMethod, BypassResult, ConnectionContext
from easynet.core.fragmentation import FragmentationBypass
from easynet.core.host_manipulation import HostManipulationBypass
from easynet.core.tcp_desync import TcpDesyncBypass
from easynet.core.ttl_desync import TtlDesyncBypass

if TYPE_CHECKING:
    from easynet.utils.config import Config

logger = logging.getLogger(__name__)


class BypassEngine:
    """Orchestrates multiple DPI bypass methods.

    The engine maintains a prioritized list of bypass methods and applies
    the appropriate ones for each connection based on the connection context
    and routing decisions.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.methods: list[BypassMethod] = []
        self._method_map: dict[str, BypassMethod] = {}
        # Track which method works for which domain
        self._domain_method_cache: dict[str, str] = {}

    async def initialize(self) -> None:
        """Initialize all bypass methods based on configuration."""
        method_classes: list[type[BypassMethod]] = [
            FragmentationBypass,
            HostManipulationBypass,
            TtlDesyncBypass,
            TcpDesyncBypass,
        ]

        for cls in method_classes:
            method = cls(self.config)
            try:
                await method.setup()
            except PermissionError:
                logger.warning(
                    f"Skipping {method.name}: requires elevated privileges"
                )
                continue
            except Exception as e:
                logger.warning(f"Skipping {method.name}: setup failed: {e}")
                continue

            self.methods.append(method)
            self._method_map[method.name] = method
            logger.info(f"Initialized bypass method: {method.name}")

        logger.info(f"Bypass engine ready with {len(self.methods)} methods")

    async def shutdown(self) -> None:
        """Teardown all bypass methods."""
        for method in self.methods:
            try:
                await method.teardown()
            except Exception as e:
                logger.warning(f"Error tearing down {method.name}: {e}")

    def get_method(self, name: str) -> BypassMethod | None:
        """Get a specific bypass method by name."""
        return self._method_map.get(name)

    async def apply_bypass(
        self,
        ctx: ConnectionContext,
        data: bytes,
        method_name: str | None = None,
    ) -> tuple[BypassResult, bytes]:
        """Apply bypass technique(s) to the given data.

        If method_name is specified, use that specific method.
        Otherwise, use the cached method for the domain, or try methods
        in priority order.

        Args:
            ctx: Connection context.
            data: Raw data to transform.
            method_name: Optional specific method to use.

        Returns:
            Tuple of (result, transformed data).
        """
        # If a specific method is requested
        if method_name:
            method = self._method_map.get(method_name)
            if method and await method.is_applicable(ctx):
                return await method.apply(ctx, data)
            return BypassResult.SKIPPED, data

        # Check domain cache
        if ctx.domain and ctx.domain in self._domain_method_cache:
            cached = self._domain_method_cache[ctx.domain]
            method = self._method_map.get(cached)
            if method and await method.is_applicable(ctx):
                result, modified = await method.apply(ctx, data)
                if result == BypassResult.SUCCESS:
                    return result, modified

        # Try methods in priority order from config
        priority = self.config.routing.method_priority
        for name in priority:
            method = self._method_map.get(name)
            if method is None:
                continue
            if not await method.is_applicable(ctx):
                continue

            result, modified = await method.apply(ctx, data)
            if result == BypassResult.SUCCESS:
                # Cache the working method for this domain
                if ctx.domain:
                    self._domain_method_cache[ctx.domain] = name
                    logger.info(f"Cached method {name!r} for domain {ctx.domain}")
                return result, modified

        logger.debug(f"No applicable bypass method for {ctx.domain}")
        return BypassResult.SKIPPED, data

    def set_domain_method(self, domain: str, method_name: str) -> None:
        """Manually set the bypass method for a domain."""
        if method_name in self._method_map:
            self._domain_method_cache[domain] = method_name

    def get_domain_method(self, domain: str) -> str | None:
        """Get the cached bypass method for a domain."""
        return self._domain_method_cache.get(domain)

    @property
    def available_methods(self) -> list[str]:
        """List names of all initialized bypass methods."""
        return [m.name for m in self.methods]
