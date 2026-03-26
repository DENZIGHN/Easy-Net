"""Base class for all bypass methods."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easynet.utils.config import Config


class BypassResult(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class ConnectionContext:
    """Context for a connection being bypassed."""

    src_host: str
    src_port: int
    dst_host: str
    dst_port: int
    domain: str | None = None  # SNI / Host header value
    is_tls: bool = False
    is_http: bool = False
    raw_data: bytes = b""


class BypassMethod(abc.ABC):
    """Abstract base for DPI bypass techniques.

    Each bypass method implements a specific technique for evading
    Deep Packet Inspection in a controlled research environment.
    """

    name: str = "base"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(f"easynet.bypass.{self.name}")

    @abc.abstractmethod
    async def apply(self, ctx: ConnectionContext, data: bytes) -> tuple[BypassResult, bytes]:
        """Apply the bypass technique to outgoing data.

        Args:
            ctx: Connection context with metadata.
            data: Raw outgoing data to transform.

        Returns:
            Tuple of (result status, transformed data).
        """

    @abc.abstractmethod
    async def is_applicable(self, ctx: ConnectionContext) -> bool:
        """Check if this bypass method is applicable to the given connection."""

    async def setup(self) -> None:
        """One-time setup (e.g., raw socket creation). Override as needed."""

    async def teardown(self) -> None:
        """Cleanup resources. Override as needed."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
