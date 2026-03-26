"""Transparent proxy mode using iptables REDIRECT/TPROXY.

In transparent mode, traffic is intercepted at the network level without
requiring applications to be configured. On Linux, this uses iptables
to redirect outgoing TCP connections to the local proxy.

How it works:
1. iptables REDIRECT rule captures outgoing TCP traffic (port 80, 443)
2. The proxy accepts the redirected connections
3. SO_ORIGINAL_DST socket option recovers the real destination
4. Bypass engine is applied, data is forwarded to the real destination

This requires root privileges and only works on Linux.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easynet.core.engine import BypassEngine
    from easynet.dns.resolver import DnsResolver
    from easynet.routing.router import SmartRouter
    from easynet.utils.config import Config

from easynet.core.base import BypassResult, ConnectionContext
from easynet.utils.platform import Platform, detect_platform

logger = logging.getLogger(__name__)

# Linux socket constant for SO_ORIGINAL_DST
SO_ORIGINAL_DST = 80


class TransparentProxy:
    """Transparent proxy using iptables REDIRECT.

    Intercepts system-wide TCP traffic without requiring per-app configuration.
    Uses SO_ORIGINAL_DST to recover the real destination address.
    """

    def __init__(
        self,
        config: Config,
        bypass_engine: BypassEngine,
        dns_resolver: DnsResolver,
        router: SmartRouter,
    ) -> None:
        self.config = config
        self.proxy_config = config.proxy.transparent
        self.engine = bypass_engine
        self.dns = dns_resolver
        self.router = router
        self._server: asyncio.Server | None = None
        self._iptables_rules: list[list[str]] = []

    async def start(self) -> None:
        """Start transparent proxy and install iptables rules."""
        if detect_platform() != Platform.LINUX:
            raise RuntimeError("Transparent proxy is only supported on Linux")

        port = self.proxy_config.port

        # Install iptables REDIRECT rules
        self._install_iptables_rules(port)

        self._server = await asyncio.start_server(
            self._handle_connection,
            "0.0.0.0",
            port,
        )
        logger.info(f"Transparent proxy listening on port {port}")

    async def stop(self) -> None:
        """Stop transparent proxy and remove iptables rules."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        self._remove_iptables_rules()
        logger.info("Transparent proxy stopped")

    def _install_iptables_rules(self, port: int) -> None:
        """Install iptables REDIRECT rules for HTTP(S) traffic."""
        rules = [
            # Redirect HTTP traffic
            ["iptables", "-t", "nat", "-A", "OUTPUT",
             "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-port", str(port)],
            # Redirect HTTPS traffic
            ["iptables", "-t", "nat", "-A", "OUTPUT",
             "-p", "tcp", "--dport", "443",
             "-j", "REDIRECT", "--to-port", str(port)],
        ]

        for rule in rules:
            try:
                subprocess.run(rule, check=True, capture_output=True)
                self._iptables_rules.append(rule)
                logger.info(f"Installed iptables rule: {' '.join(rule)}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install iptables rule: {e.stderr.decode()}")
                raise RuntimeError(f"iptables rule installation failed: {e}")

    def _remove_iptables_rules(self) -> None:
        """Remove previously installed iptables rules."""
        for rule in self._iptables_rules:
            # Replace -A (append) with -D (delete)
            delete_rule = list(rule)
            delete_rule[delete_rule.index("-A")] = "-D"
            try:
                subprocess.run(delete_rule, check=True, capture_output=True)
                logger.info(f"Removed iptables rule: {' '.join(delete_rule)}")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to remove iptables rule: {e.stderr.decode()}")
        self._iptables_rules.clear()

    def _get_original_dest(self, sock: socket.socket) -> tuple[str, int]:
        """Get original destination from SO_ORIGINAL_DST.

        When iptables REDIRECT intercepts a connection, the original
        destination is stored in the socket and can be retrieved with
        the SO_ORIGINAL_DST socket option.
        """
        # Returns packed sockaddr_in: family(2) + port(2) + addr(4) + padding(8)
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", raw[2:4])[0]
        addr = socket.inet_ntoa(raw[4:8])
        return addr, port

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a transparently intercepted connection."""
        try:
            # Get the real destination from the redirected socket
            sock = writer.transport.get_extra_info("socket")
            if not sock:
                logger.error("Cannot get socket from transport")
                writer.close()
                return

            dst_host, dst_port = self._get_original_dest(sock)
            peer = writer.get_extra_info("peername")

            logger.debug(f"Transparent intercept: {peer} -> {dst_host}:{dst_port}")

            # Reverse-resolve to domain if possible (for block detection)
            domain = None
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.getnameinfo((dst_host, dst_port), 0), timeout=2.0
                )
                domain = result[0]
            except Exception:
                pass

            needs_bypass = await self.router.should_bypass(domain or dst_host)

            # Connect to real destination
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(dst_host, dst_port),
                    timeout=10.0,
                )
            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(f"Cannot connect to {dst_host}:{dst_port}: {e}")
                writer.close()
                return

            ctx = ConnectionContext(
                src_host=peer[0] if peer else "0.0.0.0",
                src_port=peer[1] if peer else 0,
                dst_host=dst_host,
                dst_port=dst_port,
                domain=domain,
                is_tls=(dst_port == 443),
                is_http=(dst_port == 80),
            )

            # Relay with bypass
            await self._relay(reader, writer, remote_reader, remote_writer, ctx, needs_bypass)

        except Exception as e:
            logger.error(f"Transparent proxy error: {e}", exc_info=True)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        ctx: ConnectionContext,
        needs_bypass: bool,
    ) -> None:
        """Bidirectional relay with optional bypass on first packet."""
        first_packet = True

        async def client_to_remote() -> None:
            nonlocal first_packet
            try:
                while True:
                    data = await client_reader.read(65536)
                    if not data:
                        break
                    if first_packet and needs_bypass:
                        first_packet = False
                        result, modified = await self.engine.apply_bypass(ctx, data)
                        if result == BypassResult.SUCCESS:
                            fragments = getattr(ctx, "_fragments", None)
                            if fragments:
                                sock = remote_writer.transport.get_extra_info("socket")
                                if sock:
                                    sock.setsockopt(
                                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                                    )
                                for frag in fragments:
                                    remote_writer.write(frag)
                                    await remote_writer.drain()
                                continue
                            data = modified
                    remote_writer.write(data)
                    await remote_writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                try:
                    remote_writer.close()
                except Exception:
                    pass

        async def remote_to_client() -> None:
            try:
                while True:
                    data = await remote_reader.read(65536)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                try:
                    client_writer.close()
                except Exception:
                    pass

        await asyncio.gather(client_to_remote(), remote_to_client())
