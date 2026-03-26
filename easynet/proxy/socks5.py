"""SOCKS5 proxy server with DPI bypass integration.

Implements a local SOCKS5 proxy (RFC 1928) that intercepts connections
and applies the appropriate DPI bypass technique based on the destination.

Applications can be configured to use this proxy (e.g., browser SOCKS5 settings),
and all their traffic will be automatically processed through the bypass engine.

Protocol flow:
1. Client connects to local SOCKS5 proxy
2. SOCKS5 handshake (auth negotiation, connect request)
3. Proxy resolves destination via encrypted DNS (DoH/DoT)
4. Proxy connects to destination
5. Proxy applies DPI bypass to outgoing data
6. Data is relayed bidirectionally
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easynet.core.engine import BypassEngine
    from easynet.dns.resolver import DnsResolver
    from easynet.routing.router import SmartRouter
    from easynet.utils.config import Config

from easynet.core.base import BypassResult, ConnectionContext

logger = logging.getLogger(__name__)

# SOCKS5 constants
SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_REJECT = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_REFUSED = 0x05
REP_ADDR_NOT_SUPPORTED = 0x08


class Socks5Server:
    """Async SOCKS5 proxy server with bypass engine integration."""

    def __init__(
        self,
        config: Config,
        bypass_engine: BypassEngine,
        dns_resolver: DnsResolver,
        router: SmartRouter,
    ) -> None:
        self.config = config
        self.proxy_config = config.proxy.socks5
        self.engine = bypass_engine
        self.dns = dns_resolver
        self.router = router
        self._server: asyncio.Server | None = None
        self._active_connections = 0

    async def start(self) -> None:
        """Start the SOCKS5 server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.proxy_config.host,
            self.proxy_config.port,
        )
        addr = self._server.sockets[0].getsockname()
        logger.info(f"SOCKS5 proxy listening on {addr[0]}:{addr[1]}")

    async def stop(self) -> None:
        """Stop the SOCKS5 server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("SOCKS5 proxy stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single SOCKS5 client connection."""
        self._active_connections += 1
        peer = writer.get_extra_info("peername")
        logger.debug(f"New SOCKS5 connection from {peer}")

        try:
            # Step 1: Auth negotiation
            if not await self._handle_auth(reader, writer):
                return

            # Step 2: Parse connect request
            dst_host, dst_port, domain = await self._handle_connect_request(reader, writer)
            if dst_host is None:
                return

            # Step 3: Determine if bypass is needed
            needs_bypass = await self.router.should_bypass(domain or dst_host)

            # Step 4: Resolve via encrypted DNS if needed
            if domain and needs_bypass:
                result = await self.dns.resolve(domain)
                if result.addresses:
                    dst_host = result.addresses[0]
                    logger.debug(f"Resolved {domain} -> {dst_host} via {result.source}")

            # Step 5: Connect to destination
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(dst_host, dst_port),
                    timeout=10.0,
                )
            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(f"Failed to connect to {dst_host}:{dst_port}: {e}")
                await self._send_reply(writer, REP_CONNECTION_REFUSED, dst_host, dst_port)
                return

            # Step 6: Send success reply
            local = remote_writer.get_extra_info("sockname")
            await self._send_reply(writer, REP_SUCCESS, local[0], local[1])

            # Step 7: Create connection context
            ctx = ConnectionContext(
                src_host=peer[0] if peer else "0.0.0.0",
                src_port=peer[1] if peer else 0,
                dst_host=dst_host,
                dst_port=dst_port,
                domain=domain,
                is_tls=(dst_port == 443),
                is_http=(dst_port == 80),
            )

            # Step 8: Relay data with bypass
            await self._relay(reader, writer, remote_reader, remote_writer, ctx, needs_bypass)

        except (ConnectionResetError, BrokenPipeError):
            logger.debug(f"Connection reset from {peer}")
        except Exception as e:
            logger.error(f"Error handling SOCKS5 client {peer}: {e}", exc_info=True)
        finally:
            self._active_connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_auth(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Handle SOCKS5 authentication negotiation."""
        # Read version + number of auth methods
        header = await reader.readexactly(2)
        version, n_methods = struct.unpack("!BB", header)

        if version != SOCKS_VERSION:
            logger.warning(f"Invalid SOCKS version: {version}")
            writer.close()
            return False

        methods = await reader.readexactly(n_methods)

        if self.proxy_config.auth_enabled:
            if AUTH_USERPASS not in methods:
                writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_REJECT))
                await writer.drain()
                return False

            writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_USERPASS))
            await writer.drain()

            # Username/password auth (RFC 1929)
            auth_ver = (await reader.readexactly(1))[0]
            ulen = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(ulen)).decode()
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode()

            if (username == self.proxy_config.username and
                    password == self.proxy_config.password):
                writer.write(struct.pack("!BB", 0x01, 0x00))  # Success
                await writer.drain()
            else:
                writer.write(struct.pack("!BB", 0x01, 0x01))  # Failure
                await writer.drain()
                return False
        else:
            writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_NONE))
            await writer.drain()

        return True

    async def _handle_connect_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[str | None, int, str | None]:
        """Parse SOCKS5 CONNECT request. Returns (host, port, domain)."""
        # Read request header: VER(1) CMD(1) RSV(1) ATYP(1)
        header = await reader.readexactly(4)
        version, cmd, _, atyp = struct.unpack("!BBBB", header)

        if cmd != CMD_CONNECT:
            logger.warning(f"Unsupported SOCKS5 command: {cmd}")
            await self._send_reply(writer, REP_GENERAL_FAILURE, "0.0.0.0", 0)
            return None, 0, None

        domain = None

        if atyp == ATYP_IPV4:
            addr_data = await reader.readexactly(4)
            dst_host = socket.inet_ntoa(addr_data)
        elif atyp == ATYP_DOMAIN:
            domain_len = (await reader.readexactly(1))[0]
            domain_bytes = await reader.readexactly(domain_len)
            domain = domain_bytes.decode()
            dst_host = domain
        elif atyp == ATYP_IPV6:
            addr_data = await reader.readexactly(16)
            dst_host = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            await self._send_reply(writer, REP_ADDR_NOT_SUPPORTED, "0.0.0.0", 0)
            return None, 0, None

        port_data = await reader.readexactly(2)
        dst_port = struct.unpack("!H", port_data)[0]

        logger.info(f"SOCKS5 CONNECT -> {domain or dst_host}:{dst_port}")
        return dst_host, dst_port, domain

    async def _send_reply(
        self, writer: asyncio.StreamWriter, rep: int, bind_addr: str, bind_port: int
    ) -> None:
        """Send SOCKS5 reply to client."""
        try:
            addr_bytes = socket.inet_aton(bind_addr)
            atyp = ATYP_IPV4
        except OSError:
            addr_bytes = b"\x00" * 4
            atyp = ATYP_IPV4

        reply = struct.pack("!BBBB", SOCKS_VERSION, rep, 0x00, atyp)
        reply += addr_bytes + struct.pack("!H", bind_port)
        writer.write(reply)
        await writer.drain()

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        ctx: ConnectionContext,
        needs_bypass: bool,
    ) -> None:
        """Relay data between client and remote, applying bypass on first outgoing packet."""
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
                            # Check if fragmentation produced multiple fragments
                            fragments = getattr(ctx, "_fragments", None)
                            if fragments:
                                # Send fragments individually with TCP_NODELAY
                                sock = remote_writer.transport.get_extra_info("socket")
                                if sock:
                                    sock.setsockopt(
                                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                                    )
                                for frag in fragments:
                                    remote_writer.write(frag)
                                    await remote_writer.drain()
                                continue
                            else:
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

    @property
    def active_connections(self) -> int:
        return self._active_connections
