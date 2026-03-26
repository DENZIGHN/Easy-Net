"""CLI interface for EasyNet."""

from __future__ import annotations

import asyncio
import signal
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from easynet.utils.config import load_config
from easynet.utils.logging import setup_logging

console = Console()


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=False),
    default=None,
    help="Path to YAML configuration file.",
)
@click.option(
    "--log-level", "-l",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default=None,
    help="Override log level.",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, log_level: str | None) -> None:
    """EasyNet - Network censorship bypass research tool.

    A research tool for studying DPI bypass techniques in controlled
    virtual lab environments.
    """
    ctx.ensure_object(dict)
    cfg = load_config(config)
    if log_level:
        cfg.log_level = log_level
    ctx.obj["config"] = cfg
    setup_logging(cfg.log_level, cfg.log_file)


@cli.command()
@click.option("--socks5/--no-socks5", default=True, help="Enable SOCKS5 proxy.")
@click.option("--transparent/--no-transparent", default=False, help="Enable transparent proxy.")
@click.option("--web/--no-web", default=False, help="Enable web UI.")
@click.pass_context
def run(ctx: click.Context, socks5: bool, transparent: bool, web: bool) -> None:
    """Start the EasyNet proxy with configured bypass methods."""
    config = ctx.obj["config"]
    config.proxy.socks5.enabled = socks5
    config.proxy.transparent.enabled = transparent
    config.web.enabled = web

    console.print("[bold green]EasyNet[/] starting...", highlight=False)
    asyncio.run(_run_server(config))


async def _run_server(config) -> None:
    """Main async server loop."""
    from easynet.core.engine import BypassEngine
    from easynet.dns.resolver import DnsResolver
    from easynet.routing.router import SmartRouter

    # Initialize components
    dns_resolver = DnsResolver(config)
    await dns_resolver.initialize()

    bypass_engine = BypassEngine(config)
    await bypass_engine.initialize()

    router = SmartRouter(config, dns_resolver, bypass_engine)
    await router.initialize()

    servers = []

    # Start SOCKS5 proxy
    if config.proxy.socks5.enabled:
        from easynet.proxy.socks5 import Socks5Server
        socks = Socks5Server(config, bypass_engine, dns_resolver, router)
        await socks.start()
        servers.append(socks)
        console.print(
            f"  SOCKS5 proxy: [cyan]{config.proxy.socks5.host}:{config.proxy.socks5.port}[/]"
        )

    # Start transparent proxy
    if config.proxy.transparent.enabled:
        from easynet.proxy.transparent import TransparentProxy
        tproxy = TransparentProxy(config, bypass_engine, dns_resolver, router)
        await tproxy.start()
        servers.append(tproxy)
        console.print(f"  Transparent proxy: port [cyan]{config.proxy.transparent.port}[/]")

    # Start web UI
    if config.web.enabled:
        from easynet.web.app import WebUI
        webui = WebUI(config, router, bypass_engine)
        await webui.start()
        servers.append(webui)
        console.print(
            f"  Web UI: [cyan]http://{config.web.host}:{config.web.port}[/]"
        )

    console.print(
        f"  Bypass methods: [yellow]{', '.join(bypass_engine.available_methods)}[/]"
    )
    console.print("[bold green]EasyNet is running.[/] Press Ctrl+C to stop.")

    # Wait for shutdown signal
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()

    console.print("\n[yellow]Shutting down...[/]")
    for server in servers:
        await server.stop()
    await bypass_engine.shutdown()
    await dns_resolver.shutdown()
    console.print("[green]EasyNet stopped.[/]")


@cli.command()
@click.argument("domain")
@click.pass_context
def check(ctx: click.Context, domain: str) -> None:
    """Check if a domain appears to be blocked."""
    config = ctx.obj["config"]
    asyncio.run(_check_domain(config, domain))


async def _check_domain(config, domain: str) -> None:
    from easynet.dns.resolver import DnsResolver
    from easynet.routing.router import BlockDetector

    dns_resolver = DnsResolver(config)
    await dns_resolver.initialize()

    detector = BlockDetector(config, dns_resolver)
    result = await detector.check_domain(domain)

    if result.is_blocked:
        console.print(f"[bold red]BLOCKED[/]: {domain}")
        console.print(f"  Method: {result.detection_method}")
        console.print(f"  Details: {result.details}")
    else:
        console.print(f"[bold green]OK[/]: {domain}")
        console.print(f"  Details: {result.details}")

    await dns_resolver.shutdown()


@cli.command()
@click.argument("domain")
@click.pass_context
def resolve(ctx: click.Context, domain: str) -> None:
    """Resolve a domain using all configured DNS providers."""
    config = ctx.obj["config"]
    asyncio.run(_resolve_domain(config, domain))


async def _resolve_domain(config, domain: str) -> None:
    from easynet.dns.resolver import DnsResolver

    dns_resolver = DnsResolver(config)
    await dns_resolver.initialize()

    results = await dns_resolver.resolve_all_providers(domain)

    table = Table(title=f"DNS Results for {domain}")
    table.add_column("Source", style="cyan")
    table.add_column("Provider", style="green")
    table.add_column("Addresses", style="yellow")
    table.add_column("Time (ms)", style="magenta")
    table.add_column("Error", style="red")

    for r in results:
        table.add_row(
            r.source,
            r.provider,
            ", ".join(r.addresses) if r.addresses else "-",
            f"{r.query_time_ms:.1f}",
            r.error or "",
        )

    console.print(table)
    await dns_resolver.shutdown()


@cli.command("add-domain")
@click.argument("domain")
@click.pass_context
def add_domain(ctx: click.Context, domain: str) -> None:
    """Add a domain to the local blocklist."""
    config = ctx.obj["config"]
    asyncio.run(_add_domain(config, domain))


async def _add_domain(config, domain: str) -> None:
    from easynet.routing.router import Blocklist

    blocklist = Blocklist(config)
    await blocklist.load()
    blocklist.add(domain)
    await blocklist.save()
    console.print(f"Added [cyan]{domain}[/] to blocklist")


@cli.command("remove-domain")
@click.argument("domain")
@click.pass_context
def remove_domain(ctx: click.Context, domain: str) -> None:
    """Remove a domain from the local blocklist."""
    config = ctx.obj["config"]
    asyncio.run(_remove_domain(config, domain))


async def _remove_domain(config, domain: str) -> None:
    from easynet.routing.router import Blocklist

    blocklist = Blocklist(config)
    await blocklist.load()
    blocklist.remove(domain)
    await blocklist.save()
    console.print(f"Removed [cyan]{domain}[/] from blocklist")


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show current EasyNet status and configuration."""
    config = ctx.obj["config"]

    table = Table(title="EasyNet Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row("SOCKS5 Proxy", f"{config.proxy.socks5.host}:{config.proxy.socks5.port}")
    table.add_row("SOCKS5 Enabled", str(config.proxy.socks5.enabled))
    table.add_row("Transparent Proxy", str(config.proxy.transparent.enabled))
    table.add_row("Split Tunneling", str(config.proxy.split_tunnel_enabled))
    table.add_row("DoH Enabled", str(config.dns.doh_enabled))
    table.add_row("DoT Enabled", str(config.dns.dot_enabled))
    table.add_row(
        "Bypass Methods",
        ", ".join([
            m for m, e in [
                ("fragmentation", config.bypass.fragmentation.enabled),
                ("host_manipulation", config.bypass.host_manipulation.enabled),
                ("ttl_desync", config.bypass.ttl_desync.enabled),
                ("tcp_desync", config.bypass.tcp_desync.enabled),
            ] if e
        ]),
    )
    table.add_row("Web UI", f"{config.web.host}:{config.web.port}" if config.web.enabled else "disabled")

    console.print(table)


@cli.command("test-bypass")
@click.argument("domain")
@click.option("--method", "-m", default=None, help="Specific bypass method to test.")
@click.pass_context
def test_bypass(ctx: click.Context, domain: str, method: str | None) -> None:
    """Test bypass methods against a domain."""
    config = ctx.obj["config"]
    asyncio.run(_test_bypass(config, domain, method))


async def _test_bypass(config, domain: str, method: str | None) -> None:
    from easynet.core.engine import BypassEngine
    from easynet.dns.resolver import DnsResolver
    from easynet.routing.router import SmartRouter

    dns_resolver = DnsResolver(config)
    await dns_resolver.initialize()

    engine = BypassEngine(config)
    await engine.initialize()

    router = SmartRouter(config, dns_resolver, engine)
    await router.initialize()

    console.print(f"Testing bypass for [cyan]{domain}[/]...")

    # Check if blocked
    is_blocked = await router.should_bypass(domain)
    console.print(f"  Block detection: {'[red]BLOCKED[/]' if is_blocked else '[green]Not blocked[/]'}")

    # Test available methods
    from easynet.core.base import ConnectionContext

    ctx = ConnectionContext(
        src_host="127.0.0.1", src_port=12345,
        dst_host="0.0.0.0", dst_port=443,
        domain=domain, is_tls=True,
    )

    # Create a minimal TLS ClientHello-like payload for testing
    test_data = _build_test_client_hello(domain)

    methods_to_test = [method] if method else engine.available_methods
    for m in methods_to_test:
        result, _ = await engine.apply_bypass(ctx, test_data, method_name=m)
        status = "[green]OK[/]" if result.value == "success" else f"[yellow]{result.value}[/]"
        console.print(f"  {m}: {status}")

    await engine.shutdown()
    await dns_resolver.shutdown()


def _build_test_client_hello(domain: str) -> bytes:
    """Build a minimal TLS ClientHello for testing fragmentation."""
    import struct

    hostname = domain.encode()

    # SNI extension
    sni_data = struct.pack("!HBH", len(hostname) + 3, 0, len(hostname)) + hostname
    sni_ext = struct.pack("!HH", 0x0000, len(sni_data)) + sni_data

    # Extensions
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    # ClientHello body (simplified)
    client_hello_body = (
        b"\x03\x03"  # Version TLS 1.2
        + b"\x00" * 32  # Random
        + b"\x00"  # Session ID length (0)
        + b"\x00\x02\x00\xff"  # Cipher suites (1 suite)
        + b"\x01\x00"  # Compression methods
        + extensions
    )

    # Handshake header
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(client_hello_body))[1:]
    handshake += client_hello_body

    # TLS record
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


if __name__ == "__main__":
    cli()
