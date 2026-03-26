"""Shared test fixtures for EasyNet tests."""

from __future__ import annotations

import pytest

from easynet.utils.config import (
    BypassConfig,
    Config,
    DnsConfig,
    DohProvider,
    DotServer,
    FragmentationConfig,
    HostManipConfig,
    ProxyConfig,
    RoutingConfig,
    Socks5Config,
    TcpDesyncConfig,
    TransparentConfig,
    TtlDesyncConfig,
    WebConfig,
)


@pytest.fixture
def config() -> Config:
    """Create a test configuration."""
    return Config(
        log_level="DEBUG",
        dns=DnsConfig(
            doh_enabled=True,
            doh_providers=[
                DohProvider(name="cloudflare", url="https://cloudflare-dns.com/dns-query"),
                DohProvider(name="google", url="https://dns.google/dns-query", priority=2),
            ],
            dot_enabled=True,
            dot_servers=[DotServer(host="1.1.1.1")],
            system_servers=["8.8.8.8"],
        ),
        bypass=BypassConfig(
            fragmentation=FragmentationConfig(enabled=True, fragment_size=2),
            host_manipulation=HostManipConfig(enabled=True, methods=["case_randomize", "space_prefix"]),
            ttl_desync=TtlDesyncConfig(enabled=True, fake_ttl=1, real_ttl=64),
            tcp_desync=TcpDesyncConfig(enabled=True, method="fake_syn"),
        ),
        proxy=ProxyConfig(
            socks5=Socks5Config(enabled=True, host="127.0.0.1", port=10800),
            transparent=TransparentConfig(enabled=False),
            split_tunnel_enabled=True,
        ),
        routing=RoutingConfig(
            detection_enabled=True,
            blocklist_file="/tmp/easynet_test_blocklist.txt",
            method_priority=["fragmentation", "host_manipulation", "ttl_desync", "tcp_desync"],
        ),
    )


def build_test_client_hello(domain: str = "example.com") -> bytes:
    """Build a minimal TLS ClientHello with SNI for testing."""
    import struct

    hostname = domain.encode()

    # SNI extension
    sni_data = struct.pack("!HBH", len(hostname) + 3, 0, len(hostname)) + hostname
    sni_ext = struct.pack("!HH", 0x0000, len(sni_data)) + sni_data

    # Extensions
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    # ClientHello body
    client_hello_body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x00\xff"
        + b"\x01\x00"
        + extensions
    )

    # Handshake header
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(client_hello_body))[1:]
    handshake += client_hello_body

    # TLS record
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record
