"""Configuration loading and management."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _get_base_dir() -> Path:
    """Get the base directory, handling both normal and PyInstaller frozen modes."""
    if getattr(sys, "frozen", False):
        # Running as PyInstaller bundle — _MEIPASS is the temp extraction dir
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).parent.parent.parent


DEFAULT_CONFIG_PATH = _get_base_dir() / "config" / "default.yaml"


@dataclass
class DohProvider:
    name: str
    url: str
    priority: int = 1


@dataclass
class DotServer:
    host: str
    port: int = 853


@dataclass
class DnsConfig:
    doh_enabled: bool = True
    doh_providers: list[DohProvider] = field(default_factory=list)
    doh_timeout: float = 5.0
    doh_cache_ttl: int = 300
    dot_enabled: bool = True
    dot_servers: list[DotServer] = field(default_factory=list)
    dot_timeout: float = 5.0
    system_servers: list[str] = field(default_factory=list)


@dataclass
class FragmentationConfig:
    enabled: bool = True
    fragment_size: int = 2
    strategy: str = "sni_split"


@dataclass
class HostManipConfig:
    enabled: bool = True
    methods: list[str] = field(default_factory=lambda: ["case_randomize"])


@dataclass
class TtlDesyncConfig:
    enabled: bool = True
    fake_ttl: int = 1
    real_ttl: int = 64


@dataclass
class TcpDesyncConfig:
    enabled: bool = True
    method: str = "fake_syn"


@dataclass
class BypassConfig:
    fragmentation: FragmentationConfig = field(default_factory=FragmentationConfig)
    host_manipulation: HostManipConfig = field(default_factory=HostManipConfig)
    ttl_desync: TtlDesyncConfig = field(default_factory=TtlDesyncConfig)
    tcp_desync: TcpDesyncConfig = field(default_factory=TcpDesyncConfig)


@dataclass
class Socks5Config:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 1080
    auth_enabled: bool = False
    username: str = ""
    password: str = ""


@dataclass
class TransparentConfig:
    enabled: bool = False
    port: int = 8080


@dataclass
class ProxyConfig:
    socks5: Socks5Config = field(default_factory=Socks5Config)
    transparent: TransparentConfig = field(default_factory=TransparentConfig)
    split_tunnel_enabled: bool = True
    split_tunnel_mode: str = "blocklist"


@dataclass
class RoutingConfig:
    detection_enabled: bool = True
    detection_methods: list[str] = field(
        default_factory=lambda: ["dns_comparison", "ttl_analysis", "timeout_detection"]
    )
    check_interval: int = 3600
    blocklist_file: str = "~/.easynet/blocklist.txt"
    community_sources: list[str] = field(default_factory=list)
    update_interval: int = 86400
    auto_select_enabled: bool = True
    test_timeout: float = 10.0
    method_priority: list[str] = field(
        default_factory=lambda: ["fragmentation", "host_manipulation", "ttl_desync", "tcp_desync"]
    )


@dataclass
class WebConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8888


@dataclass
class Config:
    log_level: str = "INFO"
    log_file: str = "easynet.log"
    data_dir: str = "~/.easynet"
    dns: DnsConfig = field(default_factory=DnsConfig)
    bypass: BypassConfig = field(default_factory=BypassConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    web: WebConfig = field(default_factory=WebConfig)


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from YAML file, falling back to defaults."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return Config()

    with open(config_path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    return _parse_config(raw)


def _parse_config(raw: dict[str, Any]) -> Config:
    """Parse raw YAML dict into Config dataclass."""
    general = raw.get("general", {})
    dns_raw = raw.get("dns", {})
    bypass_raw = raw.get("bypass", {})
    proxy_raw = raw.get("proxy", {})
    routing_raw = raw.get("routing", {})
    web_raw = raw.get("web", {})

    # Parse DNS config
    doh_raw = dns_raw.get("doh", {})
    doh_providers = [
        DohProvider(name=p["name"], url=p["url"], priority=p.get("priority", 1))
        for p in doh_raw.get("providers", [])
    ]
    dot_raw = dns_raw.get("dot", {})
    dot_servers = [
        DotServer(host=s["host"], port=s.get("port", 853))
        for s in dot_raw.get("servers", [])
    ]

    dns_config = DnsConfig(
        doh_enabled=doh_raw.get("enabled", True),
        doh_providers=doh_providers,
        doh_timeout=doh_raw.get("timeout", 5.0),
        doh_cache_ttl=doh_raw.get("cache_ttl", 300),
        dot_enabled=dot_raw.get("enabled", True),
        dot_servers=dot_servers,
        dot_timeout=dot_raw.get("timeout", 5.0),
        system_servers=dns_raw.get("system", {}).get("servers", []),
    )

    # Parse bypass config
    frag_raw = bypass_raw.get("fragmentation", {})
    host_raw = bypass_raw.get("host_manipulation", {})
    ttl_raw = bypass_raw.get("ttl_desync", {})
    tcp_raw = bypass_raw.get("tcp_desync", {})

    bypass_config = BypassConfig(
        fragmentation=FragmentationConfig(
            enabled=frag_raw.get("enabled", True),
            fragment_size=frag_raw.get("fragment_size", 2),
            strategy=frag_raw.get("strategy", "sni_split"),
        ),
        host_manipulation=HostManipConfig(
            enabled=host_raw.get("enabled", True),
            methods=host_raw.get("methods", ["case_randomize"]),
        ),
        ttl_desync=TtlDesyncConfig(
            enabled=ttl_raw.get("enabled", True),
            fake_ttl=ttl_raw.get("fake_ttl", 1),
            real_ttl=ttl_raw.get("real_ttl", 64),
        ),
        tcp_desync=TcpDesyncConfig(
            enabled=tcp_raw.get("enabled", True),
            method=tcp_raw.get("method", "fake_syn"),
        ),
    )

    # Parse proxy config
    socks5_raw = proxy_raw.get("socks5", {})
    trans_raw = proxy_raw.get("transparent", {})
    auth_raw = socks5_raw.get("auth", {})

    proxy_config = ProxyConfig(
        socks5=Socks5Config(
            enabled=socks5_raw.get("enabled", True),
            host=socks5_raw.get("host", "127.0.0.1"),
            port=socks5_raw.get("port", 1080),
            auth_enabled=auth_raw.get("enabled", False),
            username=auth_raw.get("username", ""),
            password=auth_raw.get("password", ""),
        ),
        transparent=TransparentConfig(
            enabled=trans_raw.get("enabled", False),
            port=trans_raw.get("port", 8080),
        ),
        split_tunnel_enabled=proxy_raw.get("split_tunnel", {}).get("enabled", True),
        split_tunnel_mode=proxy_raw.get("split_tunnel", {}).get("mode", "blocklist"),
    )

    # Parse routing config
    detect_raw = routing_raw.get("detection", {})
    bl_raw = routing_raw.get("blocklist", {})
    auto_raw = routing_raw.get("auto_select", {})

    routing_config = RoutingConfig(
        detection_enabled=detect_raw.get("enabled", True),
        detection_methods=detect_raw.get("methods", ["dns_comparison"]),
        check_interval=detect_raw.get("check_interval", 3600),
        blocklist_file=bl_raw.get("local_file", "~/.easynet/blocklist.txt"),
        community_sources=bl_raw.get("community_sources", []),
        update_interval=bl_raw.get("update_interval", 86400),
        auto_select_enabled=auto_raw.get("enabled", True),
        test_timeout=auto_raw.get("test_timeout", 10.0),
        method_priority=auto_raw.get("priority", ["fragmentation"]),
    )

    # Parse web config
    web_config = WebConfig(
        enabled=web_raw.get("enabled", False),
        host=web_raw.get("host", "127.0.0.1"),
        port=web_raw.get("port", 8888),
    )

    return Config(
        log_level=general.get("log_level", "INFO"),
        log_file=general.get("log_file", "easynet.log"),
        data_dir=general.get("data_dir", "~/.easynet"),
        dns=dns_config,
        bypass=bypass_config,
        proxy=proxy_config,
        routing=routing_config,
        web=web_config,
    )
