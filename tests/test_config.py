"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from easynet.utils.config import Config, load_config


class TestLoadConfig:
    """Test YAML configuration loading."""

    def test_load_default_config(self):
        config = load_config()
        assert isinstance(config, Config)
        assert config.dns.doh_enabled is True
        assert len(config.dns.doh_providers) > 0

    def test_load_nonexistent_returns_defaults(self, tmp_path):
        config = load_config(tmp_path / "nonexistent.yaml")
        assert isinstance(config, Config)
        assert config.log_level == "INFO"

    def test_load_custom_config(self, tmp_path):
        yaml_content = """
general:
  log_level: DEBUG
dns:
  doh:
    enabled: false
bypass:
  fragmentation:
    enabled: true
    fragment_size: 4
proxy:
  socks5:
    port: 9999
"""
        config_file = tmp_path / "test.yaml"
        config_file.write_text(yaml_content)
        config = load_config(config_file)

        assert config.log_level == "DEBUG"
        assert config.dns.doh_enabled is False
        assert config.bypass.fragmentation.fragment_size == 4
        assert config.proxy.socks5.port == 9999

    def test_default_config_values(self):
        config = Config()
        assert config.log_level == "INFO"
        assert config.proxy.socks5.port == 1080
        assert config.proxy.socks5.host == "127.0.0.1"
        assert config.web.enabled is False

    def test_default_config_file_exists(self):
        from easynet.utils.config import DEFAULT_CONFIG_PATH
        assert DEFAULT_CONFIG_PATH.exists()


class TestConfigStructure:
    """Test config dataclass structure."""

    def test_bypass_config_defaults(self):
        config = Config()
        assert config.bypass.fragmentation.enabled is True
        assert config.bypass.fragmentation.strategy == "sni_split"
        assert config.bypass.host_manipulation.enabled is True
        assert config.bypass.ttl_desync.fake_ttl == 1
        assert config.bypass.tcp_desync.method == "fake_syn"

    def test_proxy_config_defaults(self):
        config = Config()
        assert config.proxy.socks5.enabled is True
        assert config.proxy.transparent.enabled is False
        assert config.proxy.split_tunnel_enabled is True

    def test_routing_config_defaults(self):
        config = Config()
        assert config.routing.detection_enabled is True
        assert config.routing.auto_select_enabled is True
