"""Tests for smart routing module."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from easynet.routing.router import Blocklist, SmartRouter


class TestBlocklist:
    """Test blocklist management."""

    @pytest.mark.asyncio
    async def test_load_empty(self, config, tmp_path):
        config.routing.blocklist_file = str(tmp_path / "blocklist.txt")
        bl = Blocklist(config)
        await bl.load()
        assert len(bl.domains) == 0

    @pytest.mark.asyncio
    async def test_load_existing(self, config, tmp_path):
        bl_file = tmp_path / "blocklist.txt"
        bl_file.write_text("example.com\nblocked.org\n# comment\n\n")
        config.routing.blocklist_file = str(bl_file)
        bl = Blocklist(config)
        await bl.load()
        assert "example.com" in bl.domains
        assert "blocked.org" in bl.domains
        assert len(bl.domains) == 2

    def test_contains_exact(self, config):
        bl = Blocklist(config)
        bl.add("example.com")
        assert bl.contains("example.com") is True
        assert bl.contains("other.com") is False

    def test_contains_subdomain(self, config):
        bl = Blocklist(config)
        bl.add("example.com")
        # Subdomain of blocked domain should match
        assert bl.contains("sub.example.com") is True
        assert bl.contains("deep.sub.example.com") is True

    def test_add_and_remove(self, config):
        bl = Blocklist(config)
        bl.add("test.com")
        assert bl.contains("test.com")
        bl.remove("test.com")
        assert not bl.contains("test.com")

    def test_case_insensitive(self, config):
        bl = Blocklist(config)
        bl.add("Example.COM")
        assert bl.contains("example.com")
        assert bl.contains("EXAMPLE.COM")

    @pytest.mark.asyncio
    async def test_save_and_reload(self, config, tmp_path):
        bl_file = tmp_path / "blocklist.txt"
        config.routing.blocklist_file = str(bl_file)
        bl = Blocklist(config)
        bl.add("test1.com")
        bl.add("test2.org")
        await bl.save()

        # Reload
        bl2 = Blocklist(config)
        await bl2.load()
        assert bl2.contains("test1.com")
        assert bl2.contains("test2.org")


class TestSmartRouter:
    """Test smart routing decisions."""

    @pytest.mark.asyncio
    async def test_bypass_blocklisted_domain(self, config, tmp_path):
        config.routing.blocklist_file = str(tmp_path / "blocklist.txt")
        config.routing.detection_enabled = False  # Disable auto-detection for this test

        dns_mock = AsyncMock()
        router = SmartRouter(config, dns_mock)
        await router.initialize()
        router.blocklist.add("blocked.com")

        assert await router.should_bypass("blocked.com") is True

    @pytest.mark.asyncio
    async def test_no_bypass_for_unblocked(self, config, tmp_path):
        config.routing.blocklist_file = str(tmp_path / "blocklist.txt")
        config.routing.detection_enabled = False

        dns_mock = AsyncMock()
        router = SmartRouter(config, dns_mock)
        await router.initialize()

        assert await router.should_bypass("allowed.com") is False

    @pytest.mark.asyncio
    async def test_bypass_all_when_split_tunnel_disabled(self, config, tmp_path):
        config.routing.blocklist_file = str(tmp_path / "blocklist.txt")
        config.proxy.split_tunnel_enabled = False

        dns_mock = AsyncMock()
        router = SmartRouter(config, dns_mock)
        await router.initialize()

        # Should bypass everything when split tunneling is off
        assert await router.should_bypass("anything.com") is True

    def test_get_status(self, config):
        dns_mock = MagicMock()
        router = SmartRouter(config, dns_mock)
        status = router.get_status()
        assert "blocklist_size" in status
        assert "tracked_domains" in status
