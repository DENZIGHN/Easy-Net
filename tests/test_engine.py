"""Tests for the bypass engine orchestrator."""

from __future__ import annotations

import pytest

from easynet.core.base import BypassResult, ConnectionContext
from easynet.core.engine import BypassEngine
from tests.conftest import build_test_client_hello


class TestBypassEngine:
    """Test bypass engine initialization and method selection."""

    @pytest.mark.asyncio
    async def test_initialize_without_root(self, config):
        """Test that engine gracefully handles methods requiring root."""
        engine = BypassEngine(config)
        await engine.initialize()
        # Fragmentation and host_manipulation don't need root
        assert "fragmentation" in engine.available_methods
        assert "host_manipulation" in engine.available_methods
        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_apply_bypass_tls(self, config):
        engine = BypassEngine(config)
        await engine.initialize()

        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=443,
            domain="example.com", is_tls=True,
        )
        data = build_test_client_hello("example.com")
        result, _ = await engine.apply_bypass(ctx, data)
        assert result == BypassResult.SUCCESS

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_apply_bypass_http(self, config):
        engine = BypassEngine(config)
        await engine.initialize()

        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=80,
            domain="example.com", is_http=True,
        )
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result, modified = await engine.apply_bypass(ctx, data)
        assert result == BypassResult.SUCCESS
        assert modified != data

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_domain_method_caching(self, config):
        engine = BypassEngine(config)
        await engine.initialize()

        engine.set_domain_method("test.com", "fragmentation")
        assert engine.get_domain_method("test.com") == "fragmentation"
        assert engine.get_domain_method("other.com") is None

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_specific_method_selection(self, config):
        engine = BypassEngine(config)
        await engine.initialize()

        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=80,
            domain="example.com", is_http=True,
        )
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result, _ = await engine.apply_bypass(ctx, data, method_name="host_manipulation")
        assert result == BypassResult.SUCCESS

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_unavailable_method_skipped(self, config):
        engine = BypassEngine(config)
        await engine.initialize()

        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=443,
            domain="example.com", is_tls=True,
        )
        result, _ = await engine.apply_bypass(ctx, b"data", method_name="nonexistent")
        assert result == BypassResult.SKIPPED

        await engine.shutdown()
