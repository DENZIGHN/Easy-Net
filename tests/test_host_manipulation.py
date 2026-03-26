"""Tests for HTTP Host header manipulation bypass."""

from __future__ import annotations

import pytest

from easynet.core.base import BypassResult, ConnectionContext
from easynet.core.host_manipulation import (
    HostManipulationBypass,
    add_trailing_dot,
    manipulate_host_header,
    randomize_case,
)


class TestRandomizeCase:
    def test_changes_case(self):
        # Run multiple times to ensure it actually randomizes
        results = set()
        for _ in range(20):
            results.add(randomize_case("example.com"))
        # Should have multiple different results
        assert len(results) > 1
        # All should be case-insensitively equal
        for r in results:
            assert r.lower() == "example.com"

    def test_preserves_dots(self):
        result = randomize_case("sub.example.com")
        assert result.lower() == "sub.example.com"
        assert "." in result


class TestAddTrailingDot:
    def test_adds_dot(self):
        assert add_trailing_dot("example.com") == "example.com."

    def test_no_double_dot(self):
        assert add_trailing_dot("example.com.") == "example.com."


class TestManipulateHostHeader:
    def test_case_randomize(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        results = set()
        for _ in range(20):
            modified = manipulate_host_header(data, ["case_randomize"])
            results.add(modified)
        # Should produce different outputs
        assert len(results) > 1
        # Should preserve HTTP structure
        for r in results:
            assert r.startswith(b"GET / HTTP/1.1\r\n")
            assert r.endswith(b"\r\n\r\n")

    def test_space_prefix(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        modified = manipulate_host_header(data, ["space_prefix"])
        # Should have extra spaces after Host:
        assert b"Host:" in modified
        assert b"example.com" in modified

    def test_dot_trailing(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        modified = manipulate_host_header(data, ["dot_trailing"])
        assert b"example.com." in modified

    def test_tab_insert(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        modified = manipulate_host_header(data, ["tab_insert"])
        assert b"Host:\t" in modified

    def test_no_host_header(self):
        data = b"GET / HTTP/1.1\r\n\r\n"
        modified = manipulate_host_header(data, ["case_randomize"])
        assert modified == data  # Unchanged


class TestHostManipulationBypass:
    @pytest.mark.asyncio
    async def test_applicable_to_http(self, config):
        bypass = HostManipulationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=80,
            domain="example.com", is_http=True,
        )
        assert await bypass.is_applicable(ctx) is True

    @pytest.mark.asyncio
    async def test_not_applicable_to_tls(self, config):
        bypass = HostManipulationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=443,
            domain="example.com", is_tls=True,
        )
        assert await bypass.is_applicable(ctx) is False

    @pytest.mark.asyncio
    async def test_apply_modifies_host(self, config):
        bypass = HostManipulationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=80,
            domain="example.com", is_http=True,
        )
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result, modified = await bypass.apply(ctx, data)
        assert result == BypassResult.SUCCESS
        assert modified != data

    @pytest.mark.asyncio
    async def test_skips_non_http(self, config):
        bypass = HostManipulationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=80,
            domain="example.com", is_http=True,
        )
        result, data = await bypass.apply(ctx, b"\x16\x03\x01binary data")
        assert result == BypassResult.SKIPPED
