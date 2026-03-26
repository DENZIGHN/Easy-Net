"""Tests for TCP fragmentation bypass method."""

from __future__ import annotations

import pytest

from easynet.core.base import BypassResult, ConnectionContext
from easynet.core.fragmentation import (
    FragmentationBypass,
    find_sni_offset,
    fragment_at_sni,
    fragment_fixed_size,
)
from tests.conftest import build_test_client_hello


class TestFindSniOffset:
    """Test SNI offset detection in TLS ClientHello."""

    def test_finds_sni_in_valid_client_hello(self):
        data = build_test_client_hello("example.com")
        offset = find_sni_offset(data)
        assert offset is not None
        # Verify the SNI hostname is at the found offset
        sni = data[offset : offset + len("example.com")]
        assert sni == b"example.com"

    def test_returns_none_for_non_tls(self):
        assert find_sni_offset(b"GET / HTTP/1.1\r\n") is None

    def test_returns_none_for_short_data(self):
        assert find_sni_offset(b"\x16\x03") is None

    def test_returns_none_for_empty_data(self):
        assert find_sni_offset(b"") is None

    def test_finds_sni_with_long_domain(self):
        domain = "subdomain.example.co.uk"
        data = build_test_client_hello(domain)
        offset = find_sni_offset(data)
        assert offset is not None
        assert data[offset : offset + len(domain)] == domain.encode()


class TestFragmentAtSni:
    """Test SNI-based fragmentation."""

    def test_splits_at_sni(self):
        data = build_test_client_hello("example.com")
        fragments = fragment_at_sni(data, fragment_size=2)
        assert len(fragments) == 2
        # Reassembled data should equal original
        assert b"".join(fragments) == data

    def test_sni_split_across_fragments(self):
        domain = "example.com"
        data = build_test_client_hello(domain)
        fragments = fragment_at_sni(data, fragment_size=3)
        assert len(fragments) == 2
        # Neither fragment should contain the full domain
        for frag in fragments:
            assert domain.encode() not in frag

    def test_returns_unchanged_for_non_tls(self):
        data = b"Hello, World!"
        fragments = fragment_at_sni(data)
        assert fragments == [data]

    def test_various_fragment_sizes(self):
        data = build_test_client_hello("test.example.com")
        for size in [1, 2, 4, 8]:
            fragments = fragment_at_sni(data, fragment_size=size)
            assert len(fragments) == 2
            assert b"".join(fragments) == data


class TestFragmentFixedSize:
    """Test fixed-size fragmentation."""

    def test_splits_evenly(self):
        data = b"A" * 100
        fragments = fragment_fixed_size(data, size=25)
        assert len(fragments) == 4
        assert b"".join(fragments) == data

    def test_handles_remainder(self):
        data = b"A" * 103
        fragments = fragment_fixed_size(data, size=25)
        assert len(fragments) == 5
        assert b"".join(fragments) == data

    def test_returns_unchanged_if_smaller_than_size(self):
        data = b"short"
        fragments = fragment_fixed_size(data, size=100)
        assert fragments == [data]


class TestFragmentationBypass:
    """Test the FragmentationBypass method class."""

    @pytest.mark.asyncio
    async def test_applicable_to_tls(self, config):
        bypass = FragmentationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=443,
            domain="example.com", is_tls=True,
        )
        assert await bypass.is_applicable(ctx) is True

    @pytest.mark.asyncio
    async def test_not_applicable_to_http(self, config):
        bypass = FragmentationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=80,
            domain="example.com", is_http=True,
        )
        assert await bypass.is_applicable(ctx) is False

    @pytest.mark.asyncio
    async def test_apply_fragments_client_hello(self, config):
        bypass = FragmentationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=443,
            domain="example.com", is_tls=True,
        )
        data = build_test_client_hello("example.com")
        result, _ = await bypass.apply(ctx, data)
        assert result == BypassResult.SUCCESS
        assert hasattr(ctx, "_fragments")
        assert len(ctx._fragments) == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_skips_non_tls_data(self, config):
        bypass = FragmentationBypass(config)
        ctx = ConnectionContext(
            src_host="127.0.0.1", src_port=1234,
            dst_host="93.184.216.34", dst_port=443,
            domain="example.com", is_tls=True,
        )
        result, data = await bypass.apply(ctx, b"not tls data")
        assert result == BypassResult.SKIPPED
