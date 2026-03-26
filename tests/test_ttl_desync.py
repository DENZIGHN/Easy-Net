"""Tests for TTL-based desync bypass method."""

from __future__ import annotations

import socket
import struct

import pytest

from easynet.core.ttl_desync import _checksum, build_tcp_rst_packet


class TestBuildTcpRstPacket:
    """Test raw TCP RST packet construction."""

    def test_packet_length(self):
        packet = build_tcp_rst_packet(
            src_ip="192.168.1.1",
            dst_ip="93.184.216.34",
            src_port=12345,
            dst_port=443,
            seq_num=1000,
            ttl=1,
        )
        # IP header (20) + TCP header (20) = 40 bytes
        assert len(packet) == 40

    def test_ip_header_fields(self):
        packet = build_tcp_rst_packet(
            src_ip="192.168.1.1",
            dst_ip="93.184.216.34",
            src_port=12345,
            dst_port=443,
            seq_num=1000,
            ttl=3,
        )
        # Check IP version + IHL
        assert packet[0] == 0x45
        # Check TTL
        assert packet[8] == 3
        # Check protocol (TCP = 6)
        assert packet[9] == socket.IPPROTO_TCP
        # Check source IP
        assert socket.inet_ntoa(packet[12:16]) == "192.168.1.1"
        # Check dest IP
        assert socket.inet_ntoa(packet[16:20]) == "93.184.216.34"

    def test_tcp_rst_flag(self):
        packet = build_tcp_rst_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=5000,
            dst_port=80,
            seq_num=42,
            ttl=1,
        )
        # TCP flags are at offset 20 (IP header) + 13 (flags byte in TCP)
        tcp_flags = packet[20 + 13]
        assert tcp_flags & 0x04  # RST flag set

    def test_tcp_ports(self):
        packet = build_tcp_rst_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=54321,
            dst_port=8080,
            seq_num=0,
            ttl=1,
        )
        # TCP src port at IP header end
        src_port = struct.unpack("!H", packet[20:22])[0]
        dst_port = struct.unpack("!H", packet[22:24])[0]
        assert src_port == 54321
        assert dst_port == 8080

    def test_tcp_sequence_number(self):
        packet = build_tcp_rst_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=443,
            seq_num=999999,
            ttl=1,
        )
        seq = struct.unpack("!I", packet[24:28])[0]
        assert seq == 999999

    def test_low_ttl_for_fake_packet(self):
        """Verify that fake packets use TTL=1 so they expire before reaching the server."""
        packet = build_tcp_rst_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=443,
            seq_num=0,
            ttl=1,
        )
        assert packet[8] == 1  # TTL field

    def test_normal_ttl_for_real_packets(self):
        """Real packets should have standard TTL (64)."""
        packet = build_tcp_rst_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=443,
            seq_num=0,
            ttl=64,
        )
        assert packet[8] == 64


class TestChecksum:
    """Test Internet checksum calculation."""

    def test_known_value(self):
        # Simple test data
        data = b"\x00\x01\x00\x02"
        chk = _checksum(data)
        # Checksum of the data + checksum should be 0xFFFF
        verify_data = data + struct.pack("!H", chk)
        assert _checksum(verify_data) == 0  # or 0xFFFF depending on convention

    def test_odd_length(self):
        # Should handle odd-length data by padding
        data = b"\x01\x02\x03"
        chk = _checksum(data)
        assert isinstance(chk, int)
        assert 0 <= chk <= 0xFFFF
