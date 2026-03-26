"""Tests for TCP desynchronization bypass method."""

from __future__ import annotations

import socket
import struct

import pytest

from easynet.core.tcp_desync import _checksum, build_fake_data_packet


class TestBuildFakeDataPacket:
    """Test raw TCP data packet construction for desync attacks."""

    def test_packet_has_payload(self):
        payload = b"FAKE_DATA_12345"
        packet = build_fake_data_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            seq_num=1000,
            fake_payload=payload,
            ttl=1,
        )
        # IP(20) + TCP(20) + payload
        assert len(packet) == 40 + len(payload)
        # Payload should be at the end
        assert packet[-len(payload) :] == payload

    def test_ip_total_length(self):
        payload = b"test"
        packet = build_fake_data_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            seq_num=0,
            fake_payload=payload,
            ttl=1,
        )
        total_len = struct.unpack("!H", packet[2:4])[0]
        assert total_len == 20 + 20 + len(payload)

    def test_psh_ack_flags(self):
        packet = build_fake_data_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=443,
            seq_num=0,
            fake_payload=b"data",
            ttl=1,
        )
        # TCP flags at offset 20+13
        flags = packet[33]
        assert flags & 0x08  # PSH
        assert flags & 0x10  # ACK

    def test_low_ttl(self):
        packet = build_fake_data_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=443,
            seq_num=0,
            fake_payload=b"x",
            ttl=2,
        )
        assert packet[8] == 2

    def test_ports_and_seq(self):
        packet = build_fake_data_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=11111,
            dst_port=22222,
            seq_num=777777,
            fake_payload=b"data",
            ttl=1,
        )
        src_port = struct.unpack("!H", packet[20:22])[0]
        dst_port = struct.unpack("!H", packet[22:24])[0]
        seq = struct.unpack("!I", packet[24:28])[0]
        assert src_port == 11111
        assert dst_port == 22222
        assert seq == 777777


class TestDesyncChecksum:
    """Test checksum implementation in tcp_desync module."""

    def test_returns_16bit_value(self):
        chk = _checksum(b"\x00\x00\x00\x00")
        assert 0 <= chk <= 0xFFFF

    def test_handles_odd_length(self):
        chk = _checksum(b"\x01\x02\x03")
        assert isinstance(chk, int)
