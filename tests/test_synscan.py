"""Tests for the SYN-scan packet logic.

These exercise the pure functions only — checksum, packet construction and
response parsing — so they need no root privileges and send no real traffic.
"""

import socket
import struct

from portscanner.synscan import build_syn_packet, parse_tcp_response, tcp_checksum

_SYN = 0x02
_ACK = 0x10
_RST = 0x04


def _pseudo_header(src_ip: str, dst_ip: str, tcp_len: int) -> bytes:
    return struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_len,
    )


def test_checksum_folds_back_to_zero():
    # The defining property of the Internet checksum: recomputing it over the
    # segment *including* the checksum field yields 0.
    src, dst = "192.168.0.1", "192.168.0.2"
    packet = build_syn_packet(src, dst, 40000, 80, seq=12345)
    assert tcp_checksum(_pseudo_header(src, dst, len(packet)) + packet) == 0


def test_syn_packet_structure():
    packet = build_syn_packet("10.0.0.1", "10.0.0.2", 40000, 443, seq=0)
    assert len(packet) == 20
    src_port, dst_port = struct.unpack("!HH", packet[0:4])
    assert (src_port, dst_port) == (40000, 443)
    assert packet[13] == _SYN  # only the SYN flag is set


def _ip_tcp(src_ip: str, src_port: int, dst_port: int, flags: int) -> bytes:
    ip = bytearray(20)
    ip[0] = (4 << 4) | 5  # IPv4, header length = 5 words
    ip[12:16] = socket.inet_aton(src_ip)
    tcp = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 0, 0, (5 << 4), flags, 0, 0, 0
    )
    return bytes(ip) + tcp


def test_parse_synack_is_open():
    packet = _ip_tcp("1.2.3.4", 80, 40000, _SYN | _ACK)
    assert parse_tcp_response(packet, "1.2.3.4", 40000) == (80, "open")


def test_parse_rst_is_closed():
    packet = _ip_tcp("1.2.3.4", 81, 40000, _RST | _ACK)
    assert parse_tcp_response(packet, "1.2.3.4", 40000) == (81, "closed")


def test_parse_ignores_other_hosts():
    packet = _ip_tcp("9.9.9.9", 80, 40000, _SYN | _ACK)
    assert parse_tcp_response(packet, "1.2.3.4", 40000) is None


def test_parse_ignores_replies_to_other_ports():
    packet = _ip_tcp("1.2.3.4", 80, 55555, _SYN | _ACK)
    assert parse_tcp_response(packet, "1.2.3.4", 40000) is None


def test_parse_handles_variable_ip_header_length():
    # An IP header with options (IHL = 6 words = 24 bytes) must still parse.
    ip = bytearray(24)
    ip[0] = (4 << 4) | 6
    ip[12:16] = socket.inet_aton("1.2.3.4")
    tcp = struct.pack("!HHIIBBHHH", 22, 40000, 0, 0, (5 << 4), _SYN | _ACK, 0, 0, 0)
    packet = bytes(ip) + tcp
    assert parse_tcp_response(packet, "1.2.3.4", 40000) == (22, "open")
