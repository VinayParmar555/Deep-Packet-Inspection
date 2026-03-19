import struct
import pytest
from app.services.packet_parser_service import PacketParser


def make_eth_header(ether_type: int) -> bytes:
    dest_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    src_mac  = b'\x11\x22\x33\x44\x55\x66'
    return dest_mac + src_mac + struct.pack("!H", ether_type)


def make_ipv4_header(protocol: int, src_ip=(192,168,1,1), dst_ip=(8,8,8,8)) -> bytes:
    version_ihl = (4 << 4) | 5        # version=4, ihl=5 (20 bytes)
    tos         = 0
    total_len   = 40
    ident       = 0
    flags_frag  = 0
    ttl         = 64
    checksum    = 0
    src         = bytes(src_ip)
    dst         = bytes(dst_ip)
    return struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident,
        flags_frag, ttl, protocol, checksum, src, dst)


def make_tcp_header(src_port=1234, dst_port=80, flags=0x02) -> bytes:
    seq       = 0
    ack       = 0
    data_off  = (5 << 4)   # 5 * 4 = 20 bytes, flags in low byte
    window    = 65535
    checksum  = 0
    urgent    = 0
    return struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack,
        data_off, flags, window, checksum, urgent)


def make_udp_header(src_port=5000, dst_port=53) -> bytes:
    length   = 8
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────

class TestPacketParser:

    def setup_method(self):
        self.parser = PacketParser()

    # ── Ethernet ──────────────────────────

    def test_parse_ethernet_macs(self):
        eth  = make_eth_header(0x0800)
        ip   = make_ipv4_header(6)
        tcp  = make_tcp_header()
        raw  = eth + ip + tcp + b'\x00' * 10
        p = self.parser.parse(raw, 1000, 500)
        assert p.src_mac  == "11:22:33:44:55:66"
        assert p.dest_mac == "aa:bb:cc:dd:ee:ff"

    def test_parse_timestamp(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(6)
        tcp = make_tcp_header()
        raw = eth + ip + tcp
        p = self.parser.parse(raw, 9999, 1234)
        assert p.timestamp_sec  == 9999
        assert p.timestamp_usec == 1234

    # ── IPv4 TCP ──────────────────────────

    def test_ipv4_tcp_packet(self):
        eth     = make_eth_header(0x0800)
        ip      = make_ipv4_header(6)
        tcp     = make_tcp_header(src_port=4444, dst_port=80, flags=0x02)
        payload = b'GET / HTTP/1.1\r\n'
        raw     = eth + ip + tcp + payload

        p = self.parser.parse(raw, 0, 0)

        assert p.has_ip       is True
        assert p.has_tcp      is True
        assert p.has_udp      is False
        assert p.ip_version   == 4
        assert p.src_ip       == "192.168.1.1"
        assert p.dest_ip      == "8.8.8.8"
        assert p.src_port     == 4444
        assert p.dest_port    == 80
        assert p.tcp_flags    == 0x02
        assert p.ttl          == 64
        assert p.protocol     == 6
        assert p.payload      == payload
        assert p.payload_length == len(payload)

    def test_ipv4_tcp_syn_flag(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(6)
        tcp = make_tcp_header(flags=0x02)   # SYN
        raw = eth + ip + tcp
        p   = self.parser.parse(raw, 0, 0)
        assert p.tcp_flags == 0x02

    def test_ipv4_tcp_ack_flag(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(6)
        tcp = make_tcp_header(flags=0x10)   # ACK
        raw = eth + ip + tcp
        p   = self.parser.parse(raw, 0, 0)
        assert p.tcp_flags == 0x10

    def test_ipv4_tcp_fin_flag(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(6)
        tcp = make_tcp_header(flags=0x01)   # FIN
        raw = eth + ip + tcp
        p   = self.parser.parse(raw, 0, 0)
        assert p.tcp_flags == 0x01

    # ── IPv4 UDP ──────────────────────────

    def test_ipv4_udp_packet(self):
        eth     = make_eth_header(0x0800)
        ip      = make_ipv4_header(17)
        udp     = make_udp_header(src_port=5000, dst_port=53)
        payload = b'\x00' * 20
        raw     = eth + ip + udp + payload

        p = self.parser.parse(raw, 0, 0)

        assert p.has_ip    is True
        assert p.has_udp   is True
        assert p.has_tcp   is False
        assert p.src_port  == 5000
        assert p.dest_port == 53
        assert p.payload   == payload

    # ── Non-IPv4 ──────────────────────────

    def test_non_ipv4_arp_packet(self):
        eth = make_eth_header(0x0806)   # ARP
        raw = eth + b'\x00' * 28       # ARP payload
        p   = self.parser.parse(raw, 0, 0)
        assert p.has_ip  is False
        assert p.has_tcp is False
        assert p.has_udp is False
        assert p.ether_type == 0x0806

    def test_non_ipv4_no_payload(self):
        eth = make_eth_header(0x0806)
        raw = eth                        # no payload
        p   = self.parser.parse(raw, 0, 0)
        assert p.payload        is None
        assert p.payload_length == 0

    # ── Payload ───────────────────────────

    def test_no_payload_tcp(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(6)
        tcp = make_tcp_header()
        raw = eth + ip + tcp            # no extra payload bytes
        p   = self.parser.parse(raw, 0, 0)
        assert p.payload_length == 0

    def test_payload_length_correct(self):
        eth     = make_eth_header(0x0800)
        ip      = make_ipv4_header(6)
        tcp     = make_tcp_header()
        payload = b'A' * 100
        raw     = eth + ip + tcp + payload
        p       = self.parser.parse(raw, 0, 0)
        assert p.payload_length == 100

    # ── Helpers ───────────────────────────

    def test_mac_to_string(self):
        mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        assert self.parser._mac_to_string(mac) == "aa:bb:cc:dd:ee:ff"

    def test_mac_leading_zero(self):
        mac = b'\x00\x0a\x0b\x0c\x0d\x0e'
        assert self.parser._mac_to_string(mac) == "00:0a:0b:0c:0d:0e"

    def test_ip_to_string(self):
        ip = b'\xc0\xa8\x01\x01'   # 192.168.1.1
        assert self.parser._ip_to_string(ip) == "192.168.1.1"

    def test_ip_to_string_google_dns(self):
        ip = b'\x08\x08\x08\x08'   # 8.8.8.8
        assert self.parser._ip_to_string(ip) == "8.8.8.8"

    # ── IP version / IHL ──────────────────

    def test_ip_version_is_4(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(6)
        tcp = make_tcp_header()
        raw = eth + ip + tcp
        p   = self.parser.parse(raw, 0, 0)
        assert p.ip_version == 4

    def test_different_src_dst_ips(self):
        eth = make_eth_header(0x0800)
        ip  = make_ipv4_header(17, src_ip=(10,0,0,1), dst_ip=(172,16,0,1))
        udp = make_udp_header()
        raw = eth + ip + udp
        p   = self.parser.parse(raw, 0, 0)
        assert p.src_ip  == "10.0.0.1"
        assert p.dest_ip == "172.16.0.1"
