import struct
import random
from pathlib import Path

class PCAPGenerator:

    def __init__(self, output_file: str):
        self.output_file = Path(output_file)
        self.file = None
        self.timestamp = 1700000000

    # -------------------------------------------------
    # Public API
    # -------------------------------------------------

    def generate_test_pcap(self):
        self._open()
        self._generate_tls_traffic()
        self._generate_http_traffic()
        self._generate_dns_traffic()
        self._generate_blocked_ip_traffic()
        self._close()

    # -------------------------------------------------
    # Core Writer
    # -------------------------------------------------

    def _open(self):
        self.file = open(self.output_file, "wb")
        self._write_global_header()

    def _close(self):
        if self.file:
            self.file.close()

    def _write_global_header(self):
        header = struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65535,
            1
        )
        self.file.write(header)

    def _write_packet(self, data: bytes):
        ts_usec = random.randint(0, 999999)
        pkt_header = struct.pack(
            "<IIII",
            self.timestamp,
            ts_usec,
            len(data),
            len(data)
        )
        self.timestamp += 1

        self.file.write(pkt_header)
        self.file.write(data)

    # -------------------------------------------------
    # Traffic Generators
    # -------------------------------------------------

    def _generate_tls_traffic(self):

        user_ip = "192.168.1.100"
        gateway_mac = "aa:bb:cc:dd:ee:ff"
        user_mac = "00:11:22:33:44:55"

        tls_connections = [
            ("142.250.185.206", "www.google.com"),
            ("157.240.1.35", "www.facebook.com"),
            ("23.52.167.61", "www.netflix.com"),
            ("140.82.114.4", "github.com"),
        ]

        for dst_ip, sni in tls_connections:
            src_port = random.randint(49152, 65535)

            eth = self._eth(user_mac, gateway_mac)
            tcp = self._tcp(src_port, 443)
            ip = self._ip(user_ip, dst_ip, 6, len(tcp))

            self._write_packet(eth + ip + tcp)

            tls_data = self._tls_client_hello(sni)
            tcp = self._tcp(src_port, 443, flags=0x18)
            ip = self._ip(user_ip, dst_ip, 6, len(tcp) + len(tls_data))

            self._write_packet(eth + ip + tcp + tls_data)

    def _generate_http_traffic(self):

        user_ip = "192.168.1.100"
        gateway_mac = "aa:bb:cc:dd:ee:ff"
        user_mac = "00:11:22:33:44:55"

        http_hosts = ["example.com", "httpbin.org"]

        for host in http_hosts:
            dst_ip = "93.184.216.34"
            src_port = random.randint(49152, 65535)

            eth = self._eth(user_mac, gateway_mac)
            tcp = self._tcp(src_port, 80)
            ip = self._ip(user_ip, dst_ip, 6, len(tcp))

            self._write_packet(eth + ip + tcp)

            http_data = self._http_request(host)
            tcp = self._tcp(src_port, 80, flags=0x18)
            ip = self._ip(user_ip, dst_ip, 6, len(tcp) + len(http_data))

            self._write_packet(eth + ip + tcp + http_data)

    def _generate_dns_traffic(self):

        user_ip = "192.168.1.100"
        gateway_mac = "aa:bb:cc:dd:ee:ff"
        user_mac = "00:11:22:33:44:55"

        domains = ["www.google.com", "api.twitter.com"]

        for domain in domains:
            dns_data = self._dns_query(domain)

            eth = self._eth(user_mac, gateway_mac)
            udp = self._udp(50000, 53, len(dns_data))
            ip = self._ip(user_ip, "8.8.8.8", 17, len(udp) + len(dns_data))

            self._write_packet(eth + ip + udp + dns_data)

    def _generate_blocked_ip_traffic(self):

        blocked_ip = "192.168.1.50"
        gateway_mac = "aa:bb:cc:dd:ee:ff"

        for _ in range(5):
            eth = self._eth("00:11:22:33:44:56", gateway_mac)
            tcp = self._tcp(50000, 443)
            ip = self._ip(blocked_ip, "172.217.0.100", 6, len(tcp))

            self._write_packet(eth + ip + tcp)

    # -------------------------------------------------
    # Packet Builders
    # -------------------------------------------------

    def _eth(self, src_mac, dst_mac):
        return bytes.fromhex(dst_mac.replace(":", "")) + \
               bytes.fromhex(src_mac.replace(":", "")) + \
               struct.pack(">H", 0x0800)

    def _ip(self, src_ip, dst_ip, protocol, payload_len):
        version_ihl = 0x45
        total_len = 20 + payload_len
        ident = random.randint(1, 65535)
        flags_frag = 0x4000
        ttl = 64

        header = struct.pack(
            ">BBHHHBBH",
            version_ihl,
            0,
            total_len,
            ident,
            flags_frag,
            ttl,
            protocol,
            0
        )

        header += bytes(int(x) for x in src_ip.split("."))
        header += bytes(int(x) for x in dst_ip.split("."))

        return header

    def _tcp(self, src_port, dst_port, flags=0x02):
        return struct.pack(
            ">HHIIBBHHH",
            src_port,
            dst_port,
            1000,
            0,
            5 << 4,
            flags,
            65535,
            0,
            0
        )

    def _udp(self, src_port, dst_port, payload_len):
        return struct.pack(">HHHH", src_port, dst_port, 8 + payload_len, 0)

    def _tls_client_hello(self, sni):
        sni_bytes = sni.encode()
        sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

        extensions = struct.pack(">H", len(sni_ext)) + sni_ext

        client_body = struct.pack(">H", 0x0303)
        client_body += bytes(random.randint(0, 255) for _ in range(32))
        client_body += struct.pack("B", 0)
        client_body += struct.pack(">H", 2) + struct.pack(">H", 0x1301)
        client_body += struct.pack("BB", 1, 0)
        client_body += extensions

        handshake = struct.pack("B", 1)
        handshake += struct.pack(">I", len(client_body))[1:]
        handshake += client_body

        record = struct.pack("B", 0x16)
        record += struct.pack(">H", 0x0301)
        record += struct.pack(">H", len(handshake))
        record += handshake

        return record

    def _http_request(self, host):
        return f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()

    def _dns_query(self, domain):
        txid = struct.pack(">H", random.randint(1, 65535))
        flags = struct.pack(">H", 0x0100)
        counts = struct.pack(">HHHH", 1, 0, 0, 0)

        question = b""
        for label in domain.split("."):
            question += struct.pack("B", len(label)) + label.encode()

        question += struct.pack("B", 0)
        question += struct.pack(">HH", 1, 1)

        return txid + flags + counts + question