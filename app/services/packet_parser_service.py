import struct
from app.schema.parsed_packet_schema import ParsedPacketSchema

class PacketParser:

    def parse(self, raw_data: bytes, ts_sec: int, ts_usec: int) -> ParsedPacketSchema:

        offset = 0

        # ----------------------------
        # Ethernet Header (14 bytes)
        # ----------------------------
        dest_mac = self._mac_to_string(raw_data[0:6])
        src_mac = self._mac_to_string(raw_data[6:12])
        ether_type = struct.unpack("!H", raw_data[12:14])[0]
        offset = 14

        parsed = ParsedPacketSchema(
            timestamp_sec=ts_sec,
            timestamp_usec=ts_usec,
            src_mac=src_mac,
            dest_mac=dest_mac,
            ether_type=ether_type,
        )

        # ----------------------------
        # IPv4
        # ----------------------------
        if ether_type == 0x0800:
            parsed.has_ip = True

            version_ihl = raw_data[offset]
            parsed.ip_version = version_ihl >> 4
            ihl = version_ihl & 0x0F
            ip_header_length = ihl * 4

            parsed.ttl = raw_data[offset + 8]
            parsed.protocol = raw_data[offset + 9]

            src_ip = raw_data[offset + 12: offset + 16]
            dst_ip = raw_data[offset + 16: offset + 20]

            parsed.src_ip = self._ip_to_string(src_ip)
            parsed.dest_ip = self._ip_to_string(dst_ip)

            offset += ip_header_length

            # ----------------------------
            # TCP
            # ----------------------------
            if parsed.protocol == 6:
                parsed.has_tcp = True

                parsed.src_port, parsed.dest_port = struct.unpack(
                    "!HH", raw_data[offset: offset + 4]
                )

                parsed.seq_number = struct.unpack(
                    "!I", raw_data[offset + 4: offset + 8]
                )[0]

                parsed.ack_number = struct.unpack(
                    "!I", raw_data[offset + 8: offset + 12]
                )[0]

                parsed.tcp_flags = raw_data[offset + 13]

                tcp_header_len = (raw_data[offset + 12] >> 4) * 4
                offset += tcp_header_len

            # ----------------------------
            # UDP
            # ----------------------------
            elif parsed.protocol == 17:
                parsed.has_udp = True

                parsed.src_port, parsed.dest_port = struct.unpack(
                    "!HH", raw_data[offset: offset + 4]
                )

                offset += 8

        # ----------------------------
        # Payload
        # ----------------------------
        if offset < len(raw_data):
            parsed.payload = raw_data[offset:]
            parsed.payload_length = len(raw_data) - offset

        return parsed

    # =========================================
    # Helpers
    # =========================================

    def _mac_to_string(self, mac: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac)

    def _ip_to_string(self, ip: bytes) -> str:
        return ".".join(str(b) for b in ip)