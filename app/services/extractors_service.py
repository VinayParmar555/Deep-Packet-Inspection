import struct
from typing import Optional

class ExtractorService:

    # ==========================================================
    # TLS SNI Extraction
    # ==========================================================

    def extract_tls_sni(self, payload: bytes) -> Optional[str]:

        if len(payload) < 9:
            return None

        # Content Type (Handshake)
        if payload[0] != 0x16:
            return None

        version = struct.unpack("!H", payload[1:3])[0]
        if version < 0x0300 or version > 0x0304:
            return None

        record_length = struct.unpack("!H", payload[3:5])[0]
        if record_length > len(payload) - 5:
            return None

        # Handshake Type
        if payload[5] != 0x01:  # ClientHello
            return None

        offset = 5

        # Skip handshake header
        handshake_length = int.from_bytes(payload[offset + 1:offset + 4], "big")
        offset += 4

        offset += 2  # client version
        offset += 32  # random

        # Session ID
        if offset >= len(payload):
            return None

        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(payload):
            return None

        # Cipher suites
        cipher_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cipher_len

        if offset >= len(payload):
            return None

        # Compression
        comp_len = payload[offset]
        offset += 1 + comp_len

        if offset + 2 > len(payload):
            return None

        # Extensions
        ext_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2

        end = min(offset + ext_len, len(payload))

        while offset + 4 <= end:
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_length = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4

            if offset + ext_length > end:
                break

            # SNI Extension (0x0000)
            if ext_type == 0x0000:
                if ext_length < 5:
                    break

                sni_list_len = struct.unpack("!H", payload[offset:offset + 2])[0]
                sni_type = payload[offset + 2]
                sni_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]

                if sni_type != 0x00:
                    break

                start = offset + 5
                return payload[start:start + sni_len].decode(errors="ignore")

            offset += ext_length

        return None

    # ==========================================================
    # HTTP Host Extraction
    # ==========================================================

    def extract_http_host(self, payload: bytes) -> Optional[str]:

        if len(payload) < 4:
            return None

        methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
        if not any(payload.startswith(m) for m in methods):
            return None

        try:
            text = payload.decode(errors="ignore")
        except:
            return None

        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()

                # Remove port if present
                if ":" in host:
                    host = host.split(":")[0]

                return host

        return None

    # ==========================================================
    # DNS Query Extraction
    # ==========================================================

    def extract_dns_query(self, payload: bytes) -> Optional[str]:

        if len(payload) < 12:
            return None

        flags = payload[2]
        if flags & 0x80:
            return None  # Response

        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount == 0:
            return None

        offset = 12
        domain_parts = []

        while offset < len(payload):
            label_len = payload[offset]

            if label_len == 0:
                break

            if label_len > 63:
                return None

            offset += 1
            domain_parts.append(
                payload[offset:offset + label_len].decode(errors="ignore")
            )
            offset += label_len

        if not domain_parts:
            return None

        return ".".join(domain_parts)

    # ==========================================================
    # QUIC SNI (Simplified)
    # ==========================================================

    def extract_quic_sni(self, payload: bytes) -> Optional[str]:

        if len(payload) < 5:
            return None

        first_byte = payload[0]
        if (first_byte & 0x80) == 0:
            return None  # Not long header

        # Very simplified scan for ClientHello pattern
        for i in range(5, len(payload) - 50):
            if payload[i] == 0x01:  # Handshake type
                result = self.extract_tls_sni(payload[i - 5:])
                if result:
                    return result

        return None