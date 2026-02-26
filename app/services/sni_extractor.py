import struct
from typing import Optional

class SNIExtractor:

    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    def is_tls_client_hello(self, payload: bytes) -> bool:
        if len(payload) < 9:
            return False

        if payload[0] != self.CONTENT_TYPE_HANDSHAKE:
            return False

        version = struct.unpack("!H", payload[1:3])[0]
        if version < 0x0300 or version > 0x0304:
            return False

        if payload[5] != self.HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    def extract(self, payload: bytes) -> Optional[str]:

        if not self.is_tls_client_hello(payload):
            return None

        offset = 5  # skip TLS record header

        handshake_length = int.from_bytes(payload[offset+1:offset+4], "big")
        offset += 4

        offset += 2      # client version
        offset += 32     # random

        session_id_length = payload[offset]
        offset += 1 + session_id_length

        cipher_suites_length = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2 + cipher_suites_length

        compression_length = payload[offset]
        offset += 1 + compression_length

        extensions_length = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        end = offset + extensions_length

        while offset + 4 <= end:

            ext_type, ext_length = struct.unpack(
                "!HH", payload[offset:offset+4]
            )
            offset += 4

            if ext_type == self.EXTENSION_SNI:
                sni_list_length = struct.unpack("!H", payload[offset:offset+2])[0]

                sni_type = payload[offset+2]
                sni_length = struct.unpack(
                    "!H", payload[offset+3:offset+5]
                )[0]

                if sni_type != self.SNI_TYPE_HOSTNAME:
                    return None

                start = offset + 5
                end_sni = start + sni_length

                return payload[start:end_sni].decode(errors="ignore")

            offset += ext_length

        return None
    
class HTTPHostExtractor:

    def is_http_request(self, payload: bytes) -> bool:
        return payload.startswith(
            (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
        )

    def extract(self, payload: bytes) -> Optional[str]:
        if not self.is_http_request(payload):
            return None

        lines = payload.split(b"\r\n")

        for line in lines:
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip()
                return host.decode(errors="ignore")

        return None
    
class DNSExtractor:

    def is_dns_query(self, payload: bytes) -> bool:
        if len(payload) < 12:
            return False

        flags = payload[2]
        if flags & 0x80:  # response
            return False

        qdcount = struct.unpack("!H", payload[4:6])[0]
        return qdcount > 0

    def extract_query(self, payload: bytes) -> Optional[str]:
        if not self.is_dns_query(payload):
            return None

        offset = 12
        domain = []

        while offset < len(payload):
            length = payload[offset]

            if length == 0:
                break

            offset += 1
            label = payload[offset:offset+length]
            domain.append(label.decode(errors="ignore"))
            offset += length

        if domain:
            return ".".join(domain)

        return None
    
class QUICSNIExtractor:

    def is_quic_initial(self, payload: bytes) -> bool:
        if len(payload) < 5:
            return False

        first_byte = payload[0]
        return (first_byte & 0x80) != 0

    def extract(self, payload: bytes) -> Optional[str]:
        # Simplified heuristic
        for i in range(len(payload) - 50):
            if payload[i] == 0x01:
                tls = SNIExtractor()
                return tls.extract(payload[i-5:])
        return None