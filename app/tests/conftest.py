import struct
import pytest


# ---------------------------------------------------------------------------
# TLS ClientHello builder for SNI tests
# ---------------------------------------------------------------------------

def build_tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 ClientHello with a single SNI extension."""
    sni_bytes = sni.encode()
    sni_name_len = len(sni_bytes)

    # SNI extension data (after type+length header)
    sni_ext_data = (
        struct.pack("!H", sni_name_len + 3)  # server_name_list_length
        + b"\x00"                             # name_type: host_name
        + struct.pack("!H", sni_name_len)     # name_length
        + sni_bytes
    )
    sni_extension = (
        b"\x00\x00"                           # extension_type: SNI
        + struct.pack("!H", len(sni_ext_data))
        + sni_ext_data
    )

    extensions = sni_extension
    client_hello_body = (
        b"\x03\x03"                           # client_version: TLS 1.2
        + b"\x00" * 32                        # random
        + b"\x00"                             # session_id_length: 0
        + b"\x00\x02"                         # cipher_suites_length: 2
        + b"\xc0\x2b"                         # one cipher suite
        + b"\x01"                             # compression_methods_length: 1
        + b"\x00"                             # null compression
        + struct.pack("!H", len(extensions))
        + extensions
    )

    handshake = (
        b"\x01"                               # handshake_type: ClientHello
        + struct.pack("!I", len(client_hello_body))[1:]  # 3-byte length
        + client_hello_body
    )

    record = (
        b"\x16"                               # content_type: Handshake
        + b"\x03\x01"                         # version: TLS 1.0
        + struct.pack("!H", len(handshake))
        + handshake
    )
    return record


# ---------------------------------------------------------------------------
# DNS query builder for extractor tests
# ---------------------------------------------------------------------------

def build_dns_query(domain: str) -> bytes:
    """Build a minimal DNS wire-format query for the given domain."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"                      # end of QNAME
    question += struct.pack("!HH", 1, 1)     # QTYPE=A, QCLASS=IN
    return header + question


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def extractor():
    from app.services.extractors_service import ExtractorService
    return ExtractorService()


@pytest.fixture
def classifier():
    from app.services.classification_service import ClassificationService
    return ClassificationService()
