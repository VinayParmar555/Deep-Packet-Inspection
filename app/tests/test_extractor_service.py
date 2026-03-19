import pytest
from app.services.extractors_service import ExtractorService
from app.tests.conftest import build_tls_client_hello, build_dns_query


@pytest.fixture
def svc():
    return ExtractorService()


# ---------------------------------------------------------------------------
# TLS SNI extraction
# ---------------------------------------------------------------------------

class TestTLSSNI:
    def test_extracts_sni(self, svc):
        payload = build_tls_client_hello("example.com")
        assert svc.extract_tls_sni(payload) == "example.com"

    def test_extracts_long_sni(self, svc):
        payload = build_tls_client_hello("very.long.subdomain.example.co.uk")
        assert svc.extract_tls_sni(payload) == "very.long.subdomain.example.co.uk"

    def test_returns_none_for_short_payload(self, svc):
        assert svc.extract_tls_sni(b"\x16\x03\x01") is None

    def test_returns_none_for_non_tls(self, svc):
        assert svc.extract_tls_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") is None

    def test_returns_none_for_wrong_content_type(self, svc):
        # Content type 0x17 = Application Data, not Handshake
        bad = b"\x17\x03\x03" + b"\x00\x05" + b"\x01\x00\x00\x00\x00"
        assert svc.extract_tls_sni(bad) is None

    def test_returns_none_for_empty(self, svc):
        assert svc.extract_tls_sni(b"") is None


# ---------------------------------------------------------------------------
# HTTP Host extraction
# ---------------------------------------------------------------------------

class TestHTTPHost:
    def test_get_request(self, svc):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        assert svc.extract_http_host(payload) == "example.com"

    def test_post_request(self, svc):
        payload = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        assert svc.extract_http_host(payload) == "api.example.com"

    def test_strips_port(self, svc):
        payload = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        assert svc.extract_http_host(payload) == "example.com"

    def test_case_insensitive_host_header(self, svc):
        payload = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"
        assert svc.extract_http_host(payload) == "example.com"

    def test_returns_none_for_non_http(self, svc):
        assert svc.extract_http_host(b"\x16\x03\x01\x00\x00") is None

    def test_returns_none_for_short_payload(self, svc):
        assert svc.extract_http_host(b"GET") is None

    def test_returns_none_when_no_host_header(self, svc):
        payload = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"
        assert svc.extract_http_host(payload) is None


# ---------------------------------------------------------------------------
# DNS query extraction
# ---------------------------------------------------------------------------

class TestDNSQuery:
    def test_extracts_domain(self, svc):
        payload = build_dns_query("example.com")
        assert svc.extract_dns_query(payload) == "example.com"

    def test_extracts_subdomain(self, svc):
        payload = build_dns_query("api.example.com")
        assert svc.extract_dns_query(payload) == "api.example.com"

    def test_returns_none_for_short_payload(self, svc):
        assert svc.extract_dns_query(b"\x00" * 8) is None

    def test_returns_none_for_dns_response(self, svc):
        # QR bit (0x80) set in flags byte → response, not query
        import struct
        payload = struct.pack("!HHHHHH", 0x1234, 0x8100, 1, 1, 0, 0) + b"\x00"
        assert svc.extract_dns_query(payload) is None
