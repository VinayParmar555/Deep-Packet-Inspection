import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from app.services.pcap_processor import PcapProcessor


def make_raw_packet(data=None, ts_sec=1000, ts_usec=0, has_data=True):
    raw = MagicMock()
    raw.data            = data if data is not None else (b'\x00' * 60 if has_data else None)
    raw.header.ts_sec   = ts_sec
    raw.header.ts_usec  = ts_usec
    raw.header.incl_len = len(raw.data) if raw.data else 0
    return raw


def make_parsed_packet(
    has_ip=True, has_tcp=True, has_udp=False,
    src_ip="192.168.1.1", dest_ip="8.8.8.8",
    src_port=1234, dest_port=80,
    payload=None,
):
    parsed = MagicMock()
    parsed.has_ip    = has_ip
    parsed.has_tcp   = has_tcp
    parsed.has_udp   = has_udp
    parsed.src_ip    = src_ip
    parsed.dest_ip   = dest_ip
    parsed.src_port  = src_port
    parsed.dest_port = dest_port
    parsed.payload   = payload or b'\x00' * 20
    return parsed


def make_processor():
    with patch("app.services.pcap_processor.RuleService"):
        proc = PcapProcessor()
    proc.parser     = MagicMock()
    proc.extractor  = MagicMock()
    proc.classifier = MagicMock()
    proc.rule_service = AsyncMock()

    proc.extractor.extract_tls_sni.return_value = None
    proc.extractor.extract_http_host.return_value = None
    proc.extractor.extract_dns_query.return_value = None
    proc.classifier.sni_to_app.return_value = MagicMock(value="UNKNOWN")

    return proc


class TestPcapProcessor:

    # ── analyze — file open failure ───────

    @pytest.mark.asyncio
    async def test_analyze_raises_on_bad_file(self):
        proc = make_processor()
        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = False
            MockReader.return_value = mock_reader

            with pytest.raises(ValueError, match="Failed to open"):
                await proc.analyze("/bad/path.pcap")

    # ── analyze — empty file ──────────────

    @pytest.mark.asyncio
    async def test_analyze_empty_file(self):
        proc = make_processor()
        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value    = True
            mock_reader.read_next_packet.return_value = None
            MockReader.return_value = mock_reader

            report = await proc.analyze("/empty.pcap")

        assert report.total_packets == 0
        assert report.forwarded_packets == 0
        assert report.dropped_packets == 0
        mock_reader.close.assert_called_once()

    # ── analyze — TCP packet forwarded ────

    @pytest.mark.asyncio
    async def test_analyze_tcp_packet_forwarded(self):
        proc = make_processor()
        parsed = make_parsed_packet(has_tcp=True, dest_port=80)
        proc.parser.parse.return_value = parsed
        proc.extractor.extract_http_host.return_value = "example.com"
        proc.classifier.sni_to_app.return_value = MagicMock(value="HTTP")
        proc.rule_service.should_block.return_value = None

        raw = make_raw_packet()

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.total_packets    == 1
        assert report.tcp_packets      == 1
        assert report.forwarded_packets == 1
        assert report.dropped_packets  == 0

    # ── analyze — UDP packet ──────────────

    @pytest.mark.asyncio
    async def test_analyze_udp_packet(self):
        proc = make_processor()
        parsed = make_parsed_packet(has_tcp=False, has_udp=True, dest_port=53)
        proc.parser.parse.return_value = parsed
        proc.extractor.extract_dns_query.return_value = "google.com"
        proc.classifier.sni_to_app.return_value = MagicMock(value="DNS")
        proc.rule_service.should_block.return_value = None

        raw = make_raw_packet()

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.udp_packets == 1

    # ── analyze — packet blocked ──────────

    @pytest.mark.asyncio
    async def test_analyze_packet_blocked(self):
        proc = make_processor()
        parsed = make_parsed_packet()
        proc.parser.parse.return_value = parsed
        proc.extractor.extract_http_host.return_value = None
        proc.rule_service.should_block.return_value = MagicMock()  # blocked!

        raw = make_raw_packet()

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.dropped_packets  == 1
        assert report.forwarded_packets == 0
        assert len(report.blocked_connections) == 1

    # ── analyze — parse exception ─────────

    @pytest.mark.asyncio
    async def test_analyze_parse_exception(self):
        proc = make_processor()
        proc.parser.parse.side_effect = Exception("bad packet")

        raw = make_raw_packet()

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.other_packets == 1

    # ── analyze — no IP ───────────────────

    @pytest.mark.asyncio
    async def test_analyze_non_ip_packet(self):
        proc = make_processor()
        parsed = make_parsed_packet(has_ip=False, has_tcp=False, has_udp=False)
        proc.parser.parse.return_value = parsed

        raw = make_raw_packet()

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.other_packets   == 1
        assert report.total_packets   == 1
        assert len(report.connections) == 0

    # ── analyze — raw.data None ───────────

    @pytest.mark.asyncio
    async def test_analyze_raw_data_none(self):
        proc = make_processor()
        raw = make_raw_packet(has_data=False)
        raw.data = None

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.total_packets  == 0
        assert report.other_packets  == 1

    # ── analyze — HTTPS SNI extraction ────

    @pytest.mark.asyncio
    async def test_analyze_https_sni_extracted(self):
        proc = make_processor()
        parsed = make_parsed_packet(dest_port=443)
        proc.parser.parse.return_value = parsed
        proc.extractor.extract_tls_sni.return_value = "youtube.com"
        proc.classifier.sni_to_app.return_value = MagicMock(value="YOUTUBE")
        proc.rule_service.should_block.return_value = None

        raw = make_raw_packet()

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = [raw, None]
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert "youtube.com" in report.domains_detected

    # ── analyze — max packets limit ───────

    @pytest.mark.asyncio
    async def test_analyze_max_packets_limit(self):
        proc = make_processor()
        parsed = make_parsed_packet()
        proc.parser.parse.return_value = parsed
        proc.rule_service.should_block.return_value = None

        # 1002 packets — should stop at 1000
        raws = [make_raw_packet() for _ in range(1002)] + [None]

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = raws
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert report.total_packets <= 1000

    # ── analyze — multiple packets flow ───

    @pytest.mark.asyncio
    async def test_analyze_same_flow_grouped(self):
        proc = make_processor()
        parsed = make_parsed_packet(
            src_ip="10.0.0.1", dest_ip="10.0.0.2",
            src_port=5000, dest_port=80,
        )
        proc.parser.parse.return_value = parsed
        proc.rule_service.should_block.return_value = None

        raws = [make_raw_packet() for _ in range(3)] + [None]

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = raws
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        # 3 packets same flow → 1 connection
        assert len(report.connections) == 1
        assert report.connections[0].packets == 3

    # ── analyze — app breakdown ───────────

    @pytest.mark.asyncio
    async def test_analyze_app_breakdown(self):
        proc = make_processor()
        parsed = make_parsed_packet(dest_port=443)
        proc.parser.parse.return_value = parsed
        proc.extractor.extract_tls_sni.return_value = "youtube.com"
        proc.classifier.sni_to_app.return_value = MagicMock(value="YOUTUBE")
        proc.rule_service.should_block.return_value = None

        raws = [make_raw_packet(), make_raw_packet(), None]

        with patch("app.services.pcap_processor.PcapReader") as MockReader:
            mock_reader = MagicMock()
            mock_reader.open.return_value = True
            mock_reader.read_next_packet.side_effect = raws
            MockReader.return_value = mock_reader

            report = await proc.analyze("/test.pcap")

        assert "YOUTUBE" in report.app_breakdown
        assert report.app_breakdown["YOUTUBE"] == 2
