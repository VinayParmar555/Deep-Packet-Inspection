import os
import tempfile
from typing import Dict, Tuple

from app.services.pcap_reader_service import PcapReader
from app.services.packet_parser_service import PacketParser
from app.services.extractors_service import ExtractorService
from app.services.classification_service import ClassificationService
from app.services.rule_service import RuleService
from app.schema.pcap_report_schema import PcapAnalysisReport, ConnectionDetail


class PcapProcessor:
    """
    Wires together the full DPI pipeline:
    PcapReader → PacketParser → ExtractorService → ClassificationService → RuleService

    This is the Python equivalent of main_working.cpp — reads a .pcap file,
    parses every packet, extracts domains, classifies apps, and checks rules.
    """

    def __init__(self):
        self.parser = PacketParser()
        self.extractor = ExtractorService()
        self.classifier = ClassificationService()
        self.rule_service = RuleService()

    async def analyze(self, pcap_path: str) -> PcapAnalysisReport:
        """
        Analyze a .pcap file and return a full DPI report.
        """

        reader = PcapReader()
        if not reader.open(pcap_path):
            raise ValueError(f"Failed to open PCAP file: {pcap_path}")

        # Flow table: (src_ip, dst_ip, src_port, dst_port, protocol) → ConnectionDetail
        flows: Dict[Tuple, ConnectionDetail] = {}

        # Stats
        total_packets = 0
        tcp_packets = 0
        udp_packets = 0
        other_packets = 0
        total_bytes = 0
        forwarded = 0
        dropped = 0
        domains_detected = set()
        app_breakdown: Dict[str, int] = {}

        # ---- Process each packet ----
        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            total_packets += 1
            total_bytes += len(raw.data)

            # Step 1: Parse protocol headers
            try:
                parsed = self.parser.parse(
                    raw.data,
                    raw.header.ts_sec,
                    raw.header.ts_usec,
                )
            except Exception:
                other_packets += 1
                continue

            # Count protocols
            if parsed.has_tcp:
                tcp_packets += 1
            elif parsed.has_udp:
                udp_packets += 1
            else:
                other_packets += 1

            if not parsed.has_ip:
                forwarded += 1
                continue

            # Step 2: Build flow key
            protocol_str = "TCP" if parsed.has_tcp else ("UDP" if parsed.has_udp else "OTHER")
            flow_key = (
                parsed.src_ip,
                parsed.dest_ip,
                parsed.src_port or 0,
                parsed.dest_port or 0,
                protocol_str,
            )

            # Step 3: Get or create flow
            if flow_key not in flows:
                flows[flow_key] = ConnectionDetail(
                    src_ip=parsed.src_ip or "0.0.0.0",
                    dst_ip=parsed.dest_ip or "0.0.0.0",
                    src_port=parsed.src_port or 0,
                    dst_port=parsed.dest_port or 0,
                    protocol=protocol_str,
                )

            flow = flows[flow_key]
            flow.packets += 1
            flow.bytes += len(raw.data)

            # Step 4: Extract domain (SNI / HTTP Host / DNS)
            if parsed.payload and len(parsed.payload) > 0:
                domain = None

                # Try TLS SNI (HTTPS, port 443)
                if parsed.dest_port == 443:
                    domain = self.extractor.extract_tls_sni(parsed.payload)

                # Try HTTP Host (port 80)
                if not domain and parsed.dest_port == 80:
                    domain = self.extractor.extract_http_host(parsed.payload)

                # Try DNS (port 53, UDP)
                if not domain and parsed.dest_port == 53 and parsed.has_udp:
                    domain = self.extractor.extract_dns_query(parsed.payload)

                if domain:
                    flow.domain = domain
                    domains_detected.add(domain)

            # Step 5: Classify app
            if flow.domain and flow.app_type == "UNKNOWN":
                app_type = self.classifier.sni_to_app(flow.domain)
                flow.app_type = app_type.value

            # Step 6: Check blocking rules
            block_reason = await self.rule_service.should_block(
                src_ip=flow.src_ip,
                dst_port=flow.dst_port,
                app=flow.app_type,
                domain=flow.domain,
            )

            if block_reason:
                flow.blocked = True
                dropped += 1
            else:
                forwarded += 1

        reader.close()

        # ---- Build app breakdown ----
        for flow in flows.values():
            app = flow.app_type
            app_breakdown[app] = app_breakdown.get(app, 0) + flow.packets

        # ---- Build report ----
        all_connections = list(flows.values())
        blocked_connections = [c for c in all_connections if c.blocked]

        return PcapAnalysisReport(
            total_packets=total_packets,
            forwarded_packets=forwarded,
            dropped_packets=dropped,
            total_bytes=total_bytes,
            tcp_packets=tcp_packets,
            udp_packets=udp_packets,
            other_packets=other_packets,
            app_breakdown=app_breakdown,
            domains_detected=sorted(domains_detected),
            blocked_connections=blocked_connections,
            connections=all_connections,
        )
