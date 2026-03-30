"""
PCAP Replay Service - Replays PCAP packets through the DPI engine
for accurate real-time metrics (packets/sec, throughput, latency).
"""
import asyncio
from typing import Optional
from datetime import datetime, timezone
from app.services.pcap_reader_service import PcapReader
from app.services.packet_parser_service import PacketParser
from app.services.extractors_service import ExtractorService
from app.services.classification_service import ClassificationService
from app.services.dpi_engine import DPIEngine
from app.schema.packet_schema import PacketSchema
from app.schema.connection_schema import FiveTupleSchema, Protocol, AppType


class PcapReplayService:
    """
    Replays packets from a PCAP file through the DPI engine,
    enabling real metrics calculation.
    """

    def __init__(self, engine: DPIEngine):
        self.engine = engine
        self.parser = PacketParser()
        self.extractor = ExtractorService()
        self.classifier = ClassificationService()

    async def replay(
        self,
        pcap_path: str,
        max_packets: int = 10000,
        realtime: bool = False,
        speed_multiplier: float = 1.0,
    ) -> dict:
        """
        Replay packets from PCAP file through the DPI engine.

        Args:
            pcap_path: Path to the PCAP file
            max_packets: Maximum number of packets to process
            realtime: If True, replay with original timing; if False, replay as fast as possible
            speed_multiplier: Speed factor for realtime replay (2.0 = 2x faster)

        Returns:
            dict with replay statistics
        """
        reader = PcapReader()
        if not reader.open(pcap_path):
            raise ValueError(f"Failed to open PCAP file: {pcap_path}")

        # Reset stats before replay
        await self.engine.stats_service.reset()

        stats = {
            "total_packets": 0,
            "processed": 0,
            "skipped": 0,
            "forwarded": 0,
            "dropped": 0,
            "errors": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        first_ts: Optional[float] = None
        replay_start = asyncio.get_event_loop().time()

        try:
            while stats["total_packets"] < max_packets:
                raw = reader.read_next_packet()
                if raw is None:
                    break

                stats["total_packets"] += 1

                if raw.data is None:
                    stats["skipped"] += 1
                    continue

                # Parse raw packet
                try:
                    parsed = self.parser.parse(
                        raw.data,
                        raw.header.ts_sec,
                        raw.header.ts_usec,
                    )
                except Exception:
                    stats["errors"] += 1
                    continue

                # Skip non-IP packets
                if not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
                    stats["skipped"] += 1
                    continue

                # Skip packets with invalid ports
                if not parsed.src_port or not parsed.dest_port:
                    stats["skipped"] += 1
                    continue

                if parsed.src_port < 1 or parsed.dest_port < 1:
                    stats["skipped"] += 1
                    continue

                # Realtime replay timing
                if realtime:
                    pkt_ts = raw.header.ts_sec + raw.header.ts_usec / 1_000_000
                    if first_ts is None:
                        first_ts = pkt_ts
                    else:
                        elapsed_in_pcap = (pkt_ts - first_ts) / speed_multiplier
                        elapsed_real = asyncio.get_event_loop().time() - replay_start
                        delay = elapsed_in_pcap - elapsed_real
                        if delay > 0:
                            await asyncio.sleep(delay)

                # Extract domain from payload
                domain = None
                app_type = AppType.UNKNOWN

                if parsed.payload and len(parsed.payload) > 0:
                    if parsed.dest_port == 443:
                        domain = self.extractor.extract_tls_sni(parsed.payload)
                    elif parsed.dest_port == 80:
                        domain = self.extractor.extract_http_host(parsed.payload)
                    elif parsed.dest_port == 53 and parsed.has_udp:
                        domain = self.extractor.extract_dns_query(parsed.payload)

                # Classify application
                app_type = self.classifier.classify_packet(
                    domain=domain,
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dest_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dest_port,
                )

                # Build PacketSchema for DPI engine
                protocol = Protocol.TCP if parsed.has_tcp else Protocol.UDP

                try:
                    packet = PacketSchema(
                        tuple=FiveTupleSchema(
                            src_ip=parsed.src_ip,
                            dst_ip=parsed.dest_ip,
                            src_port=parsed.src_port,
                            dst_port=parsed.dest_port,
                            protocol=protocol,
                        ),
                        size=len(raw.data),
                        outbound=True,
                        tcp_flags=parsed.tcp_flags or 0,
                        payload_length=parsed.payload_length,
                        domain=domain,
                        app_type=app_type,
                    )

                    # Ingest into DPI engine
                    result = await self.engine.ingest_packet(packet)
                    stats["processed"] += 1

                    if result.status == "forwarded":
                        stats["forwarded"] += 1
                    else:
                        stats["dropped"] += 1

                except Exception as e:
                    stats["errors"] += 1

        finally:
            reader.close()

        stats["end_time"] = datetime.now(timezone.utc).isoformat()
        stats["duration_seconds"] = asyncio.get_event_loop().time() - replay_start

        # Get final rate metrics
        rate_metrics = await self.engine.stats_service.get_rate_metrics()
        stats["rate_metrics"] = rate_metrics

        return stats
