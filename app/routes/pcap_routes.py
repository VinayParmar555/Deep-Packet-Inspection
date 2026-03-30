import os
import tempfile
from fastapi import APIRouter, UploadFile, File, Query
from app.schema.pcap_report_schema import PcapAnalysisReport
from app.services.pcap_processor import PcapProcessor
from app.services.pcap_replay_service import PcapReplayService
from app.services.dpi_engine import DPIEngine

router = APIRouter(prefix="", tags=["PCAP Analysis"])

pcap_processor = PcapProcessor()


def create_router(engine: DPIEngine) -> APIRouter:
    replay_service = PcapReplayService(engine)

    @router.post("/analyze", response_model=PcapAnalysisReport)
    async def analyze_pcap(file: UploadFile = File(...)):
        """
        Upload a .pcap file and get a full DPI analysis report.
        """
        tmp_file = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp_path = tmp_file.name

        try:
            while chunk := await file.read(1024 * 1024):
                tmp_file.write(chunk)

            tmp_file.close()
            await file.close()

            report = await pcap_processor.analyze(tmp_path)
            return report

        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    @router.post("/replay")
    async def replay_pcap(
        file: UploadFile = File(...),
        max_packets: int = Query(10000, ge=1, le=100000),
        realtime: bool = Query(False, description="Replay with original timing"),
        speed: float = Query(1.0, ge=0.1, le=100.0, description="Speed multiplier for realtime replay"),
    ):
        """
        Replay a PCAP file through the DPI engine for real-time metrics.
        
        - **max_packets**: Maximum packets to process (default: 10000)
        - **realtime**: If true, replay with original timing delays
        - **speed**: Speed multiplier (2.0 = 2x faster, only used if realtime=true)
        
        Returns replay statistics and rate metrics (packets/sec, throughput).
        """
        tmp_file = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp_path = tmp_file.name

        try:
            while chunk := await file.read(1024 * 1024):
                tmp_file.write(chunk)

            tmp_file.close()
            await file.close()

            result = await replay_service.replay(
                pcap_path=tmp_path,
                max_packets=max_packets,
                realtime=realtime,
                speed_multiplier=speed,
            )
            return result

        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    return router