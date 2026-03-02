import os
import tempfile
from fastapi import APIRouter, UploadFile, File
from app.schema.pcap_report_schema import PcapAnalysisReport
from app.services.pcap_processor import PcapProcessor

router = APIRouter(prefix="", tags=["PCAP Analysis"])

pcap_processor = PcapProcessor()

@router.post("/analyze", response_model=PcapAnalysisReport)
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Upload a .pcap file and get a full DPI analysis report.
    """

    tmp_file = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp_file.name

    try:
        # Stream write (memory safe)
        while chunk := await file.read(1024 * 1024):
            tmp_file.write(chunk)

        tmp_file.close()
        await file.close()

        report = await pcap_processor.analyze(tmp_path)
        return report

    finally:
        try:
            os.unlink(tmp_path)  # guaranteed cleanup
        except Exception:
            pass