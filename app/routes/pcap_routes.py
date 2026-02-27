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

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = os.path.join(tmp_dir, file.filename or "upload.pcap")

        # Stream write (memory safe)
        with open(tmp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)

        # IMPORTANT: close upload file manually
        await file.close()

        report = await pcap_processor.analyze(tmp_path)

        return report