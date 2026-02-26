from fastapi import APIRouter, Depends
from app.schemas.packet_schema import PacketSchema
from app.services.dpi_engine import DPIEngine

router = APIRouter()
engine = DPIEngine(num_workers=4)

@router.post("/ingest")
async def ingest(packet: PacketSchema):
    await engine.ingest(packet)
    return {"status": "queued"}

@router.get("/stats")
async def stats():
    return await engine.get_stats()