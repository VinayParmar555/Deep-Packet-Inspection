from fastapi import APIRouter
from app.schema.packet_schema import PacketSchema
from app.services.dpi_engine import DPIEngine

router = APIRouter(prefix="", tags=["Packet Processing"])


def create_router(engine: DPIEngine) -> APIRouter:

    @router.post("/ingest")
    async def ingest(packet: PacketSchema):
        return await engine.ingest_packet(packet)

    return router
