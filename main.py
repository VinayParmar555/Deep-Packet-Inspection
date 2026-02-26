from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.schema.dpi_config_schema import DPIConfig
from app.schema.packet_schema import PacketSchema
from app.services.dpi_engine import DPIEngine

config = DPIConfig()
engine = DPIEngine(config)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await engine.start()
    yield
    # Shutdown
    await engine.stop()

app = FastAPI(
    title="DPI Backend Service",
    lifespan=lifespan
)

@app.post("/ingest")
async def ingest(packet: PacketSchema):
    return await engine.ingest_packet(packet)

@app.get("/stats")
async def stats():
    return await engine.get_stats()

@app.post("/block/ip/{ip}")
async def block_ip(ip: str):
    await engine.block_ip(ip)
    return {"message": f"{ip} blocked"}