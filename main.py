from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.schema.dpi_config_schema import DPIConfig
from app.schema.packet_schema import PacketSchema
from app.services.dpi_engine import DPIEngine


# -------------------------------------------------
# Engine Initialization
# -------------------------------------------------

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
    version="1.0.0",
    lifespan=lifespan
)
@app.get("/", tags=["Welcome"])
def root():
    return {
        "msg" : "DPI Backend Service is live",
        "docs" : "/docs"
    }

# =================================================
# 📥 Packet Ingestion
# =================================================

@app.post("/ingest", tags=["Packet Processing"])
async def ingest(packet: PacketSchema):
    return await engine.ingest_packet(packet)


# =================================================
# 📊 Monitoring & Stats
# =================================================

@app.get("/stats", tags=["Monitoring"])
async def get_stats():
    return await engine.get_stats()

@app.get("/stats/connections", tags=["Monitoring"])
async def get_active_connections():
    return await engine.get_active_connections()

@app.get("/stats/apps", tags=["Monitoring"])
async def get_app_stats():
    return await engine.get_app_stats()

@app.get("/health", tags=["Monitoring"])
async def health_check():
    return {"status": "healthy"}


# =================================================
# 🚫 Rule Management - IP
# =================================================

@app.post("/rules/ip/{ip}", tags=["Rules - IP"])
async def block_ip(ip: str):
    await engine.block_ip(ip)
    return {"message": f"{ip} blocked"}


@app.delete("/rules/ip/{ip}", tags=["Rules - IP"])
async def unblock_ip(ip: str):
    await engine.unblock_ip(ip)
    return {"message": f"{ip} unblocked"}


@app.get("/rules/ip", tags=["Rules - IP"])
async def list_blocked_ips():
    return await engine.get_blocked_ips()


# =================================================
# 🌐 Rule Management - Domain
# =================================================

@app.post("/rules/domain/{domain}", tags=["Rules - Domain"])
async def block_domain(domain: str):
    await engine.block_domain(domain)
    return {"message": f"{domain} blocked"}


@app.delete("/rules/domain/{domain}", tags=["Rules - Domain"])
async def unblock_domain(domain: str):
    await engine.unblock_domain(domain)
    return {"message": f"{domain} unblocked"}


@app.get("/rules/domain", tags=["Rules - Domain"])
async def list_blocked_domains():
    return await engine.get_blocked_domains()


# =================================================
# 📱 Rule Management - Application
# =================================================

@app.post("/rules/app/{app_name}", tags=["Rules - App"])
async def block_app(app_name: str):
    await engine.block_app(app_name)
    return {"message": f"{app_name} blocked"}


@app.delete("/rules/app/{app_name}", tags=["Rules - App"])
async def unblock_app(app_name: str):
    await engine.unblock_app(app_name)
    return {"message": f"{app_name} unblocked"}


@app.get("/rules/app", tags=["Rules - App"])
async def list_blocked_apps():
    return await engine.get_blocked_apps()