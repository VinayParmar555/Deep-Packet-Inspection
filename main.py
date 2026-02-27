from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.schema.dpi_config_schema import DPIConfig
from app.services.dpi_engine import DPIEngine
from app.cache.redis import redis_manager
from app.routes.pcap_routes import router as pcap_router
from app.routes import ingest_routes, stats_routes, rules_routes


# -------------------------------------------------
# Engine Initialization
# -------------------------------------------------

config = DPIConfig()
engine = DPIEngine(config)


# -------------------------------------------------
# Lifespan (Redis + Engine together)
# -------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await redis_manager.connect()
    await engine.start()

    yield

    # Shutdown
    await engine.stop()
    await redis_manager.disconnect()

app = FastAPI(
    title="DPI Backend Service",
    version="1.0.0",
    lifespan=lifespan,
)


# -------------------------------------------------
# Register Routers
# -------------------------------------------------

app.include_router(pcap_router)
app.include_router(ingest_routes.create_router(engine))
app.include_router(stats_routes.create_router(engine))
app.include_router(rules_routes.create_router(engine))


# -------------------------------------------------
# Root
# -------------------------------------------------

@app.get("/", tags=["Welcome"])
def root():
    return {
        "msg": "DPI Backend Service is live",
        "docs": "/docs",
    }