from fastapi import APIRouter
from app.services.dpi_engine import DPIEngine
from app.schema.stats_schema import RateMetricsResponse

router = APIRouter(prefix="", tags=["Monitoring"])


def create_router(engine: DPIEngine) -> APIRouter:

    @router.get("/health", tags=["Monitoring"])
    async def health():
        return {"status": "ok"}

    @router.get("/stats")
    async def get_stats():
        return await engine.get_stats()

    @router.get("/stats/connections")
    async def get_active_connections():
        return await engine.get_active_connections()

    @router.get("/stats/apps")
    async def get_app_stats():
        return await engine.get_app_stats()

    @router.get("/stats/workers")
    async def get_worker_stats():
        return await engine.get_dispatch_stats()

    @router.get("/stats/rates", response_model=RateMetricsResponse)
    async def get_rate_metrics():
        """
        Get real-time rate metrics:
        - packets_per_sec: Average packets processed per second
        - bytes_per_sec: Average bytes processed per second  
        - throughput_mbps: Throughput in Megabits per second
        """
        return await engine.get_rate_metrics()

    @router.get("/stats/connections/metrics")
    async def get_connection_metrics():
        """
        Get per-connection performance metrics including:
        - duration, packets/sec, throughput for each active connection
        """
        return await engine.get_connection_metrics()

    return router
