from fastapi import APIRouter
from app.services.dpi_engine import DPIEngine

router = APIRouter(prefix="", tags=["Monitoring"])


def create_router(engine: DPIEngine) -> APIRouter:

    @router.get("/stats")
    async def get_stats():
        return await engine.get_stats()

    @router.get("/stats/connections")
    async def get_active_connections():
        return await engine.get_active_connections()

    @router.get("/stats/apps")
    async def get_app_stats():
        return await engine.get_stats()

    return router
