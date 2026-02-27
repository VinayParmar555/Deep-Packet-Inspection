from fastapi import APIRouter
from app.services.dpi_engine import DPIEngine

router = APIRouter(prefix="/rules", tags=["Rules"])

def create_router(engine: DPIEngine) -> APIRouter:

    # =================================================
    # 🚫 IP Rules
    # =================================================

    @router.post("/ip/{ip}", tags=["Rules - IP"])
    async def block_ip(ip: str):
        await engine.block_ip(ip)
        return {"message": f"{ip} blocked"}

    @router.delete("/ip/{ip}", tags=["Rules - IP"])
    async def unblock_ip(ip: str):
        await engine.unblock_ip(ip)
        return {"message": f"{ip} unblocked"}

    @router.get("/ip", tags=["Rules - IP"])
    async def list_blocked_ips():
        return await engine.get_blocked_ips()

    # =================================================
    # 🌐 Domain Rules
    # =================================================

    @router.post("/domain/{domain}", tags=["Rules - Domain"])
    async def block_domain(domain: str):
        await engine.block_domain(domain)
        return {"message": f"{domain} blocked"}

    @router.delete("/domain/{domain}", tags=["Rules - Domain"])
    async def unblock_domain(domain: str):
        await engine.unblock_domain(domain)
        return {"message": f"{domain} unblocked"}

    @router.get("/domain", tags=["Rules - Domain"])
    async def list_blocked_domains():
        return await engine.get_blocked_domains()

    # =================================================
    # 📱 App Rules
    # =================================================

    @router.post("/app/{app_name}", tags=["Rules - App"])
    async def block_app(app_name: str):
        await engine.block_app(app_name)
        return {"message": f"{app_name} blocked"}

    @router.delete("/app/{app_name}", tags=["Rules - App"])
    async def unblock_app(app_name: str):
        await engine.unblock_app(app_name)
        return {"message": f"{app_name} unblocked"}

    @router.get("/app", tags=["Rules - App"])
    async def list_blocked_apps():
        return await engine.get_blocked_apps()

    return router
