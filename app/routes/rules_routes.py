import ipaddress
import re
from fastapi import APIRouter, HTTPException
from app.services.dpi_engine import DPIEngine
from app.schema.connection_schema import AppType

router = APIRouter(prefix="/rules", tags=["Rules"])

_DOMAIN_RE = re.compile(r"^(\*\.)?(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")

def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: '{ip}'")

def _validate_domain(domain: str) -> str:
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=422, detail=f"Invalid domain format: '{domain}'")
    return domain.lower()

def _validate_app(app_name: str) -> str:
    valid = {a.value for a in AppType}
    if app_name.upper() not in valid:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown app '{app_name}'. Valid values: {sorted(valid)}",
        )
    return app_name.upper()

def create_router(engine: DPIEngine) -> APIRouter:

    # =================================================
    # 🚫 IP Rules
    # =================================================

    @router.post("/ip/{ip}", tags=["Rules - IP"])
    async def block_ip(ip: str):
        ip = _validate_ip(ip)
        await engine.block_ip(ip)
        return {"message": f"{ip} blocked"}

    @router.delete("/ip/{ip}", tags=["Rules - IP"])
    async def unblock_ip(ip: str):
        ip = _validate_ip(ip)
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
        domain = _validate_domain(domain)
        await engine.block_domain(domain)
        return {"message": f"{domain} blocked"}

    @router.delete("/domain/{domain}", tags=["Rules - Domain"])
    async def unblock_domain(domain: str):
        domain = _validate_domain(domain)
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
        app_name = _validate_app(app_name)
        await engine.block_app(app_name)
        return {"message": f"{app_name} blocked"}

    @router.delete("/app/{app_name}", tags=["Rules - App"])
    async def unblock_app(app_name: str):
        app_name = _validate_app(app_name)
        await engine.unblock_app(app_name)
        return {"message": f"{app_name} unblocked"}

    @router.get("/app", tags=["Rules - App"])
    async def list_blocked_apps():
        return await engine.get_blocked_apps()

    return router
