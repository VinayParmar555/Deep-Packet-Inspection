from typing import Optional
from app.cache.redis import redis_client
from app.schema.rule_schema import BlockReasonSchema, BlockType


class RuleService:

    # ==============================
    # IP Rules
    # ==============================

    async def block_ip(self, ip: str):
        await redis_client.sadd("blocked:ips", ip)

    async def unblock_ip(self, ip: str):
        await redis_client.srem("blocked:ips", ip)

    async def is_ip_blocked(self, ip: str) -> bool:
        return await redis_client.sismember("blocked:ips", ip)

    # ==============================
    # App Rules
    # ==============================

    async def block_app(self, app: str):
        await redis_client.sadd("blocked:apps", app)

    async def unblock_app(self, app: str):
        await redis_client.srem("blocked:apps", app)

    async def is_app_blocked(self, app: str) -> bool:
        return await redis_client.sismember("blocked:apps", app)

    # ==============================
    # Domain Rules (supports wildcard)
    # ==============================

    async def block_domain(self, domain: str):
        await redis_client.sadd("blocked:domains", domain.lower())

    async def unblock_domain(self, domain: str):
        await redis_client.srem("blocked:domains", domain.lower())

    async def is_domain_blocked(self, domain: str) -> bool:
        domain = domain.lower()
        blocked = await redis_client.smembers("blocked:domains")

        for rule in blocked:
            if rule.startswith("*."):
                if domain.endswith(rule[1:]):
                    return True
            elif rule == domain:
                return True

        return False

    # ==============================
    # Port Rules
    # ==============================

    async def block_port(self, port: int):
        await redis_client.sadd("blocked:ports", port)

    async def unblock_port(self, port: int):
        await redis_client.srem("blocked:ports", port)

    async def is_port_blocked(self, port: int) -> bool:
        return await redis_client.sismember("blocked:ports", port)

    # ==============================
    # Combined Rule Check
    # ==============================

    async def should_block(
        self,
        src_ip: str,
        dst_port: int,
        app: str,
        domain: str | None,
    ) -> Optional[BlockReasonSchema]:

        if await self.is_ip_blocked(src_ip):
            return BlockReasonSchema(type=BlockType.IP, detail=src_ip)

        if await self.is_port_blocked(dst_port):
            return BlockReasonSchema(type=BlockType.PORT, detail=str(dst_port))

        if await self.is_app_blocked(app):
            return BlockReasonSchema(type=BlockType.APP, detail=app)

        if domain and await self.is_domain_blocked(domain):
            return BlockReasonSchema(type=BlockType.DOMAIN, detail=domain)

        return None