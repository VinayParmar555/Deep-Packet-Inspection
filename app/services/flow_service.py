from datetime import datetime
from app.core.redis import redis_client


class FlowService:

    def _key(self, tuple_obj):
        return f"flow:{tuple_obj.key()}"

    async def get_or_create(self, tuple_obj):
        key = self._key(tuple_obj)
        flow = await redis_client.hgetall(key)

        if flow:
            return flow

        flow = {
            "src_ip": tuple_obj.src_ip,
            "dst_ip": tuple_obj.dst_ip,
            "src_port": tuple_obj.src_port,
            "dst_port": tuple_obj.dst_port,
            "protocol": tuple_obj.protocol,
            "packets": 0,
            "bytes": 0,
            "app_type": "UNKNOWN",
            "domain": "",
            "classified": False,
        }

        await redis_client.hset(key, mapping=flow)
        await redis_client.expire(key, 3600)
        return flow

    async def update(self, flow, packet):
        key = f"flow:{packet.tuple.key()}"
        await redis_client.hincrby(key, "packets", 1)
        await redis_client.hincrby(key, "bytes", packet.size)

    async def classify(self, flow, packet):
        # simplified classification logic
        if packet.tuple.dst_port == 443:
            await redis_client.hset(
                f"flow:{packet.tuple.key()}",
                mapping={"app_type": "HTTPS"}
            )
        elif packet.tuple.dst_port == 80:
            await redis_client.hset(
                f"flow:{packet.tuple.key()}",
                mapping={"app_type": "HTTP"}
            )