import hashlib
from typing import List

from app.schema.packet_schema import PacketSchema
from app.services.fast_path import FastPathProcessor
from app.services.rule_service import RuleService


class DispatcherService:
    """
    Python equivalent of FPManager + LoadBalancer.
    """

    def __init__(self, num_processors: int):
        self.num_processors = num_processors
        self.rule_service = RuleService()

        self.processors: List[FastPathProcessor] = []

        for i in range(num_processors):
            processor = FastPathProcessor(
                fp_id=i,
                rule_service=self.rule_service,
                output_callback=self.handle_output,
            )
            self.processors.append(processor)

    async def start(self):
        for processor in self.processors:
            await processor.start()

    async def stop(self):
        for processor in self.processors:
            await processor.stop()

    async def dispatch(self, packet: PacketSchema) -> str:
        index = self._select_processor(packet)
        await self.processors[index].input_queue.put(packet)
        return "ALLOW"

    def _select_processor(self, packet: PacketSchema) -> int:
        key = f"{packet.src_ip}:{packet.src_port}:{packet.dst_ip}:{packet.dst_port}"
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)
        return hash_value % self.num_processors

    async def handle_output(self, packet: PacketSchema, action: str):
        # For now, just pass
        # Can integrate Kafka / file writer here
        pass