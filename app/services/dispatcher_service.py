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
        key = f"{packet.tuple.src_ip}:{packet.tuple.src_port}:{packet.tuple.dst_ip}:{packet.tuple.dst_port}"
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)
        return hash_value % self.num_processors