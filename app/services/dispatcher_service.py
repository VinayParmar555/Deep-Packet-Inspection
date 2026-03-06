from typing import List
from app.schema.packet_schema import PacketSchema
from app.services.fast_path import FastPathProcessor
from app.services.rule_service import RuleService


class DispatcherService:

    def __init__(self, num_processors: int, output_callback, queue_size: int = 10000):
        self.num_processors = num_processors
        self.rule_service = RuleService()
        self.output_callback = output_callback

        self.processors: List[FastPathProcessor] = []
        self.dispatch_counts: List[int] = [0] * num_processors
        self.dropped_count = 0

        for i in range(num_processors):
            processor = FastPathProcessor(
                fp_id=i,
                rule_service=self.rule_service,
                output_callback=self.output_callback,
                queue_size=queue_size,
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

        # Try primary worker
        success = self.processors[index].input_queue.try_push(packet)

        if success:
            self.dispatch_counts[index] += 1
            return "ALLOW"

        # Fallback: try other workers round-robin before dropping
        for i in range(1, self.num_processors):
            fallback_index = (index + i) % self.num_processors
            success = self.processors[fallback_index].input_queue.try_push(packet)

            if success:
                self.dispatch_counts[fallback_index] += 1
                return "ALLOW"

        # All queues full
        self.dropped_count += 1
        return "DROPPED"

    def _select_processor(self, packet: PacketSchema) -> int:
        key = (
            f"{packet.tuple.src_ip}:"
            f"{packet.tuple.src_port}:"
            f"{packet.tuple.dst_ip}:"
            f"{packet.tuple.dst_port}:"
            f"{packet.tuple.protocol}"
        )
        return hash(key) % self.num_processors

    def get_dispatch_stats(self) -> dict:
        worker_stats = []
        for i, processor in enumerate(self.processors):
            worker_stats.append({
                "worker_id": i,
                "dispatched": self.dispatch_counts[i],
                "queue_size": processor.input_queue.size(),
                **processor.stats,
            })
        return {
            "total_dispatched": sum(self.dispatch_counts),
            "total_dropped_backpressure": self.dropped_count,
            "workers": worker_stats,
        }
