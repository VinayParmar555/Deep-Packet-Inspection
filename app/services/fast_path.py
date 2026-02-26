import asyncio
from typing import Callable, Dict

from app.schema.packet_schema import PacketSchema
from app.schema.connection_schema import (
    FiveTupleSchema,
    AppType
)

from app.services.connection import ConnectionTracker
from app.services.rule_service import RuleService


class FastPathProcessor:
    """
    Python equivalent of C++ FastPathProcessor.
    Each instance acts like one FP thread.
    """

    def __init__(
        self,
        fp_id: int,
        rule_service: RuleService,
        output_callback: Callable[[PacketSchema, str], None],
    ):
        self.fp_id = fp_id
        self.rule_service = rule_service
        self.output_callback = output_callback

        self.input_queue: asyncio.Queue[PacketSchema] = asyncio.Queue()
        self.conn_tracker = ConnectionTracker(fp_id=fp_id)

        self.running = False
        self.task: asyncio.Task | None = None

        # Stats
        self.stats: Dict[str, int] = {
            "processed": 0,
            "forwarded": 0,
            "dropped": 0,
            "sni_extractions": 0,
            "classification_hits": 0,
        }

    # ==================================================
    # Lifecycle
    # ==================================================

    async def start(self):
        self.running = True
        self.task = asyncio.create_task(self.run())

    async def stop(self):
        self.running = False
        if self.task:
            await self.task

    # ==================================================
    # Main Loop
    # ==================================================

    async def run(self):
        while self.running:
            packet = await self.input_queue.get()
            action = await self.process_packet(packet)

            await self.output_callback(packet, action)

            self.input_queue.task_done()

    # ==================================================
    # Core Logic
    # ==================================================

    async def process_packet(self, packet: PacketSchema) -> str:

        self.stats["processed"] += 1

        five_tuple = FiveTupleSchema(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        conn = await self.conn_tracker.get_or_create(five_tuple)

        # Example classification logic
        if packet.domain:
            await self.conn_tracker.classify(
                conn,
                AppType.HTTPS,
                packet.domain,
            )
            self.stats["classification_hits"] += 1

        # Rule check
        is_blocked = await self.rule_service.is_blocked(
            src_ip=packet.src_ip,
            app=conn.app_type.value,
            domain=packet.domain,
        )

        if is_blocked:
            await self.conn_tracker.block(conn)
            self.stats["dropped"] += 1
            return "DROP"

        await self.conn_tracker.update(
            conn,
            size=packet.size,
            outbound=packet.outbound,
        )

        self.stats["forwarded"] += 1
        return "ALLOW"