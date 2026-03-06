from typing import Callable, Dict

from app.schema.packet_schema import PacketSchema
from app.schema.connection_schema import (
    ConnectionState,
    AppType,
    Protocol,
)
from app.services.connection import ConnectionTracker
from app.services.rule_service import RuleService
from app.utils.thread_safe_queue import AsyncQueue


# TCP flag constants
SYN = 0x02
ACK = 0x10
FIN = 0x01
RST = 0x04


class FastPathProcessor:
    """
    Per-worker packet processor with flow tracking,
    TCP state machine, classification, and rule checking.
    """

    def __init__(
        self,
        fp_id: int,
        rule_service: RuleService,
        output_callback: Callable[[PacketSchema, str], None],
        queue_size: int = 10000,
    ):
        self.fp_id = fp_id
        self.rule_service = rule_service
        self.output_callback = output_callback

        self.input_queue: AsyncQueue[PacketSchema] = AsyncQueue(max_size=queue_size)
        self.conn_tracker = ConnectionTracker(fp_id=fp_id)

        self.task = None

        self.stats: Dict[str, int] = {
            "processed": 0,
            "forwarded": 0,
            "dropped": 0,
            "classification_hits": 0,
        }

    # ==================================================
    # Lifecycle
    # ==================================================

    async def start(self):
        if not self.task or self.task.done():
            self.task = __import__("asyncio").get_event_loop().create_task(self.run())

    async def stop(self):
        self.input_queue.shutdown()
        if self.task:
            try:
                await self.task
            except Exception:
                pass
            self.task = None

    # ==================================================
    # Main Loop
    # ==================================================

    async def run(self):
        while not self.input_queue.is_shutdown():
            packet = await self.input_queue.pop_with_timeout(0.5)
            if packet is None:
                continue

            action = await self.process_packet(packet)
            await self.output_callback(packet, action)

        # Drain remaining packets on shutdown
        while not self.input_queue.empty():
            packet = await self.input_queue.pop()
            if packet is None:
                break
            action = await self.process_packet(packet)
            await self.output_callback(packet, action)

    # ==================================================
    # Core Logic
    # ==================================================

    async def process_packet(self, packet: PacketSchema) -> str:
        self.stats["processed"] += 1
        t = packet.tuple

        # 1. Get or create connection
        conn = await self.conn_tracker.get_or_create(t)

        # 2. Update connection stats
        await self.conn_tracker.update(conn, size=packet.size, outbound=packet.outbound)

        # 3. TCP state tracking
        if t.protocol == Protocol.TCP and packet.tcp_flags:
            await self._update_tcp_state(conn, packet.tcp_flags)

        # 4. Early exit if already blocked
        if conn.state == ConnectionState.BLOCKED:
            self.stats["dropped"] += 1
            return "DROP"

        # 5. Classification (only if not yet classified)
        if conn.state != ConnectionState.CLASSIFIED and packet.domain:
            app = packet.app_type if packet.app_type and packet.app_type != AppType.UNKNOWN else AppType.HTTPS
            await self.conn_tracker.classify(conn, app, packet.domain)
            self.stats["classification_hits"] += 1

        # 6. Rule check
        block_reason = await self.rule_service.should_block(
            src_ip=t.src_ip,
            dst_port=t.dst_port,
            app=conn.app_type.value if conn.app_type else "UNKNOWN",
            domain=packet.domain,
        )

        if block_reason:
            await self.conn_tracker.block(conn)
            self.stats["dropped"] += 1
            return "DROP"

        self.stats["forwarded"] += 1
        return "ALLOW"

    # ==================================================
    # TCP State Machine
    # ==================================================

    async def _update_tcp_state(self, conn, tcp_flags: int):
        state = conn.tcp_state or "NEW"

        if tcp_flags & RST:
            state = "CLOSED"
        elif tcp_flags & FIN:
            state = "CLOSED"
        elif tcp_flags & SYN:
            state = "SYN_SENT"
        elif tcp_flags & ACK and state == "SYN_SENT":
            state = "ESTABLISHED"

        await self.conn_tracker.update_tcp_state(conn, state)
