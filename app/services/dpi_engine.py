import asyncio
from typing import Dict

from app.schema.dpi_config_schema import DPIConfig
from app.schema.packet_schema import PacketSchema
from app.schema.common_schema import IngestResponse
from app.schema.stats_schema import StatsResponse

from app.services.dispatcher_service import DispatcherService
from app.services.connection import ConnectionTracker
from app.services.rule_service import RuleService


class DPIEngine:
    """
    Python equivalent of C++ DPIEngine.
    Orchestrates dispatcher, connection tracking,
    rule evaluation and statistics.
    """

    def __init__(self, config: DPIConfig):
        self.config = config

        # Core Components
        self.dispatcher = DispatcherService(config.num_workers)
        self.connection_tracker = ConnectionTracker(fp_id=0)
        self.rule_service = RuleService()

        # Control
        self._lock = asyncio.Lock()
        self._running = False

        # Statistics
        self.stats: Dict[str, int] = {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "forwarded_packets": 0,
            "dropped_packets": 0,
        }

    # ==========================================================
    # Engine Lifecycle
    # ==========================================================

    async def start(self):
        self._running = True
        await self.dispatcher.start()

    async def stop(self):
        self._running = False
        await self.dispatcher.stop()

    def is_running(self) -> bool:
        return self._running

    # ==========================================================
    # Packet Processing
    # ==========================================================

    async def ingest_packet(self, packet: PacketSchema) -> IngestResponse:

        # ---- Update Global Stats ----
        async with self._lock:
            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += packet.size

            if packet.protocol == "TCP":
                self.stats["tcp_packets"] += 1
            elif packet.protocol == "UDP":
                self.stats["udp_packets"] += 1

        # ---- Dispatch to worker (LB + FP equivalent) ----
        action = await self.dispatcher.dispatch(packet)

        # ---- Apply Rule Check (Redis-backed) ----
        is_blocked = await self.rule_service.is_blocked(
            src_ip=packet.src_ip,
            app=packet.app,
            domain=packet.domain,
        )

        if is_blocked or action == "DROP":
            async with self._lock:
                self.stats["dropped_packets"] += 1
            return IngestResponse(status="dropped")

        async with self._lock:
            self.stats["forwarded_packets"] += 1

        return IngestResponse(status="forwarded")

    # ==========================================================
    # Rule Management APIs
    # ==========================================================

    async def block_ip(self, ip: str):
        await self.rule_service.block_ip(ip)

    async def unblock_ip(self, ip: str):
        await self.rule_service.unblock_ip(ip)

    async def block_domain(self, domain: str):
        await self.rule_service.block_domain(domain)

    async def unblock_domain(self, domain: str):
        await self.rule_service.unblock_domain(domain)

    async def block_app(self, app: str):
        await self.rule_service.block_app(app)

    async def unblock_app(self, app: str):
        await self.rule_service.unblock_app(app)

    # ==========================================================
    # Reporting
    # ==========================================================

    async def get_stats(self) -> StatsResponse:
        async with self._lock:
            return StatsResponse(**self.stats)