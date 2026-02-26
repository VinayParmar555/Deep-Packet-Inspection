from app.services.connection import ConnectionTracker
from app.services.rule_service import RuleService
from app.schema.packet_schema import PacketSchema

class FastPathService:
    """
    Handles per-packet processing:
    - Flow tracking
    - Classification
    - TCP state updates
    - Rule checking
    """

    def __init__(self, fp_id: int):
        self.fp_id = fp_id
        self.connection_tracker = ConnectionTracker(fp_id=fp_id)
        self.rule_engine = RuleService()

    # -------------------------------------------------
    # Main Processing
    # -------------------------------------------------

    async def process_packet(self, packet: PacketSchema) -> str:

        # 1️⃣ Get or create connection
        conn = await self.connection_tracker.get_or_create(packet.tuple)

        # 2️⃣ Update connection stats
        await self.connection_tracker.update(
            conn,
            packet.size,
            packet.outbound
        )

        # 3️⃣ TCP state tracking
        if packet.protocol == "TCP":
            await self._update_tcp_state(conn, packet.tcp_flags)

        # 4️⃣ If already blocked → drop
        if conn.get("state") == "BLOCKED":
            return "DROP"

        # 5️⃣ Try classification if not yet classified
        if not conn.get("classified") and packet.payload_length > 0:
            await self._inspect_payload(packet, conn)

        # 6️⃣ Rule check
        action = await self.rule_engine.evaluate(packet, conn)

        if action == "DROP":
            await self.connection_tracker.block(conn)
            return "DROP"

        return "FORWARD"

    # -------------------------------------------------
    # Payload Inspection
    # -------------------------------------------------

    async def _inspect_payload(self, packet: PacketSchema, conn: dict):

        # HTTPS SNI (simplified)
        if packet.tuple.dst_port == 443 and packet.domain:
            await self.connection_tracker.classify(
                conn,
                app="HTTPS",
                domain=packet.domain
            )
            return

        # HTTP Host
        if packet.tuple.dst_port == 80 and packet.domain:
            await self.connection_tracker.classify(
                conn,
                app="HTTP",
                domain=packet.domain
            )
            return

        # DNS
        if packet.tuple.dst_port == 53:
            await self.connection_tracker.classify(
                conn,
                app="DNS",
                domain=packet.domain or ""
            )

    # -------------------------------------------------
    # TCP State Tracking
    # -------------------------------------------------

    async def _update_tcp_state(self, conn: dict, tcp_flags: int):

        SYN = 0x02
        ACK = 0x10
        FIN = 0x01
        RST = 0x04

        state = conn.get("tcp_state", "NEW")

        if tcp_flags & RST:
            state = "CLOSED"

        elif tcp_flags & FIN:
            state = "CLOSED"

        elif tcp_flags & SYN:
            state = "SYN_SENT"

        elif tcp_flags & ACK and state == "SYN_SENT":
            state = "ESTABLISHED"

        await self.connection_tracker.update_tcp_state(conn, state)