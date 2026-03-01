from collections import defaultdict
from app.services.rule_service import RuleService
from app.schema.packet_schema import PacketSchema


class FlowProcessorService:
    """
    Simplified DPI flow processor.
    Equivalent to working C++ simplified version.
    """

    def __init__(self):
        self.rule_service = RuleService()
        self.flows = {}  # key -> flow dict
        self.app_stats = defaultdict(int)

        self.total_packets = 0
        self.forwarded = 0
        self.dropped = 0

    async def process_packet(self, packet: PacketSchema):

        self.total_packets += 1

        key = packet.tuple.key()

        # Get or create flow
        flow = self.flows.get(key)
        if not flow:
            flow = {
                "packets": 0,
                "bytes": 0,
                "app_type": "UNKNOWN",
                "domain": "",
                "blocked": False
            }
            self.flows[key] = flow

        flow["packets"] += 1
        flow["bytes"] += packet.size

        # Classification (SNI / HTTP)
        if packet.domain and flow["domain"] == "":
            flow["domain"] = packet.domain
            flow["app_type"] = packet.app_type or "UNKNOWN"

        # Blocking
        if not flow["blocked"]:
            blocked = await self.rule_service.evaluate(packet, flow)
            flow["blocked"] = (blocked == "DROP")

        # Stats
        self.app_stats[flow["app_type"]] += 1

        if flow["blocked"]:
            self.dropped += 1
            return "DROP"

        self.forwarded += 1
        return "FORWARD"

    def generate_report(self):

        report = {
            "total_packets": self.total_packets,
            "forwarded": self.forwarded,
            "dropped": self.dropped,
            "active_flows": len(self.flows),
            "app_distribution": dict(self.app_stats),
            "unique_domains": list(
                {flow["domain"] for flow in self.flows.values() if flow["domain"]}
            )
        }

        return report