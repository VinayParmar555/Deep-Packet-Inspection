from pydantic import BaseModel
from typing import List, Dict, Optional


class ConnectionDetail(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    domain: Optional[str] = None
    app_type: str = "UNKNOWN"
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


class PcapAnalysisReport(BaseModel):
    # Summary
    total_packets: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    total_bytes: int = 0

    # Protocol breakdown
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0

    # App classification
    app_breakdown: Dict[str, int] = {}

    # Domains found
    domains_detected: List[str] = []

    # Blocked connections
    blocked_connections: List[ConnectionDetail] = []

    # All connections
    connections: List[ConnectionDetail] = []
