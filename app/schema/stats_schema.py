from pydantic import BaseModel, Field
from typing import Dict, List


class StatsResponse(BaseModel):
    total_packets: int = Field(..., json_schema_extra={"example": 10000})
    total_bytes: int = Field(..., json_schema_extra={"example": 5242880})
    tcp_packets: int = Field(..., json_schema_extra={"example": 7000})
    udp_packets: int = Field(..., json_schema_extra={"example": 3000})
    forwarded_packets: int = Field(..., json_schema_extra={"example": 9500})
    dropped_packets: int = Field(..., json_schema_extra={"example": 500})

    model_config = {"from_attributes" : True}

class AppStatsResponse(BaseModel):
    app_distribution: Dict[str, int] = Field(default_factory=dict)
    unique_domains: List[str] = Field(default_factory=list)
    active_connections: int = 0


class RateMetricsResponse(BaseModel):
    """Rate-based metrics for network traffic analysis."""
    packets_per_sec: float = Field(..., description="Packets processed per second")
    bytes_per_sec: float = Field(..., description="Bytes processed per second")
    throughput_mbps: float = Field(..., description="Throughput in Megabits per second")
    window_seconds: int = Field(..., description="Sliding window size in seconds")


class ConnectionMetricsResponse(BaseModel):
    """Per-connection performance metrics."""
    duration_seconds: float = Field(..., description="Connection lifetime in seconds")
    packets_per_sec: float = Field(..., description="Packets per second for this connection")
    throughput_bps: float = Field(..., description="Bytes per second for this connection")
    throughput_mbps: float = Field(..., description="Megabits per second for this connection")
    total_packets: int = Field(..., description="Total packets in this connection")
    total_bytes: int = Field(..., description="Total bytes in this connection")