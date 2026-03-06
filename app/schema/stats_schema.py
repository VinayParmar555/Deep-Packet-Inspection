from pydantic import BaseModel, Field
from typing import Dict, List


class StatsResponse(BaseModel):
    total_packets: int = Field(..., example=10000)
    total_bytes: int = Field(..., example=5242880)

    tcp_packets: int = Field(..., example=7000)
    udp_packets: int = Field(..., example=3000)

    forwarded_packets: int = Field(..., example=9500)
    dropped_packets: int = Field(..., example=500)

    class Config:
        from_attributes = True


class AppStatsResponse(BaseModel):
    app_distribution: Dict[str, int] = Field(default_factory=dict)
    unique_domains: List[str] = Field(default_factory=list)
    active_connections: int = 0