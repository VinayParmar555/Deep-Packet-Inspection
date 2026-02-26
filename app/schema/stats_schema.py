from pydantic import BaseModel, Field


class StatsResponse(BaseModel):
    total_packets: int = Field(..., example=10000)
    total_bytes: int = Field(..., example=5242880)

    tcp_packets: int = Field(..., example=7000)
    udp_packets: int = Field(..., example=3000)

    forwarded_packets: int = Field(..., example=9500)
    dropped_packets: int = Field(..., example=500)

    class Config:
        from_attributes = True