from pydantic import BaseModel
from typing import Optional
from app.schema.connection_schema import FiveTupleSchema

class PacketSchema(BaseModel):
    tuple: FiveTupleSchema
    size: int
    outbound: bool = True
    tcp_flags: Optional[int] = 0
    payload_length: Optional[int] = 0
    domain: Optional[str] = None
    app_type: Optional[str] = "UNKNOWN"