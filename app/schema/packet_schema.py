from pydantic import BaseModel, Field, field_validator
from typing import Optional
from app.schema.connection_schema import FiveTupleSchema, AppType


class PacketSchema(BaseModel):
    tuple: FiveTupleSchema
    size: int = Field(..., gt=0, description="Packet size in bytes, must be > 0")
    outbound: bool = True
    tcp_flags: Optional[int] = Field(default=0, ge=0, le=255)
    payload_length: Optional[int] = Field(default=0, ge=0)
    domain: Optional[str] = Field(default=None, min_length=3, max_length=253)
    app_type: Optional[AppType] = AppType.UNKNOWN

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v):
        if v is None:
            return v
        import re
        pattern = r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid domain format: '{v}'")
        return v

    @field_validator("tcp_flags")
    @classmethod
    def tcp_flags_only_for_tcp(cls, v, info):
        protocol = info.data.get("tuple", {})
        # If tuple is already parsed, check protocol
        if hasattr(protocol, "protocol"):
            if protocol.protocol.value != "TCP" and v and v != 0:
                raise ValueError("tcp_flags should only be set for TCP packets")
        return v