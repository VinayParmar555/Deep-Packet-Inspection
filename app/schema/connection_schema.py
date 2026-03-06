from pydantic import BaseModel, Field, field_validator, IPvAnyAddress
from enum import Enum
from datetime import datetime
from typing import Optional
import re
import ipaddress

class ConnectionState(str, Enum):
    NEW = "NEW"
    CLASSIFIED = "CLASSIFIED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class PacketAction(str, Enum):
    ALLOW = "ALLOW"
    DROP = "DROP"


class AppType(str, Enum):
    UNKNOWN = "UNKNOWN"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "GOOGLE"
    FACEBOOK = "FACEBOOK"
    YOUTUBE = "YOUTUBE"
    TWITTER = "TWITTER"
    INSTAGRAM = "INSTAGRAM"
    NETFLIX = "NETFLIX"
    AMAZON = "AMAZON"
    MICROSOFT = "MICROSOFT"
    APPLE = "APPLE"
    WHATSAPP = "WHATSAPP"
    TELEGRAM = "TELEGRAM"
    TIKTOK = "TIKTOK"
    SPOTIFY = "SPOTIFY"
    ZOOM = "ZOOM"
    DISCORD = "DISCORD"
    GITHUB = "GITHUB"
    CLOUDFLARE = "CLOUDFLARE"


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class FiveTupleSchema(BaseModel):
    src_ip: str
    dst_ip: str                        
    src_port: int = Field(..., ge=1, le=65535)
    dst_port: int = Field(..., ge=1, le=65535)
    protocol: Protocol

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_and_normalize_ip(cls, v):
        try:
            return str(ipaddress.ip_address(str(v)))  # validates + stores as str
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")


class ConnectionSchema(BaseModel):
    tuple: FiveTupleSchema
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    action: PacketAction = PacketAction.ALLOW
    sni: Optional[str] = Field(default=None, max_length=253)
    first_seen: datetime
    last_seen: datetime
    packets_in: int = Field(default=0, ge=0)
    packets_out: int = Field(default=0, ge=0)
    bytes_in: int = Field(default=0, ge=0)
    bytes_out: int = Field(default=0, ge=0)
    tcp_state: Optional[str] = None

    @field_validator("last_seen")
    @classmethod
    def last_seen_must_be_after_first_seen(cls, v, info):
        first_seen = info.data.get("first_seen")
        if first_seen and v < first_seen:
            raise ValueError("'last_seen' must be >= 'first_seen'")
        return v

    @field_validator("sni")
    @classmethod
    def validate_sni(cls, v):
        if v is None:
            return v
        pattern = r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid SNI/domain format: '{v}'")
        return v

    class Config:
        from_attributes = True