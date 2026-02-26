from pydantic import BaseModel
from enum import Enum
from datetime import datetime
from typing import Optional

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

class FiveTupleSchema(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

class ConnectionSchema(BaseModel):
    tuple: FiveTupleSchema
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    action: PacketAction = PacketAction.ALLOW
    sni: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

    class Config:
        from_attributes = True