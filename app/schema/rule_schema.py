from pydantic import BaseModel
from enum import Enum

class BlockType(str, Enum):
    IP = "IP"
    APP = "APP"
    DOMAIN = "DOMAIN"
    PORT = "PORT"


class RuleStatsSchema(BaseModel):
    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int


class BlockReasonSchema(BaseModel):
    type: BlockType
    detail: str