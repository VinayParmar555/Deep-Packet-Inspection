from pydantic import BaseModel
from typing import Optional


class ParsedPacketSchema(BaseModel):
    # Timestamp
    timestamp_sec: int
    timestamp_usec: int

    # Ethernet
    src_mac: str
    dest_mac: str
    ether_type: int

    # IP
    has_ip: bool = False
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[int] = None
    ttl: Optional[int] = None

    # Transport
    has_tcp: bool = False
    has_udp: bool = False
    src_port: Optional[int] = None
    dest_port: Optional[int] = None

    # TCP
    tcp_flags: Optional[int] = None
    seq_number: Optional[int] = None
    ack_number: Optional[int] = None

    # Payload
    payload_length: int = 0
    payload: Optional[bytes] = None