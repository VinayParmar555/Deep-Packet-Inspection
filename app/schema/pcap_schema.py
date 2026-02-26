from pydantic import BaseModel

class PcapGlobalHeaderSchema(BaseModel):
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


class PcapPacketHeaderSchema(BaseModel):
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


class RawPacketSchema(BaseModel):
    header: PcapPacketHeaderSchema
    data: bytes