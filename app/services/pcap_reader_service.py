import struct
from typing import Optional

from app.schema.pcap_schema import (
    PcapGlobalHeaderSchema,
    PcapPacketHeaderSchema,
    RawPacketSchema,
)

class PcapReader:

    PCAP_MAGIC_NATIVE = 0xA1B2C3D4
    PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

    def __init__(self):
        self.file = None
        self.global_header: Optional[PcapGlobalHeaderSchema] = None
        self.needs_byte_swap = False

    # --------------------------------------------
    # Open PCAP
    # --------------------------------------------
    def open(self, filename: str) -> bool:
        try:
            self.file = open(filename, "rb")
        except Exception:
            return False

        header_bytes = self.file.read(24)
        if len(header_bytes) != 24:
            return False

        unpacked = struct.unpack("<IHHiiii", header_bytes)

        magic = unpacked[0]

        if magic == self.PCAP_MAGIC_NATIVE:
            self.needs_byte_swap = False
        elif magic == self.PCAP_MAGIC_SWAPPED:
            self.needs_byte_swap = True
        else:
            return False

        self.global_header = PcapGlobalHeaderSchema(
            magic_number=unpacked[0],
            version_major=unpacked[1],
            version_minor=unpacked[2],
            thiszone=unpacked[3],
            sigfigs=unpacked[4],
            snaplen=unpacked[5],
            network=unpacked[6],
        )

        return True

    # --------------------------------------------
    # Read Packet
    # --------------------------------------------
    def read_next_packet(self) -> Optional[RawPacketSchema]:

        if not self.file:
            return None

        header_bytes = self.file.read(16)
        if len(header_bytes) != 16:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            "<IIII", header_bytes
        )

        packet_data = self.file.read(incl_len)
        if len(packet_data) != incl_len:
            return None

        header = PcapPacketHeaderSchema(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=incl_len,
            orig_len=orig_len,
        )

        return RawPacketSchema(
            header=header,
            data=packet_data,
        )

    # --------------------------------------------
    # Close
    # --------------------------------------------
    def close(self):
        if self.file:
            self.file.close()
            self.file = None