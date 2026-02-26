import sys
from datetime import datetime
from scapy.all import rdpcap, Ether, IP, TCP, UDP


def print_packet_summary(pkt, packet_num):

    print(f"\n========== Packet #{packet_num} ==========")

    # Timestamp
    timestamp = datetime.fromtimestamp(pkt.time)
    print("Time:", timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"))

    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        print("\n[Ethernet]")
        print("  Source MAC:      ", eth.src)
        print("  Destination MAC: ", eth.dst)
        print("  EtherType:       ", hex(eth.type))

    # IP
    if IP in pkt:
        ip = pkt[IP]
        print("\n[IP]")
        print("  Source IP:       ", ip.src)
        print("  Destination IP:  ", ip.dst)
        print("  Protocol:        ", ip.proto)
        print("  TTL:             ", ip.ttl)

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        print("\n[TCP]")
        print("  Source Port:     ", tcp.sport)
        print("  Destination Port:", tcp.dport)
        print("  Seq Number:      ", tcp.seq)
        print("  Ack Number:      ", tcp.ack)
        print("  Flags:           ", tcp.flags)

    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        print("\n[UDP]")
        print("  Source Port:     ", udp.sport)
        print("  Destination Port:", udp.dport)

    # Payload
    payload = bytes(pkt.payload.payload) if hasattr(pkt.payload, "payload") else b""
    if payload:
        print("\n[Payload]")
        print("  Length:", len(payload), "bytes")
        preview = payload[:32]
        print("  Preview:", preview.hex(" "), "..." if len(payload) > 32 else "")


def main():
    if len(sys.argv) < 2:
        print("Usage: python packet_analyzer.py <pcap_file> [max_packets]")
        return

    filename = sys.argv[1]
    max_packets = int(sys.argv[2]) if len(sys.argv) > 2 else None

    packets = rdpcap(filename)

    packet_count = 0
    parse_errors = 0

    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================")

    for pkt in packets:
        packet_count += 1

        try:
            print_packet_summary(pkt, packet_count)
        except Exception:
            print(f"Warning: Failed to parse packet #{packet_count}")
            parse_errors += 1

        if max_packets and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break

    print("\n====================================")
    print("Summary:")
    print("  Total packets read:", packet_count)
    print("  Parse errors:", parse_errors)
    print("====================================")


if __name__ == "__main__":
    main()