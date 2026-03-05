import sys
from scapy.all import rdpcap, TCP, IP

def extract_sni(payload: bytes):
    """
    Very basic TLS ClientHello SNI extractor.
    (For demo/testing purposes)
    """
    try:
        if b"server_name" in payload:
            start = payload.find(b"server_name")
            return payload[start:start + 50].decode(errors="ignore")
    except Exception:
        pass
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        return

    pcap_file = sys.argv[1]
    packets = rdpcap(pcap_file)

    total = 0
    tls_count = 0

    print("Processing packets...\n")

    for pkt in packets:
        if IP not in pkt:
            continue

        total += 1
        src = pkt[IP].src
        dst = pkt[IP].dst

        sport = pkt[TCP].sport if TCP in pkt else "-"
        dport = pkt[TCP].dport if TCP in pkt else "-"

        print(f"Packet {total}: {src}:{sport} -> {dst}:{dport}", end="")

        # HTTPS check
        if TCP in pkt and pkt[TCP].dport == 443:
            payload = bytes(pkt[TCP].payload)
            sni = extract_sni(payload)
            if sni:
                print(f" [SNI: {sni}]")
                tls_count += 1
                continue

        print()

    print("\nTotal packets:", total)
    print("SNI extracted:", tls_count)


if __name__ == "__main__":
    main()