"""
High-performance DPI test script with PCAP replay.
Run with: python test_metrics.py
"""
import asyncio
import httpx
import time
import os


BASE_URL = "http://localhost:8001"
PCAP_FILE = "new_traffic.pcap"  # Your PCAP file


async def main():
    print("=" * 60)
    print("DPI Metrics Test Script (PCAP Replay)")
    print("=" * 60)

    async with httpx.AsyncClient(
        base_url=BASE_URL,
        timeout=120.0,
    ) as client:

        # ── Health check ──────────────────────────────────────────
        try:
            resp = await client.get("/health")
            print(f"\n Server is running: {resp.json()}")
        except Exception as e:
            print(f"\n Server not reachable: {e}")
            return

        # ── PCAP file check ───────────────────────────────────────
        if not os.path.exists(PCAP_FILE):
            print(f"\n PCAP file not found: {PCAP_FILE}")
            print("  Place your .pcap file in the current directory")
            return

        pcap_size_mb = os.path.getsize(PCAP_FILE) / (1024 * 1024)
        print(f"\n Replaying {PCAP_FILE} ({pcap_size_mb:.2f} MB) through DPI engine...")

        start = time.time()

        # ── Replay PCAP ───────────────────────────────────────────
        with open(PCAP_FILE, "rb") as f:
            files = {"file": (PCAP_FILE, f, "application/octet-stream")}
            resp = await client.post(
                "/replay",
                files=files,
                params={
                    "max_packets": 50000,
                    "realtime": False,
                },
            )

        elapsed = time.time() - start

        if resp.status_code != 200:
            print(f"\n Replay failed: {resp.status_code}")
            print(f"  {resp.text[:500]}")
            return

        result = resp.json()

        # ── Derived metrics ───────────────────────────────────────
        packets_processed = result.get("processed", 0)
        forwarded         = result.get("forwarded", 0)
        dropped           = result.get("dropped", 0)
        total_routed      = forwarded + dropped
        throughput        = packets_processed / elapsed if elapsed > 0 else 0
        avg_latency_ms    = (elapsed / packets_processed * 1000) if packets_processed > 0 else 0
        forward_rate      = (forwarded / total_routed * 100) if total_routed > 0 else 0
        drop_rate         = (dropped  / total_routed * 100) if total_routed > 0 else 0

        print(f"\n Replay completed in {elapsed:.2f}s")

        # ── Replay statistics ─────────────────────────────────────
        print("\n" + "=" * 60)
        print("REPLAY STATISTICS")
        print("=" * 60)
        print(f"  Total packets:    {result.get('total_packets', 0):,}")
        print(f"  Processed:        {packets_processed:,}")
        print(f"  Forwarded:        {forwarded:,}  ({forward_rate:.2f}%)")
        print(f"  Dropped:          {dropped:,}  ({drop_rate:.2f}%)")
        print(f"  Skipped:          {result.get('skipped', 0):,}")
        print(f"  Errors:           {result.get('errors', 0):,}")
        print(f"  Duration:         {result.get('duration_seconds', 0):.2f}s")

        # ── Rate metrics from replay ──────────────────────────────
        if "rate_metrics" in result:
            print("\n" + "=" * 60)
            print("RATE METRICS (from replay)")
            print("=" * 60)
            for k, v in result["rate_metrics"].items():
                print(f"  {k}: {v}")

        # ── Basic stats ───────────────────────────────────────────
        print("\n" + "=" * 60)
        print("BASIC STATS (/stats)")
        print("=" * 60)
        stats_resp = await client.get("/stats")
        stats = stats_resp.json()
        total_packets = stats.get("total_packets", 0)
        tcp_packets   = stats.get("tcp_packets", 0)
        udp_packets   = stats.get("udp_packets", 0)
        total_bytes   = stats.get("total_bytes", 0)
        tcp_pct = (tcp_packets / total_packets * 100) if total_packets > 0 else 0
        udp_pct = (udp_packets / total_packets * 100) if total_packets > 0 else 0
        mbps    = (total_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0

        print(f"  Total packets:    {total_packets:,}")
        print(f"  Total bytes:      {total_bytes:,}  ({total_bytes / (1024*1024):.2f} MB)")
        print(f"  TCP packets:      {tcp_packets:,}  ({tcp_pct:.1f}%)")
        print(f"  UDP packets:      {udp_packets:,}  ({udp_pct:.1f}%)")
        print(f"  Forwarded:        {stats.get('forwarded_packets', 0):,}")
        print(f"  Dropped:          {stats.get('dropped_packets', 0):,}")

        # ── Rate metrics endpoint ─────────────────────────────────
        print("\n" + "=" * 60)
        print("RATE METRICS (/stats/rates)")
        print("=" * 60)
        rates_resp = await client.get("/stats/rates")
        for k, v in rates_resp.json().items():
            print(f"  {k}: {v}")

        # ── App stats ─────────────────────────────────────────────
        print("\n" + "=" * 60)
        print("APP STATS (/stats/apps)")
        print("=" * 60)
        app_resp = await client.get("/stats/apps")
        app_data = app_resp.json()
        app_dist = app_data.get("app_distribution", {})
        unique_domains = app_data.get("unique_domains", [])
        total_app_packets = sum(app_dist.values()) if app_dist else 0

        print(f"  Active connections: {app_data.get('active_connections', 0):,}")
        print(f"  Unique domains:     {len(unique_domains):,}")
        print(f"  Apps detected:      {len(app_dist):,}")
        if app_dist:
            print("\n  App distribution:")
            for app, count in sorted(app_dist.items(), key=lambda x: -x[1]):
                pct = (count / total_app_packets * 100) if total_app_packets > 0 else 0
                print(f"    {app:<22} {count:>6,} packets  ({pct:.1f}%)")

        # ── Performance summary ───────────────────────────────────
        print("\n" + "=" * 60)
        print("PERFORMANCE SUMMARY")
        print("=" * 60)
        print(f"  Packets processed:  {packets_processed:,}")
        print(f"  Throughput:         {throughput:.2f} packets/sec")
        print(f"  Avg latency:        {avg_latency_ms:.4f} ms/packet")
        print(f"  Sustained:          {mbps:.2f} Mbps")
        print(f"  Forward rate:       {forward_rate:.2f}%")
        print(f"  Unique domains:     {len(unique_domains):,}")
        print(f"  Apps classified:    {len(app_dist):,}")
        print(f"  Duration:           {elapsed:.2f}s")
        print(f"  PCAP size:          {pcap_size_mb:.2f} MB")

        print("\n" + "=" * 60)
        print("Test complete!")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())