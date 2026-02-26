from collections import defaultdict
import threading

class StatsService:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_counts = defaultdict(int)

    def record_packet(self, packet):
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet.size

    def record_forward(self):
        with self.lock:
            self.forwarded += 1

    def record_drop(self):
        with self.lock:
            self.dropped += 1

    def snapshot(self):
        with self.lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "forwarded": self.forwarded,
                "dropped": self.dropped,
            }