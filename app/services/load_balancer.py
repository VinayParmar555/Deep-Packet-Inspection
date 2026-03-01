import asyncio
import hashlib
from typing import List
from app.schema.packet_schema import PacketSchema

class LoadBalancer:
    """
    Python equivalent of C++ LoadBalancer thread.
    Receives packets and forwards to correct FP queue.
    """

    def __init__(
        self,
        lb_id: int,
        fp_queues: List[asyncio.Queue],
        fp_start_id: int,
    ):
        self.lb_id = lb_id
        self.fp_queues = fp_queues
        self.fp_start_id = fp_start_id
        self.num_fps = len(fp_queues)

        self.input_queue: asyncio.Queue[PacketSchema] = asyncio.Queue()

        self.running = False
        self.task: asyncio.Task | None = None

        # Stats
        self.packets_received = 0
        self.packets_dispatched = 0
        self.per_fp_counts = [0] * self.num_fps

    # ==========================================
    # Lifecycle
    # ==========================================

    async def start(self):
        self.running = True
        self.task = asyncio.create_task(self.run())

    async def stop(self):
        self.running = False
        if self.task:
            await self.task

    # ==========================================
    # Core Loop
    # ==========================================

    async def run(self):
        while self.running:
            packet = await self.input_queue.get()

            self.packets_received += 1

            fp_index = self.select_fp(packet)

            await self.fp_queues[fp_index].put(packet)

            self.per_fp_counts[fp_index] += 1
            self.packets_dispatched += 1

            self.input_queue.task_done()

    # ==========================================
    # Hashing Logic (Critical)
    # ==========================================

    def select_fp(self, packet: PacketSchema) -> int:
        key = f"{packet.src_ip}:{packet.src_port}:{packet.dst_ip}:{packet.dst_port}"
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)

        # Only select within this LB's pool
        return hash_value % self.num_fps
    
class LBManager:
    """
    Python equivalent of C++ LBManager.
    Creates and manages multiple LoadBalancers.
    """

    def __init__(
        self,
        num_lbs: int,
        fps_per_lb: int,
        all_fp_queues: List[asyncio.Queue],
    ):
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb

        self.lbs: List[LoadBalancer] = []

        for i in range(num_lbs):
            start = i * fps_per_lb
            end = start + fps_per_lb

            lb = LoadBalancer(
                lb_id=i,
                fp_queues=all_fp_queues[start:end],
                fp_start_id=start,
            )

            self.lbs.append(lb)

    async def start_all(self):
        for lb in self.lbs:
            await lb.start()

    async def stop_all(self):
        for lb in self.lbs:
            await lb.stop()

    def get_lb_for_packet(self, packet: PacketSchema) -> LoadBalancer:
        key = f"{packet.src_ip}:{packet.src_port}:{packet.dst_ip}:{packet.dst_port}"
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)

        lb_index = hash_value % self.num_lbs
        return self.lbs[lb_index]