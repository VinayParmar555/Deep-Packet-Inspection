import asyncio
from typing import Generic, TypeVar, Optional

T = TypeVar("T")

class ThreadSafeQueue(Generic[T]):

    def __init__(self, max_size: int = 10000):
        self._queue = asyncio.Queue(maxsize=max_size)
        self._shutdown = False

    # ----------------------------------
    # Push (blocking)
    # ----------------------------------
    async def push(self, item: T):
        if self._shutdown:
            return
        await self._queue.put(item)

    # ----------------------------------
    # Try Push (non-blocking)
    # ----------------------------------
    def try_push(self, item: T) -> bool:
        if self._shutdown:
            return False

        if self._queue.full():
            return False

        self._queue.put_nowait(item)
        return True

    # ----------------------------------
    # Pop (blocking)
    # ----------------------------------
    async def pop(self) -> Optional[T]:
        if self._shutdown and self._queue.empty():
            return None

        item = await self._queue.get()
        return item

    # ----------------------------------
    # Pop with timeout
    # ----------------------------------
    async def pop_with_timeout(self, timeout: float) -> Optional[T]:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout)
        except asyncio.TimeoutError:
            return None

    # ----------------------------------
    # Utility
    # ----------------------------------
    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def shutdown(self):
        self._shutdown = True

    def is_shutdown(self) -> bool:
        return self._shutdown