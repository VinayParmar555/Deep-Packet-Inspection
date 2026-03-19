import asyncio
import pytest
from app.utils.thread_safe_queue import AsyncQueue


class TestAsyncQueue:
    async def test_push_and_pop(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=10)
        await q.push(42)
        item = await q.pop()
        assert item == 42

    async def test_fifo_order(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=10)
        for i in range(5):
            await q.push(i)
        results = [await q.pop() for _ in range(5)]
        assert results == list(range(5))

    async def test_try_push_returns_true_when_space(self):
        q: AsyncQueue[str] = AsyncQueue(max_size=5)
        assert q.try_push("hello") is True

    async def test_try_push_returns_false_when_full(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=2)
        q.try_push(1)
        q.try_push(2)
        assert q.try_push(3) is False

    async def test_empty_on_new_queue(self):
        q: AsyncQueue[int] = AsyncQueue()
        assert q.empty() is True

    async def test_not_empty_after_push(self):
        q: AsyncQueue[int] = AsyncQueue()
        await q.push(1)
        assert q.empty() is False

    async def test_size_tracks_items(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=10)
        assert q.size() == 0
        await q.push(1)
        await q.push(2)
        assert q.size() == 2

    async def test_pop_with_timeout_returns_item(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=5)
        await q.push(99)
        item = await q.pop_with_timeout(1.0)
        assert item == 99

    async def test_pop_with_timeout_returns_none_on_timeout(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=5)
        item = await q.pop_with_timeout(0.05)
        assert item is None

    async def test_shutdown_prevents_new_pushes(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=10)
        q.shutdown()
        await q.push(1)           # should be silently ignored
        assert q.empty() is True

    async def test_try_push_after_shutdown_returns_false(self):
        q: AsyncQueue[int] = AsyncQueue(max_size=10)
        q.shutdown()
        assert q.try_push(1) is False

    async def test_is_shutdown_flag(self):
        q: AsyncQueue[int] = AsyncQueue()
        assert q.is_shutdown() is False
        q.shutdown()
        assert q.is_shutdown() is True
