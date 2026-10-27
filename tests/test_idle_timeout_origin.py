"""Transport timeouts must terminate a stream, never start a hot retry loop."""
import asyncio
import time
import unittest
from unittest.mock import patch
from pronet import wire


class IdleTimeoutOriginTests(unittest.IsolatedAsyncioTestCase):
    async def check_transport_timeout(self, fallback):
        calls = 0
        async def broken():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError('failed socket was retried')
            raise TimeoutError('TCP connection timed out')
        original = getattr(asyncio, 'timeout', None)
        with patch.object(asyncio, 'timeout', None if fallback else original, create=True):
            with self.assertRaisesRegex(TimeoutError, 'TCP connection timed out'):
                await wire.idle_read(broken, [time.monotonic()])
        self.assertEqual(calls, 1)

    async def test_transport_timeout_propagates_modern(self):
        await self.check_transport_timeout(False)

    async def test_transport_timeout_propagates_legacy(self):
        await self.check_transport_timeout(True)

    async def test_real_idle_expiry_cancels_pending_read(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                cancelled = asyncio.Event()
                async def waiting():
                    try:
                        await asyncio.Event().wait()
                    finally:
                        cancelled.set()
                original = getattr(asyncio, 'timeout', None)
                with patch.object(asyncio, 'timeout', None if fallback else original, create=True), patch.object(wire, 'IDLE_TIMEOUT', .015):
                    with self.assertRaises(asyncio.TimeoutError):
                        await wire.idle_read(waiting, [time.monotonic() - 1])
                self.assertTrue(cancelled.is_set())

    async def test_other_direction_activity_keeps_connection_alive(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                activity = [time.monotonic()]
                calls = 0
                async def read():
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        await asyncio.Event().wait()
                    return b'continuing download'
                async def active_other_direction():
                    while True:
                        activity[0] = time.monotonic()
                        await asyncio.sleep(.005)
                updater = asyncio.create_task(active_other_direction())
                original = getattr(asyncio, 'timeout', None)
                try:
                    with patch.object(asyncio, 'timeout', None if fallback else original, create=True), patch.object(wire, 'IDLE_TIMEOUT', .025):
                        self.assertEqual(await wire.idle_read(read, activity), b'continuing download')
                    self.assertEqual(calls, 2)
                finally:
                    updater.cancel()
                    await asyncio.gather(updater, return_exceptions=True)

    async def test_caller_cancellation_cleans_pending_read(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                started, stopped = asyncio.Event(), asyncio.Event()
                async def waiting():
                    started.set()
                    try:
                        await asyncio.Event().wait()
                    finally:
                        stopped.set()
                original = getattr(asyncio, 'timeout', None)
                with patch.object(asyncio, 'timeout', None if fallback else original, create=True):
                    task = asyncio.create_task(wire.idle_read(waiting, [time.monotonic()]))
                    await started.wait()
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                self.assertTrue(stopped.is_set())
