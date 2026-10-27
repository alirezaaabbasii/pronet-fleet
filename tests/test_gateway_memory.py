"""Closed broken streams must release buffers without waiting for cyclic GC."""
import asyncio
import gc
import unittest
import weakref

from pronet.common import PronetError
from pronet.wire import framed_stream


class Reader:
    def __init__(self, malformed=False):
        self.malformed = malformed
        self.buffer = bytearray(256 * 1024)

    async def read(self, size):
        await asyncio.Event().wait()

    async def readexactly(self, size):
        if self.malformed:
            return b"\x03\x00\x00\x00\x00"
        raise OSError("broken carrier")


class Writer:
    def write(self, value):
        pass

    async def drain(self):
        pass


class GatewayMemoryTests(unittest.IsolatedAsyncioTestCase):
    async def check_released(self, malformed):
        was_enabled = gc.isenabled()
        gc.disable()
        references = []
        try:
            for _ in range(20):
                raw, framed, writer = Reader(), Reader(malformed), Writer()
                references.extend((weakref.ref(raw), weakref.ref(framed)))
                try:
                    await framed_stream(raw, writer, framed, writer)
                except (OSError, PronetError):
                    pass
                del raw, framed, writer
                await asyncio.sleep(0)
            # Let task completion callbacks finish, without forcing collection.
            for _ in range(4):
                await asyncio.sleep(0)
            self.assertTrue(all(ref() is None for ref in references),
                            "failed child task traceback still retains stream buffers")
        finally:
            if was_enabled:
                gc.enable()

    async def test_broken_carriers_release_buffers_immediately(self):
        await self.check_released(False)

    async def test_malformed_records_release_buffers_immediately(self):
        await self.check_released(True)
