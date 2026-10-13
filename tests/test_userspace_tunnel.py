"""Run with: python -m unittest discover -s tests -v (requirements installed)."""
import asyncio
import json
import socket
import struct
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ufade import userspace_tunnel as ut


class VersionTests(unittest.TestCase):
    def test_boundaries(self):
        for version, device, expected in [
            ("17.3.1", "iPhone", False), ("17.4", "iPhone", True),
            ("17.4.1", "iPad", True), ("18.0", "iPhone", True),
            ("10.3.9", "Watch", False), ("10.4", "Watch", True),
            ("11", "Watch", True), ("17.10", "iPhone", True),
            ("unknown", "iPhone", False), ("16.7.10", "iPhone", False),
        ]:
            with self.subTest(version=version, device=device):
                self.assertEqual(ut.supports_userspace_tunnel(version, device), expected)


class EchoSocket:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.closed = False

    async def send(self, data):
        # Simulate partial writes, which must not truncate the application data.
        size = min(len(data), 7)
        await self.queue.put(data[:size])
        return size

    async def recv(self, size):
        return await self.queue.get()

    def close(self):
        self.closed = True


class EchoTun:
    def __init__(self):
        self.sockets = []

    async def connect_tcp(self, address, port):
        sock = EchoSocket()
        self.sockets.append(sock)
        return sock


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tun = EchoTun()
        self.relay = ut._Relay(self.tun, "fd00::2")
        await self.relay.start()

    async def asyncTearDown(self):
        await self.relay.close()
        self.assertTrue(all(sock.closed for sock in self.tun.sockets))
        self.assertFalse(self.relay.tasks)

    async def test_sync_service_socket_and_async_service(self):
        data = b"developer-service-payload" * 50

        def synchronous():
            with self.relay.connect(12345) as sock:
                sock.settimeout(3)
                sock.sendall(data)
                result = bytearray()
                while len(result) < len(data):
                    result.extend(sock.recv(len(data) - len(result)))
                return result

        self.assertEqual(await asyncio.to_thread(synchronous), data)
        reader, writer = await self.relay.dial(12346)
        writer.write(data)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 3), data)
        writer.close()
        await writer.wait_closed()

    async def test_authentication_rejects_local_stranger(self):
        reader, writer = await asyncio.open_connection(*self.relay.endpoint)
        writer.write(b"x" * 34)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b"")
        self.assertFalse(self.tun.sockets)
        writer.close()
        await writer.wait_closed()

    async def test_connect_failure_reaches_sync_caller(self):
        self.tun.connect_tcp = AsyncMock(side_effect=ConnectionRefusedError())
        with self.assertRaises(ConnectionError):
            await asyncio.to_thread(self.relay.connect, 1234)

    async def test_close_wakes_blocked_service(self):
        reader, writer = await self.relay.dial(1234)
        await self.relay.close()
        self.assertEqual(await asyncio.wait_for(reader.read(), 3), b"")
        writer.close()
        await writer.wait_closed()

    async def test_rsd_sync_and_remotexpc_routing(self):
        rsd = ut.UserspaceRSD(self.relay, 58783)
        rsd.peer_info = {"Services": {"test": {"Port": 12345}}}
        service = await asyncio.to_thread(rsd.start_lockdown_service_without_checkin, "test")
        self.assertIsInstance(service, ut.ServiceConnection)
        service.close()
        xpc = rsd.start_remote_service("test")
        with patch.object(xpc, "_do_handshake", new=AsyncMock()):
            await xpc.connect()
            xpc._writer.write(b"xpc")
            await xpc._writer.drain()
            self.assertEqual(await xpc._reader.readexactly(3), b"xpc")
            await xpc.close()


class StackTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_pytcp_start_stop_restart_and_ethernet_shim(self):
        for _ in range(2):
            tun = ut.UserspaceTun()
            try:
                tun.addr = "fd00::1"
                tun.mtu = 16000
                await tun.up()
                tun.set_peer("fd00::2")
                packet = bytes.fromhex("6000000000000640") + b"\x00" * 32
                tun._pend.send(ut._ETH_HDR_TO_STACK + packet)
                # The real stack also emits multicast/neighbor control packets.
                async def find_packet():
                    while await tun.async_read() != packet:
                        pass
                await asyncio.wait_for(find_packet(), 3)
            finally:
                await tun.close()
            self.assertEqual(tun._peer.fileno(), -1)
            self.assertEqual(tun._pend.fileno(), -1)


class FakeService:
    """CoreDeviceProxy peer with a deliberately fragmented handshake reply."""
    def __init__(self):
        self.socket, self.peer = socket.socketpair()
        self.peer.setblocking(False)
        self.connection = ut.ServiceConnection(self.socket)
        self.reader = None
        self.writer = None
        self.start_count = 0
        self.task = None
        self.packets = []

    async def aio_start(self):
        self.start_count += 1
        if self.start_count > 1:
            raise AssertionError("An established asyncio stream must not be attached again")
        await self.connection.aio_start()
        self.reader, self.writer = self.connection.reader, self.connection.writer
        self.task = asyncio.create_task(self.device())

    async def device(self):
        reader, writer = await asyncio.open_connection(sock=self.peer)
        try:
            header = await reader.readexactly(10)
            request = json.loads(await reader.readexactly(struct.unpack("!H", header[8:])[0]))
            assert request["type"] == "clientHandshakeRequest"
            body = json.dumps({"clientParameters": {"address": "fd00::1", "mtu": 16000},
                               "serverAddress": "fd00::2", "serverRSDPort": 58783}).encode()
            response = b"CDTunnel" + struct.pack("!H", len(body)) + body
            for byte in response:
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(0)
            while True:
                header = await reader.readexactly(40)
                body = await reader.readexactly(struct.unpack("!H", header[4:6])[0])
                self.packets.append(header + body)
                writer.write(header + body)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def aio_close(self):
        await self.connection.aio_close()
        if self.task:
            await self.task

    def close(self):
        self.socket.close()
        self.peer.close()


class FakeLockdown:
    def __init__(self, tls=False):
        self.service = FakeService()
        self.closed = False
        self.tls = tls

    async def aio_start_lockdown_service(self, name):
        assert name == "com.apple.internal.devicecompute.CoreDeviceProxy"
        # 7.8.3 initializes streams inside the factory only for TLS services.
        if self.tls:
            await self.service.aio_start()
        return self.service

    def close(self):
        self.closed = True


class FakeRSD:
    def __init__(self, relay, port):
        self.udid = "test-udid"
        self.closed = False
        self.connect_count = 0

    async def connect(self):
        self.connect_count += 1

    async def close(self):
        self.closed = True


class LifecycleTests(unittest.TestCase):
    def test_failed_rebuild_propagates_after_one_attempt(self):
        lockdown = FakeLockdown()
        tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
        with patch.object(ut, "create_using_usbmux", side_effect=[lockdown, ConnectionError("device unavailable")]) as factory, \
                patch.object(ut, "UserspaceRSD", FakeRSD):
            try:
                tunnel.open()
                with patch.object(tunnel, "refresh", side_effect=TimeoutError("stale")):
                    with self.assertRaisesRegex(ConnectionError, "device unavailable"):
                        tunnel.ensure_connected()
                self.assertEqual(factory.call_count, 2)
                self.assertFalse(tunnel.active)
                self.assertFalse(ut._stack_guard.locked())
            finally:
                tunnel.close()

    def test_live_thread_with_unresponsive_rsd_is_rebuilt(self):
        lockdowns = []

        def create(**kwargs):
            lockdown = FakeLockdown()
            lockdowns.append(lockdown)
            return lockdown

        tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
        retry = Mock()
        with patch.object(ut, "create_using_usbmux", side_effect=create), patch.object(ut, "UserspaceRSD", FakeRSD):
            try:
                old_rsd = tunnel.open()

                async def stalled():
                    await asyncio.Event().wait()

                old_rsd.connect = stalled
                refresh = tunnel.refresh
                # Use the real timeout/cancellation path with a shorter test deadline.
                with patch.object(tunnel, "refresh", side_effect=lambda **kw: refresh(timeout=0.02)):
                    new_rsd = tunnel.ensure_connected(on_retry=retry)
                self.assertIsNot(new_rsd, old_rsd)
                self.assertTrue(tunnel.active)
                self.assertEqual(len(lockdowns), 2)
                self.assertTrue(lockdowns[0].closed)
                retry.assert_called_once()
                self.assertIsInstance(retry.call_args.args[0], TimeoutError)
                self.assertIs(tunnel.ensure_connected(), new_rsd)
                self.assertEqual(len(lockdowns), 2)
            finally:
                tunnel.close()
        self.assertFalse(ut._stack_guard.locked())

    def test_factory_initialized_tls_stream_is_not_started_twice(self):
        lockdown = FakeLockdown(tls=True)
        tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
        with patch.object(ut, "create_using_usbmux", return_value=lockdown), patch.object(ut, "UserspaceRSD", FakeRSD):
            try:
                tunnel.open()
                self.assertTrue(tunnel.active)
                self.assertEqual(lockdown.service.start_count, 1)
            finally:
                tunnel.close()
        self.assertTrue(lockdown.closed)

    def test_disconnect_cleans_up_and_allows_reopen(self):
        lockdown = FakeLockdown()
        tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
        with patch.object(ut, "create_using_usbmux", return_value=lockdown), patch.object(ut, "UserspaceRSD", FakeRSD):
            try:
                rsd = tunnel.open()
                loop, thread = tunnel._loop, tunnel._thread
                loop.call_soon_threadsafe(lockdown.service.writer.close)
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertFalse(tunnel.active)
                self.assertTrue(rsd.closed)
                self.assertTrue(lockdown.closed)
            finally:
                tunnel.close()

    def test_rsd_failure_cleans_up_transport_and_stack(self):
        lockdown = FakeLockdown()
        tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
        with patch.object(ut, "create_using_usbmux", return_value=lockdown), \
                patch.object(ut, "UserspaceRSD", FakeRSD), \
                patch.object(FakeRSD, "connect", new=AsyncMock(side_effect=ConnectionError("RSD failed"))):
            with self.assertRaisesRegex(ConnectionError, "RSD failed"):
                tunnel.open()
        self.assertTrue(lockdown.closed)
        self.assertFalse(tunnel.active)
        self.assertFalse(ut._stack_guard.locked())

    def test_open_refresh_close_reopen_real_transport_and_stack(self):
        lockdowns = []

        def create(**kwargs):
            self.assertEqual(kwargs["serial"], "test-udid")
            lockdown = FakeLockdown()
            lockdowns.append(lockdown)
            return lockdown

        tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
        with patch.object(ut, "create_using_usbmux", side_effect=create), patch.object(ut, "UserspaceRSD", FakeRSD):
            try:
                for _ in range(2):
                    rsd = tunnel.open()
                    self.assertTrue(tunnel.active)
                    self.assertIs(tunnel.open(), rsd)
                    self.assertIs(tunnel.refresh(), rsd)
                    self.assertEqual(rsd.connect_count, 2)
                    other = ut.UserspaceRsdTunnel()
                    with self.assertRaises(RuntimeError):
                        other.open()
                    tunnel.close()
                    self.assertFalse(tunnel.active)
                    self.assertTrue(rsd.closed)
                    self.assertTrue(lockdowns[-1].closed)
            finally:
                tunnel.close()
        self.assertFalse(any(t.name == "ufade-userspace" for t in threading.enumerate()))

    def test_start_failure_releases_singleton(self):
        for _ in range(2):
            tunnel = ut.UserspaceRsdTunnel(serial="test-udid")
            with patch.object(ut, "create_using_usbmux", side_effect=ConnectionError("no device")):
                with self.assertRaisesRegex(ConnectionError, "no device"):
                    tunnel.open()
            self.assertFalse(tunnel.active)
            tunnel.close()


if __name__ == "__main__":
    unittest.main()
