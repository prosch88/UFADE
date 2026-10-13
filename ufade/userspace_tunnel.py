"""Root-free USB tunnel for pymobiledevice3 7.8.3 (iOS 17.4 / watchOS 10.4+).

UserspaceTun is adapted from doronz88/pymobiledevice3 (GPL-3.0), commit
6e7c92f5584c8bd3338967ccffbdf4ae4c5a0072, remote/userspace_tunnel.py.
The UFADE adapter retains the synchronous service API of 7.8.3. A dedicated
selector loop owns the async PyTCP stack and USB transport. Authenticated local
relays provide real sockets to synchronous services and async RemoteXPC alike.
No kernel interface, global socket patches, or privileged tunneld is needed.
Only one userspace stack can run per process. Its IPv6 address is not reachable
by external programs. Use open()/close() from outside the tunnel thread.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import secrets
import socket
import struct
import threading
from contextlib import AsyncExitStack, suppress
from typing import Any, Optional, Protocol, cast

from packaging.version import InvalidVersion, Version
from pmd_net_addr import Ip6Address, Ip6IfAddr, MacAddress
from pmd_pytcp import stack
from pmd_pytcp.lib.interface_layer import InterfaceLayer
from pmd_pytcp.lib.io_backend import register_interface_fd, unregister_interface_fd
from pmd_pytcp.socket import AF_INET6, SOCK_STREAM
from pmd_pytcp.socket import socket as pytcp_socket
from pymobiledevice3.exceptions import InvalidServiceError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import create_using_remote, create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.service_connection import ServiceConnection

logger = logging.getLogger(__name__)
logging.getLogger("pmd_pytcp").setLevel(logging.WARNING)
_ETH_IPV6 = 0x86DD
_STACK_MAC = "02:00:00:00:00:01"
_PEER_MAC = "02:00:00:00:00:02"
INTERFACE_MTU = 16000
SOCKET_BUFFER_SIZE = 6 * 1024 * 1024
LOOPBACK_HEADER = get_os_utils().loopback_header


def throughput_sysctls():
    return {
        "tcp.rcv_wnd_max": 4 * 1024 * 1024,
        "tcp.delayed_ack.delay_ms": 1,
        "tcp.rto.min_ms": 200,
        "tcp.default.mtu_probing": 2,
        "tcp.default.base_mss": 1400,
        "tcp.plpmtud.default.probe_timer_ms": 1500,
    }


class _AsyncPytcpSocket(Protocol):
    async def connect(self, address): ...
    async def send(self, data): ...
    async def recv(self, bufsize): ...
    def close(self): ...


def _mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _eth_header(dst_mac: str, src_mac: str) -> bytes:
    return _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac) + struct.pack("!H", _ETH_IPV6)


#: Hot-path constants: the (fixed) Ethernet header prepended to every inbound packet, and the
#: EtherType bytes checked on every outbound frame — precomputed so the per-packet paths do no
#: string parsing / struct packing.
_ETH_HDR_TO_STACK = _eth_header(_STACK_MAC, _PEER_MAC)
_ETH_IPV6_BYTES = struct.pack("!H", _ETH_IPV6)


def _packet_socketpair() -> tuple[socket.socket, socket.socket]:
    """A connected datagram socket pair preserving packet boundaries (one send == one recv).
    Unix uses an AF_UNIX SOCK_DGRAM socketpair; Windows (no such socketpair) uses a connected
    localhost UDP pair."""
    try:
        return socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    except (AttributeError, OSError):
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        a.connect(b.getsockname())
        b.connect(a.getsockname())
        return a, b


class UserspaceTun:
    """PyTCP L2 interface with an Ethernet shim around the tunnel's IPv6 packets.

    The adapter awaits up(), async_read() and close() on its worker loop.
    PyTCP's stack is a process-global singleton: one tunnel per process.
    """

    def __init__(self, interface_name: str = "utun-userspace") -> None:
        self.name = interface_name
        self._mtu = 1500
        self._addr: Optional[str] = None
        self._ifidx: Optional[int] = None
        self._closed = False
        self._peer, self._pend = _packet_socketpair()
        for s in (self._peer, self._pend):
            # Buffer tuning is optional; OS limits must not require privileges.
            with suppress(OSError):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        # Both directions run on the event loop (async_read via loop.sock_recv, write via a
        # direct non-blocking send), so neither end may block the loop.
        self._peer.setblocking(False)

    # --- TunTapDevice-compatible surface ---
    @property
    def mtu(self) -> int:
        return self._mtu

    @mtu.setter
    def mtu(self, value: int) -> None:
        self._mtu = int(value)

    @property
    def addr(self) -> Optional[str]:
        return self._addr

    @addr.setter
    def addr(self, address: str) -> None:
        self._addr = address

    async def up(self) -> None:
        self._mtu = min(self._mtu, INTERFACE_MTU)

        if not getattr(stack, "_pmd3_inited", False):
            # accept_dad off (point-to-point link, no DAD peer) + the throughput sysctls
            # (public PyTCP knobs; omitted automatically on a PyTCP too old to have them).
            sysctls = {"icmp6.default.accept_dad": 0, **throughput_sysctls()}
            stack.init(sysctls=sysctls)
            stack._pmd3_inited = True  # type: ignore[attr-defined]
        register_interface_fd(self._pend)
        self._ifidx = stack.add_interface(
            fd=self._pend.fileno(),
            layer=InterfaceLayer.L2,
            mac_address=MacAddress(_STACK_MAC),
            mtu=self._mtu,
            ip6_support=True,
            ip6_host=Ip6IfAddr(f"{self._addr}/64"),
            ip6_lla_autoconfig=True,
            ip6_gua_autoconfig=False,
            ip4_support=False,
        )
        await stack.start()  # pyright: ignore[reportGeneralTypeIssues]  # pmd-pytcp types start() as sync; it is a coroutine at runtime
        # The interface address is installed by the stack's own tasks shortly AFTER start()
        # returns; until it lands, source-address selection finds no local host and a stack
        # connect fails with gaierror. Today the dial plane's localhost-relay hop happens to
        # add enough event-loop round trips to win that race, but nothing guarantees it — and
        # an embedder calling connect_tcp() right after aopen() has no such slack. The tun is
        # not "up" until its address is actually usable, so wait for it (yielding, not
        # sleeping: the install normally lands within a loop tick or two).
        target = Ip6Address(self._addr)
        deadline = asyncio.get_running_loop().time() + 5
        while not any(host.address == target for host in stack.local_ip6_hosts()):
            if asyncio.get_running_loop().time() > deadline:
                raise PyMobileDevice3Exception(f"userspace stack address {self._addr} was not assigned within 5s")
            await asyncio.sleep(0)
        logger.debug("userspace tunnel up: pytcp L2 iface=%s addr=%s/64 mtu=%s", self._ifidx, self._addr, self._mtu)

    def set_peer(self, device_addr: str) -> None:
        """Install a static neighbor for the device (point-to-point; skips ND)."""
        assert self._ifidx is not None
        stack.neighbor.interface(self._ifidx).add(ip=Ip6Address(device_addr), mac=MacAddress(_PEER_MAC))

    def write(self, data: bytes) -> None:
        # inbound (device -> stack): strip pmd3 loopback header, add Ethernet, enqueue. The
        # socket is non-blocking; a full buffer drops the packet (tunnel loss, TCP recovers).
        ipv6 = data[len(LOOPBACK_HEADER) :] if data[: len(LOOPBACK_HEADER)] == LOOPBACK_HEADER else data
        with suppress(OSError):
            self._peer.send(_ETH_HDR_TO_STACK + ipv6)

    async def async_read(self) -> bytes:
        # outbound (stack -> device): await an Ethernet frame off the stack's socketpair and
        # return its raw IPv6 payload (no loopback header — tun_read_task checks the version
        # nibble). Raises OSError once the socketpair is closed, which ends tun_read_task.
        while not self._closed:
            frame = await asyncio.get_running_loop().sock_recv(self._peer, 65535)
            if len(frame) < 14 or frame[12:14] != _ETH_IPV6_BYTES:
                continue
            return frame[14:]
        return b""

    async def async_read_batch(self) -> list[bytes]:
        """Await at least one outbound frame, then greedily drain every further frame already
        queued on the socketpair, returning their raw IPv6 payloads in arrival order.

        One event-loop wakeup services a whole egress burst — the userspace counterpart of the
        kernel tun's ``_tun_read_loop_via_reader`` batch-drain. Paying a loop reschedule per
        MSS-sized packet caps uploads at a few thousand packets/s, because the same loop also
        runs the pytcp stack. Raises OSError once the socketpair is closed, which ends
        ``tun_read_task``."""
        frame = await asyncio.get_running_loop().sock_recv(self._peer, 65535)
        packets: list[bytes] = []
        while True:
            if len(frame) > 14 and frame[12:14] == _ETH_IPV6_BYTES:
                packets.append(frame[14:])
            try:
                frame = self._peer.recv(65535)
            except (BlockingIOError, InterruptedError):
                return packets

    async def connect_tcp(self, addr: str, port: int) -> _AsyncPytcpSocket:
        """Open a PyTCP TCP socket connected to (addr, port) over this stack."""
        s = cast(_AsyncPytcpSocket, pytcp_socket(AF_INET6, SOCK_STREAM))
        try:
            await s.connect((addr, port))
            return s
        except BaseException:
            s.close()
            raise

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Stop the stack first (clean teardown against live fds: loop readers/writers are
        # removed, worker tasks cancelled and awaited), then release the socketpair. No
        # thread-wakeup gymnastics remain — the pure-asyncio stack has nothing parked off-loop.
        try:
            await stack.stop()  # pyright: ignore[reportGeneralTypeIssues]  # pmd-pytcp types stop() as sync; it is a coroutine at runtime
        except Exception:
            logger.debug("error stopping pytcp stack", exc_info=True)
        finally:
            # Clear the init marker even when stop() raised: a later open->close->open cycle
            # must re-run stack.init() rather than reuse a half-stopped stack.
            stack._pmd3_inited = False  # type: ignore[attr-defined]
        unregister_interface_fd(self._pend)
        for s in (self._peer, self._pend):
            with suppress(Exception):
                s.close()


def supports_userspace_tunnel(product_version: str, device_class: str) -> bool:
    """Compare complete versions; unknown/malformed versions keep the old path."""
    try:
        return Version(product_version) >= Version("10.4" if device_class == "Watch" else "17.4")
    except (InvalidVersion, TypeError):
        return False


class _Relay:
    """One loopback listener, with a per-tunnel secret and destination port header."""

    def __init__(self, tun, address):
        self.tun, self.address = tun, address
        self.token = secrets.token_bytes(32)
        self.server = None
        self.tasks = set()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.endpoint = self.server.sockets[0].getsockname()

    async def close(self):
        if self.server is not None:
            self.server.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.server is not None:
            await self.server.wait_closed()

    def connect(self, port):
        sock = socket.create_connection(self.endpoint, timeout=30)
        try:
            sock.sendall(self.token + struct.pack("!H", port))
            if sock.recv(1) != b"\x00":
                raise ConnectionError(f"Userspace connection to port {port} failed")
            sock.settimeout(None)
            return sock
        except BaseException:
            sock.close()
            raise

    async def dial(self, port):
        reader, writer = await asyncio.open_connection(*self.endpoint)
        try:
            writer.write(self.token + struct.pack("!H", port))
            await writer.drain()
            if await asyncio.wait_for(reader.readexactly(1), 30) != b"\x00":
                raise ConnectionError(f"Userspace connection to port {port} failed")
            return reader, writer
        except BaseException:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            raise

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        psock = None
        pumps = []
        try:
            header = await asyncio.wait_for(reader.readexactly(34), 10)
            if not secrets.compare_digest(header[:32], self.token):
                return
            port = struct.unpack("!H", header[32:])[0]
            psock = await asyncio.wait_for(self.tun.connect_tcp(self.address, port), 20)
            writer.write(b"\x00")
            await writer.drain()

            async def upload():
                while data := await reader.read(65536):
                    offset = 0
                    while offset < len(data):
                        sent = await psock.send(data[offset:])
                        if not sent:
                            raise ConnectionError("Userspace socket closed during send")
                        offset += sent

            async def download():
                while data := await psock.recv(65536):
                    writer.write(data)
                    await writer.drain()

            pumps = [asyncio.create_task(upload()), asyncio.create_task(download())]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
        except (OSError, EOFError, asyncio.IncompleteReadError, TimeoutError):
            logger.debug("Userspace relay closed", exc_info=True)
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            if psock is not None:
                psock.close()
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            self.tasks.discard(task)


class _UserspaceXPC(RemoteXPCConnection):
    def __init__(self, relay, port):
        super().__init__((relay.address, port))
        self._relay = relay

    async def connect(self):
        self._reader, self._writer = await self._relay.dial(self.address[1])
        try:
            await self._do_handshake()
        except BaseException:
            await self.close()
            raise

    async def close(self):
        writer, self._writer = self._writer, None
        self._reader = None
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=3)
            except (OSError, TimeoutError):
                writer.transport.abort()


class UserspaceRSD(RemoteServiceDiscoveryService):
    """7.8.3 RSD with instance-local routing for both service API variants."""

    def __init__(self, relay, port):
        super().__init__((relay.address, port), name="ufade-userspace")
        self._relay = relay
        self.service = _UserspaceXPC(relay, port)

    async def connect(self):
        self.service = _UserspaceXPC(self._relay, self.service.address[1])
        await self.service.connect()
        try:
            self.peer_info = await self.service.receive_response()
            self.udid = self.peer_info["Properties"]["UniqueDeviceID"]
            self.product_type = self.peer_info["Properties"]["ProductType"]
            # 7.8.3 performs blocking check-in and lockdown initialization here.
            # Offload them so the relay/packet loop can keep making progress.
            await asyncio.to_thread(self._connect_lockdown)
        except BaseException:
            await self.close()
            raise

    def _connect_lockdown(self):
        self.lockdown = None
        for name in ("com.apple.mobile.lockdown.remote.trusted",
                     "com.apple.mobile.lockdown.remote.untrusted"):
            with suppress(InvalidServiceError):
                connection = self.start_lockdown_service(name)
                try:
                    self.lockdown = create_using_remote(connection)
                except BaseException:
                    connection.close()
                    raise
                break
        self.all_values = self.lockdown.all_values if self.lockdown else {}

    def start_lockdown_service_without_checkin(self, name):
        return ServiceConnection(self._relay.connect(self.get_service_port(name)))

    async def aio_start_lockdown_service(self, name, include_escrow_bag=False):
        service = await asyncio.to_thread(self.start_lockdown_service, name, include_escrow_bag)
        try:
            await service.aio_start()
        except BaseException:
            service.close()
            raise
        return service

    def start_remote_service(self, name):
        return _UserspaceXPC(self._relay, self.get_service_port(name))


_stack_guard = threading.Lock()


class UserspaceRsdTunnel:
    """Synchronous UFADE handle; the worker loop lives until close/disconnect.

    ``rsd = UserspaceRsdTunnel(serial=udid).open()`` returns the usual 7.8.3
    service provider. Retain the handle and close it when the application exits.
    Calls to open()/close() must be serialized by the caller.
    """

    def __init__(self, serial=None):
        self.serial = serial
        self.rsd = None
        self.error = None
        self._thread = None
        self._loop = None
        self._stop = None
        self._ready = None

    @property
    def active(self):
        return self.rsd is not None and self._thread is not None and self._thread.is_alive()

    def open(self):
        if self.active:
            return self.rsd
        self.close()
        if not _stack_guard.acquire(blocking=False):
            raise RuntimeError("Another userspace tunnel is already running")
        self.error = None
        self._ready = concurrent.futures.Future()
        self._thread = threading.Thread(target=self._worker, name="ufade-userspace", daemon=True)
        try:
            self._thread.start()
        except BaseException:
            _stack_guard.release()
            self._thread = None
            raise
        try:
            return self._ready.result(timeout=75)
        except BaseException:
            self.close()
            raise

    def ensure_connected(self, on_retry=None):
        """Probe RSD, not just the worker thread; rebuild a stale tunnel once.

        Call outside the GUI thread because probing and rebuilding involve I/O.
        A failed rebuild propagates to the caller's legacy-tunnel fallback.
        """
        if self.active:
            try:
                return self.refresh(timeout=10)
            except Exception as exc:
                if on_retry is not None:
                    on_retry(exc)
                self.close()
        return self.open()

    def close(self):
        if self._thread is None:
            return
        if self._loop is not None and self._stop is not None:
            with suppress(RuntimeError):
                self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(timeout=35)
        if self._thread.is_alive():
            raise TimeoutError("Userspace tunnel cleanup has not completed")
        self._thread = None
        self.rsd = None

    def refresh(self, timeout=10):
        """Refresh services after DDI mounting without restarting the transport."""
        if not self.active:
            raise ConnectionError("Userspace tunnel is disconnected")

        async def reconnect():
            rsd = self.rsd
            await rsd.close()
            await rsd.connect()
            return rsd

        async def bounded_reconnect():
            return await asyncio.wait_for(reconnect(), timeout=timeout)

        future = asyncio.run_coroutine_threadsafe(bounded_reconnect(), self._loop)
        try:
            return future.result(timeout=timeout + 5)
        except BaseException:
            future.cancel()
            raise

    def _worker(self):
        # PyTCP registers file-descriptor readers; Windows' Proactor loop does not.
        loop = asyncio.SelectorEventLoop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run())
        except BaseException as exc:
            self.error = exc
            if not self._ready.done():
                self._ready.set_exception(exc)
            else:
                logger.warning("Userspace tunnel stopped: %s", exc)
        finally:
            self.rsd = None
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()
            self._loop = None
            self._stop = None
            _stack_guard.release()

    async def _run(self):
        self._stop = asyncio.Event()
        async with AsyncExitStack() as resources:
            async def establish():
                lockdown = await asyncio.to_thread(create_using_usbmux, serial=self.serial)
                resources.callback(lockdown.close)
                # Let asyncio own TLS from the outset. The synchronous factory
                # returns an SSLSocket for EnableServiceSSL, which aio_start()
                # cannot accept. In 7.8.3 only the non-TLS path needs aio_start().
                service = await lockdown.aio_start_lockdown_service(
                    "com.apple.internal.devicecompute.CoreDeviceProxy",
                )
                resources.callback(service.close)
                if service.reader is None:
                    await service.aio_start()

                async def close_service():
                    writer = service.writer
                    try:
                        await asyncio.wait_for(service.aio_close(), timeout=3)
                    except (OSError, TimeoutError):
                        if writer is not None:
                            writer.transport.abort()

                resources.push_async_callback(close_service)
                body = json.dumps({"type": "clientHandshakeRequest", "mtu": INTERFACE_MTU}).encode()
                service.writer.write(b"CDTunnel" + struct.pack("!H", len(body)) + body)
                await service.writer.drain()
                header = await service.reader.readexactly(10)
                if header[:8] != b"CDTunnel":
                    raise ConnectionError("Invalid CoreDeviceProxy tunnel handshake")
                response = json.loads(await service.reader.readexactly(struct.unpack("!H", header[8:])[0]))
                tun = UserspaceTun()
                resources.push_async_callback(tun.close)
                tun.addr = response["clientParameters"]["address"]
                tun.mtu = response["clientParameters"]["mtu"]
                await tun.up()
                tun.set_peer(response["serverAddress"])

                async def receive():
                    while True:
                        header = await service.reader.readexactly(40)
                        if header[0] >> 4 != 6:
                            raise ConnectionError("Invalid IPv6 tunnel packet")
                        body = await service.reader.readexactly(struct.unpack("!H", header[4:6])[0])
                        tun.write(header + body)

                async def send():
                    while True:
                        service.writer.write(await tun.async_read())
                        await service.writer.drain()

                transports = [asyncio.create_task(receive()), asyncio.create_task(send())]

                async def stop_transports():
                    for task in transports:
                        task.cancel()
                    await asyncio.gather(*transports, return_exceptions=True)

                resources.push_async_callback(stop_transports)
                relay = _Relay(tun, response["serverAddress"])
                resources.push_async_callback(relay.close)
                await relay.start()
                rsd = UserspaceRSD(relay, response["serverRSDPort"])
                resources.push_async_callback(rsd.close)
                await rsd.connect()
                if self.serial is not None and rsd.udid != self.serial:
                    raise ConnectionError("Userspace tunnel connected to a different device")
                self.rsd = rsd
                return transports

            transports = await asyncio.wait_for(establish(), timeout=60)
            self._ready.set_result(self.rsd)
            stop_task = asyncio.create_task(self._stop.wait())
            try:
                done, _ = await asyncio.wait([stop_task, *transports], return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            finally:
                self.rsd = None
                stop_task.cancel()
                await asyncio.gather(stop_task, return_exceptions=True)
