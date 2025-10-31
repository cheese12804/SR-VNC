"""Secure Reliable UDP transport for SR-VNC.

The module implements a dual-stream transport with the following features:

* AES-GCM protection with deterministic nonces, replay protection, and
  periodic rekeying derived from an X25519 + HKDF handshake.
* Cookie-based handshake to prevent spoofed floods.
* Reliable selective-repeat ARQ with SACK feedback and RTT/RTO estimation for
  the control stream.
* Bandwidth pacing and fragmentation that keeps payloads under 1200 bytes to
  avoid IP fragmentation while prioritising control traffic.
* Replay detection using a 64-packet sliding window keyed by packet numbers.
* Basic telemetry for RTT, loss, jitter, and video throughput to drive the
  demo overlays.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, Iterable, Optional, Tuple

import struct

from .crypto import (
    RekeyRequired,
    ReplayError,
    SecureCodec,
    create_cookie,
    derive_session_keys_with_psk,
    generate_ephemeral_keypair,
    verify_cookie,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


STREAM_CONTROL = 0x01
STREAM_VIDEO = 0x02

CONTROL_EVENT = 0x01
CONTROL_METRICS = 0x03

VERSION = 1

FLAG_RELIABLE = 0x01
FLAG_ACK = 0x02
FLAG_HANDSHAKE = 0x80

MAX_UDP_PAYLOAD = 1200
AEAD_TAG_SIZE = 16

BASE_HEADER_SIZE = 1 + 1 + 1 + 6 + 4 + 4
TLV_HEADER_SIZE = 2
TLV_TYPE_ACK = 0x01
TLV_TYPE_FRAGMENT = 0x02
TLV_TYPE_FEC = 0x03

FRAGMENT_VALUE_SIZE = 4  # index + count
MAX_FRAGMENT_PAYLOAD = (
    MAX_UDP_PAYLOAD - (BASE_HEADER_SIZE + TLV_HEADER_SIZE + FRAGMENT_VALUE_SIZE + AEAD_TAG_SIZE)
)

SACK_WINDOW = 32
INITIAL_RTO = 0.2
MAX_RTO = 3.0
MIN_RTO = 0.1

Address = Tuple[str, int]
ControlHandler = Callable[[int, dict, Address], None]
VideoHandler = Callable[[int, bytes, Address], None]
AckHandler = Callable[[Iterable[int]], None]

HANDSHAKE_CLIENT_HELLO = "client_hello"
HANDSHAKE_RETRY = "hello_retry"
HANDSHAKE_SERVER_HELLO = "server_hello"
HANDSHAKE_CLIENT_FINISH = "client_finish"
HANDSHAKE_REKEY_REQUEST = "rekey_request"
HANDSHAKE_REKEY_ACK = "rekey_ack"
HANDSHAKE_VERSION = VERSION

COOKIE_TTL = 8  # seconds


class HandshakeError(Exception):
    """Raised when the initial or rekey handshake fails."""


class ProtocolError(Exception):
    """Raised when a malformed packet is encountered."""


@dataclass
class Packet:
    stream_id: int
    flags: int
    sequence_number: int
    packet_number: int
    timestamp: int
    fragment_index: int
    fragment_count: int
    payload: bytes
    address: Address
    tlvs: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class PendingCommand:
    sequence_number: int
    payload: bytes
    last_sent: float
    requires_ack: bool = True
    retries: int = 0
    sent_at: float = 0.0


@dataclass
class Metrics:
    rtt_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=256))
    estimated_loss_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=256))
    control_sent: int = 0
    control_retrans: int = 0
    control_lost: int = 0
    last_send_window: int = 0
    last_ack_base: int = 0
    last_sack_mask: int = 0
    last_sack_blocks: int = 0
    ack_updates: int = 0
    video_frames: int = 0
    video_bytes: int = 0
    video_jitter_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=256))
    last_frame_ts: float = 0.0
    start_time: float = field(default_factory=time.time)

    def record_send_window(self, size: int) -> None:
        self.last_send_window = size

    def record_ack(self, ack_base: int, sack_mask: int, window_size: int) -> None:
        self.last_ack_base = ack_base
        self.last_sack_mask = sack_mask
        self.last_sack_blocks = bin(sack_mask).count("1")
        self.ack_updates += 1
        self.last_send_window = window_size
        if self.control_sent:
            estimate = (self.control_retrans / self.control_sent) * 100.0
            self.estimated_loss_samples.append(estimate)

    def snapshot(self) -> dict:
        rtts = list(self.rtt_samples)
        rtt_p50 = median(rtts) if rtts else 0.0
        rtt_p95 = percentile(rtts, 95) if rtts else 0.0
        rtt_p99 = percentile(rtts, 99) if rtts else 0.0
        jitter = list(self.video_jitter_samples)
        jitter_p50 = median(jitter) if jitter else 0.0
        jitter_p95 = percentile(jitter, 95) if jitter else 0.0
        elapsed = max(time.time() - self.start_time, 1e-6)
        fps = self.video_frames / elapsed if self.video_frames else 0.0
        bitrate_mbps = (self.video_bytes * 8.0) / (elapsed * 1_000_000)
        loss_percent = (
            (self.control_lost / self.control_sent) * 100.0 if self.control_sent else 0.0
        )
        est_loss_samples = list(self.estimated_loss_samples)
        est_loss_percent = median(est_loss_samples) if est_loss_samples else 0.0
        return {
            "control_sent": self.control_sent,
            "control_retrans": self.control_retrans,
            "control_lost": self.control_lost,
            "control_loss_percent": loss_percent,
            "control_est_loss_percent": est_loss_percent,
            "control_inflight": self.last_send_window,
            "ack_base": self.last_ack_base,
            "sack_blocks": self.last_sack_blocks,
            "ack_updates": self.ack_updates,
            "rtt_ms_p50": rtt_p50 * 1000.0,
            "rtt_ms_p95": rtt_p95 * 1000.0,
            "rtt_ms_p99": rtt_p99 * 1000.0,
            "video_frames": self.video_frames,
            "video_bytes": self.video_bytes,
            "video_fps_avg": fps,
            "video_bitrate_mbps": bitrate_mbps,
            "video_jitter_p50_ms": jitter_p50 * 1000.0,
            "video_jitter_p95_ms": jitter_p95 * 1000.0,
        }


def median(values: Iterable[float]) -> float:
    values = sorted(values)
    n = len(values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return values[mid]
    return 0.5 * (values[mid - 1] + values[mid])


def percentile(values: Iterable[float], pct: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def build_header(
    *,
    flags: int,
    stream_id: int,
    packet_number: int,
    sequence: int,
    timestamp: int,
    tlvs: Iterable[Tuple[int, bytes]] = (),
) -> bytes:
    header = bytearray(BASE_HEADER_SIZE)
    header[0] = ((VERSION & 0x0F) << 4) | (flags & 0x0F)
    header[1] = stream_id & 0xFF
    header[2] = 0  # Placeholder for header length
    header[3:9] = packet_number.to_bytes(6, "big")
    header[9:13] = sequence.to_bytes(4, "big")
    header[13:17] = timestamp.to_bytes(4, "big")
    for tlv_type, value in tlvs:
        if len(value) > 255:
            raise ValueError("TLV value too large")
        header.extend(bytes((tlv_type & 0xFF, len(value))) + value)
    header_len = len(header)
    if header_len > 255:
        raise ValueError("Header length exceeds 255 bytes")
    header[2] = header_len
    return bytes(header)


def parse_header(data: bytes) -> Tuple[int, int, int, int, int, int, Dict[int, bytes], int]:
    if len(data) < BASE_HEADER_SIZE:
        raise ProtocolError("Header shorter than minimum length")
    header_len = data[2]
    if header_len < BASE_HEADER_SIZE or header_len > len(data):
        raise ProtocolError("Invalid header length")
    version = data[0] >> 4
    flags = data[0] & 0x0F
    stream_id = data[1]
    packet_number = int.from_bytes(data[3:9], "big")
    sequence = int.from_bytes(data[9:13], "big")
    timestamp = int.from_bytes(data[13:17], "big")
    offset = BASE_HEADER_SIZE
    tlvs: Dict[int, bytes] = {}
    while offset + TLV_HEADER_SIZE <= header_len:
        tlv_type = data[offset]
        tlv_len = data[offset + 1]
        offset += TLV_HEADER_SIZE
        if offset + tlv_len > header_len:
            raise ProtocolError("TLV length exceeds header")
        tlvs[tlv_type] = data[offset : offset + tlv_len]
        offset += tlv_len
    if offset != header_len:
        raise ProtocolError("Header padding mismatch")
    return version, flags, stream_id, packet_number, sequence, timestamp, tlvs, header_len


def pack_fragment_tlv(index: int, count: int) -> bytes:
    return struct.pack("!HH", index, count)


def unpack_fragment_tlv(value: bytes) -> Tuple[int, int]:
    if len(value) != FRAGMENT_VALUE_SIZE:
        raise ProtocolError("Invalid fragment TLV size")
    return struct.unpack("!HH", value)


class RttEstimator:
    """RTT estimator based on RFC 6298."""

    def __init__(self) -> None:
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto: float = INITIAL_RTO

    def backoff(self) -> None:
        self.rto = min(MAX_RTO, self.rto * 2.0)

    def observe(self, sample: float) -> None:
        sample = max(sample, 0.0)
        if self.srtt is None:
            self.srtt = sample
            self.rttvar = sample / 2
        else:
            assert self.rttvar is not None
            alpha = 1 / 8
            beta = 1 / 4
            self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - sample)
            self.srtt = (1 - alpha) * self.srtt + alpha * sample
        self.rto = self.srtt + max(MIN_RTO, 4 * (self.rttvar or 0.0))
        self.rto = max(MIN_RTO, min(self.rto, MAX_RTO))


class SackTracker:
    """Tracks received sequence numbers for SACK generation."""

    def __init__(self) -> None:
        self.base = 0
        self.pending: set[int] = set()

    def mark_received(self, sequence: int) -> Tuple[int, int]:
        if sequence <= self.base:
            return self.base, self._mask()
        self.pending.add(sequence)
        while (self.base + 1) in self.pending:
            self.base += 1
            self.pending.remove(self.base)
        return self.base, self._mask()

    def _mask(self) -> int:
        mask = 0
        for i in range(SACK_WINDOW):
            seq = self.base + 1 + i
            if seq in self.pending:
                mask |= 1 << i
        return mask


class TokenBucket:
    """Simple token bucket used for pacing video traffic."""

    def __init__(self, rate_bps: int, burst_bytes: int) -> None:
        self.rate_bps = max(rate_bps, 64_000)
        # Use explicit burst capacity to keep queue small
        self.capacity = max(1, burst_bytes)
        self.tokens = self.capacity
        self.timestamp = time.monotonic()

    def consume(self, amount: int) -> float:
        self._refill()
        if amount <= self.tokens:
            self.tokens -= amount
            return 0.0
        required = amount - self.tokens
        rate_bytes = self.rate_bps / 8.0
        wait = required / rate_bytes
        self.tokens = 0
        return wait

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.timestamp
        if elapsed <= 0:
            return
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + elapsed * (self.rate_bps / 8.0))


class SRUDPConnection:
    """Secure and partially reliable UDP abstraction."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        is_server: bool,
        cookie_secret: bytes | None = None,
        psk: bytes | None = None,
        peer: Optional[Address] = None,
    ) -> None:
        self.socket = sock
        self.socket.setblocking(False)

        # --- Windows workaround: bỏ lỗi ICMP 'Port Unreachable' nếu có hỗ trợ ---
        if os.name == "nt":
            try:
                SIO_UDP_CONNRESET = 0x9800000C
                # Không phải build nào cũng hỗ trợ .ioctl; bắt mọi lỗi và bỏ qua
                self.socket.ioctl(SIO_UDP_CONNRESET, b"\x00\x00\x00\x00")
                print("[DEBUG] UDP_CONNRESET patch: enabled")
            except (AttributeError, OSError, ValueError):
                # Không hỗ trợ ioctl -> bỏ qua, sẽ xử lý bằng try/except ở recv()
                print("[DEBUG] UDP_CONNRESET patch: not supported")
                pass
        self.socket.setblocking(False)
        self.peer = peer
        self.is_server = is_server
        self.cookie_secret = cookie_secret or os.urandom(32)
        self._codec: Optional[SecureCodec] = None
        self._psk = psk
        self._session_id = secrets_token32()
        self._running = threading.Event()
        self._recv_thread: Optional[threading.Thread] = None
        self._retransmit_thread: Optional[threading.Thread] = None
        self._send_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        self._incoming: "queue.Queue[Packet]" = queue.Queue()
        self._control_handler: Optional[ControlHandler] = None
        self._video_handler: Optional[VideoHandler] = None
        self._ack_handler: Optional[AckHandler] = None
        self._metrics = Metrics()

        self._control_seq = 0
        self._video_seq = 0
        self._send_window: Dict[int, PendingCommand] = {}
        self._sack = SackTracker()
        self._rtt = RttEstimator()

        self._video_queue: "queue.Queue[tuple[int, int, int, bytes]]" = queue.Queue()
        self._video_bucket = TokenBucket(rate_bps=2_000_000, burst_bytes=MAX_UDP_PAYLOAD * 2)
        self._video_reassembly: Dict[
            tuple[int, Address], tuple[list[Optional[bytes]], float]
        ] = {}
        self._video_buffer: Deque[tuple[float, int, bytes, Address]] = deque()
        self._video_jitter_target = 0.03
        self._video_last_render_seq = 0
        self._fragment_timeout = 0.5
        self._last_rekey = time.monotonic()
        self._session_timeout = 30.0
        self._keepalive_interval = 2.0
        self._last_rx = time.monotonic()
        self._last_control_sent = time.monotonic()
        self._handshake_session: Optional[int] = None

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------
    def client_handshake(self, *, timeout: float = 10.0) -> None:
        if not self.peer:
            raise RuntimeError("Peer must be set before initiating handshake")
        self._perform_handshake(initiator=True, timeout=timeout)
        if self._codec is None:
            raise HandshakeError("Client handshake failed to establish codec")

    def server_handshake(self, *, timeout: float = 10.0) -> Address:
        address = self._await_handshake(timeout=timeout)
        self.peer = address
        self._perform_handshake(initiator=False, timeout=timeout)
        if self._codec is None:
            raise HandshakeError("Server handshake failed to establish codec")
        return address

    def _await_handshake(self, *, timeout: float) -> Address:
        end = time.time() + timeout
        self.socket.settimeout(timeout)
        try:
            print("[DEBUG] server waiting on", self.socket.getsockname())
            while True:
                remaining = end - time.time()
                if remaining <= 0:
                    raise HandshakeError("Timed out waiting for client hello")
                try:
                    data, addr = self.socket.recvfrom(2048)
                except ConnectionResetError:
                    # Windows ném 10054 khi peer chưa lắng nghe -> bỏ qua gói ICMP này
                    continue
                try:
                    message = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                if message.get("type") == HANDSHAKE_CLIENT_HELLO:
                    self.peer = addr
                    self._process_handshake_message(message, addr)
                    break
        finally:
            self.socket.settimeout(0.0)
        return addr

    def _perform_handshake(self, *, initiator: bool, timeout: float) -> None:
        if initiator:
            self._send_client_hello()
        end = time.time() + timeout
        self.socket.settimeout(timeout)
        try:
            while True:
                remaining = end - time.time()
                if remaining <= 0:
                    raise HandshakeError("Handshake timed out")
                try:
                    data, addr = self.socket.recvfrom(2048)
                except ConnectionResetError:
                    # Windows ném 10054 khi peer chưa lắng nghe -> bỏ qua gói ICMP này
                    continue
                try:
                    message = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                self._process_handshake_message(message, addr)
                if self._codec is not None:
                    break
        finally:
            self.socket.settimeout(0.0)

    def _process_handshake_message(self, message: dict, address: Address) -> None:
        session = message.get("session")
        if session is None:
            raise HandshakeError("Handshake message missing session")
        if self._handshake_session is None:
            self._handshake_session = session
        elif session != self._handshake_session:
            return
        if message.get("version") != HANDSHAKE_VERSION:
            raise HandshakeError("Protocol version mismatch")
        msg_type = message.get("type")
        if msg_type == HANDSHAKE_CLIENT_HELLO:
            self._handle_client_hello(message, address)
        elif msg_type == HANDSHAKE_RETRY:
            self._handle_retry(message)
        elif msg_type == HANDSHAKE_SERVER_HELLO:
            self._handle_server_hello(message)
        elif msg_type == HANDSHAKE_CLIENT_FINISH:
            self._handle_client_finish(message)
        elif msg_type == HANDSHAKE_REKEY_REQUEST:
            self._handle_rekey_request(message, address)
        elif msg_type == HANDSHAKE_REKEY_ACK:
            self._handle_rekey_ack(message)

    def _send_client_hello(self, *, cookie: bytes | None = None, ts: int | None = None) -> None:
        # Khi retry với cookie từ server, PHẢI giữ nguyên client_random và keypair
        # để server verify cookie thành công.
        if cookie is None or not hasattr(self, "_client_priv") or not hasattr(self, "_client_random"):
            priv, pub = generate_ephemeral_keypair()
            self._client_priv = priv
            self._client_pub_bytes = pub
            self._client_random = os.urandom(32)
        else:
            # Tái sử dụng khóa/nonce đã gửi lần đầu
            if not hasattr(self, "_client_pub_bytes"):
                # Khởi tạo lại pub từ private nếu chưa có cache
                _, pub = generate_ephemeral_keypair()
                self._client_pub_bytes = pub
        self._client_cookie = cookie
        self._client_cookie_ts = ts or int(time.time())
        self._handshake_session = self._session_id
        message = {
            "type": HANDSHAKE_CLIENT_HELLO,
            "client_random": self._client_random.hex(),
            "client_pub": self._client_pub_bytes.hex(),
            "timestamp": self._client_cookie_ts,
        }
        if cookie is not None:
            message["cookie"] = cookie.hex()
        self._send_handshake(message)

    def _handle_client_hello(self, message: dict, address: Address) -> None:
        if not self.is_server:
            return
        print("[DEBUG] server got client_hello from", address)
        client_random = bytes.fromhex(message.get("client_random", ""))
        client_pub = bytes.fromhex(message.get("client_pub", ""))
        ts = int(message.get("timestamp", 0))
        cookie_hex = message.get("cookie")
        if not client_random or not client_pub:
            raise HandshakeError("Malformed client hello")
        now = int(time.time())
        if (
            cookie_hex is None
            or abs(int(time.time()) - ts) > COOKIE_TTL
            or not verify_cookie(
                self.cookie_secret,
                address,
                client_random,
                ts,
                bytes.fromhex(cookie_hex) if cookie_hex else b"",
                tolerance=1,
            )
        ):
            print(
                "[DEBUG] cookie invalid or expired; now=",
                int(time.time()),
                "ttl=",
                COOKIE_TTL,
            )
            cookie = create_cookie(self.cookie_secret, address, client_random, now)
            retry = {
                "type": HANDSHAKE_RETRY,
                "session": message.get("session"),
                "cookie": cookie.hex(),
                "timestamp": now,
            }
            self._send_handshake(retry, address=address)
            return

        self._server_priv, server_pub = generate_ephemeral_keypair()
        self._server_random = os.urandom(32)
        self._pending_client_random = client_random
        self._pending_client_pub = client_pub
        server_message = {
            "type": HANDSHAKE_SERVER_HELLO,
            "session": message.get("session"),
            "server_random": self._server_random.hex(),
            "server_pub": server_pub.hex(),
            "timestamp": now,
        }
        self.peer = address
        self._send_handshake(server_message, address=address)

    def _handle_retry(self, message: dict) -> None:
        cookie_hex = message.get("cookie")
        ts = int(message.get("timestamp", 0))
        if cookie_hex is None:
            raise HandshakeError("Server retry missing cookie")
        cookie = bytes.fromhex(cookie_hex)
        self._send_client_hello(cookie=cookie, ts=ts)

    def _handle_server_hello(self, message: dict) -> None:
        server_random = bytes.fromhex(message.get("server_random", ""))
        server_pub = bytes.fromhex(message.get("server_pub", ""))
        if not hasattr(self, "_client_priv"):
            raise HandshakeError("Received server hello without client state")
        shared = self._client_priv.exchange(bytes_to_x25519(server_pub))
        self._codec = derive_session_keys_with_psk(
            shared,
            client_random=self._client_random,
            server_random=server_random,
            initiator=True,
            session_id=self._handshake_session or self._session_id,
            psk=self._psk,
        )
        finish = {
            "type": HANDSHAKE_CLIENT_FINISH,
            "session": message.get("session"),
        }
        self._send_handshake(finish)

    def _handle_client_finish(self, message: dict) -> None:
        if not self.is_server:
            return
        if not hasattr(self, "_server_priv"):
            raise HandshakeError("Client finish without server state")
        shared = self._server_priv.exchange(bytes_to_x25519(self._pending_client_pub))
        self._codec = derive_session_keys_with_psk(
            shared,
            client_random=self._pending_client_random,
            server_random=self._server_random,
            initiator=False,
            session_id=self._handshake_session or self._session_id,
            psk=self._psk,
        )
        self._last_rekey = time.monotonic()

    def _handle_rekey_request(self, message: dict, address: Address) -> None:
        client_random = bytes.fromhex(message.get("client_random", ""))
        client_pub = bytes.fromhex(message.get("client_pub", ""))
        if not client_random or not client_pub:
            raise HandshakeError("Malformed rekey request")
        priv, pub = generate_ephemeral_keypair()
        server_random = os.urandom(32)
        shared = priv.exchange(bytes_to_x25519(client_pub))
        codec = derive_session_keys_with_psk(
            shared,
            client_random=client_random,
            server_random=server_random,
            initiator=False,
            session_id=self._handshake_session or self._session_id,
            psk=self._psk,
        )
        response = {
            "type": HANDSHAKE_REKEY_ACK,
            "server_random": server_random.hex(),
            "server_pub": pub.hex(),
        }
        self._codec = codec
        self._last_rekey = time.monotonic()
        self._send_handshake(response, address=address)

    def _handle_rekey_ack(self, message: dict) -> None:
        if not hasattr(self, "_rekey_priv"):
            raise HandshakeError("Unexpected rekey ack")
        server_random = bytes.fromhex(message.get("server_random", ""))
        server_pub = bytes.fromhex(message.get("server_pub", ""))
        shared = self._rekey_priv.exchange(bytes_to_x25519(server_pub))
        self._codec = derive_session_keys_with_psk(
            shared,
            client_random=self._rekey_client_random,
            server_random=server_random,
            initiator=True,
            session_id=self._handshake_session or self._session_id,
            psk=self._psk,
        )
        self._last_rekey = time.monotonic()

    def _send_rekey(self) -> None:
        self._rekey_priv, client_pub = generate_ephemeral_keypair()
        self._rekey_client_random = os.urandom(32)
        message = {
            "type": HANDSHAKE_REKEY_REQUEST,
            "client_random": self._rekey_client_random.hex(),
            "client_pub": client_pub.hex(),
        }
        self._send_handshake(message)

    def _send_handshake(self, message: dict, *, address: Optional[Address] = None) -> None:
        target = address or self.peer
        if not target:
            raise HandshakeError("Peer not known for handshake message")
        envelope = dict(message)
        if self._handshake_session is None:
            self._handshake_session = self._session_id
        envelope.setdefault("session", self._handshake_session)
        envelope.setdefault("version", HANDSHAKE_VERSION)
        payload = json.dumps(envelope).encode("utf-8")
        print(f"[DEBUG] send_handshake to {target} type={message.get('type')}")
        self.socket.sendto(payload, target)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def register_control_handler(self, handler: ControlHandler) -> None:
        self._control_handler = handler

    def register_video_handler(self, handler: VideoHandler) -> None:
        self._video_handler = handler

    def register_ack_handler(self, handler: AckHandler) -> None:
        self._ack_handler = handler

    def start(self) -> None:
        if self._codec is None:
            raise RuntimeError("Handshake must complete before starting transport")
        if self._running.is_set():
            return
        self._running.set()
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()
        self._retransmit_thread = threading.Thread(
            target=self._retransmit_loop, daemon=True
        )
        self._retransmit_thread.start()
        self._send_thread = threading.Thread(target=self._video_send_loop, daemon=True)
        self._send_thread.start()
        self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._keepalive_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._recv_thread:
            self._recv_thread.join(timeout=1.0)
        if self._retransmit_thread:
            self._retransmit_thread.join(timeout=1.0)
        if self._send_thread:
            self._send_thread.join(timeout=1.0)
        if self._keepalive_thread:
            self._keepalive_thread.join(timeout=1.0)

    def set_video_bitrate(self, rate_bps: int) -> None:
        self._video_bucket = TokenBucket(rate_bps=rate_bps, burst_bytes=MAX_UDP_PAYLOAD * 2)

    def get_metrics(self) -> dict:
        return self._metrics.snapshot()

    # ------------------------------------------------------------------
    # Sending helpers
    # ------------------------------------------------------------------
    def send_control_event(self, event: dict, *, reliable: bool = True) -> int:
        payload = bytes([CONTROL_EVENT]) + json.dumps(event).encode("utf-8")
        if reliable:
            sequence = self._next_control_seq()
            self._wait_for_window()
            command = PendingCommand(
                sequence_number=sequence,
                payload=payload,
                last_sent=0.0,
                requires_ack=True,
            )
            self._send_window[sequence] = command
            self._metrics.record_send_window(len(self._send_window))
            self._transmit_control(sequence, command)
            self._metrics.control_sent += 1
        else:
            sequence = 0
            self._send_packet(
                stream_id=STREAM_CONTROL,
                flags=0,
                sequence=sequence,
                fragment_index=0,
                fragment_count=1,
                payload=payload,
            )
        self._last_control_sent = time.monotonic()
        return sequence

    def send_video_frame(self, frame: bytes) -> int:
        seq = self._next_video_seq()
        fragments = [
            frame[i : i + MAX_FRAGMENT_PAYLOAD]
            for i in range(0, len(frame), MAX_FRAGMENT_PAYLOAD)
        ] or [b""]
        fragment_count = len(fragments)
        for index, chunk in enumerate(fragments):
            self._video_queue.put((seq, index, fragment_count, chunk))
        self._metrics.video_frames += 1
        self._metrics.video_bytes += len(frame)
        return seq

    def _transmit_control(self, sequence: int, command: PendingCommand) -> None:
        if command.requires_ack:
            flags = FLAG_RELIABLE
        else:
            flags = 0
        self._send_packet(
            stream_id=STREAM_CONTROL,
            flags=flags,
            sequence=sequence,
            fragment_index=0,
            fragment_count=1,
            payload=command.payload,
        )
        command.last_sent = time.monotonic()
        command.sent_at = command.last_sent
        self._last_control_sent = command.last_sent

    def _wait_for_window(self) -> None:
        if not self._running.is_set():
            return
        while len(self._send_window) >= SACK_WINDOW and self._running.is_set():
            time.sleep(0.001)

    def send_metrics_overlay(self, extra: Optional[dict] = None) -> None:
        values = self._metrics.snapshot()
        if extra:
            values.update(extra)
        payload = bytes([CONTROL_METRICS]) + json.dumps(
            {"type": "metrics", "values": values}
        ).encode("utf-8")
        self._send_packet(
            stream_id=STREAM_CONTROL,
            flags=0,
            sequence=0,
            fragment_index=0,
            fragment_count=1,
            payload=payload,
        )

    def _video_send_loop(self) -> None:
        while self._running.is_set():
            try:
                seq, index, count, chunk = self._video_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            overhead = BASE_HEADER_SIZE + TLV_HEADER_SIZE + FRAGMENT_VALUE_SIZE + AEAD_TAG_SIZE
            wait = self._video_bucket.consume(len(chunk) + overhead)
            if wait > 0:
                if wait > 0.2:
                    # Congested: drop stale frames to keep latency low
                    dropped = 0
                    try:
                        while True:
                            _ = self._video_queue.get_nowait()
                            dropped += 1
                    except queue.Empty:
                        pass
                    # Skip sleeping; continue with current chunk to catch up
                else:
                    time.sleep(wait)
            self._send_packet(
                stream_id=STREAM_VIDEO,
                flags=0,
                sequence=seq,
                fragment_index=index,
                fragment_count=count,
                payload=chunk,
            )

    def _keepalive_loop(self) -> None:
        while self._running.is_set():
            now = time.monotonic()
            if now - self._last_rx > self._session_timeout:
                logging.warning("SRUDP session timed out due to inactivity")
                self._running.clear()
                break
            if now - self._last_control_sent >= self._keepalive_interval:
                try:
                    self.send_control_event({"type": "keepalive"}, reliable=False)
                except Exception:
                    logging.exception("Failed to send keepalive")
                else:
                    self._last_control_sent = time.monotonic()
            time.sleep(0.5)

    def _send_packet(
        self,
        *,
        stream_id: int,
        flags: int,
        sequence: int,
        fragment_index: int,
        fragment_count: int,
        payload: bytes = b"",
        extra_tlvs: Iterable[Tuple[int, bytes]] = (),
    ) -> None:
        if not self.peer:
            raise RuntimeError("Peer address is not set")
        if len(payload) > MAX_FRAGMENT_PAYLOAD:
            raise ValueError("Payload exceeds maximum fragment size")
        if self._codec is None:
            raise RuntimeError("Transport not ready - handshake missing")
        try:
            packet_number = self._codec.next_packet_number()
        except RekeyRequired:
            self._initiate_rekey()
            packet_number = self._codec.next_packet_number()
        timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        tlvs: list[Tuple[int, bytes]] = list(extra_tlvs)
        if fragment_count > 1:
            tlvs.append((TLV_TYPE_FRAGMENT, pack_fragment_tlv(fragment_index, fragment_count)))
        header = build_header(
            flags=flags,
            stream_id=stream_id,
            packet_number=packet_number,
            sequence=sequence,
            timestamp=timestamp,
            tlvs=tlvs,
        )
        ciphertext = self._codec.encrypt(packet_number, header, payload)
        wire = header + ciphertext
        self.socket.sendto(wire, self.peer)

    def _initiate_rekey(self) -> None:
        now = time.monotonic()
        if now - self._last_rekey < 1.0:
            return
        self._last_rekey = now
        self._send_rekey()

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------
    def poll(self, timeout: float | None = None) -> Optional[Packet]:
        try:
            return self._incoming.get(timeout=timeout)
        except queue.Empty:
            return None

    def _recv_loop(self) -> None:
        while self._running.is_set():
            try:
                data, addr = self.socket.recvfrom(MAX_UDP_PAYLOAD + 64)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError:
                break
            if len(data) < BASE_HEADER_SIZE:
                continue
            try:
                (
                    version,
                    flags,
                    stream_id,
                    packet_number,
                    sequence,
                    timestamp,
                    tlvs,
                    header_len,
                ) = parse_header(data)
            except ProtocolError:
                continue
            if version != VERSION:
                continue
            if len(data) < header_len:
                continue
            header = data[:header_len]
            payload = data[header_len:]
            try:
                plaintext = self._codec.decrypt(packet_number, header, payload)
            except ReplayError:
                print("[DEBUG] decrypt dropped: ReplayError pn=", packet_number)
                continue
            except RekeyRequired:
                print("[DEBUG] decrypt signaled RekeyRequired pn=", packet_number)
                self._initiate_rekey()
                continue
            except Exception as exc:
                print("[DEBUG] decrypt failed:", type(exc).__name__)
                continue
            self._last_rx = time.monotonic()
            fragment_index = 0
            fragment_count = 1
            if TLV_TYPE_FRAGMENT in tlvs:
                try:
                    fragment_index, fragment_count = unpack_fragment_tlv(tlvs[TLV_TYPE_FRAGMENT])
                except ProtocolError:
                    continue
            packet = Packet(
                stream_id=stream_id,
                flags=flags,
                sequence_number=sequence,
                packet_number=packet_number,
                timestamp=timestamp,
                fragment_index=fragment_index,
                fragment_count=fragment_count,
                payload=plaintext,
                address=addr,
                tlvs=tlvs,
            )
            self._incoming.put(packet)
            self._dispatch(packet)

    def _dispatch(self, packet: Packet) -> None:
        if packet.flags & FLAG_ACK:
            ack_payload = packet.tlvs.get(TLV_TYPE_ACK)
            if ack_payload:
                self._process_ack(ack_payload)
        if packet.stream_id == STREAM_CONTROL:
            self._handle_control(packet)
        elif packet.stream_id == STREAM_VIDEO:
            self._handle_video(packet)

    def _handle_control(self, packet: Packet) -> None:
        if not packet.payload:
            return
        msg_type = packet.payload[0]
        if msg_type == CONTROL_EVENT:
            if self._control_handler:
                try:
                    body = json.loads(packet.payload[1:].decode("utf-8"))
                except json.JSONDecodeError:
                    return
                self._control_handler(packet.sequence_number, body, packet.address)
            if packet.flags & FLAG_RELIABLE:
                ack_base, sack_mask = self._sack.mark_received(packet.sequence_number)
                self._send_ack(ack_base, sack_mask)
        elif msg_type == CONTROL_METRICS:
            if self._control_handler:
                try:
                    overlay = json.loads(packet.payload[1:].decode("utf-8"))
                except json.JSONDecodeError:
                    overlay = {}
                self._control_handler(packet.sequence_number, overlay, packet.address)

    def _handle_video(self, packet: Packet) -> None:
        if not self._video_handler:
            return
        if packet.fragment_count <= 1:
            self._queue_video_frame(packet.sequence_number, packet.payload, packet.address)
            return
        key = (packet.sequence_number, packet.address)
        entry = self._video_reassembly.get(key)
        now = time.monotonic()
        if not entry or len(entry[0]) != packet.fragment_count:
            fragments = [None] * packet.fragment_count
            created = now
        else:
            fragments, created = entry
        if 0 <= packet.fragment_index < packet.fragment_count:
            fragments[packet.fragment_index] = packet.payload
        self._video_reassembly[key] = (fragments, created)
        if all(fragment is not None for fragment in fragments):
            data = b"".join(fragment for fragment in fragments if fragment)
            self._queue_video_frame(packet.sequence_number, data, packet.address)
            del self._video_reassembly[key]
        elif now - created > self._fragment_timeout:
            del self._video_reassembly[key]

    def _record_frame_metrics(self) -> None:
        now = time.time()
        if self._metrics.last_frame_ts:
            jitter = now - self._metrics.last_frame_ts
            self._metrics.video_jitter_samples.append(jitter)
        self._metrics.last_frame_ts = now

    def _queue_video_frame(self, sequence: int, payload: bytes, address: Address) -> None:
        if sequence <= self._video_last_render_seq:
            return
        self._video_buffer.append((time.time(), sequence, payload, address))
        if len(self._video_buffer) > 4:
            self._flush_video_buffer(force=True)
        else:
            self._flush_video_buffer(force=False)

    def _flush_video_buffer(self, *, force: bool) -> None:
        now = time.time()
        while self._video_buffer:
            ts, sequence, payload, address = self._video_buffer[0]
            if not force and now - ts < self._video_jitter_target and len(self._video_buffer) <= 2:
                break
            self._video_buffer.popleft()
            if sequence <= self._video_last_render_seq:
                continue
            self._video_last_render_seq = sequence
            self._video_handler(sequence, payload, address)
            self._record_frame_metrics()
            if force and len(self._video_buffer) <= 2:
                break

    def _send_ack(self, ack_base: int, sack_mask: int) -> None:
        payload = struct.pack("!II", ack_base, sack_mask)
        self._send_packet(
            stream_id=STREAM_CONTROL,
            flags=FLAG_ACK,
            sequence=ack_base,
            fragment_index=0,
            fragment_count=1,
            payload=b"",
            extra_tlvs=[(TLV_TYPE_ACK, payload)],
        )

    def _process_ack(self, payload: bytes) -> None:
        if len(payload) < 8:
            return
        ack_base, sack_mask = struct.unpack("!II", payload[:8])
        acknowledged = set()
        for seq, pending in list(self._send_window.items()):
            if seq <= ack_base:
                acknowledged.add(seq)
            else:
                offset = seq - (ack_base + 1)
                if 0 <= offset < SACK_WINDOW and sack_mask & (1 << offset):
                    acknowledged.add(seq)
        now = time.monotonic()
        for seq in acknowledged:
            pending = self._send_window.pop(seq, None)
            if not pending:
                continue
            sample = now - pending.sent_at
            if sample > 0:
                self._rtt.observe(sample)
                self._metrics.rtt_samples.append(sample)
        self._metrics.record_ack(ack_base, sack_mask, len(self._send_window))
        if acknowledged and self._ack_handler:
            self._ack_handler(sorted(acknowledged))

    def _retransmit_loop(self) -> None:
        while self._running.is_set():
            now = time.monotonic()
            for seq, pending in list(self._send_window.items()):
                deadline = pending.last_sent + self._rtt.rto
                if now >= deadline:
                    if pending.retries >= 10:
                        self._metrics.control_lost += 1
                        del self._send_window[seq]
                        self._metrics.record_send_window(len(self._send_window))
                        continue
                    pending.retries += 1
                    self._metrics.control_retrans += 1
                    self._rtt.backoff()
                    self._transmit_control(seq, pending)
            time.sleep(0.01)

    # ------------------------------------------------------------------
    # Sequence helpers
    # ------------------------------------------------------------------
    def _next_control_seq(self) -> int:
        self._control_seq += 1
        return self._control_seq

    def _next_video_seq(self) -> int:
        self._video_seq += 1
        return self._video_seq


def bytes_to_x25519(public_bytes: bytes):
    from cryptography.hazmat.primitives.asymmetric import x25519

    return x25519.X25519PublicKey.from_public_bytes(public_bytes)


def secrets_token32() -> int:
    return int.from_bytes(os.urandom(4), "big")

