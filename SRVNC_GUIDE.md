# 📚 SR-VNC: Hướng dẫn toàn diện về nội dung & kỹ thuật

## 🎯 Mục đích dự án

**SR-VNC** là một demo hoàn chỉnh cho ý tưởng **"Secure Reliable UDP"** (SRUDP) – một giao thức mạng tùy biến chạy trên UDP nhưng:

- ✅ **Bảo mật**: Toàn bộ payload mã hóa bằng AES-GCM, chống replay attacks
- ✅ **Đáng tin cậy**: Luồng điều khiển (chuột/phím) 100% reliable qua Selective Repeat ARQ
- ✅ **Hiệu suất cao**: Luồng video (màn hình) best-effort, drop frame cũ để giảm độ trễ
- ✅ **NAT traversal**: Hỗ trợ STUN, UDP hole punching, fallback TURN relay
- ✅ **Telemetry**: Đo lường RTT, loss%, jitter, bitrate real-time

**Ứng dụng thực tế**: Remote desktop, game streaming, video conferencing, IoT control qua mạng không ổn định.

---

## 🏗️ Kiến trúc tổng quan

```
┌─────────────────────────────────────────────────────────────────┐
│                        Ứng dụng (Application)                    │
├─────────────────────────────────────────────────────────────────┤
│  SRVNCServer (server.py)     │     SRVNCClient (client.py)     │
│  - Chụp màn hình (PIL)       │     - Hiển thị video (Tkinter) │
│  - Điều khiển input (PyAuto) │     - Thu thập events          │
│  - JPEG encoding             │     - Metrics overlay          │
├─────────────────────────────────────────────────────────────────┤
│              Lớp vận chuyển (Transport) SRUDP                  │
├─────────────────────────────────────────────────────────────────┤
│  SRUDPConnection (srudp.py)                                     │
│  ├─ Handshake: X25519 + HKDF + Cookie                          │
│  ├─ Encryption: AES-GCM (SecureCodec)                          │
│  ├─ Control Stream: Selective Repeat ARQ + SACK + RTO          │
│  ├─ Video Stream: Best-effort + Token Bucket + Fragment        │
│  └─ Telemetry: RTT, Loss, Jitter, Bitrate                      │
├─────────────────────────────────────────────────────────────────┤
│                      Lớp mạng (Network)                         │
│           UDP (1200-byte MTU) + STUN/Relay fallback            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Kỹ thuật 1: Handshake & mã hóa (crypto.py)

### Quy trình bắt tay (X25519 + HKDF + Cookie)

```
1. CLIENT                         SERVER
   |── client_hello (X25519 pub, client_random) ──>|
   |                                               |
   |<── hello_retry (cookie=HMAC(secret, msg)) ───|
   |       cookie_msg = IP|port|client_random|ts   |
   |                                               |
   |── client_hello (cùng client_random, cookie) ─>|
   |                                               |
   |<── server_hello (X25519 pub, server_random) ─|
   |                                               |
   |── client_finish (encrypted) ─────────────────>|
   |                                               |
   [SESSION ESTABLISHED] Tất cả payload mã hóa AES-GCM
```

**Code thực tế** (dạng đơn giản):

```python
# Client
self._client_random = os.urandom(32)
self._client_priv, client_pub = generate_ephemeral_keypair()  # X25519
# Gửi client_hello với client_pub, client_random

# Server
shared = server_priv.exchange(bytes_to_x25519(client_pub))  # ECDH
codec = derive_session_keys_with_psk(
    shared,
    client_random=self._client_random,
    server_random=self._server_random,
    initiator=False,  # Client là initiator
    session_id=self._handshake_session,  # ✅ Dùng chung session
    psk=hashlib.sha256("demo123".encode()).digest()
)
# Codec chứa send_key, recv_key (256-bit), send_prefix, recv_prefix (6 bytes)
```

### HKDF Key Derivation

```python
def derive_session_keys_with_psk(shared_secret, client_random, server_random, 
                                  initiator, session_id, psk):
    salt = client_random + server_random
    if psk:
        salt += hashes.Hash(hashes.SHA256()).update(psk).finalize()
    
    info = b"SRVNC-HANDSHAKE-1" + struct.pack("!I", session_id)
    material = HKDF(SHA256, length=84).derive(shared_secret, salt, info)
    
    send_key = material[:32]
    recv_key = material[32:64]
    send_prefix = material[64:70]
    recv_prefix = material[70:76]
    
    # Đảo role nếu không phải initiator
    if not initiator:
        send_key, recv_key = recv_key, send_key
        send_prefix, recv_prefix = recv_prefix, send_prefix
    
    return SecureCodec(send_key, recv_key, send_prefix, recv_prefix, session_id)
```

### AES-GCM Nonce Construction

```python
def _build_nonce(prefix, counter):
    return prefix + counter.to_bytes(6, "big")  # 12 bytes total

# Mỗi gói có nonce duy nhất = prefix (6B) + packet_number (6B)
# → Không bao giờ lặp vì counter tăng dần
# Header plaintext (stream, seq, packet_number) vào AAD → chống sửa đổi
```

**Ví dụ**:
- `prefix = b'\x01\x02\x03\x04\x05\x06'`
- `packet_number = 1001`
- → `nonce = b'\x01\x02\x03\x04\x05\x06' + 1001.to_bytes(6, "big")`

### Cookie HMAC (Chống Spoof)

```python
def _cookie_msg(address, client_random, timestamp):
    ip, port = address
    ip_bytes = socket.inet_aton(ip)  # 4 bytes IPv4
    port_bytes = struct.pack("!H", int(port))  # 2 bytes
    ts_bytes = struct.pack("!I", int(timestamp))  # 4 bytes
    return ip_bytes + port_bytes + client_random + ts_bytes

cookie = HMAC-SHA256(secret, _cookie_msg(IP|port|random|ts))
# Verify: cho phép lệch ±1 giây, constant-time compare
```

Lý do dùng binary: tránh encoding khác nhau khi chuyển số thành chuỗi.

### Replay Protection

```python
@dataclass
class ReplayWindow:
    highest: int = -1  # Packet number cao nhất đã nhận
    mask: int = 0  # Bitmask 64-bit cho window

def check_and_update(self, number):
    if number > self.highest:
        # Window shift → clear bit cũ nếu quá xa
        self.mask = (self.mask << shift) | 1
        self.highest = number
    else:
        # Đã nhận → reject
        bit = 1 << (self.highest - number)
        if self.mask & bit:
            raise ReplayError("Duplicate packet")
        self.mask |= bit
```

---

## 📡 Kỹ thuật 2: Selective Repeat ARQ (Control Stream)

### SACK (Selective Acknowledgment)

```python
class SackTracker:
    def mark_received(self, sequence):
        if sequence <= self.base:
            return self.base, self._mask()
        
        self.pending.add(sequence)
        # Tìm cửa sổ liên tục bắt đầu từ base
        while (self.base + 1) in self.pending:
            self.base += 1
            self.pending.remove(self.base)
        
        return self.base, self._mask()  # ACK base + bitmap 32-bit
```

**Ví dụ**:
- Nhận sequence: `[1, 2, 4, 5, 7]`
- `base = 2`, `pending = {4, 5, 7}` → `mask = 0b11010` (bit 2, 4, 5 set)

**Code ACK**:
```python
# Sender nhận ACK
ack_base, sack_mask = struct.unpack("!II", ack_payload)

# ACK sequence <= base
acknowledged.add(seq for seq in send_window if seq <= ack_base)

# ACK sequence trong SACK bitmap
for offset in range(32):
    if sack_mask & (1 << offset):
        acknowledged.add(ack_base + 1 + offset)
```

### RTT Estimation (RFC 6298)

```python
class RttEstimator:
    def observe(self, sample):  # sample = now - sent_at
        if self.srtt is None:
            self.srtt = sample
            self.rttvar = sample / 2
        else:
            alpha = 1/8  # Low-pass filter
            beta = 1/4
            self.rttvar = (1-beta) * self.rttvar + beta * abs(self.srtt - sample)
            self.srtt = (1-alpha) * self.srtt + alpha * sample
        
        # RTO = SRTT + 4 * RTTVAR
        self.rto = self.srtt + max(0.1, 4 * self.rttvar)
        self.rto = min(3.0, max(0.1, self.rto))  # Clamp 100ms - 3s
```

**Backoff khi timeout**:
```python
if now >= pending.last_sent + self._rtt.rto:
    if pending.retries >= 10:
        self._metrics.control_lost += 1
        del self._send_window[seq]
    else:
        pending.retries += 1
        self._rtt.backoff()  # RTO *= 2
        self._transmit_control(seq, pending)
```

### Retransmission Logic

```python
# Sender đợi window < 32 packets
while len(self._send_window) >= SACK_WINDOW:
    time.sleep(0.001)

# Chạy retransmit loop mỗi 10ms
while self._running.is_set():
    now = time.monotonic()
    for seq, pending in list(self._send_window.items()):
        if now >= pending.last_sent + self._rtt.rto:
            if pending.retries >= 10:
                self._metrics.control_lost += 1
                del self._send_window[seq]
            else:
                pending.retries += 1
                self._rtt.backoff()
                self._transmit_control(seq, pending)
    time.sleep(0.01)
```

---

## 🎬 Kỹ thuật 3: Best-effort + Token Bucket (Video Stream)

### Fragmentation

```python
MAX_UDP_PAYLOAD = 1200  # Tránh IP fragmentation
BASE_HEADER_SIZE = 17 bytes
FRAGMENT_TLV = 4 bytes (index + count)
AEAD_TAG = 16 bytes
MAX_FRAGMENT_PAYLOAD = 1200 - 17 - 4 - 16 = 1163 bytes

def send_video_frame(self, frame):
    fragments = [frame[i:i+MAX_FRAGMENT_PAYLOAD] 
                 for i in range(0, len(frame), MAX_FRAGMENT_PAYLOAD)]
    
    for index, chunk in enumerate(fragments):
        header = build_header(
            stream_id=STREAM_VIDEO,
            fragment_index=index,
            fragment_count=len(fragments),
            ...
        )
        self._send_packet(...)
```

### Token Bucket Pacing

```python
class TokenBucket:
    def __init__(self, rate_bps, burst_bytes):
        self.rate_bps = max(64000, rate_bps)  # Min 64 Kbps
        self.capacity = burst_bytes  # ✅ Không phình
        self.tokens = burst_bytes
    
    def consume(self, amount):
        self._refill()  # tokens += elapsed * rate
        if amount <= self.tokens:
            self.tokens -= amount
            return 0.0
        wait = (amount - self.tokens) / (rate_bps / 8.0)
        self.tokens = 0
        return wait  # Thời gian sleep để đợi token tích lũy
```

**Tại sao phải pacing**: Không pacing → client queue phình → độ trễ tăng.

### Drop old frames khi congestion

```python
wait = self._video_bucket.consume(len(chunk) + overhead)
if wait > 0.2:  # Nghẽn > 200ms
    # Bỏ hết frame backlog để đuổi kịp real-time
    while True:
        try:
            _ = self._video_queue.get_nowait()
        except queue.Empty:
            break
else:
    time.sleep(wait)
```

Lý do drop: Bỏ frame cũ tốt hơn trễ dài.

### Reassembly + Jitter Buffer

```python
def _handle_video(self, packet):
    if packet.fragment_count > 1:
        key = (packet.sequence_number, packet.address)
        entry = self._video_reassembly.get(key)
        
        if not entry:
            fragments = [None] * packet.fragment_count
            created = time.monotonic()
        else:
            fragments, created = entry
        
        fragments[packet.fragment_index] = packet.payload
        self._video_reassembly[key] = (fragments, created)
        
        # Chờ đủ fragments
        if all(f is not None for f in fragments):
            data = b"".join(f for f in fragments)
            self._queue_video_frame(packet.sequence_number, data, packet.address)
            
        # Timeout sau 500ms → drop partial frame
        if now - created > 0.5:
            del self._video_reassembly[key]
```

Jitter buffer 33ms:
```python
self._video_buffer.append((time.time(), sequence, payload, address))
if len(self._video_buffer) > 4:
    self._flush_video_buffer(force=True)

def _flush_video_buffer(self, force):
    now = time.time()
    while self._video_buffer:
        ts, sequence, payload, address = self._video_buffer[0]
        if not force and now - ts < 0.03:  # Đợi 33ms để giảm jitter
            break
        self._video_buffer.popleft()
        self._video_handler(sequence, payload, address)
```

---

## 🎨 Kỹ thuật 4: Video Capture & Compression

### JPEG Encoding (server.py)

```python
def _video_loop(self):
    frame_interval = 1.0 / self.config.fps  # 10 FPS → 100ms
    
    while self._running:
        start = time.time()
        frame = ImageGrab.grab()  # PIL capture
        
        # ✅ Tối ưu 1: Downscale 50%
        w, h = frame.size
        frame = frame.resize((w//2, h//2))
        
        buffer = io.BytesIO()
        # ✅ Tối ưu 2: Quality 45
        frame.save(buffer, format="JPEG", quality=45)
        data = buffer.getvalue()
        
        self.connection.send_video_frame(data)
        
        elapsed = time.time() - start
        time.sleep(max(0, frame_interval - elapsed))
```

Chất lượng:
- Không resize, 100%: ~500 KB/frame
- 50% size, quality 45: ~50 KB/frame
- Bitrate: 50 KB * 10 FPS * 8 = 4 Mbps → 500 Kbps

### Display (client.py)

```python
class VideoWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.label = tk.Label(self.root)
        self._frames = queue.Queue()
        self._photo = None
    
    def enqueue_frame(self, frame_bytes):
        self._frames.put(frame_bytes)
    
    def _pump_frames(self):
        while True:
            try:
                frame = self._frames.get_nowait()
            except queue.Empty:
                break
            image = Image.open(io.BytesIO(frame))
            self._photo = ImageTk.PhotoImage(image=image)
            self.label.configure(image=self._photo)
        
        self.root.update_idletasks()
        self.root.after(30, self._pump_frames)  # 30ms refresh
```

---

## 📊 Kỹ thuật 5: Telemetry & Metrics

### Metrics Collection (srudp.py)

```python
@dataclass
class Metrics:
    rtt_samples: Deque[float]
    control_sent: int
    control_retrans: int
    control_lost: int
    video_frames: int
    video_bytes: int
    video_jitter_samples: Deque[float]
    
    def snapshot(self):
        rtt_p50 = median(self.rtt_samples) if self.rtt_samples else 0
        loss_percent = (self.control_lost / self.control_sent) * 100
        jitter_p95 = percentile(self.video_jitter_samples, 95)
        
        return {
            "rtt_ms_p50": rtt_p50 * 1000,
            "ctrl_loss_percent": loss_percent,
            "video_jitter_p95_ms": jitter_p95 * 1000,
            ...
        }
```

Overlay hiển thị:
- `ctrl_rtt_p50_ms`: độ trễ phản hồi chuột/phím
- `ctrl_loss_percent`: mất gói control (kỳ vọng 0% sau ARQ)
- `video_render_fps`: FPS hiển thị
- `video_jitter_p95_ms`: độ dao động khung hình

---

## 🌐 Kỹ thuật 6: NAT Traversal

### UDP Hole Punching

```python
def send_hole_punch(sock, peer):
    # Đánh thức NAT state table
    for _ in range(3):
        sock.sendto(b"\x00", peer)
        time.sleep(0.05)
```

Khi client/server có NAT:
1. Lần đầu `sendto` từ nội bộ → NAT mở mapping
2. Peer gửi ngược → packet đi qua mapping
3. Thiết lập kết nối P2P

### STUN (Session Traversal Utilities for NAT)

```python
def discover_reflexive_address(sock, stun_server):
    request = struct.pack("!HHHI12x", 0x0001, 0, 0, 0x2112A442)
    sock.sendto(request, stun_server)
    
    try:
        response, _ = sock.recvfrom(1024)
        # Parse RESPONSE với MAPPED-ADDRESS (IPv4)
        if response[0:2] == b'\x01\x01':  # Response + Success
            msg_type, msg_len, magic = struct.unpack("!HHI12x", response[:20])
            # Parse XOR-MAPPED-ADDRESS
            return (ip, port)
    except:
        return None
```

Tác dụng: biết IP:port public khi ngồi sau NAT.

### Relay Fallback

```python
class RelayClient:
    def register(self, sock, role):
        message = {
            "action": "register",
            "session": self.config.session,
            "role": role
        }
        sock.sendto(json.dumps(message).encode(), self.config.relay_addr)
        
        try:
            data, _ = sock.recvfrom(2048)
            reply = json.loads(data)
            if reply.get("status") == "ok":
                self._peer_addr = reply.get("peer")
                return True
        except:
            pass
        return False
```

Khi hole punching lỗi → dùng relay TURN/STUN.

---

## 🚀 Cách áp dụng code

### 1. Remote Desktop

```bash
# Server (host)
python -m srvnc.server --host 0.0.0.0 --port 5000 \
    --client-host 192.168.1.100 --client-port 5001 \
    --password mypass --fps 10 --bitrate 2000000

# Client (viewer)
python -m srvnc.client --host 0.0.0.0 --port 5001 \
    --server-host 192.168.1.50 --server-port 5000 --password mypass
```

### 2. Game streaming

Chỉnh `--fps 30`, `--bitrate 10000000`.

### 3. Tích hợp vào app Python

```python
from srvnc import SRUDPConnection, STREAM_CONTROL, STREAM_VIDEO

# Server side
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 5000))
psk = hashlib.sha256("mypass".encode()).digest()

conn = SRUDPConnection(sock, is_server=True, psk=psk)
conn.register_control_handler(my_control_handler)
conn.server_handshake()
conn.start()

# Gửi control event
conn.send_control_event({"type": "mouse_move", "x": 100, "y": 200})

# Gửi video frame
conn.send_video_frame(jpeg_bytes)
```

### 4. NAT traversal

```bash
# Relay server
python -m srvnc.relay --host 0.0.0.0 --port 7000

# Server với STUN
python -m srvnc.server ... --stun-server stun.l.google.com:19302

# Fallback relay
python -m srvnc.server ... --relay 1.2.3.4:7000 --session abc123
```

---

## 🎓 Kiến thức cần nắm

### Network

- UDP (`socket.SOCK_DGRAM`)
- MTU 1200, IP fragmentation
- NAT/PAT
- STUN
- Hole punching
- TURN/Relay

### Cryptography

- ECDH (X25519)
- HKDF
- AES-GCM
- HMAC-SHA256
- PSK
- Nonce uniqueness, AAD

### Protocols

- Selective Repeat ARQ
- SACK
- RTT/RTO (RFC 6298)
- Token bucket
- Jitter buffer

### Python

- `threading` (daemon)
- `queue.Queue`
- `collections.deque`
- `socket`
- PIL
- tkinter

---

## 📈 Telemetry và hiệu năng

Vai trò của overlay:
1. Xác nhận hoạt động (RTT FPS loss thấp)
2. Đánh giá mạng
3. Điều chỉnh tham số
4. Demo và phô bày công việc

Kỳ vọng:
- `ctrl_loss_percent = 0%` sau ARQ
- `ctrl_rtt_p50_ms ≤ 80` ở jitter80
- `video_send_fps ≥ 12`
- `video_render_fps ≈ video_send_fps`
- `video_jitter_p95_ms ≤ 50`

---

## 🔗 Tài liệu liên quan

- RFC 6298: RTT/RTO
- TLS 1.3: Handshake, HKDF
- QUIC: UDP transport, ARQ, multiplexing
- WebRTC: NAT traversal, pacing

---

## ✅ Tổng kết

SR-VNC là một demo về SRUDP trên UDP, có:
- Mã hóa AES-GCM với nonce định danh
- Control 100% reliable (Selective Repeat ARQ)
- Video best-effort với pacing
- Cookie chống spoof
- Telemetry thời gian thực
- NAT traversal

Áp dụng: remote desktop, streaming, IoT, automation qua mạng kém ổn định.

**Các kỹ thuật chính**:
1. X25519 ECDH + HKDF
2. AES-GCM 12-byte nonce
3. Replay window 64-bit
4. Selective Repeat + SACK
5. RFC 6298 RTT/RTO
6. Token bucket
7. STUN/Relay
8. PIL, tkinter

