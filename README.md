# BÀI TẬP LỚN: LẬP TRÌNH MẠNG  

## SR-VNC: Secure Reliable Virtual Network Computing

> 📘 *Hệ thống Remote Desktop qua UDP với bảo mật và độ tin cậy. Server chụp và truyền màn hình, client hiển thị và gửi điều khiển chuột/phím. Sử dụng SRUDP (Secure Reliable UDP) với mã hóa AES-GCM, Selective Repeat ARQ cho control stream, và best-effort cho video stream.*

---

## 🧑‍💻 THÔNG TIN NHÓM

| STT | Họ và Tên | MSSV | Email | Đóng góp |
|-----|-----------|------|-------|----------|
| 1 | [Họ tên sinh viên 1] | [MSSV] | [Email] | Client module, GUI, telemetry |
| 2 | [Họ tên sinh viên 2] | [MSSV] | [Email] | Server module, video capture, control |
| 3 | [Họ tên sinh viên 3] | [MSSV] | [Email] | SRUDP transport, crypto, NAT traversal |

**Tên nhóm:** [Tên nhóm của bạn]  
**Chủ đề đã đăng ký:** Remote Desktop / Secure UDP Transport

---

## 🧠 MÔ TẢ HỆ THỐNG

> **SR-VNC** là hệ thống Remote Desktop cho phép điều khiển máy tính từ xa qua mạng UDP với hai đặc điểm chính: **bảo mật** (mã hóa AES-GCM) và **độ tin cậy** (Selective Repeat ARQ cho control, best-effort cho video).

**Tổng quan:**
- **Server (Host)**: Chụp màn hình bằng `PIL.ImageGrab`, nén JPEG, gửi qua luồng video (best-effort). Nhận lệnh điều khiển chuột/phím từ client và thực thi bằng `pyautogui`.
- **Client (Viewer)**: Hiển thị video frames real-time bằng Tkinter GUI, thu thập input events (chuột/phím) và gửi lên server qua luồng điều khiển (100% reliable với ARQ retransmission).
- **SRUDP Transport**: Lớp transport tùy biến trên UDP với handshake X25519 + HKDF, mã hóa AES-GCM, replay protection, và hai luồng song song (control reliable + video best-effort).

**Cấu trúc logic tổng quát:**
```
┌─────────────┐                    ┌─────────────┐
│   Client    │ ◄─── SRUDP ───► │   Server    │
│  (Viewer)   │  AES-GCM + ARQ   │   (Host)    │
│             │                  │             │
│ - Display   │                  │ - Capture   │
│ - Input     │                  │ - Control   │
│ - Telemetry │                  │ - Encode    │
└─────────────┘                  └─────────────┘
```

**Sơ đồ hệ thống:**

![System Diagram](./statics/diagram.png)

---

## ⚙️ CÔNG NGHỆ SỬ DỤNG

> Liệt kê công nghệ, framework, thư viện chính mà nhóm sử dụng.

| Thành phần | Công nghệ | Ghi chú |
|------------|-----------|---------|
| Ngôn ngữ | Python 3.8+ | Server và Client đều dùng Python |
| Server | `PIL`/`Pillow` (ImageGrab), `pyautogui` | Chụp màn hình, điều khiển input |
| Client | `tkinter`, `PIL` (ImageTk) | GUI hiển thị video, capture input |
| Transport | **SRUDP** (Custom UDP protocol) | Dual-stream: control (ARQ) + video (best-effort) |
| Cryptography | `cryptography` | X25519 ECDH, HKDF, AES-GCM (256-bit) |
| NAT Traversal | STUN protocol, UDP hole punching, Relay fallback | Tự implement STUN client và relay server |
| Mã hóa | AES-GCM với nonce deterministic | Prefix (6B) + packet number (6B), AAD = header |
| Reliability | Selective Repeat ARQ + SACK | RFC 6298 RTT/RTO estimation |

---

## 🚀 HƯỚNG DẪN CHẠY DỰ ÁN

### 1. Clone repository
```bash
git clone <repository-url>
cd assignment-network-project
```

### Cài đặt dependencies
```bash
# Từ thư mục gốc dự án
pip install -r requirements.txt
```

**Dependencies chính:**
- `cryptography` - X25519, AES-GCM, HKDF
- `Pillow` - ImageGrab (server), Image/ImageTk (client)
- `pyautogui` - Điều khiển chuột/phím (server)
- `tkinter` - GUI (thường có sẵn với Python)

### 2. Chạy server
```bash
# Cơ bản (localhost)
python -m source.server.server --host 0.0.0.0 --port 5000 \
    --client-host 127.0.0.1 --client-port 5001 --password demo123

# Với tùy chỉnh FPS và bitrate
python -m source.server.server --host 0.0.0.0 --port 5000 \
    --client-host 127.0.0.1 --client-port 5001 \
    --password demo123 --fps 15 --bitrate 1000000

# Với NAT traversal (STUN) hoặc relay
python -m source.server.server ... --stun-server stun.l.google.com:19302
python -m source.server.server ... --relay 1.2.3.4:7000 --session abc123
```

### 3. Chạy client
```bash
# Cơ bản (localhost) - chạy trong terminal riêng sau khi server đã khởi động
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 127.0.0.1 --server-port 5000 --password demo123

# Qua mạng LAN
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 192.168.1.50 --server-port 5000 --password secret123

# Với NAT traversal hoặc relay (cấu hình giống server)
python -m source.client.client ... --stun-server stun.l.google.com:19302
python -m source.client.client ... --relay 1.2.3.4:7000 --session abc123
```

### 4. Kiểm thử nhanh
```bash
# Terminal 1: Server
python -m source.server.server --host 127.0.0.1 --port 6000 \
    --client-host 127.0.0.1 --client-port 6001 --password test123

# Terminal 2: Client (sau khi server đã chạy)
python -m source.client.client --host 0.0.0.0 --port 6001 \
    --server-host 127.0.0.1 --server-port 6000 --password test123

# Kết quả mong đợi:
# - Server log: "[INFO] Starting SR-VNC host on..."
# - Client hiển thị cửa sổ với màn hình remote desktop
# - Di chuyển chuột trong cửa sổ client → server di chuyển con trỏ tương ứng
# - Click chuột/phím trong client → server thực hiện action
# - Overlay telemetry hiển thị RTT, FPS, loss% ở góc trên trái cửa sổ
```

**Lưu ý:** Đảm bảo server đã chạy trước khi khởi động client. Password phải khớp giữa client và server.

---

## 🔗 GIAO TIẾP (GIAO THỨC SỬ DỤNG)

**SRUDP Protocol** - Secure Reliable UDP với handshake X25519 và hai luồng song song.

### Handshake Messages (JSON qua UDP, trước khi mã hóa)

| Message Type | Direction | Protocol | Input | Output |
|--------------|-----------|----------|-------|--------|
| `client_hello` | Client → Server | UDP/JSON | `{"type":"client_hello","client_random":"...","client_pub":"...","timestamp":...}` | `{"type":"hello_retry","cookie":"...","timestamp":...}` hoặc `{"type":"server_hello","server_random":"...","server_pub":"..."}` |
| `hello_retry` | Server → Client | UDP/JSON | (Cookie challenge) | Client gửi lại `client_hello` với cookie |
| `server_hello` | Server → Client | UDP/JSON | (Server public key + nonce) | `{"type":"client_finish"}` |
| `client_finish` | Client → Server | UDP/JSON | (Finalize handshake) | Session established |

**Sau handshake**: Tất cả payload được mã hóa AES-GCM.

### Data Streams (AES-GCM encrypted)

| Stream ID | Type | Protocol | Reliability | Mục đích |
|-----------|------|----------|-------------|----------|
| `0x01` | Control | SRUDP | **100% reliable** (Selective Repeat ARQ) | Chuột/phím events, metrics |
| `0x02` | Video | SRUDP | **Best-effort** (drop old frames) | Video frames (JPEG), fragmentation |

### Control Events (JSON trong control stream)

| Event Type | Direction | Input | Mục đích |
|------------|-----------|-------|----------|
| `mouse_move` | Client → Server | `{"type":"mouse_move","x":100,"y":200}` | Di chuyển con trỏ |
| `mouse_click` | Client → Server | `{"type":"mouse_click","x":100,"y":200,"button":"left","pressed":true}` | Click chuột |
| `key_down` / `key_up` | Client → Server | `{"type":"key_down","key":"a"}` | Nhấn phím |
| `metrics` | Server → Client | `{"type":"metrics","values":{...}}` | Telemetry (FPS, bitrate) |

---

## 📊 KẾT QUẢ THỰC NGHIỆM

> Đưa ảnh chụp kết quả hoặc mô tả log chạy thử.

![Demo Result](./statics/result.png)

---

## 🧩 CẤU TRÚC DỰ ÁN
```
assignment-network-project/
├── README.md                    # File này
├── INSTRUCTION.md               # Hướng dẫn (KHÔNG chỉnh sửa)
├── requirements.txt             # Dependencies (root)
├── statics/                     # Hình ảnh, diagram
│   ├── diagram.png
│   └── result.png
└── source/                      # Toàn bộ mã nguồn
    ├── .gitignore
    ├── __init__.py
    ├── requirements.txt
    ├── client/                  # Module phía client
    │   ├── README.md
    │   ├── __init__.py
    │   └── client.py           # SRVNCClient, VideoWindow
    ├── server/                  # Module phía server
    │   ├── README.md
    │   ├── __init__.py
    │   └── server.py            # SRVNCServer
    ├── srudp.py                 # SRUDP transport layer
    ├── crypto.py                # X25519 handshake, AES-GCM, HKDF
    ├── nat.py                   # STUN, UDP hole punching
    ├── relay.py                 # UDP relay server (TURN fallback)
    └── metrics_overlay.py        # Telemetry formatting
```

**Giải thích cấu trúc:**
- `client/`: Viewer application với Tkinter GUI
- `server/`: Host application với video capture và input control
- `srudp.py`: Core transport với handshake, encryption, ARQ, fragmentation
- `crypto.py`: Cryptographic primitives (X25519, HKDF, AES-GCM, cookie HMAC)
- `nat.py`: NAT traversal helpers (STUN discovery, hole punching)
- `relay.py`: Fallback relay server khi NAT strict
- `metrics_overlay.py`: Tính toán và format telemetry metrics

---

## 🧩 HƯỚNG PHÁT TRIỂN THÊM

> Nêu ý tưởng mở rộng hoặc cải tiến hệ thống.

- [ ] **Video codec nâng cao**: Thay JPEG bằng H.264/H.265 với hardware encoding để giảm bitrate và tăng chất lượng
- [ ] **Adaptive bitrate**: Tự động điều chỉnh FPS/quality dựa trên RTT và loss rate
- [ ] **Multi-monitor support**: Hỗ trợ nhiều màn hình, cho phép chọn monitor để share
- [ ] **File transfer**: Thêm luồng reliable thứ 3 cho file transfer qua SRUDP
- [ ] **Clipboard sync**: Đồng bộ clipboard giữa client và server
- [ ] **Audio streaming**: Truyền audio qua luồng best-effort riêng
- [ ] **Mobile client**: Port client lên Android/iOS với UI touch-friendly
- [ ] **Web client**: WebRTC-based client chạy trên browser
- [ ] **Session recording**: Ghi lại session để playback sau
- [ ] **Multi-user support**: Nhiều client cùng xem một server session
- [ ] **Permission system**: Phân quyền (chỉ xem, chỉ điều khiển, full access)
- [ ] **Cloud deployment**: Deploy relay server lên cloud (AWS/GCP) với load balancing

---

## 📝 GHI CHÚ

- Repo tuân thủ đúng cấu trúc đã hướng dẫn trong `INSTRUCTION.md`.
- Đảm bảo test kỹ trước khi submit.

---

## 📚 TÀI LIỆU THAM KHẢO

> Liệt kê các tài liệu, API docs, hoặc nguồn tham khảo đã sử dụng.

### RFC Standards
- **RFC 5389**: Session Traversal Utilities for NAT (STUN)
- **RFC 6298**: Computing TCP's Retransmission Timer (RTT/RTO estimation)
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3 (HKDF inspiration)
- **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport (Selective Repeat ARQ, dual-stream design)

### Cryptography
- **X25519**: Elliptic Curve Diffie-Hellman Key Exchange (`cryptography` library)
- **AES-GCM**: Authenticated Encryption (NIST SP 800-38D)
- **HKDF**: HMAC-based Key Derivation Function (RFC 5869)

### Libraries & Tools
- **cryptography**: [https://cryptography.io/](https://cryptography.io/) - Python cryptography library
- **Pillow (PIL)**: [https://pillow.readthedocs.io/](https://pillow.readthedocs.io/) - Python Imaging Library
- **tkinter**: Built-in Python GUI toolkit

### Protocols & Techniques
- **Selective Repeat ARQ**: Reliable data transmission over unreliable channels
- **SACK (Selective Acknowledgment)**: Efficient ACK mechanism for out-of-order packets
- **Token Bucket**: Bandwidth pacing algorithm
- **UDP Hole Punching**: NAT traversal technique
- **STUN Protocol**: NAT type discovery

### Related Projects
- **VNC**: Remote desktop protocol (inspiration, nhưng dùng TCP)
- **WebRTC**: Real-time communication (similar dual-stream approach)
- **QUIC**: Secure UDP transport (inspiration for SRUDP design)