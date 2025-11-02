# MODULE CLIENT

> 📘 *Module **client** của SR-VNC – Remote Desktop Viewer. Hiển thị màn hình remote desktop real-time và gửi sự kiện điều khiển chuột/phím đến server qua SRUDP (Secure Reliable UDP) transport.*

---

## 🎯 MỤC TIÊU

Client chịu trách nhiệm:
- **Hiển thị màn hình remote**: Nhận video frames (JPEG) từ server qua luồng video và render real-time bằng Tkinter GUI
- **Thu thập input events**: Bắt sự kiện chuột/phím từ người dùng và gửi lên server qua luồng điều khiển (100% reliable với Selective Repeat ARQ)
- **Hiển thị telemetry**: Overlay metrics (RTT, FPS, loss%, jitter) lên cửa sổ video để theo dõi chất lượng kết nối
- **Quản lý kết nối bảo mật**: Thực hiện handshake X25519 + HKDF, duy trì session SRUDP với AES-GCM encryption, xử lý NAT traversal

---

## ⚙️ CÔNG NGHỆ SỬ DỤNG

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ | Python 3.8+ |
| Thư viện chính | `tkinter` (GUI), `PIL`/`Pillow` (Image processing), `cryptography` (X25519, AES-GCM, HKDF) |
| Giao thức | **SRUDP** (Secure Reliable UDP) - X25519 ECDH + HKDF key derivation + AES-GCM encryption + Selective Repeat ARQ |
| Module phụ thuộc | `..srudp` (transport layer), `..crypto` (handshake), `..nat` (STUN/relay), `..metrics_overlay` (telemetry) |

**Kiến trúc chính**:
- `SRVNCClient`: Logic chính, quản lý SRUDP connection, handlers cho video/control
- `VideoWindow`: Tkinter window hiển thị frames và capture mouse/keyboard input
- `SRUDPConnection`: Lớp transport (handshake X25519, AES-GCM encryption, reliable control stream + best-effort video stream)

---

## 🚀 HƯỚNG DẪN CHẠY

### Cài đặt
```bash
# Cài đặt dependencies (từ thư mục gốc dự án)
pip install -r requirements.txt
```

**Dependencies chính**:
- `cryptography` - X25519, AES-GCM, HKDF key derivation
- `Pillow` - JPEG decode và display
- `tkinter` - GUI (thường có sẵn với Python, trên Linux có thể cần `python3-tk`)

### Chạy chương trình

**Cơ bản (localhost)**:
```bash
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 127.0.0.1 --server-port 5000 \
    --password demo123
```

**Qua mạng LAN**:
```bash
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 192.168.1.50 --server-port 5000 \
    --password secret123
```

**Với NAT traversal (STUN)**:
```bash
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 192.168.1.50 --server-port 5000 \
    --password demo123 \
    --stun-server stun.l.google.com:19302
```

**Fallback qua relay server**:
```bash
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 192.168.1.50 --server-port 5000 \
    --password demo123 \
    --relay 1.2.3.4:7000 --session abc123
```

### Cấu hình (nếu cần)

**Tham số dòng lệnh**:
- `--host`: IP bind cho UDP socket (mặc định `0.0.0.0`)
- `--port`: Port local (mặc định `5001`)
- `--server-host`: IP server (mặc định `127.0.0.1`)
- `--server-port`: Port server (mặc định `5000`)
- `--password`: Mật khẩu PSK (SHA-256 dùng cho HKDF key derivation)
- `--stun-server`: STUN server cho NAT traversal (format `host:port`)
- `--relay`: Relay server fallback khi NAT strict (format `host:port`)
- `--session`: Session ID khi dùng relay (mặc định UUID tự động)
- `--bitrate`: Bitrate video pacing (mặc định `2000000` = 2 Mbps)

**Lưu ý**: Đảm bảo server đã chạy trước khi khởi động client.

---

## 📦 CẤU TRÚC
```
source/client/
├── README.md          # File này
├── __init__.py        # Module exports (SRVNCClient, ClientConfig, main)
└── client.py          # Module chính: SRVNCClient, VideoWindow, main()
```

**Luồng hoạt động**:
1. `main()` → parse command-line arguments → tạo `ClientConfig` → khởi tạo `SRVNCClient`
2. `client.start()` → tạo UDP socket → tạo `SRUDPConnection` → thực hiện `client_handshake()` (X25519 + HKDF) → `start()` transport threads
3. `VideoWindow` → Tkinter event loop → capture mouse/keyboard events → gọi `send_mouse_move()`, `send_key_event()`
4. Video frames nhận được từ server → `_handle_video()` → `enqueue_frame()` → `_pump_frames()` → decode JPEG → render lên GUI
5. Metrics loop (background thread) → `get_metrics()` từ connection → compose overlay → `update_overlay()` hiển thị telemetry

---

## 💡 SỬ DỤNG

### Ví dụ 1: Kết nối localhost
```bash
# Terminal 1: Server
python -m source.server.server --host 127.0.0.1 --port 6000 \
    --client-host 127.0.0.1 --client-port 6001 \
    --password demo123

# Terminal 2: Client
python -m source.client.client --host 0.0.0.0 --port 6001 \
    --server-host 127.0.0.1 --server-port 6000 \
    --password demo123
```

### Ví dụ 2: Qua mạng LAN với bitrate thấp
```bash
python -m source.client.client --host 0.0.0.0 --port 5001 \
    --server-host 192.168.1.50 --server-port 5000 \
    --password secret123 --bitrate 500000
```

### Tương tác với ứng dụng
- **Di chuyển chuột**: Di chuyển chuột trong cửa sổ client → server di chuyển con trỏ tương ứng
- **Click chuột**: Click trong cửa sổ → server thực hiện click event
- **Nhấn phím**: Gõ phím trong cửa sổ → server nhận key event
- **Xem metrics**: Overlay telemetry hiển thị RTT, FPS, loss%, jitter ở góc trên trái cửa sổ

---

## 📝 GHI CHÚ

### Yêu cầu hệ thống
- **Python 3.8+**
- **Tkinter**: Thường có sẵn với Python (trên Linux có thể cần cài `python3-tk`)
- **Windows**: Không cần quyền đặc biệt cho client (chỉ server cần quyền để control desktop)

### Troubleshooting

**Lỗi "Handshake timed out"**:
- Kiểm tra server đã chạy chưa: `python -m source.server.server ...`
- Kiểm tra firewall có chặn UDP port không
- Thử dùng `--relay` nếu có NAT strict (symmetric NAT)

**Không hiển thị video (black screen)**:
- Kiểm tra overlay metrics: `video_render_fps` phải > 0
- Nếu `video_render_fps = 0` nhưng `video_send_fps > 0` → client không decode được (có thể do session keys lệch, xem log `[DEBUG] decrypt failed: InvalidTag`)
- Đảm bảo password khớp giữa client và server

**Control (chuột/phím) không hoạt động**:
- Kiểm tra `ctrl_rtt_p50_ms` trong overlay (kỳ vọng < 100ms trong LAN)
- Nếu `ctrl_loss_percent > 0` → mạng mất gói, ARQ sẽ tự động retransmit
- Xem log: `[DEBUG] ACK received for sequences` để xác nhận control packets được acknowledge

**Windows UDP lỗi 10054 (ConnectionResetError)**:
- Đã có workaround trong code (bỏ qua `ConnectionResetError`)
- Nếu vẫn lỗi, thử chạy với quyền admin

### Best practices
- Dùng `--bitrate` phù hợp với băng thông mạng (ví dụ: LAN 2 Mbps, WAN 500 Kbps)
- Enable STUN nếu có NAT: `--stun-server stun.l.google.com:19302`
- Session relay nên dùng UUID để tránh conflict: `--session $(uuidgen)` hoặc dùng `--session my-unique-id`

### Telemetry metrics
Overlay hiển thị các metrics quan trọng:
- `ctrl_rtt_p50_ms`: Độ trễ phản hồi control (kỳ vọng < 100ms trong LAN)
- `ctrl_loss_percent`: Tỷ lệ mất gói control (kỳ vọng 0% sau ARQ retransmission)
- `video_render_fps`: FPS hiển thị thực tế
- `video_jitter_p95_ms`: Độ dao động khung hình (kỳ vọng < 50ms)