# MODULE SERVER

> 📘 *Module **server** của SR-VNC – Remote Desktop Host. Chụp màn hình, nén JPEG và gửi qua luồng video. Nhận lệnh điều khiển chuột/phím và thực thi bằng pyautogui.*

---

## 🎯 MỤC TIÊU

Server chịu trách nhiệm:
- **Chụp màn hình**: Sử dụng `PIL.ImageGrab` để capture desktop, downscale và encode JPEG
- **Gửi video frames**: Truyền video qua luồng best-effort của SRUDP với token bucket pacing
- **Nhận điều khiển**: Xử lý lệnh chuột/phím từ client qua luồng reliable control
- **Quản lý session**: Thực hiện handshake X25519, duy trì SRUDP connection, NAT traversal

---

## ⚙️ CÔNG NGHỆ SỬ DỤNG

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ | Python 3.8+ |
| Thư viện chính | `PIL`/`Pillow` (ImageGrab, JPEG encoding), `pyautogui` (Input control) |
| Giao thức | **SRUDP** (Secure Reliable UDP) - X25519 + AES-GCM + Selective Repeat ARQ |
| Module phụ thuộc | `..srudp`, `..crypto`, `..nat` |

**Kiến trúc**:
- `SRVNCServer`: Logic chính, quản lý video capture loop, control handlers
- `SRUDPConnection`: Lớp transport (handshake, encryption, reliable/best-effort streams)
- Thread riêng cho video capture và metrics reporting

---

## 🚀 HƯỚNG DẪN CHẠY

### Cài đặt
```bash
# Cài đặt dependencies (từ thư mục gốc dự án)
pip install -r requirements.txt
```

**Dependencies chính**:
- `Pillow` - ImageGrab, JPEG encoding
- `pyautogui` - Mouse/keyboard control
- `cryptography` - X25519, AES-GCM

### Chạy chương trình

**Cơ bản (localhost)**:
```bash
python -m source.server.server --host 0.0.0.0 --port 5000 \
    --client-host 127.0.0.1 --client-port 5001 \
    --password demo123
```

**Với NAT traversal**:
```bash
# Sử dụng STUN để discover reflexive address
python -m source.server.server --host 0.0.0.0 --port 5000 \
    --client-host 192.168.1.100 --client-port 5001 \
    --password demo123 \
    --stun-server stun.l.google.com:19302

# Fallback qua relay server
python -m source.server.server --host 0.0.0.0 --port 5000 \
    --client-host 192.168.1.100 --client-port 5001 \
    --password demo123 \
    --relay 1.2.3.4:7000 --session abc123
```

**Tùy chỉnh video quality**:
```bash
python -m source.server.server ... --fps 15 --bitrate 1000000  # 15 FPS, 1 Mbps
```

### Cấu hình

**Tham số dòng lệnh**:
- `--host`: IP bind cho UDP socket (mặc định `0.0.0.0`)
- `--port`: Port server (mặc định `5000`)
- `--client-host`: IP client dự kiến (mặc định `127.0.0.1`)
- `--client-port`: Port client dự kiến (mặc định `5001`)
- `--password`: Mật khẩu PSK (SHA-256 dùng cho HKDF)
- `--fps`: Frame rate capture (mặc định `10`)
- `--stun-server`: STUN server cho NAT traversal (format `host:port`)
- `--relay`: Relay server fallback (format `host:port`)
- `--session`: Session ID khi dùng relay (mặc định `srvnc-demo`)
- `--bitrate`: Bitrate video pacing (mặc định `2000000` = 2 Mbps)

---

## 📦 CẤU TRÚC

```
source/server/
├── README.md          # File này
├── __init__.py        # Module exports
└── server.py          # Module chính: SRVNCServer
```

**Luồng hoạt động**:
1. `main()` → parse arguments → tạo `SRVNCServer(config)`
2. `server.start()` → tạo `SRUDPConnection` → `server_handshake()` → `start()`
3. `_video_thread`: Loop capture → `ImageGrab.grab()` → resize → JPEG encode → `send_video_frame()`
4. `_metrics_thread`: Tính toán FPS, bitrate → `send_metrics_overlay()`
5. Control messages nhận được → `_handle_control()` → `pyautogui` thực thi

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
# Server IP: 192.168.1.50
python -m source.server.server --host 0.0.0.0 --port 5000 \
    --client-host 192.168.1.100 --client-port 5001 \
    --password secret123 --fps 5 --bitrate 500000
```

### Ví dụ 3: High quality cho game streaming
```bash
python -m source.server.server ... --fps 30 --bitrate 10000000
```

---

## 📝 GHI CHÚ

### Yêu cầu hệ thống
- **Python 3.8+**
- **PIL/Pillow**: `pip install Pillow`
- **pyautogui**: `pip install pyautogui`
- **Windows**: Cần quyền admin cho một số thao tác input

### Troubleshooting

**Lỗi "Handshake timed out"**:
- Kiểm tra client đã kết nối chưa
- Kiểm tra firewall chặn UDP port
- Thử dùng `--relay` nếu có NAT strict

**Video không gửi được**:
- Kiểm tra `host_video_fps` trong log metrics
- Nếu FPS = 0 → vấn đề với `ImageGrab.grab()` (có thể thiếu quyền trên headless server)
- Xem log: `[INFO] Starting SR-VNC host on...`

**Control không phản hồi**:
- Kiểm tra `ctrl_loss_percent` trong metrics
- Nếu loss > 0 → mạng mất gói, ARQ retransmit
- Xem log: `[DEBUG] Reliable control acknowledged`

**Windows pyautogui lỗi**:
- Chạy với quyền admin nếu cần
- Kiểm tra `pyautogui.FAILSAFE = False` đã set

### Best practices
- Dùng `--fps` và `--bitrate` phù hợp với băng thông (ví dụ: WAN dùng 5 FPS, 500 Kbps)
- Enable STUN nếu có NAT: `--stun-server stun.l.google.com:19302`
- Session relay nên dùng unique ID để tránh conflict

### Video optimization
- Code đã tự động downscale 50% và quality 45 để giảm bitrate
- Nếu vẫn quá nặng, có thể chỉnh trong `_video_loop()`:
  - Giảm quality xuống 30-40
  - Tăng downscale lên 25% (1/4 size)

