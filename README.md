# SR-VNC – Secure Reliable Virtual Network Computing

SR-VNC là một bản demo đầy đủ cho ý tưởng "Secure Reliable UDP" (SRUDP),
cho phép truyền hình ảnh màn hình qua UDP nhưng vẫn ưu tiên độ tin cậy cho
luồng điều khiển chuột/phím. Dự án được tách thành hai phần chính: lớp vận
chuyển SRUDP và ứng dụng remote desktop.

## Kiến trúc Giao thức

Phiên bản nâng cấp của SRUDP có hai pha: **bắt tay bảo mật** và **truyền tải
song song**.

### Bắt tay (X25519 + cookie)

1. Client gửi `client_hello` với khóa công khai X25519 ngẫu nhiên và nonce.
2. Server trả lời `hello_retry` kèm cookie HMAC (chống spoof) nếu chưa xác
   thực địa chỉ nguồn.
3. Khi client gửi lại `client_hello` kèm cookie hợp lệ, server phản hồi
   `server_hello` (khóa công khai + nonce).
4. Hai bên sinh khóa chung qua X25519, đưa vào HKDF cùng nonce, session-id và
   PSK (SHA-256 của mật khẩu) → sinh ra cặp khóa AES-GCM và prefix nonce.
5. Client gửi `client_finish`. Từ đây mọi payload đều được mã hóa, replay check
   bằng số packet 64-bit và cửa sổ trượt.
6. Rekey tự động sau 1 GiB hoặc 60 phút bằng thủ tục tương tự (`rekey_request`).

Nonce của AES-GCM không bao giờ lặp vì được xây dựng từ prefix (4 byte) + packet
number 64-bit. Header plaintext (`stream`, `seq`, `fragment`, `packet_number`) được
đưa vào AAD để chống sửa đổi.

### Truyền tải hai luồng

* **Luồng điều khiển (ID `0x01`)** – Selective Repeat ARQ với SACK 32-bit,
  ước lượng RTT/RTO theo RFC 6298, tự động backoff khi retransmit. 100% tin cậy.
* **Luồng video (ID `0x02`)** – Best effort, bỏ frame cũ, chia mảnh mỗi gói ≤
  1200 byte để tránh IP fragmentation. Token bucket pacing đảm bảo control không
  bị block khi bitrate video tăng đột biến.

Mỗi gói đều đi kèm telemetry: RTT p50/p95, tỷ lệ mất control, jitter, bitrate
video… dùng cho overlay demo.

## Thành phần chính

- `srvnc/crypto.py`: Phiên handshake X25519 + HKDF, quản lý nonce, replay,
  rekey và SecureCodec.
- `srvnc/srudp.py`: SRUDP thế hệ mới (Selective Repeat + SACK, pacing, telemetry,
  reassembly video, rekey).
- `srvnc/server.py`: Host (máy bị điều khiển). Chụp màn hình bằng
  `PIL.ImageGrab`, nén JPEG và gửi qua luồng video. Nhận lệnh điều khiển và
  thực thi bằng `pyautogui`.
- `srvnc/client.py`: Viewer (máy điều khiển). Tkinter hiển thị frame, overlay
  telemetry real-time, thu thập sự kiện và gửi đi.
- `srvnc/nat.py`: STUN discovery, UDP hole punching, TURN-style relay fallback.
- `srvnc/relay.py`: UDP relay cực nhẹ (chạy `python -m srvnc.relay`).
- `requirements.txt`: Danh sách thư viện phụ thuộc.

## Cách chạy demo

1. Cài đặt phụ thuộc (khuyến nghị tạo virtualenv):

   ```bash
   pip install -r requirements.txt
   ```

2. (Tuỳ chọn) chạy relay UDP nội bộ để làm TURN fallback:

   ```bash
   python -m srvnc.relay --host 0.0.0.0 --port 7000
   ```

3. Trên Host (máy bị điều khiển), chạy:

   ```bash
   python -m srvnc.server --host 0.0.0.0 --port 5000 \
       --client-host <IP_CLIENT> --client-port 5001 --password <SECRET>
   ```

   Tuỳ chọn NAT/relay:

   * `--stun-server stun.l.google.com:19302` để in reflexive address.
   * `--relay 1.2.3.4:7000 --session demo-1` để sử dụng TURN fallback.
   * `--bitrate 1500000` để giới hạn video 1.5 Mbps.

4. Trên Client (máy điều khiển), chạy:

   ```bash
   python -m srvnc.client --host 0.0.0.0 --port 5001 \
       --server-host <IP_HOST> --server-port 5000 --password <SECRET>
   ```

   Tuỳ chọn: thêm `--relay <HOST:PORT>` hoặc `--stun-server ...` giống server.

Sau khi kết nối, client hiển thị overlay màu xanh với các số đo RTT, FPS,
bitrate, loss%. Server log metrics cùng lúc.

## Telemetry Overlay

Overlay cập nhật mỗi giây với các chỉ số chính để đối chiếu tiêu chí chất lượng:

- `ctrl_rtt_p50_ms`, `ctrl_rtt_p95_ms`, `ctrl_rtt_p99_ms`: RTT của luồng điều khiển sau ARQ.
- `ctrl_loss_percent`, `ctrl_est_loss_percent`, `ctrl_retrans`, `ctrl_inflight`: Tỷ lệ mất thực tế, tỷ lệ ước lượng từ số lần retransmit và số gói đang chờ ACK.
- `video_send_fps`, `video_send_mbps`: FPS và bitrate từ phía host (được gửi kèm gói metrics).
- `video_render_fps`, `video_render_mbps`: FPS/bitrate sau khi client thực sự render frame.
- `video_jitter_p95_ms`, `host_video_fps`, `host_video_mbps`: độ dao động giữa các frame và tốc độ capture hiện tại.

Ảnh chụp overlay là bằng chứng trực quan cho việc control vẫn "mượt" trong khi video chịu mất mát.

## Hồ sơ mạng gợi ý cho phần demo "so găng"

Script `scripts/netem_profiles.sh` giúp áp dụng nhanh ba cấu hình mạng chuẩn:

```bash
sudo ./scripts/netem_profiles.sh <iface> loss15      # 15% packet loss ngẫu nhiên
sudo ./scripts/netem_profiles.sh <iface> jitter80    # RTT ~80 ms ±5 ms jitter
sudo ./scripts/netem_profiles.sh <iface> throttle2m  # Giới hạn ~2 Mbps + delay nhẹ

# Reset giữa các bài test
sudo ./scripts/netem_profiles.sh <iface> clear
```

Thực hiện trên cả hai chiều để mô phỏng mạng đối xứng. Xem thêm hướng dẫn chi tiết trong
[`scripts/ab_compare.md`](scripts/ab_compare.md).

## Tiêu chí "Done" & kiểm chứng

* **Control:** overlay phải báo `ctrl_loss_percent = 0%` sau ARQ và `ctrl_rtt_p50_ms ≤ 80` ở profile `jitter80`.
* **Video:** `video_send_fps ≥ 12` và `video_send_mbps ≈ 2` khi dùng profile `throttle2m`, đồng thời con trỏ vẫn phản hồi tức thì.
* **Bảo mật:** Wireshark với filter `udp.port == <PORT>` chỉ hiển thị payload đã mã hóa; kiểm tra log rekey xác nhận xoay khóa ≤ 1 GiB hoặc 60 phút.
* **NAT traversal:** ưu tiên kết nối trực tiếp/hole-punch; chỉ fallback relay khi cần và ghi chú lại trong báo cáo.
* **Replay & telemetry:** đối chiếu `ack_updates`, `ctrl_retrans`, `ctrl_inflight` trên overlay để chứng minh selective-repeat + replay window hoạt động.

Lưu ảnh overlay, cấu hình `tc`, và capture Wireshark để làm bằng chứng hoàn tất bộ tiêu chí trên.

## Kịch bản demo gợi ý

1. **So sánh với VNC/TCP**: Với profile loss 15%, quay clip con trỏ vẫn mượt
   (control stream giữ ACK đầy đủ, retransmission không block video).
2. **Stress-test**: kéo cửa sổ liên tục, gõ phím nhanh – overlay hiển thị FPS
   ≥ 12 ở 2 Mbps, trong khi control RTT p95 < 80 ms.
3. **Chứng minh bảo mật**: mở Wireshark – chỉ thấy UDP "rác" vì header đã bảo
   vệ bằng AAD và payload AES-GCM.

> ⚠️ Việc chụp màn hình & điều khiển chuột/phím yêu cầu quyền hệ thống. Trên
> môi trường headless (CI) các thư viện như `ImageGrab` hay `pyautogui` có
> thể không hoạt động; tuy nhiên, mã nguồn đã sẵn sàng để demo trên desktop
> thực tế.
