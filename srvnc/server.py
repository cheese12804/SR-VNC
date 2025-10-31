"""SR-VNC host implementation."""
from __future__ import annotations

import hashlib
import io
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import pyautogui
from PIL import ImageGrab

from .nat import RelayClient, RelayConfig, discover_reflexive_address, send_hole_punch
from .srudp import SRUDPConnection

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
pyautogui.FAILSAFE = False


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 5000
    client_host: str = "127.0.0.1"
    client_port: int = 5001
    password: str = "changeme"
    fps: int = 10
    stun_server: Optional[str] = None
    relay: Optional[str] = None
    session: str = "srvnc-demo"
    bitrate: int = 2_000_000


class SRVNCServer:
    """Remote desktop host using the SRUDP transport."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((config.host, config.port))
        self._running = threading.Event()
        self._video_thread: Optional[threading.Thread] = None
        self._metrics_thread: Optional[threading.Thread] = None
        self.connection: Optional[SRUDPConnection] = None
        self._metrics_lock = threading.Lock()
        self._sent_frames = 0
        self._sent_bytes = 0

    # ------------------------------------------------------------------
    def start(self) -> None:
        logging.info(
            "Starting SR-VNC host on %s:%s targeting %s:%s",
            self.config.host,
            self.config.port,
            self.config.client_host,
            self.config.client_port,
        )
        self._running.set()
        peer = self._prepare_transport()
        psk = hashlib.sha256(self.config.password.encode("utf-8")).digest()
        self.connection = SRUDPConnection(
            self.socket,
            is_server=True,
            cookie_secret=None,
            psk=psk,
            peer=peer,
        )
        self.connection.register_control_handler(self._handle_control)
        self.connection.register_ack_handler(self._handle_ack)
        self.connection.set_video_bitrate(self.config.bitrate)
        self.connection.server_handshake()
        self.connection.start()
        self._video_thread = threading.Thread(target=self._video_loop, daemon=True)
        self._video_thread.start()
        self._metrics_thread = threading.Thread(target=self._metrics_loop, daemon=True)
        self._metrics_thread.start()

    def stop(self) -> None:
        logging.info("Stopping SR-VNC host")
        self._running.clear()
        if self._video_thread:
            self._video_thread.join(timeout=1.0)
        if self._metrics_thread:
            self._metrics_thread.join(timeout=1.0)
        connection = self.connection
        if connection is not None:
            try:
                connection.stop()
            finally:
                self.connection = None
        self.socket.close()

    # ------------------------------------------------------------------
    def _video_loop(self) -> None:
        frame_interval = 1.0 / max(1, self.config.fps)
        while self._running.is_set() and self.connection:
            start = time.time()
            frame = ImageGrab.grab()
            buffer = io.BytesIO()
            frame.save(buffer, format="JPEG", quality=60)
            data = buffer.getvalue()
            self.connection.send_video_frame(data)
            with self._metrics_lock:
                self._sent_frames += 1
                self._sent_bytes += len(data)
            elapsed = time.time() - start
            time.sleep(max(0.0, frame_interval - elapsed))

    def _metrics_loop(self) -> None:
        last_frames = 0
        last_bytes = 0
        last_time = time.time()
        while self._running.is_set() and self.connection:
            now = time.time()
            with self._metrics_lock:
                frames = self._sent_frames
                bytes_sent = self._sent_bytes
            dt = max(now - last_time, 1e-6)
            fps = (frames - last_frames) / dt
            mbps = ((bytes_sent - last_bytes) * 8.0) / (dt * 1_000_000)
            extra = {
                "host_video_fps": max(fps, 0.0),
                "host_video_mbps": max(mbps, 0.0),
                "video_frames": frames,
                "video_bytes": bytes_sent,
            }
            self.connection.send_metrics_overlay(extra=extra)
            logging.debug("Server metrics: %s", self.connection.get_metrics())
            last_frames = frames
            last_bytes = bytes_sent
            last_time = now
            time.sleep(1.0)

    # ------------------------------------------------------------------
    def _handle_control(self, seq: int, message: dict, address: Tuple[str, int]) -> None:
        """Handle incoming control messages (mouse/keyboard)."""

        event_type = message.get("type")
        try:
            if event_type == "mouse_move":
                x = message.get("x")
                y = message.get("y")
                duration = message.get("duration", 0.0)
                pyautogui.moveTo(x, y, duration=duration)
            elif event_type == "mouse_click":
                x = message.get("x")
                y = message.get("y")
                button = message.get("button", "left")
                pressed = message.get("pressed", True)
                if pressed:
                    pyautogui.mouseDown(x=x, y=y, button=button)
                else:
                    pyautogui.mouseUp(x=x, y=y, button=button)
            elif event_type == "key_down":
                key = message.get("key")
                if key:
                    pyautogui.keyDown(key)
            elif event_type == "key_up":
                key = message.get("key")
                if key:
                    pyautogui.keyUp(key)
            elif event_type == "type_text":
                text = message.get("text", "")
                interval = message.get("interval", 0.0)
                pyautogui.typewrite(text, interval=interval)
            else:
                logging.debug("Unknown control message: %s", message)
        except Exception as exc:  # pragma: no cover - defensive log
            logging.error("Failed to execute control command %s: %s", message, exc)

    def _handle_ack(self, sequences) -> None:
        logging.debug("Reliable control acknowledged: %s", list(sequences))

    def _prepare_transport(self) -> Tuple[str, int]:
        peer = (self.config.client_host, self.config.client_port)
        if self.config.stun_server:
            stun_host, stun_port = parse_host_port(self.config.stun_server, 19302)
            reflexive = discover_reflexive_address(self.socket, (stun_host, stun_port))
            if reflexive:
                logging.info("Server reflexive address %s:%s", *reflexive)
        if self.config.relay:
            relay_host, relay_port = parse_host_port(self.config.relay, 7000)
            relay = RelayClient(RelayConfig((relay_host, relay_port), self.config.session))
            if not relay.register(self.socket, role="host"):
                raise RuntimeError("Failed to register with relay server")
            peer = (relay_host, relay_port)
            logging.info("Using relay %s:%s for session %s", relay_host, relay_port, self.config.session)
        else:
            send_hole_punch(self.socket, peer)
        return peer


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SR-VNC host")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--client-host", default="127.0.0.1")
    parser.add_argument("--client-port", type=int, default=5001)
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--fps", type=int, default=10)
    parser.add_argument("--stun-server")
    parser.add_argument("--relay")
    parser.add_argument("--session", default="srvnc-demo")
    parser.add_argument("--bitrate", type=int, default=2_000_000)
    args = parser.parse_args()

    server = SRVNCServer(
        ServerConfig(
            host=args.host,
            port=args.port,
            client_host=args.client_host,
            client_port=args.client_port,
            password=args.password,
            fps=args.fps,
            stun_server=args.stun_server,
            relay=args.relay,
            session=args.session,
            bitrate=args.bitrate,
        )
    )
    try:
        server.start()
        logging.info("SR-VNC host ready")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        return host, int(port_str)
    return value, default_port
