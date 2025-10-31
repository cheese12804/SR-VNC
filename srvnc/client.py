"""SR-VNC controller implementation."""
from __future__ import annotations

import hashlib
import io
import logging
import queue
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

import tkinter as tk
from PIL import Image, ImageTk

from .nat import RelayClient, RelayConfig, discover_reflexive_address, send_hole_punch
from .metrics_overlay import LocalVideoStats, MetricsOverlay
from .srudp import SRUDPConnection

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


@dataclass
class ClientConfig:
    host: str = "0.0.0.0"
    port: int = 5001
    server_host: str = "127.0.0.1"
    server_port: int = 5000
    password: str = "changeme"
    stun_server: Optional[str] = None
    relay: Optional[str] = None
    session: str = "srvnc-demo"
    bitrate: int = 2_000_000


class VideoWindow:
    """Tkinter window that displays remote frames and captures input."""

    def __init__(self, client: "SRVNCClient") -> None:
        self.client = client
        self.root = tk.Tk()
        self.root.title("SR-VNC Client")
        self.label = tk.Label(self.root)
        self.label.pack(fill=tk.BOTH, expand=True)
        self._photo: Optional[ImageTk.PhotoImage] = None
        self._frames: "queue.Queue[bytes]" = queue.Queue()
        self.overlay_var = tk.StringVar(value="")
        self.overlay = tk.Label(
            self.root,
            textvariable=self.overlay_var,
            anchor="nw",
            justify="left",
            bg="#101010",
            fg="#00ff5f",
            font=("TkFixedFont", 10),
        )
        self.overlay.place(relx=0.0, rely=0.0, anchor="nw")
        self.root.bind("<Motion>", self._on_motion)
        self.root.bind("<ButtonPress>", self._on_button_press)
        self.root.bind("<ButtonRelease>", self._on_button_release)
        self.root.bind("<KeyPress>", self._on_key_press)
        self.root.bind("<KeyRelease>", self._on_key_release)
        self.root.bind("<Configure>", lambda event: self.root.focus_set())
        self.root.after(30, self._pump_frames)

    def update_overlay(self, metrics) -> None:
        lines = ["SR-VNC Telemetry"]
        if isinstance(metrics, dict):
            items = sorted(metrics.items())
        else:
            items = metrics
        for key, value in items:
            lines.append(f"{key}: {value}")
        text = "\n".join(lines)
        self.root.after(0, self.overlay_var.set, text)

    def enqueue_frame(self, frame: bytes) -> None:
        self._frames.put(frame)

    def _pump_frames(self) -> None:
        updated = False
        while True:
            try:
                frame = self._frames.get_nowait()
            except queue.Empty:
                break
            try:
                image = Image.open(io.BytesIO(frame))
            except Exception:
                continue
            self._photo = ImageTk.PhotoImage(image=image)
            self.label.configure(image=self._photo)
            self.client.record_render(len(frame))
            updated = True
        if updated:
            self.root.update_idletasks()
        self.root.after(30, self._pump_frames)

    # ------------------------------------------------------------------
    def _on_motion(self, event: tk.Event) -> None:
        self.client.send_mouse_move(int(event.x), int(event.y))

    def _on_button_press(self, event: tk.Event) -> None:
        button = self._tk_button_to_name(event.num)
        self.client.send_mouse_click(int(event.x), int(event.y), button=button, pressed=True)

    def _on_button_release(self, event: tk.Event) -> None:
        button = self._tk_button_to_name(event.num)
        self.client.send_mouse_click(int(event.x), int(event.y), button=button, pressed=False)

    def _on_key_press(self, event: tk.Event) -> None:
        key = self._normalize_key(event.keysym)
        if key:
            self.client.send_key_event(key, pressed=True)

    def _on_key_release(self, event: tk.Event) -> None:
        key = self._normalize_key(event.keysym)
        if key:
            self.client.send_key_event(key, pressed=False)

    @staticmethod
    def _tk_button_to_name(num: int) -> str:
        return {1: "left", 2: "middle", 3: "right"}.get(num, "left")

    @staticmethod
    def _normalize_key(keysym: str) -> Optional[str]:
        if len(keysym) == 1:
            return keysym.lower()
        special_map = {
            "Return": "enter",
            "Escape": "esc",
            "BackSpace": "backspace",
            "Tab": "tab",
            "Shift_L": "shift",
            "Shift_R": "shift",
            "Control_L": "ctrl",
            "Control_R": "ctrl",
            "Alt_L": "alt",
            "Alt_R": "alt",
            "Super_L": "win",
            "Super_R": "win",
        }
        return special_map.get(keysym)


class SRVNCClient:
    """SR-VNC viewer and input forwarder."""

    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((config.host, config.port))
        self.window = VideoWindow(self)
        self._last_frame_seq = 0
        self._running = threading.Event()
        self._stats_thread: Optional[threading.Thread] = None
        self.connection: Optional[SRUDPConnection] = None
        self._metrics_overlay = MetricsOverlay()
        self._local_video = LocalVideoStats()
        self._metrics_lock = threading.Lock()
        self._pending_metrics: Optional[dict] = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        logging.info(
            "Starting SR-VNC client on %s:%s talking to %s:%s",
            self.config.host,
            self.config.port,
            self.config.server_host,
            self.config.server_port,
        )
        self._running.set()
        peer = self._prepare_transport()
        psk = hashlib.sha256(self.config.password.encode("utf-8")).digest()
        self.connection = SRUDPConnection(
            self.socket,
            is_server=False,
            peer=peer,
            psk=psk,
        )
        self.connection.register_video_handler(self._handle_video)
        self.connection.register_ack_handler(self._handle_ack)
        self.connection.register_control_handler(self._handle_control_message)
        self.connection.set_video_bitrate(self.config.bitrate)
        self.connection.client_handshake()
        self.connection.start()
        self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self._stats_thread.start()
        try:
            self.window.root.mainloop()
        finally:
            self.stop()

    def stop(self) -> None:
        if not self._running.is_set():
            return
        self._running.clear()
        connection = self.connection
        if connection is not None:
            try:
                connection.stop()
            finally:
                self.connection = None
        self.socket.close()

    # ------------------------------------------------------------------
    def send_mouse_move(self, x: int, y: int) -> None:
        event = {"type": "mouse_move", "x": x, "y": y}
        if self.connection:
            self.connection.send_control_event(event)

    def send_mouse_click(self, x: int, y: int, *, button: str, pressed: bool) -> None:
        event = {
            "type": "mouse_click",
            "x": x,
            "y": y,
            "button": button,
            "clicks": 1,
            "pressed": pressed,
        }
        if self.connection:
            self.connection.send_control_event(event)

    def send_key_event(self, key: str, *, pressed: bool) -> None:
        event = {"type": "key_down" if pressed else "key_up", "key": key}
        if self.connection:
            self.connection.send_control_event(event)

    # ------------------------------------------------------------------
    def _handle_video(self, seq: int, payload: bytes, address: Tuple[str, int]) -> None:
        if seq <= self._last_frame_seq:
            return
        self._last_frame_seq = seq
        self.window.enqueue_frame(payload)

    def _handle_ack(self, sequences) -> None:
        logging.debug("ACK received for sequences %s", list(sequences))

    def _handle_control_message(self, seq: int, body: dict, address: Tuple[str, int]) -> None:
        if body.get("type") == "metrics":
            metrics = body.get("values", {})
            with self._metrics_lock:
                self._pending_metrics = metrics

    def _stats_loop(self) -> None:
        while self._running.is_set():
            connection_metrics: dict = {}
            if self.connection:
                connection_metrics = self.connection.get_metrics()
                logging.debug("Client metrics: %s", connection_metrics)
            with self._metrics_lock:
                local_metrics = self._local_video.snapshot()
                remote_metrics = dict(self._pending_metrics) if self._pending_metrics else {}
            overlay = self._metrics_overlay.compose(connection_metrics, local_metrics, remote_metrics)
            if overlay:
                self.window.update_overlay(overlay)
            time.sleep(1.0)

    def record_render(self, payload_size: int) -> None:
        with self._metrics_lock:
            self._local_video.record_frame(payload_size)

    def _prepare_transport(self) -> Tuple[str, int]:
        peer = (self.config.server_host, self.config.server_port)
        if self.config.stun_server:
            stun_host, stun_port = parse_host_port(self.config.stun_server, 19302)
            reflexive = discover_reflexive_address(self.socket, (stun_host, stun_port))
            if reflexive:
                logging.info("Client reflexive address %s:%s", *reflexive)
        if self.config.relay:
            relay_host, relay_port = parse_host_port(self.config.relay, 7000)
            relay = RelayClient(RelayConfig((relay_host, relay_port), self.config.session))
            if not relay.register(self.socket, role="client"):
                raise RuntimeError("Failed to register with relay server")
            peer = (relay_host, relay_port)
            logging.info("Using relay %s:%s for session %s", relay_host, relay_port, self.config.session)
        else:
            send_hole_punch(self.socket, peer)
        return peer


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SR-VNC client")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=5000)
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--stun-server")
    parser.add_argument("--relay")
    parser.add_argument("--session", default=str(uuid.uuid4()))
    parser.add_argument("--bitrate", type=int, default=2_000_000)
    args = parser.parse_args()

    client = SRVNCClient(
        ClientConfig(
            host=args.host,
            port=args.port,
            server_host=args.server_host,
            server_port=args.server_port,
            password=args.password,
            stun_server=args.stun_server,
            relay=args.relay,
            session=args.session,
            bitrate=args.bitrate,
        )
    )
    try:
        client.start()
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        return host, int(port_str)
    return value, default_port


if __name__ == "__main__":
    main()
