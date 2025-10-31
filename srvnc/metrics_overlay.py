"""Utilities for assembling and formatting telemetry overlays."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, MutableMapping, Optional, Tuple

Number = Optional[float]


@dataclass
class LocalVideoStats:
    """Tracks cumulative render statistics on the client side."""

    frames: int = 0
    bytes: int = 0

    def record_frame(self, payload_size: int) -> None:
        self.frames += 1
        self.bytes += payload_size

    def snapshot(self) -> Dict[str, int]:
        return {"render_frames": self.frames, "render_bytes": self.bytes}


@dataclass
class _OverlayState:
    last_update: float = field(default_factory=time.time)
    prev_conn_control_sent: int = 0
    prev_conn_control_retrans: int = 0
    prev_remote_frames: int = 0
    prev_remote_bytes: int = 0
    prev_render_frames: int = 0
    prev_render_bytes: int = 0


class MetricsOverlay:
    """Formats transport and application metrics for the HUD overlay."""

    def __init__(self) -> None:
        self._state = _OverlayState()

    def compose(
        self,
        connection_metrics: MutableMapping[str, float] | None,
        local_metrics: MutableMapping[str, int] | None,
        remote_metrics: MutableMapping[str, float] | None,
    ) -> List[Tuple[str, str]]:
        now = time.time()
        dt = max(now - self._state.last_update, 1e-6)
        overlay: List[Tuple[str, str]] = []

        conn = connection_metrics or {}
        remote = remote_metrics or {}
        local = local_metrics or {}

        overlay.extend(
            [
                ("ctrl_rtt_p50_ms", _fmt_ms(conn.get("rtt_ms_p50"))),
                ("ctrl_rtt_p95_ms", _fmt_ms(conn.get("rtt_ms_p95"))),
                ("ctrl_rtt_p99_ms", _fmt_ms(conn.get("rtt_ms_p99"))),
                (
                    "ctrl_loss_percent",
                    _fmt_percent(conn.get("control_loss_percent")),
                ),
                (
                    "ctrl_est_loss_percent",
                    _fmt_percent(conn.get("control_est_loss_percent")),
                ),
                (
                    "ctrl_retrans",
                    _fmt_int(conn.get("control_retrans")),
                ),
                (
                    "ctrl_inflight",
                    _fmt_int(conn.get("control_inflight")),
                ),
                (
                    "ctrl_ack_base",
                    _fmt_int(conn.get("ack_base")),
                ),
                (
                    "ctrl_sack_blocks",
                    _fmt_int(conn.get("sack_blocks")),
                ),
                (
                    "ctrl_ack_updates",
                    _fmt_int(conn.get("ack_updates")),
                ),
            ]
        )

        remote_frames = int(remote.get("video_frames", conn.get("video_frames", 0)) or 0)
        remote_bytes = int(remote.get("video_bytes", conn.get("video_bytes", 0)) or 0)
        send_fps = (remote_frames - self._state.prev_remote_frames) / dt
        send_mbps = _bytes_to_mbps(remote_bytes - self._state.prev_remote_bytes, dt)
        overlay.append(("video_send_fps", f"{max(send_fps, 0.0):.2f}"))
        overlay.append(("video_send_mbps", f"{max(send_mbps, 0.0):.2f}"))
        overlay.append(
            (
                "video_jitter_p95_ms",
                _fmt_ms(remote.get("video_jitter_p95_ms", conn.get("video_jitter_p95_ms"))),
            )
        )

        render_frames = int(local.get("render_frames", 0) or 0)
        render_bytes = int(local.get("render_bytes", 0) or 0)
        render_fps = (render_frames - self._state.prev_render_frames) / dt
        render_mbps = _bytes_to_mbps(render_bytes - self._state.prev_render_bytes, dt)
        overlay.append(("video_render_fps", f"{max(render_fps, 0.0):.2f}"))
        overlay.append(("video_render_mbps", f"{max(render_mbps, 0.0):.2f}"))

        if "host_video_fps" in remote:
            overlay.append(("host_video_fps", f"{max(float(remote['host_video_fps']), 0.0):.2f}"))
        if "host_video_mbps" in remote:
            overlay.append(("host_video_mbps", f"{max(float(remote['host_video_mbps']), 0.0):.2f}"))

        self._state.prev_remote_frames = remote_frames
        self._state.prev_remote_bytes = remote_bytes
        self._state.prev_render_frames = render_frames
        self._state.prev_render_bytes = render_bytes
        self._state.last_update = now

        return overlay


def _fmt_ms(value: Number) -> str:
    if value is None:
        return "n/a"
    return f"{float(value or 0.0):.2f}"


def _fmt_percent(value: Number) -> str:
    if value is None:
        return "n/a"
    return f"{float(value or 0.0):.2f}"


def _fmt_int(value: Number) -> str:
    if value is None:
        return "0"
    return f"{int(float(value))}"


def _bytes_to_mbps(delta_bytes: int, dt: float) -> float:
    if dt <= 0:
        return 0.0
    return (max(delta_bytes, 0) * 8.0) / (dt * 1_000_000)
