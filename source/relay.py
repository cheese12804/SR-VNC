"""Tiny UDP relay used as TURN-style fallback for SR-VNC."""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple


Address = Tuple[str, int]


@dataclass
class Session:
    participants: Dict[str, Address] = field(default_factory=dict)
    last_update: float = field(default_factory=time.time)

    def add(self, role: str, address: Address) -> None:
        self.participants[role] = address
        self.last_update = time.time()

    def counterpart(self, role: str) -> Address | None:
        for other_role, addr in self.participants.items():
            if other_role != role:
                return addr
        return None

    def ready(self) -> bool:
        return len(self.participants) >= 2


class RelayServer:
    """Minimal UDP relay that forwards packets once both peers register."""

    def __init__(self, host: str = "0.0.0.0", port: int = 7000) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, port))
        self.sessions: Dict[str, Session] = {}
        self.addr_to_session: Dict[Address, Tuple[str, str]] = {}
        self._running = threading.Event()

    def start(self) -> None:
        logging.info("SR-VNC relay listening on %s:%s", *self.socket.getsockname())
        self._running.set()
        while self._running.is_set():
            try:
                data, addr = self.socket.recvfrom(2048)
            except OSError:
                break
            if data.startswith(b"{"):
                self._handle_control(data, addr)
            else:
                self._forward(addr, data)

    def stop(self) -> None:
        self._running.clear()
        try:
            self.socket.close()
        except OSError:
            pass

    def _handle_control(self, payload: bytes, addr: Address) -> None:
        try:
            message = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            return
        if message.get("type") != "register":
            return
        session_id = str(message.get("session"))
        role = message.get("role", "client")
        session = self.sessions.setdefault(session_id, Session())
        session.add(role, addr)
        self.addr_to_session[addr] = (session_id, role)
        logging.info("Registered %s for session %s", addr, session_id)
        if session.ready():
            for participant in session.participants.values():
                self._send_ready(participant)

    def _send_ready(self, addr: Address) -> None:
        message = json.dumps({"type": "ready"}).encode("utf-8")
        try:
            self.socket.sendto(message, addr)
        except OSError:
            pass

    def _forward(self, src: Address, payload: bytes) -> None:
        entry = self.addr_to_session.get(src)
        if not entry:
            return
        session_id, role = entry
        session = self.sessions.get(session_id)
        if not session:
            return
        peer = session.counterpart(role)
        if not peer:
            return
        try:
            self.socket.sendto(payload, peer)
        except OSError:
            pass


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SR-VNC UDP relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    server = RelayServer(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()

