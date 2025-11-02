"""NAT traversal helpers for SR-VNC."""
from __future__ import annotations

import json
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple


STUN_BINDING_REQUEST = 0x0001
STUN_MAGIC_COOKIE = 0x2112A442
STUN_ATTRIBUTE_XOR_MAPPED = 0x0020


Address = Tuple[str, int]


def build_stun_request() -> tuple[bytes, bytes]:
    transaction_id = os.urandom(12)
    header = struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE, transaction_id)
    return header, transaction_id


def parse_xor_mapped_attribute(data: bytes) -> Optional[Address]:
    if len(data) < 20:
        return None
    message_type, length, cookie = struct.unpack("!HHI", data[:8])
    if message_type != 0x0101:  # Binding Success Response
        return None
    transaction_id = data[8:20]
    offset = 20
    end = 20 + length
    while offset + 4 <= end and offset + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        value = data[offset : offset + attr_len]
        offset += attr_len
        offset += (4 - (attr_len % 4)) % 4
        if attr_type != STUN_ATTRIBUTE_XOR_MAPPED:
            continue
        if len(value) < 8:
            continue
        family = value[1]
        port = struct.unpack("!H", value[2:4])[0] ^ (cookie >> 16)
        if family == 0x01:  # IPv4
            ip_xor = struct.unpack("!I", value[4:8])[0]
            ip_int = ip_xor ^ cookie
            ip_bytes = struct.pack("!I", ip_int)
            ip = socket.inet_ntoa(ip_bytes)
            return ip, port
        elif family == 0x02 and len(value) >= 20:  # IPv6
            xor_bytes = value[4:20]
            cookie_bytes = struct.pack("!I", cookie) + transaction_id
            ip_bytes = bytes(a ^ b for a, b in zip(xor_bytes, cookie_bytes))
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            return ip, port
    return None


def discover_reflexive_address(
    sock: socket.socket, server: Address = ("stun.l.google.com", 19302), timeout: float = 2.0
) -> Optional[Address]:
    """Return the reflexive address discovered via STUN."""

    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        request, _ = build_stun_request()
        sock.sendto(request, server)
        while True:
            response, addr = sock.recvfrom(2048)
            if addr != server:
                continue
            mapped = parse_xor_mapped_attribute(response)
            if mapped:
                return mapped
    except socket.timeout:
        return None
    finally:
        sock.settimeout(previous_timeout)


def send_hole_punch(sock: socket.socket, peer: Address, duration: float = 2.0, interval: float = 0.1) -> None:
    """Send periodic empty datagrams to assist UDP hole punching."""

    end = time.time() + duration
    payload = b"SRVNC-HP"
    while time.time() < end:
        try:
            sock.sendto(payload, peer)
        except OSError:
            break
        time.sleep(interval)


@dataclass
class RelayConfig:
    server: Address
    session: str


class RelayClient:
    """Minimal UDP relay helper used as a TURN-style fallback."""

    def __init__(self, config: RelayConfig) -> None:
        self.config = config

    def register(self, sock: socket.socket, role: str, timeout: float = 5.0) -> bool:
        message = {
            "type": "register",
            "session": self.config.session,
            "role": role,
        }
        data = json.dumps(message).encode("utf-8")
        sock.sendto(data, self.config.server)
        end = time.time() + timeout
        previous_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            while time.time() < end:
                try:
                    payload, addr = sock.recvfrom(2048)
                except socket.timeout:
                    break
                if addr != self.config.server:
                    continue
                try:
                    response = json.loads(payload.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                if response.get("type") == "ready":
                    return True
        finally:
            sock.settimeout(previous_timeout)
        return False

