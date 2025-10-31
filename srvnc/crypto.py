"""Cryptographic helpers and session management for SR-VNC."""
from __future__ import annotations

import os
import socket
import secrets
import struct
import time
import hmac as std_hmac
from cryptography.hazmat.primitives import hmac as crypto_hmac
from dataclasses import dataclass
from typing import ClassVar, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


NONCE_SIZE = 12
SALT_SIZE = 16
PBKDF2_ITERATIONS = 200_000

# Rekey every GiB or hour whichever comes first
REKEY_BYTES = 1 << 30
REKEY_INTERVAL = 60 * 60


class ReplayError(Exception):
    """Raised when a packet is outside of the replay protection window."""


class RekeyRequired(Exception):
    """Raised when a secure session must perform a rekey operation."""


@dataclass
class ReplayWindow:
    """Simple 64-bit sliding replay window tracker."""

    highest: int = -1
    mask: int = 0

    def check_and_update(self, number: int) -> None:
        if self.highest == -1:
            self.highest = number
            self.mask = 1
            return
        if number > self.highest:
            shift = number - self.highest
            if shift >= 64:
                self.mask = 0
            else:
                self.mask = ((self.mask << shift) & ((1 << 64) - 1)) | 1
            self.highest = number
            return
        distance = self.highest - number
        if distance >= 64:
            raise ReplayError("Packet number outside of replay window")
        bit = 1 << distance
        if self.mask & bit:
            raise ReplayError("Duplicate packet number detected")
        self.mask |= bit


@dataclass(frozen=True)
class DerivedKey:
    """Container for a derived symmetric key and associated salt."""

    key: bytes
    salt: bytes

    HEADER: ClassVar[bytes] = b"SRVNC1"

    def serialize(self) -> bytes:
        """Serialize the derived key for storage or transfer."""
        return self.HEADER + self.salt + self.key

    @classmethod
    def deserialize(cls, blob: bytes) -> "DerivedKey":
        """Create an instance from :func:`serialize` output."""
        if len(blob) < len(cls.HEADER) + SALT_SIZE + 16:
            raise ValueError("Serialized key blob is too small")
        header = blob[: len(cls.HEADER)]
        if header != cls.HEADER:
            raise ValueError("Invalid key header")
        salt = blob[len(cls.HEADER) : len(cls.HEADER) + SALT_SIZE]
        key = blob[len(cls.HEADER) + SALT_SIZE :]
        return cls(key=key, salt=salt)


def derive_key_from_password(password: str, *, salt: bytes | None = None) -> DerivedKey:
    """Derive a 256-bit AES key from a password.

    The function uses PBKDF2-HMAC-SHA256 with 200k iterations.  If *salt*
    is not provided a cryptographically secure random salt is generated.
    """

    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return DerivedKey(key=key, salt=salt)


class SecureCodec:
    """Secure session state implementing nonce management and replay checks."""

    def __init__(
        self,
        *,
        send_key: bytes,
        recv_key: bytes,
        send_prefix: bytes,
        recv_prefix: bytes,
        session_id: int,
    ) -> None:
        if len(send_key) not in {16, 24, 32} or len(recv_key) not in {16, 24, 32}:
            raise ValueError("AES-GCM key must be 128, 192, or 256 bits long")
        if len(send_prefix) != 6 or len(recv_prefix) != 6:
            raise ValueError("Nonce prefixes must be 6 bytes")
        self._send_aead = AESGCM(send_key)
        self._recv_aead = AESGCM(recv_key)
        self._send_prefix = send_prefix
        self._recv_prefix = recv_prefix
        self._send_counter = 0
        self._replay_window = ReplayWindow()
        self._bytes_sent = 0
        self._established = time.time()
        self.session_id = session_id

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _build_nonce(self, prefix: bytes, counter: int) -> bytes:
        return prefix + counter.to_bytes(6, "big")

    def _check_rekey(self, payload_len: int) -> None:
        self._bytes_sent += payload_len
        if self._bytes_sent >= REKEY_BYTES or time.time() - self._established > REKEY_INTERVAL:
            raise RekeyRequired

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def next_packet_number(self) -> int:
        packet_number = self._send_counter
        self._send_counter += 1
        if self._send_counter >= (1 << 48):
            raise RekeyRequired
        return packet_number

    def encrypt(self, packet_number: int, header: bytes, plaintext: bytes) -> bytes:
        nonce = self._build_nonce(self._send_prefix, packet_number)
        ciphertext = self._send_aead.encrypt(nonce, plaintext, header)
        self._check_rekey(len(ciphertext))
        return ciphertext

    def decrypt(self, packet_number: int, header: bytes, ciphertext: bytes) -> bytes:
        self._replay_window.check_and_update(packet_number)
        nonce = self._build_nonce(self._recv_prefix, packet_number)
        return self._recv_aead.decrypt(nonce, ciphertext, header)


# ---------------------------------------------------------------------------
# Handshake helpers
# ---------------------------------------------------------------------------


def _hkdf_expand(shared_secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        shared_secret
    )


def generate_ephemeral_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def derive_session_keys(
    shared_secret: bytes,
    *,
    client_random: bytes,
    server_random: bytes,
    initiator: bool,
    session_id: int,
) -> SecureCodec:
    return derive_session_keys_with_psk(
        shared_secret,
        client_random=client_random,
        server_random=server_random,
        initiator=initiator,
        session_id=session_id,
        psk=None,
    )


def derive_session_keys_with_psk(
    shared_secret: bytes,
    *,
    client_random: bytes,
    server_random: bytes,
    initiator: bool,
    session_id: int,
    psk: bytes | None,
) -> SecureCodec:
    salt = client_random + server_random
    if psk:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(psk)
        salt += digest.finalize()
    info = b"SRVNC-HANDSHAKE-1" + struct.pack("!I", session_id)
    material = _hkdf_expand(shared_secret, salt, info, 84)
    send_key = material[:32]
    recv_key = material[32:64]
    send_prefix = material[64:70]
    recv_prefix = material[70:76]
    if not initiator:
        send_key, recv_key = recv_key, send_key
        send_prefix, recv_prefix = recv_prefix, send_prefix
    return SecureCodec(
        send_key=send_key,
        recv_key=recv_key,
        send_prefix=send_prefix,
        recv_prefix=recv_prefix,
        session_id=session_id,
    )


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _cookie_msg(address: Tuple[str, int], client_random: bytes, timestamp: int) -> bytes:
    ip, port = address
    ip_bytes = socket.inet_aton(ip)
    port_bytes = struct.pack("!H", int(port))
    ts_bytes = struct.pack("!I", int(timestamp))
    if not isinstance(client_random, (bytes, bytearray)) or len(client_random) != 32:
        raise ValueError("client_random must be 32 bytes")
    return ip_bytes + port_bytes + client_random + ts_bytes


def create_cookie(secret: bytes, address: Tuple[str, int], client_random: bytes, ts: int) -> bytes:
    return _hmac_sha256(secret, _cookie_msg(address, client_random, ts))


def verify_cookie(
    secret: bytes,
    address: Tuple[str, int],
    client_random: bytes,
    ts: int,
    cookie: bytes,
    *,
    tolerance: int = 1,
) -> bool:
    if not isinstance(client_random, (bytes, bytearray)):
        raise TypeError("client_random must be bytes")
    if not isinstance(cookie, (bytes, bytearray)) or len(cookie) != 32:
        return False

    last_expected: bytes | None = None
    for delta in range(-tolerance, tolerance + 1):
        expected = _hmac_sha256(secret, _cookie_msg(address, client_random, ts + delta))
        last_expected = expected
        if std_hmac.compare_digest(expected, cookie):
            print(f"[DEBUG] cookie verify: True (exp_len={len(expected)} got_len={len(cookie)})")
            return True
    if last_expected is not None:
        print(f"[DEBUG] cookie verify: False (exp_len={len(last_expected)} got_len={len(cookie)})")
    return False
