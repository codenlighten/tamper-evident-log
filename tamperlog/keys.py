"""Ed25519 keys, stored the way SSH expects private keys to be stored: readable by the owner only."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


class KeyError_(ValueError):
    """A key file is missing, malformed, or stored unsafely."""


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate(private_path: Path, public_path: Path) -> Ed25519PublicKey:
    """Creates a key pair. Refuses to overwrite an existing file; the private file is created with mode 0600."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(seed.hex() + "\n")
    with open(public_path, "x") as handle:
        handle.write(_raw_public(key).hex() + "\n")
    return key.public_key()


def _read_hex(path: Path, size: int, what: str) -> bytes:
    try:
        text = path.read_text().strip()
    except OSError as err:
        raise KeyError_(f"cannot read {what} {path}: {err.strerror}") from err
    try:
        raw = bytes.fromhex(text)
    except ValueError as err:
        raise KeyError_(f"{what} {path} is not hexadecimal") from err
    if len(raw) != size:
        raise KeyError_(f"{what} {path} must be {size} bytes, found {len(raw)}")
    return raw


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Loads a private key, refusing a file that anyone but its owner can read or write."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as err:
        raise KeyError_(f"cannot read private key {path}: {err.strerror}") from err
    if mode & 0o077:
        raise KeyError_(f"private key {path} has mode {mode:04o}; make it private with: chmod 600 {path}")
    return Ed25519PrivateKey.from_private_bytes(_read_hex(path, 32, "private key"))


def load_public_key(path: Path) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_read_hex(path, 32, "public key"))


def public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def verify_signature(key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
