"""Build throwaway RSA SubjectPublicKeyInfo blobs for DKIM tests (random modulus, not a real key)."""

from __future__ import annotations

import base64
import random


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def fake_spki_b64(bits: int, seed: int = 1, pkcs1: bool = False) -> str:
    rng = random.Random(seed)
    n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
    rsa = _tlv(0x30, _tlv(0x02, b"\x00" + n.to_bytes(bits // 8, "big")) + _tlv(0x02, b"\x01\x00\x01"))
    if pkcs1:
        return base64.b64encode(rsa).decode()
    alg = _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    return base64.b64encode(_tlv(0x30, alg + _tlv(0x03, b"\x00" + rsa))).decode()
