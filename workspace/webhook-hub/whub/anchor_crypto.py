"""Pure-stdlib Ed25519 primitives used by periodic sealing anchors.

The implementation deliberately exposes only the three operations Whub needs:
deterministic key generation, signing and verification.  Private sealing keys
live outside the SQLite database/export bundles; only public keys and signed
statements are part of verifiable history.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x & 1:
        x = P - x
    return x

_BY = 4 * _inv(5) % P
_BX = _xrecover(_BY)
B = (_BX, _BY, 1, (_BX * _BY) % P)


def _edadd(P1: Tuple[int, int, int, int],
           P2: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = P1
    x2, y2, z2, t2 = P2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = (2 * D * t1 * t2) % P
    d = (2 * z1 * z2) % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point: Tuple[int, int, int, int], scalar: int
                ) -> Tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _edadd(result, point)
        point = _edadd(point, point)
        scalar >>= 1
    return result


def _encode_point(point: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % P
    y = y * zi % P
    bits = y.to_bytes(32, "little")
    if x & 1:
        bits = bytearray(bits)
        bits[31] |= 0x80
        bits = bytes(bits)
    return bits


def _decode_point(data: bytes) -> Tuple[int, int, int, int]:
    if len(data) != 32:
        raise ValueError("compressed point must be 32 bytes")
    b = bytearray(data)
    sign = b[31] >> 7
    b[31] &= 0x7F
    y = int.from_bytes(b, "little")
    if y >= P:
        raise ValueError("point y outside field")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = P - x
    point = (x, y, 1, x * y % P)
    if not _on_curve(point):
        raise ValueError("point is not on Edwards25519")
    return point


def _on_curve(point: Tuple[int, int, int, int]) -> bool:
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % P
    y = y * zi % P
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _same_point(a: Tuple[int, int, int, int],
                b: Tuple[int, int, int, int]) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and \
           (a[1] * b[2] - b[1] * a[2]) % P == 0


def _scalar_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, "little") % L


def generate_key() -> Tuple[bytes, bytes]:
    seed = secrets.token_bytes(32)
    return seed, public_key(seed)


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return _encode_point(_scalarmult(B, int.from_bytes(a, "little")))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    a_i = int.from_bytes(a, "little")
    pub = public_key(seed)
    r = _scalar_from_bytes(hashlib.sha512(h[32:] + message).digest())
    r_point = _scalarmult(B, r)
    r_bytes = _encode_point(r_point)
    k = _scalar_from_bytes(hashlib.sha512(r_bytes + pub + message).digest())
    s = (r + k * a_i) % L
    return r_bytes + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64 or len(public) != 32:
            return False
        r_bytes = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        r_point = _decode_point(r_bytes)
        a_point = _decode_point(public)
        k = _scalar_from_bytes(hashlib.sha512(r_bytes + public + message).digest())
        return _same_point(_scalarmult(B, s),
                           _edadd(r_point, _scalarmult(a_point, k)))
    except Exception:
        return False
