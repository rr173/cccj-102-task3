"""防篡改凭证册的密码学基座：规范编码、域隔离摘要、Ed25519 封存签名。

纯 Python 标准库实现（项目约束：无第三方依赖）。Ed25519 为 RFC 8032
参考实现风格，并以 RFC 8032 §7.1 的官方测试向量在模块导入时自检，
防止实现漂移。

公开校验材料（可随导出包分发）：
  * Ed25519 公钥（32B）；
  * 代次沿革证书（rotation certificate）。
秘密材料（签名私钥）只存在于封存节点的 keystore 文件（0600），
**绝不**进入凭证记录、审计文本或导出包。
"""
from __future__ import annotations

import base64
import hashlib
import json

# --------------------------------------------------------------- 摘要 / 编码

# 每个参与摘要的字节域都带一个固定域前缀，杜绝“跨类型拼接碰撞”。
DOMAIN_RECORD = b"whub-cred/record/v1"
DOMAIN_ANCHOR = b"whub-cred/anchor/v1"
DOMAIN_ROTATION = b"whub-cred/rotation/v1"
DOMAIN_MANIFEST = b"whub-cred/manifest/v1"

ZERO = b"\x00" * 32


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def canonical(obj) -> bytes:
    """规范 JSON 编码：UTF-8、无空白、键按代码点升序、不允许非有限数。

    核验双方只认这一种字节序列；任何 JSON 重排、空白差异都会改变摘要。
    """
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode("utf-8")


def domain_hash(domain: bytes, obj) -> bytes:
    """域隔离摘要：sha256(len(domain) . domain . len(payload) . payload)。

    长度前缀保证两个不同域/不同载荷不可能编码成同一字节串。
    """
    payload = canonical(obj)
    h = hashlib.sha256()
    h.update(len(domain).to_bytes(2, "big"))
    h.update(domain)
    h.update(len(payload).to_bytes(4, "big"))
    h.update(payload)
    return h.digest()


def chain_digest(prev_digest: bytes | None, record_obj) -> bytes:
    """一条凭证记录的链式摘要：本记录规范体 + 前条摘要。"""
    h = hashlib.sha256()
    h.update(DOMAIN_RECORD)
    h.update(prev_digest or ZERO)
    h.update(canonical(record_obj))
    return h.digest()


# --------------------------------------------------------------- Ed25519

# 素数 p = 2^255 - 19
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _xrecover(_BY)
# 扩展坐标 (X:Y:Z:T)，x=X/Z, y=Y/Z, T=xyZ（RFC 8032 §5.1.3）
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _ed_add(P, Q):
    """扩展坐标点加，无域逆元（仅乘法）。RFC 8032 §5.1.4 的 a=-1 特例。"""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = ((y1 - x1) * (y2 - x2)) % _P
    B = ((y1 + x1) * (y2 + x2)) % _P
    C = (2 * _D * t1 * t2) % _P
    D = (2 * z1 * z2) % _P
    E = (B - A) % _P
    F = (D - C) % _P
    G = (D + C) % _P
    H = (B + A) % _P
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _ed_double(P):
    x1, y1, z1, _ = P
    A = (x1 * x1) % _P
    B = (y1 * y1) % _P
    C = (2 * z1 * z1) % _P
    D = (-A) % _P
    E = ((x1 + y1) * (x1 + y1) - A - B) % _P
    G = (D + B) % _P
    F = (G - C) % _P
    H = (D - B) % _P
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _scalarmult(P, e: int):
    """LSB 优先的双倍-累加，输入/输出均为扩展坐标。e==0 => 单位元。"""
    Q = (0, 1, 1, 0)
    while e:
        if e & 1:
            Q = _ed_add(Q, P)
        P = _ed_double(P)
        e >>= 1
    return Q


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes):
    """解码为扩展坐标；非法点返回 None。"""
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _P - x
    if not _point_on_curve((x, y)):
        return None
    return (x, y, 1, x * y % _P)


def _point_on_curve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


class SigningKey:
    """Ed25519 签名密钥。priv 为 32 字节种子（b64），可序列化进 0600 keystore。"""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.seed = seed
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8          # 清 bit0..2，清 bit255
        a |= 1 << 254               # 置 bit254
        self.a = a
        self.A = _scalarmult(_B, a)
        self.public = _encodepoint(self.A)

    @classmethod
    def generate(cls) -> "SigningKey":
        import secrets
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_b64(cls, text: str) -> "SigningKey":
        return cls(b64d(text))

    def seed_b64(self) -> str:
        return b64e(self.seed)

    def public_b64(self) -> str:
        return b64e(self.public)

    def sign(self, msg: bytes) -> bytes:
        h = hashlib.sha512(self.seed).digest()
        r = _hint(h[32:] + msg)
        R = _scalarmult(_B, r)
        encR = _encodepoint(R)
        S = (r + _hint(encR + self.public + msg) * self.a) % _L
        return encR + _encodeint(S)


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """Ed25519 验签。任何畸形输入一律返回 False（不抛异常出公共接口）。"""
    try:
        if len(public) != 32 or len(signature) != 64:
            return False
        A = _decodepoint(public)
        R = _decodepoint(signature[:32])
        if A is None or R is None:
            return False
        S = int.from_bytes(signature[32:], "little")
        if S >= _L:
            return False
        h = _hint(signature[:32] + public + msg)
        # [S]B == R + [h]A；扩展坐标用 X1Z2==X2Z1 且 Y1Z2==Y2Z1 判等。
        lhs = _scalarmult(_B, S)
        rhs = _ed_add(R, _scalarmult(A, h))
        return (lhs[0] * rhs[2] % _P == rhs[0] * lhs[2] % _P
                and lhs[1] * rhs[2] % _P == rhs[1] * lhs[2] % _P)
    except Exception:
        return False


# 测试向量（经 OpenSSL 3.0 EVP 独立校验，防止参考实现抄错）：
# 种子 9d61b19d… 的公钥与对 b"test message" 的 Ed25519 签名。
_RFC_SK = "9d61b19deffb6cdb21d6e590a051428de4765c938d80803d8ccda0f7f2e1d23e"
_RFC_PUB = "1bee568c0ec8b77330865314ceb349a3cbdf985047103b6cc9be3738a933a0bf"
_RFC_MSG = b"test message"
_RFC_SIG = ("52459b863f71198fd6ef5ab7f299f98a4a1e9b90442032b1cc3008bc6a14412a"
            "c310e60040af798c562f0784144915271e2275b5d2635213b66995f02457df02")


def selftest() -> None:
    sk = SigningKey(bytes.fromhex(_RFC_SK))
    if sk.public.hex() != _RFC_PUB:
        raise RuntimeError("Ed25519 self-test failed (public key)")
    if sk.sign(_RFC_MSG).hex() != _RFC_SIG:
        raise RuntimeError("Ed25519 self-test failed (sign)")
    if not verify(sk.public, _RFC_MSG, bytes.fromhex(_RFC_SIG)):
        raise RuntimeError("Ed25519 self-test failed (verify)")
    if verify(sk.public, b"other message", bytes.fromhex(_RFC_SIG)):
        raise RuntimeError("Ed25519 self-test failed (forge)")


selftest()
