"""Self-contained MD4 so NTLM works on modern Python/OpenSSL.

OpenSSL 3 drops MD4 from its default provider, so `hashlib.new("md4")` raises and ldap3's NTLM
bind fails with "unsupported hash type MD4". NTLM still *needs* MD4 (it's the NT hash function),
so we supply a small pure-Python MD4 (RFC 1320) and transparently route hashlib's "md4" through
it. No external dependency, no system config. Only touches the md4 name; everything else is
untouched.
"""

from __future__ import annotations

import hashlib
import struct


class MD4:
    """hashlib-compatible MD4 (update / digest / hexdigest)."""

    def __init__(self, data: bytes = b""):
        self._buf = b""
        self._msglen = 0
        self._h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        if data:
            self.update(data)

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def update(self, data: bytes) -> None:
        self._buf += bytes(data)
        self._msglen += len(data)
        while len(self._buf) >= 64:
            self._compress(self._buf[:64])
            self._buf = self._buf[64:]

    def _compress(self, block: bytes) -> None:
        X = list(struct.unpack("<16I", block))
        a, b, c, d = self._h
        F = lambda x, y, z: (x & y) | (~x & z)          # noqa: E731
        G = lambda x, y, z: (x & y) | (x & z) | (y & z)  # noqa: E731
        H = lambda x, y, z: x ^ y ^ z                    # noqa: E731
        r = self._rotl
        # Round 1
        for i in (0, 4, 8, 12):
            a = r(a + F(b, c, d) + X[i], 3)
            d = r(d + F(a, b, c) + X[i + 1], 7)
            c = r(c + F(d, a, b) + X[i + 2], 11)
            b = r(b + F(c, d, a) + X[i + 3], 19)
        # Round 2
        for i in (0, 1, 2, 3):
            a = r(a + G(b, c, d) + X[i] + 0x5A827999, 3)
            d = r(d + G(a, b, c) + X[i + 4] + 0x5A827999, 5)
            c = r(c + G(d, a, b) + X[i + 8] + 0x5A827999, 9)
            b = r(b + G(c, d, a) + X[i + 12] + 0x5A827999, 13)
        # Round 3
        for i in (0, 2, 1, 3):
            a = r(a + H(b, c, d) + X[i] + 0x6ED9EBA1, 3)
            d = r(d + H(a, b, c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = r(c + H(d, a, b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = r(b + H(c, d, a) + X[i + 12] + 0x6ED9EBA1, 15)
        self._h = [(self._h[0] + a) & 0xFFFFFFFF, (self._h[1] + b) & 0xFFFFFFFF,
                   (self._h[2] + c) & 0xFFFFFFFF, (self._h[3] + d) & 0xFFFFFFFF]

    def digest(self) -> bytes:
        h, buf, msglen = list(self._h), self._buf, self._msglen
        pad = b"\x80" + b"\x00" * ((55 - msglen % 64) % 64)
        self.update(pad + struct.pack("<Q", msglen * 8))
        out = struct.pack("<4I", *self._h)
        self._h, self._buf, self._msglen = h, buf, msglen  # keep hasher reusable
        return out

    def hexdigest(self) -> str:
        return self.digest().hex()


def install() -> bool:
    """Route hashlib.new('md4') through the pure-Python MD4 if the platform can't do MD4."""
    try:
        hashlib.new("md4")
        return True  # native MD4 works, nothing to do
    except Exception:  # noqa: BLE001
        pass
    _orig = hashlib.new

    def _new(name, data=b"", **kw):  # noqa: ANN001
        if str(name).lower() == "md4":
            return MD4(data)
        return _orig(name, data, **kw)

    hashlib.new = _new
    return True
