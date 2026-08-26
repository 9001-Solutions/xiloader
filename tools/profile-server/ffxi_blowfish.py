"""
FFXI Blowfish — Python port of LandSandBoat src/common/blowfish.cpp.

Uses modified TT round function and custom subkey constants (not standard pi).
Compatible with FFXiMain's blowfish and LSB's C++ blowfish_init/encipher/decipher.
"""

import struct

# FFXI subkey constants (4168 bytes LE), from LSB blowfish.cpp.
# First 72 bytes = P-array (18 x uint32 LE), remaining 4096 = S-boxes (1024 x uint32 LE).
_SUBKEY_HEX = (
    "886a3f24d308a3852e8a19134473700322380"
    # ... this would be huge. Instead, load from the C header or embed.
)

# Load subkey from LSB blowfish.cpp binary blob.
# We read it once at import time.
import os as _os
_SUBKEY_PATH = _os.path.join(_os.path.dirname(__file__), "ffxi_subkey.bin")

def _load_subkey_from_lsb():
    """Parse the subkey[4168] array from LSB blowfish.cpp."""
    # Path to LandSandBoat blowfish.cpp — adjust to your local repo
    path = _os.path.join(_os.environ.get('LSB_ROOT', '.'), 'src', 'common', 'blowfish.cpp')
    with open(path, 'r') as f:
        src = f.read()

    # Find the subkey array bytes
    start = src.index("uint8 subkey[4168] = {")
    end = src.index("};", start) + 2
    block = src[start:end]

    # Extract hex bytes
    import re
    hexvals = re.findall(r'0x([0-9A-Fa-f]{2})', block)
    assert len(hexvals) == 4168, f"Expected 4168 bytes, got {len(hexvals)}"
    return bytes(int(h, 16) for h in hexvals)

_SUBKEY = _load_subkey_from_lsb()


def _u32_le(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


class FFXIBlowfish:
    """FFXI-variant Blowfish cipher."""

    def __init__(self, key: bytes):
        """Initialize with key bytes (typically 16 bytes = MD5 hash of session key)."""
        assert 1 <= len(key) <= 56

        # Load P and S from subkey constants (LE uint32)
        self.P = [_u32_le(_SUBKEY, i * 4) for i in range(18)]
        self.S = [_u32_le(_SUBKEY, 72 + i * 4) for i in range(1024)]

        # XOR key into P-array
        j = 0
        for i in range(18):
            data = 0
            for _ in range(4):
                data = ((data << 8) | key[j]) & 0xFFFFFFFF
                j = (j + 1) % len(key)
            self.P[i] ^= data

        # Encrypt-and-replace P-array
        l, r = 0, 0
        for i in range(0, 18, 2):
            l, r = self._encipher(l, r)
            self.P[i] = l
            self.P[i + 1] = r

        # Encrypt-and-replace S-boxes
        for i in range(4):
            for j in range(0, 256, 2):
                l, r = self._encipher(l, r)
                self.S[i * 256 + j] = l
                self.S[i * 256 + j + 1] = r

    def _tt(self, x):
        """FFXI modified round function."""
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF
        return (
            ((self.S[256 + c] & 1) ^ 32)
            + ((self.S[768 + a] & 1) ^ 32)
            + self.S[512 + b]
            + self.S[d]
        ) & 0xFFFFFFFF

    def _encipher(self, xl, xr):
        for i in range(16):
            xl = (xl ^ self.P[i]) & 0xFFFFFFFF
            xr = (self._tt(xl) ^ xr) & 0xFFFFFFFF
            xl, xr = xr, xl
        xl, xr = xr, xl
        xr = (xr ^ self.P[16]) & 0xFFFFFFFF
        xl = (xl ^ self.P[17]) & 0xFFFFFFFF
        return xl, xr

    def _decipher(self, xl, xr):
        for i in range(17, 1, -1):
            xl = (xl ^ self.P[i]) & 0xFFFFFFFF
            xr = (self._tt(xl) ^ xr) & 0xFFFFFFFF
            xl, xr = xr, xl
        xl, xr = xr, xl
        xr = (xr ^ self.P[1]) & 0xFFFFFFFF
        xl = (xl ^ self.P[0]) & 0xFFFFFFFF
        return xl, xr

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt 8 bytes (64-bit block)."""
        assert len(data) == 8
        xl = struct.unpack_from('<I', data, 0)[0]
        xr = struct.unpack_from('<I', data, 4)[0]
        xl, xr = self._encipher(xl, xr)
        return struct.pack('<II', xl, xr)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt 8 bytes (64-bit block)."""
        assert len(data) == 8
        xl = struct.unpack_from('<I', data, 0)[0]
        xr = struct.unpack_from('<I', data, 4)[0]
        xl, xr = self._decipher(xl, xr)
        return struct.pack('<II', xl, xr)

    def decrypt_block(self, data: bytes) -> bytes:
        """Decrypt arbitrary-length data in 8-byte ECB blocks."""
        out = bytearray()
        for i in range(0, len(data) - (len(data) % 8), 8):
            out += self.decrypt(data[i:i+8])
        return bytes(out)

    def encrypt_block(self, data: bytes) -> bytes:
        """Encrypt arbitrary-length data in 8-byte ECB blocks."""
        out = bytearray()
        for i in range(0, len(data) - (len(data) % 8), 8):
            out += self.encrypt(data[i:i+8])
        return bytes(out)
