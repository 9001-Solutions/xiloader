"""Filename IV derivation and the triple-XOR polcore applies to msg-file
filename blocks.

Symmetric: decrypt = encrypt. The 8-byte account ID drives the IV; the two
XOR_MAGIC constants are polcore's fixed keys.
"""

import struct


XOR_MAGIC_LO = 0x67891133
XOR_MAGIC_HI = 0x1C273E45


def derive_iv(account_id_8b: bytes) -> tuple[int, int]:
    """Return (IV_LO, IV_HI) — 32-bit each — from the 8-byte account ID."""
    if len(account_id_8b) != 8:
        raise ValueError(f"account_id must be 8 bytes, got {len(account_id_8b)}")

    accid = bytearray(account_id_8b)

    # Loop 1
    for i in range(1, 8):
        accid[i] = (accid[i] ^ accid[i - 1]) & 0xFF
        if accid[i] & 2:
            accid[i] |= 0x80

    # Loop 2
    u_lo = 1
    u_hi = 0
    big = 0x7048860DDF79
    for i in range(1, 8):
        bi = accid[i]
        bp = accid[i - 1]
        s = u_lo + bi
        if s > 0xFFFFFFFF:
            u_hi = (u_hi + 1) & 0xFFFFFFFF
        u_lo = s & 0xFFFFFFFF
        big = (bp * bi * big) & 0xFFFFFFFFFFFFFFFF

    # Loop 3
    lcg = 0
    for i in range(0, 8):
        if accid[i] > 0x30:
            for _ in range(accid[i] - 0x30):
                lcg = (lcg * 0x425F0CBD + 0x7F4F) & 0xFFFFFFFF

    combined = (big + ((u_hi << 32) | u_lo)) & 0xFFFFFFFFFFFFFFFF
    iv_hi = (combined >> 32) & 0xFFFFFFFF
    iv_lo = ((combined & 0xFFFFFFFF) ^ lcg) & 0xFFFFFFFF
    return (iv_lo, iv_hi)


def encrypt_filename_block(plain_lo: int, plain_hi: int, iv_lo: int, iv_hi: int) -> tuple[int, int]:
    """Apply the same triple-XOR polcore uses to decode filename blocks 0 and 1.
    Symmetric — call once to encrypt before writing the filename, polcore's
    decrypt undoes it on read."""
    return (
        (plain_lo ^ XOR_MAGIC_LO ^ iv_lo) & 0xFFFFFFFF,
        (plain_hi ^ XOR_MAGIC_HI ^ iv_hi) & 0xFFFFFFFF,
    )


def encrypt_filename_accid_fields(decoded_72b: bytes, iv_lo: int, iv_hi: int) -> bytes:
    """Encrypt the sender (bytes [0:8]) and recipient (bytes [8:16]) accid fields
    of a 72-byte decoded filename record. Returns the encrypted 72-byte record;
    feed it to the base64 encoder to get the on-disk filename string."""
    if len(decoded_72b) != 72:
        raise ValueError(f"need 72 bytes, got {len(decoded_72b)}")

    out = bytearray(decoded_72b)

    # Block 0: sender accid hash at [0..8]
    plain_lo = struct.unpack_from("<I", out, 0)[0]
    plain_hi = struct.unpack_from("<I", out, 4)[0]
    enc_lo, enc_hi = encrypt_filename_block(plain_lo, plain_hi, iv_lo, iv_hi)
    struct.pack_into("<I", out, 0, enc_lo)
    struct.pack_into("<I", out, 4, enc_hi)

    # Block 1: recipient accid hash at [8..16] — only when polcore's
    # `(decoded[0x3E] & 0xF80) != 0x880` test passes, which it does for every
    # retail file we've seen. Encrypt unconditionally so retail-shape decode works.
    plain_lo = struct.unpack_from("<I", out, 8)[0]
    plain_hi = struct.unpack_from("<I", out, 12)[0]
    enc_lo, enc_hi = encrypt_filename_block(plain_lo, plain_hi, iv_lo, iv_hi)
    struct.pack_into("<I", out, 8, enc_lo)
    struct.pack_into("<I", out, 12, enc_hi)

    return bytes(out)
