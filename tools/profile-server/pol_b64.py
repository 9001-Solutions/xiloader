"""POL push-channel text codec (polcore FUN_100078A0 / its inverse).

Custom base64: 4 chars -> 3 bytes, MSB-first, alphabet lifted from polcore's
char->value table at 0x10065D64.
"""
ALPHA = "TSG8IncW3HFKokOg79qzeCmZs2yBYEQVAUxR5rbwi4P@jMDLtpvad0f_J1hlN6uX"
REV = {c: i for i, c in enumerate(ALPHA)}


def decode(text):
    out = bytearray()
    for i in range(0, len(text) - 3, 4):
        v = 0
        for c in text[i:i + 4]:
            v = (v << 6) | REV[c]
        out += bytes(((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF))
    return bytes(out)


def encode(data):
    out = []
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        while len(chunk) < 3:
            chunk += b"\0"
        v = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]
        for s in (18, 12, 6, 0):
            out.append(ALPHA[(v >> s) & 0x3F])
    return "".join(out)


if __name__ == "__main__":
    # Round-trip sanity
    import os
    r = os.urandom(72)
    assert decode(encode(r))[:72] == r, "round-trip failed"
    print("round-trip OK")
    # Decode a real polcore token to see if it looks structured
    tok = "5mP8NkdvGIQSGG9eNrpaxgc6KazoyuthLje7ip3dG5sidWo"
    print("USER realname token decodes to:")
    print(" ", decode(tok).hex())


KEY_LO = 0x67891133
KEY_HI = 0x1C273E45


def build_status_notice(friend_index, online, ident_lo, ident_hi=0,
                        iv_lo=0, iv_hi=0, ts_hi=0x7FFFFFFF, ts_lo=0x7FFFFFFF,
                        rec0=0x00, rec2=0x07, match18=0x00):
    """Build the 96-char payload for a friend online/offline status push.

    Gates enforced by status_update_dispatch (polcore+0x1B6F0); every one is
    required or the record is silently dropped:
      +0x42 u16  bit 0 set
      +0x3E u16  (val & 0xF80) == 0xF80   <- NOT 0x880; that is the parser's
                                             own separate check at +0x1B640
      +0x1B u8   non-zero
      +0x1C u8   friend index, must be < 0xC8

    The record passed on to FUN_100250B0 (the type-0x1F apply) starts at +0x10,
    so +0x11 is rec[1]: 2 = ONLINE, 1 = OFFLINE.
    """
    import struct
    rec = bytearray(72)
    struct.pack_into("<H", rec, 0x42, 0x0001)
    struct.pack_into("<H", rec, 0x3E, 0x0F80)
    rec[0x1B] = 0x01
    rec[0x1C] = friend_index & 0xFF

    # The parser XORs the first 8 bytes with (KEY ^ IV); the dispatcher then
    # requires the result to equal the friend's identity from
    # FUN_10023DA0(index), or it drops the update. XOR is self-inverse.
    struct.pack_into("<I", rec, 0x00, (ident_lo ^ KEY_LO ^ iv_lo) & 0xFFFFFFFF)
    struct.pack_into("<I", rec, 0x04, (ident_hi ^ KEY_HI ^ iv_hi) & 0xFFFFFFFF)

    # Compared as ((lookup[0x9C] >> 13) & 0x3F) == record[0x18].
    rec[0x18] = match18 & 0xFF

    rec[0x10] = rec0 & 0xFF
    rec[0x11] = 0x02 if online else 0x01
    rec[0x12] = (rec2 & 0xFF) if online else 0x00

    # Game type -> entry+0x0C bits 1-10. 1 = FFXI, and this is what drives the
    # XI icon on the row. Leaving it 0 renders the friend online but with no
    # game icon.
    struct.pack_into('<H', rec, 0x14, 1 if online else 0)

    # Must be strictly newer than the stored pair or the update is ignored.
    struct.pack_into("<I", rec, 0x30, ts_hi & 0xFFFFFFFF)
    struct.pack_into("<I", rec, 0x34, ts_lo & 0xFFFFFFFF)
    return encode(bytes(rec))


def build_status_notice_rich(friend_index, online, ident_lo, charname,
                             zone_id, ident_hi=0, ts=0, dispname=None,
                             rec0=0x00, rec2=0x07, match18=0x00):
    """Build a NOTICE payload that pushes the WHOLE row, not just online bits.

    status_update_dispatch (polcore+0x1B6F0) has two branches:

      A  record[0x1B] != 0  -> FUN_100250B0 -> FUN_1001ECB0
         Writes ONLY the bit-fields in Array2 entry+0x08/+0x0C. No name, no
         zone, no sub-entry -- the friend renders online but blank.

      B  record[0x1B] == 0 and record[0x1A] == 0 and record[0x19] & 1
         and record[0x38] < 0x158
         -> FUN_100250F0, which also writes the name, the status-table blob
            (zone lives in it) and the sub-entry the in-game render predicate
            FUN_03ED77A0 gates on.

    This builds B. The second payload is base64 text appended directly after
    the 96-char base record (polcore reads it from base + 0x60) and decodes to
    a byte block whose FIRST byte is a presence bitmask:

        0x01  apply the base record's status bytes
        0x02  ROUTES TO A DIFFERENT HANDLER (FUN_10029650) -- must stay CLEAR
        0x04    8B  type word    -> status table +0x00
        0x08   16B  sub-entry    -> entry+0x18 + (idx&7)*0x10, bit 0 set
        0x10   16B  name (15B)   -> Array2 entry+0xA0
        0x20  104B  struct blob (0x32 used) -> status table +0x1C; zone at +0x14
        0x40  rest  display name (0x17) -> status table +0x04

    Blocks are packed in that order, starting at offset 8.
    """
    import struct as _s

    mask = 0x01 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40
    blk = bytearray(8)
    blk[0] = mask

    # 0x04: type word -> the 0x41 the status table carries at +0x00
    blk += _s.pack('<II', 0x00000041, 0)

    # 0x08: sub-entry. FUN_100250F0 reads +2 (u16), +4, +8, +0xC (u32) and
    # sets bit 0 of the destination itself, which is what satisfies
    # FUN_03ED77A0's "== 1" test.
    sub = bytearray(16)
    _s.pack_into('<H', sub, 2, 1)
    blk += sub

    # 0x10: 15-byte character name -> Array2 entry+0xA0
    nm = bytearray(16)
    cn = charname.encode('ascii', 'replace')[:15]
    nm[0:len(cn)] = cn
    blk += nm

    # 0x20: 104B block, first 0x32 copied to status table +0x1C. Mirrors what
    # do_sync_status step 2 synthesises: 0x0101 words, 0x0100 at index 22, and
    # the zone at blob+0x14 (status table +0x30) tagged with 0x4000.
    blob = bytearray(104)
    for j in range(25):
        _s.pack_into('<H', blob, j * 2, 0x0100 if j == 22 else 0x0101)
    if zone_id:
        _s.pack_into('<H', blob, 0x14, (zone_id & 0x3FFF) | 0x4000)
    blk += blob

    # 0x40: 23-byte display name -> status table +0x04
    dn = bytearray(24)
    d = (dispname or charname).encode('ascii', 'replace')[:23]
    dn[0:len(d)] = d
    blk += dn

    second = encode(bytes(blk))

    rec = bytearray(72)
    _s.pack_into('<H', rec, 0x42, 0x0001)
    _s.pack_into('<H', rec, 0x3E, 0x0F80)
    _s.pack_into('<I', rec, 0x00, (ident_lo ^ KEY_LO) & 0xFFFFFFFF)
    _s.pack_into('<I', rec, 0x04, (ident_hi ^ KEY_HI) & 0xFFFFFFFF)
    rec[0x18] = match18 & 0xFF
    rec[0x19] = 0x01          # local_3f bit 0 -- required for branch B
    rec[0x1A] = 0x00          # local_3e must be 0
    rec[0x1B] = 0x00          # local_3d must be 0, else branch A wins
    rec[0x1C] = friend_index & 0xFF
    rec[0x10] = rec0 & 0xFF
    rec[0x11] = 0x02 if online else 0x01
    rec[0x12] = (rec2 & 0xFF) if online else 0x00
    _s.pack_into('<H', rec, 0x14, 1 if online else 0)
    _s.pack_into('<I', rec, 0x30, ts & 0xFFFFFFFF)
    _s.pack_into('<I', rec, 0x34, ts & 0xFFFFFFFF)
    # Length of the SECOND payload, in base64 characters.
    _s.pack_into('<I', rec, 0x38, len(second))

    return encode(bytes(rec)) + second
