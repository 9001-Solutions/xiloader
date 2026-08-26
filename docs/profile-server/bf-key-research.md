# Friend Server BF-OFB Cipher

## Cipher

FFXI custom Blowfish (non-standard P-array + S-boxes, custom `tt` round function). Identical to LSB `src/common/blowfish.cpp`.

`tt` formula:

```
((S[256+b1] & 1) ^ 32) + ((S[768+b3] & 1) ^ 32) + S[512+b2] + S[b0]
```

## Mode

OFB stream over BF block cipher. Per-context state at `ctx+0x50..0x60` (prev_block + counter).

## Polcore Entry Points

| Symbol | Address | Purpose |
|--------|---------|---------|
| BF cipher (stream OFB) | polcore+0x63EF0 | OFB stream |
| BF block encipher (16-round) | polcore+0x64220 | Single block |

Per-connection BF contexts are keyed from the 8-byte session key at
`polcore+0xAA8E8`. The full key-derivation chain (lobby session token →
mixer → MD5 → 8-byte BF key) is documented in
`docs/profile-server/pol-bf-key-derivation.md`.

## Per-Context Layout (80 bytes)

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 0x48 | P-array (18 dwords) |
| +0x48 | 4 | Pointer to global S-box (4×256 dwords) |
| +0x50 | 4 | Mode-0 prev_block lo |
| +0x54 | 4 | Mode-0 prev_block hi |
| +0x58 | 4 | Mode-1 prev_block lo |
| +0x5C | 4 | Mode-1 prev_block hi |
| +0x60 | 4 | Mode-0 byte counter |

## Current LSB Configuration

`friend.cpp` writes `desc[0x0B] = 0` to disable crypto on all 4 polcore descriptor slots. Polcore's BF callsites gate on this byte (e.g. `polcore+0x263A8` / `polcore+0x263AD` skip the BF call when zero).

`tools/profile-server/profile_test_server.py` `BFOFBStream` class is
implemented but unused (server sends plaintext while polcore is in disabled
mode). Production polcore uses the per-session derived key (see
`docs/profile-server/pol-bf-key-derivation.md`).
