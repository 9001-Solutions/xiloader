# POL BF session key derivation

How polcore derives the 8-byte Blowfish session key used for IXFF profile-
server traffic. All polcore addresses use image base `0x04580000`.

## Inputs

The session token (`token`) — 8 bytes, the lobby/auth handshake response. xiloader
captures it during the auth flow and is also visible at runtime in the polcore
global at `polcore+0x404A88`.

## Output

8-byte BF session key, written to `polcore+0xAA8E8` (`DAT_0462A8E8` low,
`DAT_0462A8EC` high). Per-connection BF contexts are keyed from this when
`desc[0x0B] != 0` (BF-enabled).

## Chain

```
polcore_set_session_key (polcore+0x1EA60)
  ─ called when polcore receives the lobby session response
  ─ args: (token_ptr, hash_ptr)
  │
  └── polcore_derive_session_mask (polcore+0x19F20)
       ─ args: (token_ptr)
       ─ produces 8-byte mask
       ─ output stored at polcore+0xAA848  (DAT_0462A848 / 0462A84C)
       │
       └── polcore_derive_bf_session_key (polcore+0x1A1E0)
            ─ args: (mask_lo, mask_hi)
            ─ MD5(mask, 8 bytes) → first 8 bytes are the BF key
            ─ output stored at polcore+0xAA8E8 (DAT_0462A8E8 / 0462A8EC)
```

## Per-connection BF context init

After the session key exists in the global at `polcore+0xAA8E8`, the
HTTP-handshake response handler (`FUN_04595E80`) initialises a per-connection
BF context for each new IXFF connection:

```
polcore_init_bf_ctx_with_key(ctx, sbox_mem, key_lo, key_hi, iv_ptr)   polcore+0x63EB0
  └── polcore_blowfish_init_key (polcore+0x64300)
        ─ standard Blowfish key schedule:
        ─ 4 KB S-box init via the 8-byte key
        ─ P-array XOR with key
        ─ 521 BF-round mixing pass
```

The 5th arg is a pointer to an 8-byte IV taken from the handshake response
payload (`*(uint32*)**(uint32**)(param_1 + 0x39c8)`). Stored at
`bf_ctx+0x58..0x5F`. Encrypt direction starts at `bf_ctx+0x50`, reset before
each frame in `polcore_send_body_sm` case 1
(`polcore_blowfish_ofb_xform(buf, buf, len, ctx, 0)`). Decrypt direction
reuses the IV-shadow at `+0x58` (call with last-arg `1`).

## Key-derivation pseudocode

```python
def derive_session_mask(token: bytes) -> bytes:
    """
    polcore+0x19F20 — port of the deterministic mask-mixing function.
    Same algorithm used to derive the filename-XOR IV in
    docs/profile-server/native-notification-re.md §IV derivation.
    """
    local_10 = bytearray(token[0:4])
    local_c  = bytearray(token[4:8])
    lVar8    = 0x7048860DDF79
    local_14 = 0

    for i in range(1, 8):
        b = (local_10 + local_c)[i]
        if b & 2:
            (local_10 + local_c)[i] = b | 0x80

    # acc1 sum (with carry bookkeeping)
    acc1 = sum((local_10 + local_c)[1:8])

    for i in range(1, 8):
        b = (local_10 + local_c)[i]
        # __allmul: 64-bit multiply via WinSDK helper
        lVar8 = ((local_14_byte_at(i + 3) * b) * lVar8) & ((1 << 64) - 1)

    for i in range(0, 8):
        b = (local_10 + local_c)[i]
        if b > 0x30:
            for _ in range(b - 0x30):
                local_14 = (local_14 * 0x425F0CBD + 0x7F4F) & 0xFFFFFFFF

    iv_lo = (lVar8 & 0xFFFFFFFF) ^ local_14
    iv_hi = (lVar8 >> 32) & 0xFFFFFFFF
    return iv_lo.to_bytes(4, 'little') + iv_hi.to_bytes(4, 'little')


def derive_bf_session_key(mask: bytes) -> bytes:
    """
    polcore+0x1A1E0 — MD5(mask) truncated to 8 bytes.
    """
    import hashlib
    return hashlib.md5(mask).digest()[:8]
```

A working Python port lives at `tools/profile-server/ffxi_blowfish.py`

## Cipher mechanics

The cipher layer (Blowfish-OFB with newline preservation) and per-context
data layout are documented separately in
`docs/profile-server/bf-key-research.md`.

## Notable globals

| Address              | Role                                          |
|----------------------|-----------------------------------------------|
| `polcore+0x404A88`   | session token (8B, raw input)                 |
| `polcore+0xAA848`    | derived 8-byte session mask (post-mixer)      |
| `polcore+0xAA8E8`    | derived 8-byte BF session key (post-MD5)      |
| `polcore+0x39C8`-rel | per-connection IV source (from HTTP handshake)|
| `desc+0x50..0x60`    | per-connection BF context (key schedule + IV) |
| `desc+0x0B`          | per-descriptor BF-enabled flag (0 = disabled) |

## Related code paths

- `polcore+0x63EF0` — `polcore_blowfish_ofb_xform` (OFB stream xform with
  CR/LF passthrough).
- `polcore+0x63EB0` — `polcore_init_bf_ctx_with_key` (per-connection ctx
  init).
- `polcore+0x64300` — `polcore_blowfish_init_key` (standard BF schedule).
- `polcore+0x1F5E0` — `polcore_pack_ixff_header` (uses session token in the
  16-byte digest at `hdr[0x18..0x27]`).

## Confirmation

- Befriend wire format work (`docs/profile-server/befriend-ixff-wire-format.md`
  §5c) verified the chain end-to-end against a real session.
- Filename XOR IV derivation in `docs/profile-server/native-notification-re.md`
  §"IV derivation" uses the same mask-mixing function (`polcore+0x99F20` /
  `polcore+0x19F20`).
- Production polcore uses only the per-session derived key documented here.
  Any fixed-bytes constant referenced in older scaffolding code is dev-only
  and does not appear in production traffic.
