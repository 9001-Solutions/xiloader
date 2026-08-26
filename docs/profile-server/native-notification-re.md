# Native NotificationResponse

Reverse-engineering reference for polcore's native `NotificationResponse`
delivery path: the SM call graph, the msg-file I/O cluster, and the
notification queue globals. The (3,3) 416B request and the post-pump record
fetch are documented separately in `msgrec-entry-layout.md` and the polcore
audit.

## Polcore Call Graph

```
FFXi -> polcore vtable+0x70070 -> notif_pickup_wrapper (polcore+0x1AD60, __cdecl, 2 args)
                                  -> notif_drv (polcore+0x25D10)
                                    -> notif_pump (polcore+0x25B90, 7 states)
                                      state 4: send 0x1A0 bytes (the 416B request)
                                      state 5: recv via polcore+0x1F690 (24B AuthConfirm)
                                      state 6: recv 8B size header into slot+0x3C,
                                               write first dword to caller's *param_2
```

The pump returns the 8-byte header's first dword to the caller (FFXi). The notification BODY recv happens elsewhere — pump only fetches the size header.

## File API IAT Slots (runtime base 0x04580000)

| Function | IAT slot |
|----------|----------|
| `CreateFileA` | 0x045E5110 |
| `WriteFile` | 0x045E5188 |
| `ReadFile` | 0x045E5194 |
| `FindFirstFileA` | 0x045E5250 |
| `FindNextFileA` | 0x045E5254 |
| `MoveFileA` | 0x045E51D4 |
| `DeleteFileA` | 0x045E5190 |
| `GetFileSize` | 0x045E51E4 |

## Msg-File Cluster (polcore RVAs)

The polcore+0x41xxx..polcore+0x4Bxxx range holds message-file I/O.

| RVA | Function |
|-----|----------|
| polcore+0x421D3 | File-open wrapper (`__thiscall`, 3 args). `arg3` = mode selector |
| polcore+0x423DD | `WriteFile` (msg body write path) |
| polcore+0x42383 | `ReadFile` (msg body read path) |
| polcore+0x422C0 | `GetFileSize` |
| polcore+0x4BB68 | Second `CreateFileA` (sent-msg path, unconfirmed) |
| polcore+0x5428D | `FindFirstFileA` (directory enumerator) |
| polcore+0x543BD | `FindNextFileA` |
| polcore+0x41D35 | `DeleteFileA` (msg cleanup) |
| polcore+0x41D67 | `DeleteFileA` |
| polcore+0x4BC75 | `DeleteFileA` |
| polcore+0x41D43 | `MoveFileA` (unread→read transition) |

### File-open wrapper modes (polcore+0x421D3 `arg3`)

| Mode | Behavior |
|------|----------|
| 1 | `CreateFileA(name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0x88000000, 0)` — read existing |
| 3 | `CreateFileA(name, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0x88000020, 0)` — write/create |
| 4 | Seek + open variant (callsite polcore+0x4227D) |

### Callers of polcore+0x421D3

`polcore+0x41D97`, `polcore+0x41DC1`, `polcore+0x41E04`, `polcore+0x41E1B`, `polcore+0x41E5B`, `polcore+0x4206B`, `polcore+0x4217C`.

## Polcore Notification Queue

| Address | Purpose |
|---------|---------|
| polcore+0xAA974 | Registered callback fn pointer (set via polcore+0x1B500, dispatched via polcore+0x1C600) |
| polcore+0xAA980 | Notification queue base (32 entries × 0x40 bytes, total 0x800) |
| polcore+0xAA968 | Dispatch lock |
| polcore+0xAAA94 | Pending notification count |

The pump writes to a `slot+0x18`-derived buffer at `+0x190`/`+0x192`/`+0x194`. Separate post-pump code drains this and queues a notification record at polcore+0xAA980 for the callback at polcore+0xAA974 to fire.

## NotifPickup Pump (polcore+0x45A5B90)

Case 3 (build request payload) reads from slot fields:

- `puVar2 = (&DAT_04984B10)[slot * 0xCE]` — per-slot output buffer ptr (0x1A0 bytes)
- `*puVar2 = slot+0xCC byte`, `puVar2[1] = slot+0xCD byte` — 2-byte header
- `*(u16*)(puVar2 + 0x190) = 0`, `*(u16*)(puVar2 + 0x192) = 0`, `*(u32*)(puVar2 + 0x194) = 0` — clear trailer
- `polcore+0x592330(puVar2 + 0x10, slot+0xC8, 0x17F)` — copy 383 bytes from slot+0xC8
- `polcore+0x599D40(slot+0xC0, slot+0xC4)` → returns 64-bit hash, written to `puVar2 + 8`

Total: 1+1+8+0x17F = 0x191 bytes occupied of the 0x1A0 (416) request. Source data lives at `slot+0xC0..slot+0xCC` (caller-supplied) and `slot+0xC8` (383B opaque blob).

Case 6 (recv) writes the first 4 bytes of the 8-byte recv header to `*param_2`.

## Filename Decoder

vtable+0x70074 → polcore+0x59B6D0 → polcore+0x59B640 — decode msg filename → 72B record. **Not** a body fetcher.

`polcore+0x59B640(out_72B, filename_str)`:

1. `if (strlen(filename) < 0x60) return -5120` — filename must be ≥ 96 chars
2. `polcore+0x5878A0(filename, out, 0x60)` — base64 decode 96 chars → 72 bytes (alphabet inverse table at `polcore+0x5E5D64`)
3. **XOR-decrypt block 0 unconditionally**: `out[0..7] ^= 0x1C273E45_67891133 ^ IV`
4. **XOR-decrypt block 1 conditionally**: `if ((out[0x3E word] & 0xF80) != 0x880) out[8..15] ^= 0x1C273E45_67891133 ^ IV`

`IV = (DAT_0462A848, DAT_0462A84C)` — two 32-bit globals.

`polcore+0x59A080(lo, hi, magic_lo, magic_hi, iv_lo, iv_hi) = (lo^magic_lo^iv_lo, hi^magic_hi^iv_hi)` — pure triple-XOR. Symmetric. **No Blowfish.**

### IV derivation

`IV` globals are written by `polcore+0x599F20(account_id_8B_ptr)`:

- Custom hash mixing the 8-byte account ID with constant `0x7048860DDF79` and an LCG `state * 0x425F0CBD + 0x7F4F`.
- Pseudocode:

  ```
  local_10 = accid[0..3];  local_c = accid[4..7];  lVar8 = 0x7048860DDF79;  local_14 = 0
  for i in 1..7: byte = local_10[i]; if byte & 2: local_10[i] = byte | 0x80
  acc1 = sum(local_10[1..7])  // with carry into iVar5
  for i in 1..7: lVar8 = __allmul(local_14_byte_at_i+3 * local_10[i], 0, lVar8)
  for i in 0..7: if local_10[i] > 0x30: repeat (local_10[i] - 0x30) times: local_14 = local_14 * 0x425F0CBD + 0x7F4F
  IV_LO = (lVar8 lo) ^ local_14
  IV_HI = (lVar8 hi)
  ```

### IV is set during polcore COM init

```
polcore+0x59EB00(arg1, account_id_ptr, charname_ptr)   ; one-shot, gated by DAT_0462FBD8 == 0
  -> 4-slot pool setup
  -> polcore+0x59EA60(account_id_ptr, charname_ptr)    ; SetAccountInfo
       -> polcore+0x599F20(account_id_ptr)             ; derive IV from account ID
```

`IV` is a deterministic function of the player's own 8-byte account ID, which polcore is fed at session start.

## BF-OFB on Msg File Content

Per `polcore-audit.md`: `polcore+0x63EF0` BF-OFB cipher is referenced from msg paths at `polcore+0x251E0`, `polcore+0xA61F0`, `polcore+0xA68B3`, `polcore+0xA6FC4`, `polcore+0xA7083` (7+ xrefs). Implication: when polcore writes a msg file, the body is encrypted with BF-OFB. Redirected msg files containing plaintext produce garbage on decryption ("Downloading data" hang).

## Capture-Side Observations

`charb_befriends_chara_chara_accepts.json`, `chara_befriend_syra.json`:

- C→S `NotificationPickup` is 416 bytes (encrypted)
- S→C `NotificationResponse` is 22/26/30/34 bytes (encrypted)

Pump receives 24B (AuthConfirm) + 8B (size header) = 32B from the NotificationPickup state machine. Capture sizes do not match either individually; reconciliation is open work.

## Tooling


Both rebase to runtime base `0x04580000`.
