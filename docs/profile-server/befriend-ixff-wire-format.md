# /befriend IXFF wire format

Reverse-engineering record of the `/befriend` command path from FFXiMain
through polcore. All FFXiMain addresses use image base `0x04610000`; RVA =
addr − base. polcore image base is `0x04580000` for the runtime-unpacked dump
at `re_dumps/polcore_dumped.bin`.

## 1. Chat handler

`befriend_chat_handler @ 0x04689F50` (RVA `0x79F50`) is the entry registered
for the `/befriend` chat command (id `0x0D`).

```c
int __cdecl befriend_chat_handler(void* buf, const char* servmes, int id)
{
    if (token_count != 2) return -id;             // [0x047C488]
    sentinel = 0;                                  // [0x047C4B8]
    strncpy(target_buf, token_ptrs[1], 0x10);      // [0x047C338], [0x3541F4]
    normalize_charname(target_buf);
    FUN_04713D60(stack_dialog_struct);             // zero-init
    FUN_047179E0(stack_dialog_struct);             // populate friend rows
    FUN_04717530(stack_dialog_struct, target_buf); // copy charname into struct
    befriend_show_confirm_dialog(
        stack_dialog_struct,
        /*type=*/0,
        /*flag=*/3,
        /*callback=*/befriend_dialog_callback,
        /*user_data=*/target_buf);
    return id;
}
```

Globals:
- `token_count` at FFXiMain `0x47C488` — chat-tokenizer output count.
- `token_ptrs` at FFXiMain `0x3541F0` — array of `char*`; `[0]="/befriend"`, `[1]=target charname`.
- `target_buf` at FFXiMain `0x47C338` — 16-byte target charname buffer.
- `sentinel` at FFXiMain `0x47C4B8` — set to 1 after a successful submit; gates the
  cancel-error path in the dialog callback.

## 2. Dialog confirm + selection

`befriend_show_confirm_dialog @ 0x046F2850` is a thin wrapper around
`FUN_046F1A50` which guards on `DAT_04AEE768 != 0 && *(DAT_04AEE768+0x1369C) != 0`.
`DAT_04AEE768` is the FFXi friend-system root; `+0x1369C` is the per-character
dialog-manager pointer. Both must be non-NULL or the dialog silently fails to
open and the chat handler returns to caller with no visible effect.

`befriend_dialog_callback @ 0x04689FE0`:

```c
void befriend_dialog_callback(void* unused, int* selection)
{
    if (selection == NULL) {                       // dialog cancelled
        if (sentinel == 0)
            FUN_04739CD0(0xa2);                    // emit cat=7 msg=0xa2
        return;
    }
    if (*selection == 3) {                          // friend record selected
        int* record = (int*)selection[2];           // pointer to friend record
        if (charname_in_record_matches(target_buf)) {
            befriend_submit(record, /*caller_id=*/1);
            sentinel = 1;
        }
    }
}
```

Selection types `1`, `2`, `4`, `5` map to other menu actions in
`befriend_dispatch_caller @ 0x0481C4D0` (friend-list right-click menu):
`/tell`, `befriend_submit(record, 0)`, party invite, party-request add,
party-request remove. The chat path always uses caller_id=1; the menu path
uses caller_id=0.

## 3. Submit pipeline

`befriend_submit @ 0x0480F550`:

```c
void __thiscall befriend_submit(void* this, uint32_t* record, uint32_t caller_id)
{
    if (already_inflight)                          // [0x04C3FFA0]
        { FUN_04739CD0(0x7a); return; }            // emit cat=7 msg=0x7a
    memcpy(this+0x184, record, 72);                // 0x12 dwords copied; payload
                                                   // is dead in this build (never
                                                   // read by op-table state fns)
    uint32_t lo16 = record[6];
    uint8_t  zone = friend_zone_byte_lookup(*(PTR_DAT_0496F1C4 + 0x80));
    int rc = friend_op_send_check_conn(
        record[5],                                  // -> slot[0x38] account_id_hi
        ((zone<<8) | (lo16 & 0xF0000)) << 8        // -> slot[0x3c] packed
            | (lo16 & 0xFFFF),
        0,
        befriend_response_callback,                 // -> slot[0x104c]
        caller_id & 0xff);                          // -> slot[0x1048]
    if (rc == 0) already_inflight = 1;
}
```

Record fields consumed by the wire send (not the dead 72-byte copy):
- `record[5]` (offset 0x14) — account_id high half.
- `record[6]` (offset 0x18) bits `[15:0]` — account_id low half.
- `record[6]` bits `[19:16]` — world / realm nibble.
- `zone` — current character's zone byte from the FFXi character manager.

The chain past `befriend_submit`:

```
friend_op_send_check_conn @ 0x04707520
    if DAT_04AEE900 == 0 → return 2 (no friend connection object)
    → friend_op_increment_seq @ 0x04702350
        if [conn+0x20] == 0 → return 0x10 (op slot pool not allocated)
        slot.seq16++; if seq16 == 0 → seq16 = 1
        → friend_op_fill_slot @ 0x04703880
            if slot[0x416] != 0 → return 3 (slot busy)
            populate slot fields:
                slot[0]      = caller (acct_hi packed)
                slot[8]      = seq16
                slot[0xe..f] = result-callback ctx
                slot[0x11]   = -bool(caller_id) & 0x78
                slot[0x412]  = caller_id  (-> later returned as cb arg0)
                slot[0x413]  = unused
                slot[0x416]  = seq16 again (busy marker)
            → inner_send(&op_table_befriend = 0x04971188)
                → state_dispatcher(slot, 0) returns 0x16 (init); pump owns the
                  slot from here, returns 0 from inner_send
```

`DAT_04AEE900` (FFXi `0x4DE900`) is the friend connection object, lazily
allocated by `FUN_04707550`. It owns two op-slot buffers (0x1060 bytes each)
allocated at `[conn+0x20]` and `[conn+0x24]`.

## 4. Op-state table (befriend submit)

Located at FFXiMain `0x04971188` (RVA `0x361188`). Three function-pointer
entries plus terminator:

| Slot | Address    | RVA      | Function                     |
|------|------------|----------|------------------------------|
| 0    | 0x04704400 | 0x0F4400 | `friend_op_state_dispatcher` |
| 1    | 0x047049F0 | 0x0F49F0 | `befriend_op_send`           |
| 2    | 0x04704840 | 0x0F4840 | `befriend_op_parse_response` |
| 3    | 0x00000000 | —        | terminator                   |

Slot 0 returns op codes for slot lifecycle:
state 0 → `0x16` (init), state 1 → `0x17` (advance), state 2 → `6`,
state 3 → `0`, default → `0x15` (terminal-error).

This same table address is hardcoded as the operand of the `PUSH 0x4971188`
at `0x04703897` inside `friend_op_fill_slot`. The other ~17 op-tables in the
range `0x049710C8 .. 0x0497131C` are reached only through different submit
factories (FUN_047033D0/04703490/04703560/04703630/04703700/04703900 etc.)
and represent message-send, dismiss, inbox-fetch, body-fetch, and follow-up
operations.

The slot pump is `friend_op_slot_pump @ 0x04702B20`. It indexes
`slot[0x105C] = table_ptr`, `slot[0x105A] = state_index`, calls
`table[state_index](slot, advance_flag)`, and routes the return:
- `0x17` → advance state_index, repeat.
- `0x16` → wait for tick.
- terminal value → invoke result callback as
  `(*slot[0x104C])(slot[0x1048], 0, return_code, slot+8 if return_code != 0 else NULL)`.

The pump is driven from `friend_op_tick @ 0x04701BC0` →
`friend_op_tick_outer @ 0x047075A0`, called by `FUN_0484B7E0` and
`FUN_047137C0` in the FFXi main loop.

## 5. Wire send — polcore boundary

`befriend_op_send` calls polcore via the service vtable. The two outbound
thunks are stack-coupled in cdecl:

```asm
PUSH packed         ; → 4th arg of submit
PUSH 0              ; → 3rd arg
PUSH account_id_hi  ; → 2nd arg
CALL [vt+0x33C]     ; polcore_get_seq_id — returns ushort token in EAX
PUSH EAX            ; token becomes 1st arg (short seq)
CALL [vt+0x340]     ; polcore_befriend_begin — the real submit
ADD ESP, 0x10       ; cleans 4 dwords (combined call site)
```

Polcore service vtable base: `polcore+0x6FBE8` (abs `0x045EFBE8`). Slot map:

| Thunk                     | FFXiMain addr | vtable slot | Polcore target                   | RVA      |
|---------------------------|---------------|-------------|----------------------------------|----------|
| `ixff_send_packet`        | 0x0491FAEB    | vt+0x33C    | `polcore_get_seq_id`             | 0x1CB50  |
| `ixff_finalize_send`      | 0x0491FAF6    | vt+0x340    | `polcore_befriend_begin`         | 0x23050  |
| `ixff_poll_response`      | 0x0491FB01    | vt+0x344    | `polcore_befriend_poll`          | 0x23330  |
| `ixff_cancel_send`        | 0x0491FA93    | vt+0x31C    | `polcore_cancel_send`            | 0x25280  |
| `ixff_get_inbox_entry`    | 0x0491F933    | vt+0x29C    | `polcore_inbox_get_entry_main`   | 0x23DA0  |
| `ixff_get_inbox_entry_alt`| 0x0491F949    | vt+0x2A4    | `polcore_inbox_get_entry_alt`    | 0x23F90  |

> Vtable slots `0x29C` / `0x2A4` for the inbox getters supersede the prior
> memo's `0x274` / `0x278`. The earlier offsets were a mis-read of the trampoline
> `JMP [EAX+disp32]` field.

`vt+0x33C` is **NOT** the submit — it just returns the next seq id (counter
initialised at 1000, stored at polcore `0x045F5428`). The real submit is
`vt+0x340 = polcore_befriend_begin` which receives `(seq, acct_hi, 0, packed)`.

`DAT_04A65A24` (FFXiMain) is set during FFXi entry (`FUN_04625700`) from
`DAT_04A659AC`, which holds the polcore service vtable handed back by the
COM init handshake. Polcore exposes the vtable via `FUN_0458690E`
(`IClassFactory`-style getter writing `&DAT_045EFBE8` to its out-param).

For comparison, the message-send op-tables (e.g., `0x049710C8`) DO go through
a body-allocator path `vt+0x440` (`polcore+0x1A8E0`) invoked from a builder
function `FUN_04702EF0`. Befriend never uses that path.

## 5a. polcore submit — `polcore_befriend_begin` (vt+0x340)

`polcore+0x23050`, signature
`int polcore_befriend_begin(short seq, uint32_t acct_hi, uint32_t reserved, uint32_t packed)`.

Steps:

1. Allocate a free slot from descriptor array `polcore+0x404AD0` (4 slots
   × stride `0x338`, slot[0]=alloc-flag). On exhaustion: return `-0x1C12`.
2. Initialise the descriptor via `polcore_init_descriptor` (`polcore+0x1EA00`).
3. Resolve the body buffer via parallel array `polcore+0x404DF8` indexed by
   `slot * 0xCE` dwords.
4. Populate the **24-byte request body** at body buffer:

| body offset | size | source                           | role                                |
|-------------|------|----------------------------------|-------------------------------------|
| `0x00..0x03`| 4    | `acct_hi`                        | account id, high half               |
| `0x04..0x07`| 4    | `0` (reserved arg)               | reserved                            |
| `0x08..0x0B`| 4    | `packed`                         | `(zone<<16) | (world<<8) | extra`   |
| `0x0C..0x0D`| 2    | `seq`                            | sequence id (1000+, monotonic)      |
| `0x0E`      | 1    | `FUN_0459CBB0()` return          | sub-id (per-call counter)           |
| `0x0F`      | 1    | `0`                              | pad                                 |
| `0x10..0x17`| 8    | (zero at submit)                 | filled later by header packer       |

5. Set `desc.state = 1`, `desc[0x328] = 6` via `FUN_0459FF20(desc, 6, 0)` —
   initial SM state.
6. Set `polcore+0x404B90 + slot*0x338 = (seq == 1000 ? 1 : 0)` —
   first-of-session sentinel.
7. Return slot index (used as opaque handle).

**Submit does NOT touch the wire.** Wire I/O happens later, driven by the
state machine via `polcore_befriend_poll` (vt+0x344, `polcore+0x23330`),
which forwards to `polcore_befriend_finalize_sm` (`polcore+0x23100`).

## 5b. polcore state machine — `polcore_befriend_finalize_sm`

Seven-state machine, polled by FFXi via `ixff_poll_response`. Wire-relevant
transitions:

| State | Address              | Call                                                   | Wire effect                              |
|-------|----------------------|--------------------------------------------------------|------------------------------------------|
| 1→2   | `polcore+0x2315D`    | `polcore_connect_sm(desc)`                             | TCP connect to game/map data port        |
| 2→3   | `polcore+0x23193`    | `polcore_send_ixff_header_sm(desc, 1, 0xB, 0x18)`      | encrypt + send 0x28-byte IXFF header     |
| 3→4   | `polcore+0x231CE`    | `polcore_send_body_sm(desc, 0x18, 1, body)`            | encrypt + send 24-byte body              |
| 4→5   | `polcore+0x231FE`    | `polcore_drain_sm(desc)`                               | flush / wait                             |
| 5→6   | `polcore+0x23239`    | `polcore_recv_body_sm(desc, 0x30, 1, body)`            | receive 48-byte response                 |
| 6     | `polcore+0x23268..`  | parse                                                  | extract result fields, return to FFXi    |

**Wire opcode: class=`1`, opcode=`0x0B`.** Hardcoded as immediate operands at
`polcore+0x23193`. The seq value lives inside the body at `[0x0C..0x0D]`,
not in the header.

**Decrypted wire sizes**:
- Request:  IXFF header `0x28` + body `0x18` = `0x40` (64) bytes plaintext.
- Response: IXFF header `0x28` + body `0x30` = `0x58` (88) bytes plaintext.
- On-wire: framed as `[len32 | "IXFF" | encrypted-payload | digest]`. The
  76-byte (`0x4C`) capture aligns with: `4 (len) + 4 (magic) + 0x40 (encrypted)
  + 0x10 (MD5-truncated tail digest) = 0x4C`.

`polcore_pack_ixff_header` (`polcore+0x1F5E0`) builds the 0x28-byte header
at `desc+0x40`:

```
hdr[0x00]  = 0x02                      // packet kind
hdr[0x01]  = class                     // = 1 for befriend
hdr[0x02]  = opcode                    // = 0x0B for befriend
hdr[0x03]  = 0
hdr[0x04..07] = body_len               // = 0x18
hdr[0x08..0F] = 0
hdr[0x10..17] = 0                      // echo of [8..F]
hdr[0x18..27] = MD5-truncated digest of (session_token, session_hash[15], desc+0xB8[4 bytes])
```

If `desc[0x0B] != 0` (BF-enabled flag), the entire header is encrypted
in-place by `polcore_blowfish_ofb_xform(hdr, hdr, 0x28, desc+0x50, 1)`.

## 5c. Encryption — Blowfish OFB stream

`polcore_blowfish_ofb_xform @ polcore+0x63EF0`. Blowfish in OFB-stream mode
**with newline sentinel preservation**: bytes `0x0A` (LF) and `0x0D` (CR)
pass through unencrypted in both plaintext and ciphertext directions:

```c
out[i] = (b == 0x0A || b == 0x0D || (b ^ stream) == 0x0A
                                  || (b ^ stream) == 0x0D) ? b : (b ^ stream);
```

Per-descriptor BF context layout at `desc+0x50`:

| offset       | role                                                  |
|--------------|--------------------------------------------------------|
| `+0x50..0x57`| OFB stream state (encrypt direction, key+counter)      |
| `+0x58..0x5F`| OFB stream state (decrypt direction, IV shadow)        |
| `+0x60`      | byte counter (re-encrypts every 8 bytes)               |
| `+0x48`      | sbox memory pointer (4 KB Blowfish S-box)              |

**Key derivation** (per session — see
`docs/profile-server/pol-bf-key-derivation.md` for the full chain):

1. `polcore_set_session_key(token_ptr, hash_ptr)` `polcore+0x1EA60` —
   entry, called when polcore receives the lobby session response.
2. → `polcore_derive_session_mask(token_ptr)` `polcore+0x19F20` — builds an
   8-byte mask from the auth token. Same function the Python test server's
   IV derivation was previously ported from. Output stored at
   `polcore+0xAA848` (`DAT_0462A848 / 0462A84C`).
3. → `polcore_derive_bf_session_key(mask_lo, mask_hi)` `polcore+0x1A1E0` —
   `MD5(mask, 8) → first 8 bytes`. Stored at `polcore+0xAA8E8`
   (`DAT_0462A8E8 / 0462A8EC`). **This is the Blowfish 8-byte session key.**
4. Per-connection BF context init in `FUN_04595E80` (HTTP-handshake response
   handler) calls `polcore_init_bf_ctx_with_key(ctx, sbox_mem, key_lo,
   key_hi, iv_ptr)` `polcore+0x63EB0`. Standard Blowfish key schedule in
   `polcore_blowfish_init_key` `polcore+0x64300` — 4 KB S-box init via the
   8-byte key, P-array XOR, 521 BF-round mixing pass.
5. **IV is per-connection**, derived at handshake time from the handshake
   response payload (`*(undefined4 *)**(undefined4 **)(param_1 + 0x39c8)`).
   Encrypt direction starts at `bf_ctx+0x50`, reset before each frame
   (`polcore_send_body_sm` case 1: `xform(buf, buf, len, ctx, 0)`).
   Decrypt direction reuses the IV-shadow at `+0x58`.

## 6. Response handling

Befriend (opcode `0x0B`, class `1`) is **synchronous request/response** —
the response does NOT flow through the polcore notification inbox. Instead,
`polcore_befriend_finalize_sm` state 6 (`polcore+0x23268..0x232E0`) extracts
fields directly from `desc.body` and returns them via the poll's
out-arguments.

**Response body layout (48 bytes, decrypted)**:

| body offset | size | meaning                                      | FFXi destination                         |
|-------------|------|----------------------------------------------|------------------------------------------|
| `0x00..0x07`| 8    | account_id (hashed via `FUN_04599D40`)       | `local_8/uStack_4` in `befriend_op_send` |
| `0x08..0x0F`| 8    | unused                                       | —                                        |
| `0x10..0x1E`| 15   | nickname                                     | `slot+0x40` (15B name buffer)            |
| `0x1F`      | 1    | NUL pad                                      | —                                        |
| `0x20`      | 1    | accept/reject flag (0 = rejected → -0x1C12)  | gates SM return value                    |
| `0x21`      | 1    | status code byte                             | (not consumed)                           |
| `0x22..0x2F`| 14   | reserved                                     | —                                        |

State 6 logic:

```c
if (polcore+0x404B90[slot*0x338] != 0)         // first-of-session sentinel
    rc = 1;                                     // unconditional accept
else
    rc = (body[0x20] != 0) ? 1 : -0x1C12;       // status check

if (out_acct_id) *out_acct_id = FUN_04599D40(body[0..3], body[4..7]);
if (out_status)  *out_status  = body[0x21];
if (out_name)    memcpy(out_name, body+0x10, 0x0F);
return rc;
```

**Error code translation lives client-side** in `befriend_op_send`
(`0x04704B04..B2D`):

| polcore retval     | FFXi `result_code` | source                                          |
|--------------------|--------------------|-------------------------------------------------|
| `-0x14CB`          | `8`                | network error from `polcore_connect_sm` etc.    |
| `-0x1C12`          | `0xB`              | response.body[0x20] == 0 (server rejected)      |
| other negative     | retry up to 4×     | unreachable on transient errors                 |
| no match in 0x3D polls | `5`            | poll loop timeout                               |

The `(5)` we observe in "Unable to send. (5)" therefore means
**`polcore_befriend_poll` returned no terminal value within ~61 retries** —
the SM is stuck in a non-terminal state. Most likely the connect or
send-header step failed and the SM is parked, OR the receive never
completed. To distinguish, instrument polcore SM state transitions.

`befriend_response_callback @ 0x0480F5E0`:

```c
int befriend_response_callback(int caller_id, int _, int result_code, int* extra)
{
    already_inflight = 0;                          // clear [0x04C3FFA0]
    switch (result_code) {
    case 0:
        if (caller_id == 0) befriend_msgline_default();   // FUN_0480F4D0
        else                FUN_04739CD0(0xa1);           // emit cat=7 msg=0xa1
        break;
    case 1:
        if (DAT_04B871F0 != 0) FUN_04830DE0(0x10);
        break;
    case 10:
        befriend_msgline_full_list();              // FUN_0480F510
        break;
    default:                                       // 2..9, 11..
        formatted = thunk_FUN_04762DD0(10, 0x70, result_code);
        FUN_049219F1(buf, formatted);
        FUN_04739D50(buf);                         // "Unable to send. (N)"
        break;
    }
    return 1;
}
```

The DAT message for the generic-error path is `(category=10, msg_id=0x70)`.
The `(N)` placeholder is `result_code`.

> The inbox-getters `vt+0x29C` / `vt+0x2A4` are present in the codebase and
> consumed by `friend_inbox_find_response @ 0x04706C90`, but **not used by the
> befriend submit path**. They serve other friend-system features (CallerC
> notification pickup, friend-list-download response buffering). The friend-
> list download SM `polcore_friendlist_download_sm @ polcore+0x24170` writes
> entries into the inbox arrays at `polcore+0xB40D8` (200 × `0x2C`) and
> `polcore+0xAFC18` (100 × `0x2C`) using **opcode 6 class 2**.

## 7. The 76-byte IXFF capture (port 54002)

Captured during `/befriend chara`:

```
4c 00 00 00 49 58 46 46 dd c6 16 89 44 bb 3c a0 13 a8 19 1a 29 f6 47 1d ...
```

This **IS** the polcore befriend request from §5b — opcode `0x0B`, class `1`.
Wire framing:

```
[0x00..0x03] = 0x0000004C            // total length (76 = 0x4C)
[0x04..0x07] = "IXFF" (49 58 46 46)  // magic
[0x08..0x47] = 0x40 bytes encrypted  // = 0x28 IXFF header + 0x18 body
[0x48..0x57] = 0x10 bytes            // MD5-truncated tail digest
```

Total: `4 + 4 + 0x40 + 0x10 = 0x4C` (76 bytes) — matches the capture. Sent
to the LSB map-server data port via the xiloader FFXi relay.

This packet is the **befriend-handshake probe** (the 24-byte body carries
`(account_id_hi, 0, packed_lo16+world+zone, seq, sub_id)`) — the LSB
map-server side currently has no handler. To implement, decrypt the
0x18-byte body with the per-connection BF-OFB session key, parse fields
per §5a/5b, perform the lookup against the LSB `chars` table (using
`charutils::getAccountIdFromName` or the equivalent), and reply with a
0x30-byte response body matching §6.

## 7a. Relationship to the 304-byte BefriendRequest (profile server, port 51220)

The 76-byte IXFF packet (this section) and the 304-byte BefriendRequest
captured against the profile server in retail traces are **two distinct
sends, not the same packet**:

- **76B / opcode 0x0B class 1 / port 54002** — the polcore befriend handshake
  documented in §5a-§5c. Sent first.
- **304B BefriendRequest / port 51220** — a separate polcore submit on a
  different SM family. Originates from a callback-driven slot system
  initiated by FFXi's chat-helper path (the FFXi op-table at `0x04971188`
  with stub dispatcher); the actual emit fires from a polcore SM whose
  registration site has not yet been pinned down. **Undetermined**: which
  polcore SM driver is responsible. Probable candidates (from earlier RE):
  `polcore_notification_sm @ polcore+0x1E5D0` or a sibling in the
  `polcore+0x23000..0x25000` range.

To pin down the 304B emitter, instrument every call site of
`polcore_send_ixff_header_sm` (`polcore+0x1F4D0`) and log
`(class, opcode, body_len, dest_port)`. The 304B wire size implies a
decrypted-body length of approximately `304 - 4 - 4 - 0x28 - 0x10 ≈ 0xC4`
(196 bytes). Look for any SM that calls `polcore_send_body_sm` with a
length in that range.

## 8. Caller summary

Two binary-wide call sites for `befriend_submit`:

| Caller                       | FFXiMain addr | RVA      | Path                  |
|------------------------------|---------------|----------|-----------------------|
| `befriend_dialog_callback`   | `0x0468A06C`  | `0x7A06C`| chat `/befriend` flow |
| `befriend_dispatch_caller`   | `0x0481C5EF`  | `0x20C5EF`| friend-list menu     |

Both go through the same op-table at `0x04971188` and the same response
callback `befriend_response_callback`.

## 9. Renames committed in Ghidra

### FFXiMain (image base 0x04610000)

| Address      | New name                       |
|--------------|--------------------------------|
| `0x04701BC0` | `friend_op_tick`               |
| `0x04702350` | `friend_op_increment_seq`      |
| `0x04702B20` | `friend_op_slot_pump`          |
| `0x04703880` | `friend_op_fill_slot`          |
| `0x04704400` | `friend_op_state_dispatcher`   |
| `0x04704840` | `befriend_op_parse_response`   |
| `0x047049F0` | `befriend_op_send`             |
| `0x04706C90` | `friend_inbox_find_response`   |
| `0x04707520` | `friend_op_send_check_conn`    |
| `0x047075A0` | `friend_op_tick_outer`         |
| `0x046EB640` | `friend_zone_byte_lookup`      |
| `0x0480F4D0` | `befriend_msgline_default`     |
| `0x0480F510` | `befriend_msgline_full_list`   |
| `0x0480F550` | `befriend_submit`              |
| `0x0480F5E0` | `befriend_response_callback`   |
| `0x0481C4D0` | `befriend_dispatch_caller`     |
| `0x0491F933` | `ixff_get_inbox_entry`         |
| `0x0491F949` | `ixff_get_inbox_entry_alt`     |
| `0x0491FA93` | `ixff_cancel_send`             |
| `0x0491FAEB` | `ixff_send_packet`             |
| `0x0491FAF6` | `ixff_finalize_send`           |
| `0x0491FB01` | `ixff_poll_response`           |

### polcore (image base 0x04580000)

| Address      | New name                            |
|--------------|-------------------------------------|
| `0x04599F20` | `polcore_derive_session_mask`       |
| `0x0459A1E0` | `polcore_derive_bf_session_key`     |
| `0x0459CB50` | `polcore_get_seq_id`                |
| `0x0459D490` | `polcore_session_refresh_sm`        |
| `0x0459E5D0` | `polcore_notification_sm`           |
| `0x0459EA00` | `polcore_init_descriptor`           |
| `0x0459EA60` | `polcore_set_session_key`           |
| `0x0459F0F0` | `polcore_connect_sm`                |
| `0x0459F4D0` | `polcore_send_ixff_header_sm`       |
| `0x0459F5E0` | `polcore_pack_ixff_header`          |
| `0x0459F690` | `polcore_drain_sm`                  |
| `0x0459F800` | `polcore_recv_body_sm`              |
| `0x0459F970` | `polcore_send_body_sm`              |
| `0x0459FC30` | `polcore_cancel_send_inner`        |
| `0x045A3050` | `polcore_befriend_begin`            |
| `0x045A3100` | `polcore_befriend_finalize_sm`      |
| `0x045A3330` | `polcore_befriend_poll`             |
| `0x045A3DA0` | `polcore_inbox_get_entry_main`      |
| `0x045A3E10` | `polcore_inbox_copy_entry`          |
| `0x045A3F90` | `polcore_inbox_get_entry_alt`       |
| `0x045A4170` | `polcore_friendlist_download_sm`    |
| `0x045A5280` | `polcore_cancel_send`               |
| `0x045E3EB0` | `polcore_init_bf_ctx_with_key`      |
| `0x045E3EF0` | `polcore_blowfish_ofb_xform`        |
| `0x045E4220` | `polcore_blowfish_round`            |
| `0x045E4300` | `polcore_blowfish_init_key`         |

### Key polcore data tables

| Address      | RVA       | Role                                                        |
|--------------|-----------|-------------------------------------------------------------|
| `0x045EFBE8` | `0x6FBE8` | service vtable base (slots 0x29C/0x2A4/0x31C/0x33C/0x340/0x344) |
| `0x04984AD0` | `0x404AD0`| descriptor array (4 × `0x338`)                              |
| `0x04984DF8` | `0x404DF8`| per-descriptor body buffer pointer table                    |
| `0x046340D8` | `0xB40D8` | inbox main (200 × `0x2C`)                                   |
| `0x0462FC18` | `0xAFC18` | inbox alt (100 × `0x2C`)                                    |
| `0x0462A8E8` | `0xAA8E8` | derived 8-byte BF session key (post-MD5)                    |
| `0x04984A88` | `0x404A88`| session token (raw input to mask derivation)                |
| `0x045F5428` | `0x75428` | seq counter (init 1000), returned by `polcore_get_seq_id`   |

## 10. Open items (next RE pass)

- Identify the polcore SM that emits the 304-byte BefriendRequest to the
  profile server (port 51220). Hook every `polcore_send_ixff_header_sm`
  call site and log `(class, opcode, body_len, dest_port)` during a
  `/befriend` test. Expected decrypted body length ~`0xC4` (196 bytes).
- Determine whether `result_code = 5` in current builds is caused by SM
  parking at connect, send-header, or recv. Add an SM-state hook in
  `polcore_befriend_finalize_sm` to log every state transition with the
  return code.
- Document the `FUN_04599D40(account_id)` hash function used to compose
  the 8-byte account_id in response body offset `0x00..0x07` (currently
  unnamed in Ghidra).
- Verify the LSB-side handler implementation:
  - decrypt the 24-byte body with the per-connection BF-OFB session key,
  - extract `account_id_hi` (`body[0]`), packed `(zone, world)` (`body[8]`),
    `seq` (`body[0xC]`), `sub_id` (`body[0xE]`),
  - look up `account_id_lo` from `chars` table by name,
  - reply with the 48-byte response body per §6.
