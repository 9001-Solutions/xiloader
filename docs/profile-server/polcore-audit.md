# Polcore Reference — Friends List + Messaging

Reference for polcore.dll's friend/message subsystems. Polcore base `0x04580000`; conversion `addr_in_ghidra = 0x04580000 + RVA`.

## Connection Lifecycle

### CallerA (Keepalive) — `+0x1E580`

`__cdecl int CallerA()`. Acquires lock (`+0x1ABA00`), `get_free_slot`, `slot[0]=1`, `auth_builder(slot)`, `setup_connection(slot, 5, 0)`, releases lock (`+0x1ABA40`). Returns slot index or `-256` if no slot.

### CallerB Init — `+0x22210`

`__cdecl int CallerB()`. `get_free_slot`, `slot[0]=1`, `auth_builder(slot)`, `setup_connection(slot, 8, 0x1000)`. conn_type=8, param=0x1000.

### CallerB Pump — `+0x22260`

`__cdecl int CallerB_pump(int slot)`. 9 cases (modes 0-8).

- Case 0: clears slot+0x44, slot+0x48; sets slot+0xC4 = -1; memsets `OFF_ARRAY1` (+0x403080) entries (stride 0x68, 64 entries) clearing low bit of word at +0; clears bit 0x8000 at +0x10; touches bytes at `+0x405820`
- Case 1: TCP SM (+0x1F0F0)
- Case 2: Auth SM with args (1, 3, 0) — auth_type1=1, auth_type2=3 (CallerB auth = 01,03)
- Case 3: receive auth response
- Case 4: setup for friend list pull (size = 0x68 * count, capped 0x800/0x68 = 19)
- Case 5: receive friend list chunk
- Case 6: friend list parser — for each entry (stride 0x1A * 4 = 0x68 bytes):
  - Sets `Array1[idx*0x68]` |= 1 (online flag bit 0)
  - Writes `Array1[idx*0x68 + 2]` (some short field)
  - Writes `Array1[idx*0x68 + 4]`, `+8`, `+0xC` (4-byte fields)
  - Copies 15-byte name to `Array1[idx*0x68 + 0x18]`
  - Sets bits in `Array1[idx*0x68 + 0x10]` (game type / zone packed bits via shifts)
  - Touches `Array1[idx*0x68 + 0x14]` (more packed bits)
  - Conditionally writes to `+0x405800 + extra*0x28 + 0x20` (additional table)
  - Copies 0x3F bytes to `Array1[idx*0x68 + 0x28]` (extra strings)
- Case 7: send ack
- Case 8: cleanup, calls `+0x28F0` and `+0x34F0` twice (FFXiMain handoff)

### CallerC — `+0x28330`

```c
int __cdecl CallerC() {
    acquire_lock();
    int slot = get_free_slot();
    if (slot < 0) goto end;
    desc = &desc_array[slot];
    desc[0] = 1;
    auth_builder(desc);
    setup_connection(desc, /*conn_type=*/8, /*param=*/0);
end:
    release_lock();
    return slot;
}
```

Bytes:
```
56              PUSH ESI
E8 CA 36 00 00  CALL +0x36CA → +0x1ABA00 (acquire_lock)
E8 65 68 FF FF  CALL -0x979B → +0x1EBA0 (get_free_slot)
8B F0           MOV ESI, EAX
85 F6           TEST ESI, ESI
7C 2A           JL +0x2A
C1 E0 04        SHL EAX, 4
03 C6           ADD EAX, ESI
57              PUSH EDI
8D 04 40        LEA EAX, [EAX+EAX*2]
8D 0C 46        LEA ECX, [ESI+EAX*2]
8D 3C CD D0 4A 98 04   LEA EDI, [ECX*8 + 0x04984AD0]
57              PUSH EDI
C6 07 01        MOV BYTE [EDI], 1
E8 A3 66 FF FF  CALL +0x1EA00 (auth_builder)
6A 00           PUSH 0
6A 08           PUSH 8
57              PUSH EDI
E8 B9 7B FF FF  CALL +0x1FF20 (setup_connection)
83 C4 10        ADD ESP, 0x10
5F              POP EDI
E8 D0 36 00 00  CALL +0x1ABA40 (release_lock)
8B C6           MOV EAX, ESI
5E              POP ESI
C3              RET
```

`setup_connection`'s conn_type field (slot+0x323) is just a tag — it does not drive the choice of driver. The caller (xiloader's `friend.cpp` or retail's per-frame dispatcher) explicitly picks which driver to invoke for each slot.

### CallerC Driver — `+0x1E5D0`

`int __cdecl driver(int slot_idx)`. Acquires lock, validates slot, switch on slot+0x08 (outer mode). 6 cases (modes 0-5).

- Case 0: clears slot+0x44, slot+0x48; mode++
- Case 1: TCP SM (`+0x1F0F0`)
- Case 2: Auth SM with args (4, 7, 0x40) — hardcodes CallerC's auth (04,07) with size 0x40
- Case 3: send (size=0x40, slot+0x40 buffer)
- Case 4: receive (calls polcore +0x1F690)
- Case 5: finalize via polcore +0x1FBD0

The (4,7,0x40) hardcode means this driver is CallerC-specific, not generic.

### get_free_slot — `+0x1EBA0`

`int __cdecl get_free_slot()`. Loops 4 slots checking slot[0]==0; returns idx or -256.

### slot_validity_check — `+0x1EBD0`

`int __cdecl check(slot, slot_idx)`. Validates slot_idx ∈ [0,3], slot[0]!=0, calls prereq `+0x19BC0`. Connection timeout: 100,000 ms (slot+0x330 + 100000 ≤ now → kill with -260). Reads global `+0xAC550` — 10-second cooldown gate. Returns 1=OK, negative=error code.

### auth_builder — `+0x1EA00`

`__cdecl auth_builder(slot)`. Calls `mask_gen +0x19D40` with conn-type keys at `+0x404A88`/`+0x404A8C` and slot+2. Calls `+0x19E20` (write results). Initializes slot fields:
- slot+0x08 = 0 (outer mode)
- slot+0x09 = 0 (inner SM state)
- slot+0x38 = -1 (DNS result)
- slot+0x01 = 0xFF
- slot+0x14 = 0
- slot+0x330 = `GetTickCount()` (connection start timestamp for timeout)
- slot+0x334 = 0, slot+0x335 = 0

### TCP Handshake SM — `+0x1F0F0`

10 states, switch on slot+9.

- State 0: clear slot+0x44, +0x48, +0xC, +0x10
- State 1: set slot+4 = -1; if `+0x404AB8` (sockaddr) != 0: copy 20 bytes from sockaddr to slot+0x24, jump state 3; ELSE format `pp%03d.pol.com` from slot+2, call `+0xFF40` (DNS resolve), store fd in slot+0x38
- State 2: poll DNS; on success set slot+0x26 = `0xC814` (port 51220); state 3
- State 3: connect (`+0x903A0`); store socket in slot+4; clear slot+1; state 4
- State 4: connect status check (`+0x10800`); on success state 5
- State 5: build Init packet (`+0x1F390`); state 6
- State 6: send Init (40 bytes from slot+0x40 + slot+0x44 offset; cap 0x28); state 7
- State 7: receive Init ACK (until slot+0x44 ≥ 0x28); state 8
- State 8: send Pre-Auth (24 bytes from slot+0x3C + slot+0x48; cap 0x18); state 9
- State 9: receive Pre-Auth Response (until slot+0x48 ≥ 0x18); state default
- Default: read `*(slot+0x3C)+1` byte. If 0: success path — clear slot+0x44, +0x48, copy `*(slot+0x3C)+0x14` (4 bytes — server-assigned account ID) to slot+0xB8 AND slot+0x32C, return 1. If non-zero: return error code -0x1450 - byte

### Init Builder — `+0x1F390`

`void __cdecl init_builder(slot)`. Reads slot+0x40 (Init buffer).
- buf[0] = 0
- buf[1] = (slot+0xB == 0) ? 1 : 0  (1 if no crypto, 0 if BF)
- buf[2] = 0, buf[3] = 0
- buf[4:6] = 1 (IsFriendInit marker)
- buf[6:8] = random
- buf[8:12] = random
- buf[0x18:0x28] = zeros

### Auth Packet SM — `+0x1F4D0`

5 states, switch on slot+9. Args: (slot, type1, type2, size).

- State 0: clear slot+0x44, +0x48; state 1
- State 1: build Auth packet via `+0x1F5E0(slot, type1, type2, size)`; if slot+0xB!=0 (crypto): call `+0x63EF0` (BF encrypt) with (slot+0x40, slot+0x40, 0x28, slot+0x50, 1); state 2
- State 2: send 0x28 bytes from slot+0x40
- State 3: receive until slot+0x44 ≥ 0x28
- State 4: done

The TCP SM and Auth SM share `slot+9` as the state byte. The TCP SM ends in its "default" case and falls through; the next driver call enters Auth SM with slot+9 already past 9, which Auth SM treats as state 0 (modulo).

### Auth Packet Builder — `+0x1F5E0`

`void __cdecl auth_pkt_build(slot, type1, type2, size)`. Reads slot+0x40 (Auth buffer).
- buf[3] = 0; buf[8] = buf[0xC] = buf[0x10] = buf[0x14] = 0
- buf[1] = type1, buf[2] = type2, **buf[0] = 2** (hardcoded)
- buf[4] = size (4 bytes)
- Calls `+0x18830` (init local 88-byte buf)
- Calls `+0x1A050(+0x404A88, +0x404A8C, local_60)` — uses conn-type keys
- Calls `+0x18860(local, local_60, 8)` — mix 8 bytes
- Calls `+0x1A670(local, +0x404A94, 0xF)` — uses 15 bytes from `config_data_copy`
- Calls `+0x18860(local, slot+0xB8, 4)` — mix the 4-byte server-assigned acctid (set by TCP SM default)
- Calls `+0x18910(buf+0x18, local)` — write processed data into Auth packet at +0x18

`buf[0xB8]` (server acctid from Pre-Auth response) is mixed into the Auth packet.

### setup_connection — `+0x1FF20`

`void __cdecl setup(slot, conn_type, param)`. Calls `+0x126B0(slot+0x318, 8)` (zero 8 bytes).
- slot+0x320 = 10 (count?)
- slot+0x322 = 4 (byte)
- slot+0x323 = conn_type
- slot+0x324 = 3 (short)
- slot+0x326 = param

### CreateFriendList — `+0x1EB00`

`void __cdecl init(arg1, arg2, arg3)` — called once via flag at `+0xAFBD8`. Loops 4 slots:
- slot+0x3C = `+0xACD78 + idx*0x208` (Pre-Auth buffer)
- slot+0x40 = `+0xADBD8 + idx*0x398` (Init/Auth buffer)
- slot+0x328 = `+0xADBD8 + idx*0x800` (3rd buffer)
- slot+0x0B = 1 (crypto enabled for ALL slots)

Calls `+0x1B9C0` (init1), `+0x1BA80` (init2), `+0x1E930(arg1)`, `set_globals +0x1EA60(arg2, arg3)`. Sets `+0xAFBD8` = 1.

### Globals (Connection)

| RVA | Symbol | Purpose |
|-----|--------|---------|
| `+0x404AD0` | `OFF_DESC_ARRAY` | Descriptor array, 4 slots × 0x338 |
| `+0x404AB8` | `OFF_SOCKADDR` | 20-byte sockaddr (host order) |
| `+0xAFBD8` | `OFF_INIT_FLAG` | Once-only init guard |
| `+0x404A88` | conn_type_key_1 | |
| `+0x404A8C` | conn_type_key_2 | |
| `+0x404A94` | config_data_copy | 15 bytes used in Auth builder |
| `+0xAC550` | | 10-second cooldown gate (slot_validity_check) |

## Auth & Crypto

### mask_gen — `+0x19D40`

`__cdecl uint64 mask_gen(uint key1_in, uint key2_in)`. Returns `CONCAT44(session_key_2 ^ key2_in, session_key_1 ^ key1_in)`. Session keys at `+0xAA848` and `+0xAA84C`.

### crypto_processor — `+0x19F20`

Takes 8-byte input array. XORs with `0x7048860DDF79`, applies bit shifts and arithmetic. Result written to `+0xAA848` (session_key_1) and `+0xAA84C` (session_key_2). Calls `+0x1A1E0` to propagate.

### set_globals — `+0x1EA60`

Acquires lock. If data ptr (param_1) ≠ 0:
1. Calls `crypto_processor (+0x19F20)` (writes session keys at `+0xAA848/4C`)
2. Calls `+0x1A020` to derive a value
3. Writes the derived value to **conn-type keys at +0x404A88/4C**
4. If config ptr (param_2) ≠ 0: calls `+0x1A550(config_data_copy +0x404A94, config, 15)`

Calls `+0x1E980` (notify/wake). Updates BOTH session keys (indirect via crypto_processor) AND conn-type keys (direct).

### set_globals_v2 — `+0x1EAB0`

Same as set_globals but takes 3rd param (mode byte) and calls `+0x1A5E0` instead of `+0x1A550`. Called from `+0x44BBF` on retail (PlayOnline bootstrap path that xiloader skips).

### BF-OFB encrypt/decrypt — `+0x63EF0`

Args: `(input, output, length, ctx, mode_flag)`.
- mode_flag=0: load ctx state from `ctx+0x50/+0x54/+0x60`
- mode_flag=1: counter=0, load ctx state from `ctx+0x58/+0x5C`
- For each 8 bytes: call BF block encrypt `+0x64220(ctx, prev_block)`, XOR plaintext with shifted block byte
- Skips XOR for bytes 0x0A or 0x0D in either input or output (line ending preservation — protocol-specific quirk)
- Updates ctx state on exit

ctx fields:
- +0x50, +0x54: prev_block (mode 0)
- +0x58, +0x5C: prev_block (mode 1)
- +0x60: counter (mode 0)

For Auth SM, ctx_ptr = slot+0x50, so BF state lives at slot+0xA0..slot+0xB0. Called from many sites: Auth SM, all send/recv wrappers, +0x251E0, +0xA61F0, +0xA68B3, +0xA6FC4, +0xA7083.

The friend-server wire cipher is BF-OFB at this location. Msg files at rest are plaintext.

### g_auth_mode block — `+0xAAA98`, 48 bytes

| Offset | Field |
|--------|-------|
| +0x00 | mode (0=clear, 1=healthy, 2=degraded) |
| +0x04 | sentinel/padding (always 0) |
| +0x05-0x14 | mask16_rev — NOT'd char name (16B, reversed) |
| +0x15-0x28 | mask20_fwd — NOT'd session hash (20B); cleared after consumption |
| +0x29-0x2E | extra6 — mode-2 only: ~(extra[i] + i) |

### g_auth_mode consumer — `+0x1E760`

Called by generic driver between cases 1 and 2 (after TCP SM completes). Reads g_auth_mode (un-NOTs each byte), constructs hex string, prepends timestamp / 60-sec round. Writes formatted auth string to `slot+0x20` (auth send buffer area). Copies un-NOT'd char name bytes to `slot+1` to `slot+0x10` (16 bytes, reading reversed). For mode 2: writes 6 extra bytes to `slot+0x12` to `slot+0x17`, processed as `~byte - i`. Clears g_auth_mode mask bytes after consumption — the mask is one-shot per auth handshake.

## Profile Protocol Packet Layer

### recv_auth_response — `+0x1F690`

Used by generic driver / NotificationPickup / etc as the post-auth response receiver.
- States 0/1: send Pre-Auth (same as TCP SM state 8 but standalone)
- State 2: receive 0x18 bytes
- Default: process response:
  - If crypto enabled (slot+0xB ≠ 0): BF decrypt with mode_flag=1 (`+0x63EF0(buf, buf, 0x18, slot+0x50, 1)`)
  - If `response[1] == 0` (success):
    - Read big-endian 4-byte IP from `response[+0x0B..+0x0E]`
    - If IP ≠ 0 AND sockaddr global `+0x404AB8` is currently 0:
      - Set `+0x404AB8 = 1` (family flag)
      - Set `+0x404ABA = 0xC814` (port 51220)
      - Set `+0x404ABC = parsed IP`
      - This is the server discovery mechanism: the lobby server's response tells the client where the friend server lives. After this, all subsequent connections (CallerB/C) skip DNS and connect directly.
    - Copy 4 bytes from `response[+4]` to `slot+0x14` (session/account ID)
  - If `response[1] != 0` (error): return `-0x1450 - byte` error code

### send_auth_marker — `+0x1F970`

Generic "send X bytes then receive ack" helper. States 0-3: BF prepare → BF encrypt (mode_flag=0) → send → recv ack. Used by all post-auth driver phases.

## Notification System

### NotificationPickup init wrapper — `+0x25B50`

Lock + call `+0x25AD0` + unlock. 5 args (slot setup args).

### NotificationPickup driver — `+0x25D10`

`int __cdecl notif_drv(slot_idx, callback?)`. Acquires lock, validates slot via `+0x1EC80` (which wraps `+0x1EBD0`), pumps state machine `+0x25B90`. Closes via `+0x1FBD0` on error.

### NotificationPickup pump — `+0x25B90`

7 states (0-6). Uses `slot+0x0A` for outer mode byte (NOT `slot+0x08` like other drivers).

- State 0: clear slot+0x44, +0x48; state++
- State 1: TCP SM (`+0x1F0F0`)
- State 2: Auth SM with **(3, 3, 0x1A0)** — auth_type=(3,3), size=416 bytes
- State 3: build response notification record (writes to slot+0x18 derived buffer at +0x190 / +0x192 / +0x194; mask_gen with slot+0x10/+0x14)
- State 4: send 0x1A0 bytes
- State 5: recv auth response
- State 6: receive size header (8 bytes) and write result to caller's `param_2`

### Notification callback system

Polcore's internal notification queue is distinct from FFXiMain's notification overlay. Polcore queues notifications at `+0xAA980` (32-entry buffer of 0x40 bytes each, total 0x800 = 2 KB) and dispatches via callback registered at `+0xAA974`.

**Callback registration** — `+0x1B500`: `void __cdecl set_notif_callback(void* fn)`. Calls `+0x1AD80(-1)` (lock?), then writes `+0xAA974 = fn`.

**Callback dispatcher** — `+0x1C600`: Acquires lock on `+0xAA968`, reads callback `+0xAA974`, releases lock. If `+0xAAA94` (pending notif count) > 0 AND callback is non-NULL, loops count times invoking `callback(buf[0], buf[4])` per notif entry; advance 0x40 bytes; reset count to 0. Calls `+0x1B900` (cleanup) with callback pointer.

### Globals (Notification)

| RVA | Purpose |
|-----|---------|
| `+0xAA968` | notification dispatch lock |
| `+0xAA974` | registered callback fn pointer |
| `+0xAA980` | notification queue base (entries 0x40 bytes each) |
| `+0xAAA94` | pending notification count |

## Friend Data Tables

### enrich function — `+0x23E60`

`int __cdecl enrich(account_idx, dest_struct)`. Bounds check: `account_idx < 200` (0xC8) — 200-account capacity. Reads from three arrays:

1. **Array2** at `+0xB40D8`: source for sub-enrich. Stride `0x2C` per index, but sub-enrich copies `0xB0` bytes.
2. **Status table** at `+0x3FC920` (`OFF_STATUS_TABLE`): `dest+0xB0 = StatusTable[idx*0x21 dwords]` (= idx * 0x84 bytes), confirms stride 0x84.
3. **Secondary table** at `+0x3FC93C`: `dest+0xCC ← src + idx*0x42, 0x33 bytes`.

Calls `sub_enrich +0x23E10`: memcpy 0xB0 bytes, conditional bit-mask of `dest+0x08` if `(dest+8) & 0xE000 >= 0xA000`.

## Slot Field Map

| Offset | Type | Purpose | Set By |
|--------|------|---------|--------|
| +0x00 | byte | mode_byte (0=free, 1=active) | CallerA/B/C, get_free_slot, CreateFriendList |
| +0x01 | byte | sentinel/flag (init to 0xFF, cleared in TCP SM state 3) | auth_builder, TCP SM |
| +0x02 | byte | server number (used in `pp%03d.pol.com`) | mask_gen output |
| +0x04 | dword | socket fd (init -1) | TCP SM state 1, 3 |
| +0x08 | byte | outer mode (driver state) | auth_builder, drivers |
| +0x09 | byte | inner SM state (TCP SM and Auth SM share) | auth_builder, SMs |
| +0x0B | byte | crypto flag (1=BF on) | CreateFriendList |
| +0x0C | dword | cleared in TCP SM state 0 | TCP SM |
| +0x10 | dword | cleared in TCP SM state 0 | TCP SM |
| +0x14 | dword | cleared in auth_builder | auth_builder |
| +0x18 | byte | flags (read by pump cases) | unknown |
| +0x24 | 20B | sockaddr (host order) | TCP SM state 1 |
| +0x26 | word | port (within sockaddr) = 0xC814 (51220) | TCP SM state 2 |
| +0x38 | dword | DNS resolve fd (init -1) | auth_builder, TCP SM |
| +0x3C | ptr | Pre-Auth buffer | CreateFriendList |
| +0x40 | ptr | Init/Auth buffer | CreateFriendList |
| +0x44 | dword | recv counter | TCP SM, Auth SM |
| +0x48 | dword | recv counter (Pre-Auth) | TCP SM |
| +0x50 | 48B | BF key material | unknown (NOT init by CreateFriendList) |
| +0xB8 | dword | server-assigned acctid (from Pre-Auth response +0x14) | TCP SM default |
| +0xC4 | dword | init -1 by pump case 0 | CallerB pump |
| +0x318 | 8B | zeroed by setup_connection | setup_connection |
| +0x320 | word | 10 (count?) | setup_connection |
| +0x322 | byte | 4 | setup_connection |
| +0x323 | byte | conn_type (5/8) | setup_connection |
| +0x324 | word | 3 | setup_connection |
| +0x326 | word | param (0/0x1000) | setup_connection |
| +0x328 | ptr | 3rd buffer | CreateFriendList |
| +0x32C | dword | server acctid (duplicate of +0xB8) | TCP SM default |
| +0x330 | dword | connection start timestamp (GetTickCount) | auth_builder |
| +0x334 | byte | 0 | auth_builder |
| +0x335 | byte | 0 | auth_builder |

## Driver Inventory

There are 5 distinct driver functions, each for a different connection type/purpose. They share the underlying TCP SM (`+0x1F0F0`) and Auth SM (`+0x1F4D0`) but pass different `(auth_type1, auth_type2, auth_size)` arguments and have different post-auth processing.

| RVA | Ghidra | Auth (t1, t2, size) | Purpose | Post-auth processing |
|-----|--------|---------------------|---------|---------------------|
| `+0x1D490` | 0x0459D490 | (4, 6, 0x18) | WhoIs / status query | Writes 11+ globals: account index, online flags, name lookup data |
| `+0x1E5D0` | 0x0459E5D0 | (4, 7, 0x40) | CallerC: notification/befriend trigger | Closes connection (no result processing) |
| `+0x20BB0` | 0x045A0BB0 | (5, 4, slot+0xC8) | Variable request-response (size driven by slot+0xC8 = 0x800 cap) | Calls polcore +0x20DA0 with (slot+0xC4, response, caller-buf) |
| `+0x210E0` | 0x045A10E0 | (5, 3, slot+0xC8) | Query (16-byte response check) | Validates resp size == 0x10, writes 12 bytes to caller-provided struct, caches in `+0xAFBE0` table |
| `+0x23100` | 0x045A3100 | (1, 0xB, 0x18) | ShortAuth / session-token query | Returns 8-byte token (param_2), 1-byte flag (param_3), 15-byte name (param_4 buf) |

## Function Inventory

| RVA | Ghidra | Role |
|-----|--------|------|
| `+0x1ABA00` | 0x045ABA00 | acquire_lock — guards CallerA, generic driver |
| `+0x1ABA40` | 0x045ABA40 | release_lock |
| `+0x1ABAC0` | 0x045ABAC0 | acquire_lock_2 — different lock used in CallerB pump |
| `+0x1ABB00` | 0x045ABB00 | release_lock_2 |
| `+0xFF40` | 0x0458FF40 | DNS resolve — TCP SM state 1 |
| `+0x901E0` | 0x046101E0 | DNS poll — TCP SM state 2 |
| `+0x903A0` | 0x046103A0 | TCP connect — TCP SM state 3 |
| `+0x90800` | 0x04610800 | TCP connect status — TCP SM state 4 |
| `+0x91100` | 0x04611100 | send wrapper — TCP SM state 6, Auth SM state 2 |
| `+0x91170` | 0x04611170 | recv wrapper (Init ACK) — TCP SM state 7, Auth SM state 3 |
| `+0x90DC0` | 0x04610DC0 | send Pre-Auth — TCP SM state 8 |
| `+0x90E30` | 0x04610E30 | recv Pre-Auth response — TCP SM state 9 |
| `+0x1F400` | 0x0459F400 | error handler — TCP SM default error path |
| `+0x1F690` | 0x0459F690 | recv auth response — Auth SM/Generic driver case 4 |
| `+0x1F970` | 0x0459F970 | send auth+marker — Generic driver case 3 |
| `+0x1FAB0` | 0x0459FAB0 | flist request setup — CallerB pump case 4 |
| `+0x1FAD0` | 0x0459FAD0 | flist final receive — CallerB pump case 7 |
| `+0x1FBD0` | 0x0459FBD0 | connection finalize/close (slot, retcode) |
| `+0x1F800` | 0x0459F800 | send chunk request — CallerB pump case 5 |
| `+0x18830` | 0x04598830 | local-buf init for auth packet |
| `+0x18860` | 0x04598860 | local-buf mix-in (data, len) |
| `+0x18910` | 0x04598910 | local-buf write-out (dst, src) |
| `+0x1A050` | 0x0459A050 | conn-key processor (key1, key2, out) |
| `+0x1A670` | 0x0459A670 | config-mix (local, +0x404A94, 0xF) |
| `+0x19BC0` | 0x04599BC0 | prereq check — slot_validity_check |
| `+0x19BE0` | 0x04599BE0 | TCP SM error path -0x200 fallback |
| `+0x126B0` | 0x045926B0 | memset/zero (dst, len) — used by setup_connection |
| `+0x12330` | 0x04592330 | memcpy variant (dst, src, len) — used by CallerB pump case 6 |
| `+0x12420` | 0x04592420 | sprintf-style format (`pp%03d.pol.com`) |
| `+0x12380` | 0x04592380 | memcpy (dst, src, 0x14) — copies sockaddr global |
| `+0x1E760` | 0x0459E760 | g_auth_mode consumer — called by generic driver between cases 1 and 2 |
| `+0x28F0` | 0x045A28F0 | flist completion handler — CallerB pump case 8 |
| `+0x34F0` | 0x045A34F0 | flist FFXiMain handoff (called twice) — CallerB pump case 8 |

## Other Globals

| RVA | Ghidra | Purpose |
|-----|--------|---------|
| `+0xAC550` | 0x0462C550 | 10-second cooldown gate (slot_validity_check) |
| `+0x405820` | 0x04985820 | Friend status table — 64 entries × 0x28 stride; cleared by CallerB pump case 0 |
| `+0x405800` | 0x04985800 | Adjacent table base for `+0x20` field writes (sub-entries) |
| `+0xAC528` | 0x0462C528 | unknown 32-bit (low byte = WhoIs result flag) |
| `+0xAC530` | 0x0462C530 | unknown 32-bit (set from slot+0xB90) |
| `+0xAC534` | 0x0462C534 | unknown 32-bit (set from slot+0xB94) |
| `+0xAC540` | 0x0462C540 | WhoIs result (online flag / acctid lo) |
| `+0xAC54C` | 0x0462C54C | WhoIs `pbVar3[3] == 1` flag |
| `+0xAAAC8` | 0x0462AAC8 | WhoIs result byte (from result+0x07) |
| `+0xAAB24` | 0x0462AB24 | WhoIs result dword (from result+0x08) |
| `+0xAAB20` | 0x0462AB20 | WhoIs result dword (from result+0x0C) |
| `+0x7541C` | 0x045F541C | WhoIs result account index (-1 if invalid) |
| `+0x75420` | 0x045F5420 | WhoIs result subindex (computed from status table) |
| `+0x75424` | 0x045F5424 | WhoIs result count-1 |
| `+0x75428` | 0x045F5428 | WhoIs result word (from result+4) |
| `+0xAFBE0` | 0x0462FBE0 | 4 entries × 0xC bytes — query driver result cache |

## Function Table (`+0x6FBE8`)

Returned by `GetCommonFunctionTable`. First `0x1F0` bytes are NULL — entries start at `+0x1F4`.

| Slot | Polcore RVA | Function |
|------|-------------|----------|
| +0x29C | `+0x255A0` | Unknown |
| +0x2A0 | `+0x23DA0` | Array 2 reader |
| +0x2A4 | `+0x23FD0` | Array 2 writer |
| +0x2B4 | `+0x1CC40` | handle read_entry |
| +0x2B8 | `+0x1CC80` | handle write_entry |
| +0x440 | `+0x1A8E0` | Buffer packer (str1\x07str2\0[blob]) |
| +0x444 | `+0x1ABA0` | `polcore_vt444_post_built` — submit body-upload SM |
| +0x448 | `+0x1ABC0` | `polcore_vt448_poll_status` — poll SM |
| +0x454 | `+0x1AC00` | Cancel/cleanup |
| +0x470 | `+0x1C8BE0` | `polcore_msg_format_writer` |

## Patch Site Catalog

### Dynamic pattern resolutions (friend.cpp `resolve_polcore_offsets`)

| Pattern name | Match count | First match RVA | Correct target |
|--------------|-------------|-----------------|----------------|
| CallerB pump | 1 | `+0x22260` | `+0x22260` |
| CallerB init (proximity-guarded) | 1 | `+0x22210` | `+0x22210` |
| Enrich fn | — | — | `+0x23E60` |
| Generic driver | 5 | `+0x1D490` | `+0x1E5D0` (CallerC) |
| CallerC init | 2 | `+0x1E580` | `+0x28330` |
| Tick fn entry | 1 | `+0x45484` | `+0x45484` |
| Tick-killer JGE (scan inside tick fn) | 0 | — | `+0x457BB` |

### main.cpp patches

| Pattern name | Match count | First match RVA |
|--------------|-------------|-----------------|
| Auth mode setter #1 (`SetAuthMode`) | 1 | `+0x1E864` (inside `+0x1E760` consumer) |
| Auth mode setter #2 | 1 | `+0x22BBD` |
| Profile port #1 (`66 C7 46 26...`) | 1 | `+0x1F1B5` (inside TCP SM) |
| Profile port #2 (`66 C7 05 ?? 14 C8`) | 2 | `+0x1E95C` (in auth consumer) and `+0x1F781` (in TCP SM state 2) |
| FindINETMutex | 1 | `+0x1B824` |
| FindPolConn | 1 | `+0x1E991` |

### Runtime patches applied

| RVA | Target | Original | Replacement | Purpose |
|-----|--------|----------|-------------|---------|
| +0x1E864 + 2 | g_auth_mode ptr | — | — | Locates g_auth_mode block (+0xAAA98) |
| +0xAAA98+0 | mode | (varies) | 1 | Set healthy mode |
| +0xAAA98+5..+0x14 | mask16 | (varies) | NOT'd reversed char name | Pass char name to auth |
| +0xAAA98+0x15..+0x28 | mask20 | (varies) | g_SessionHash (16 of 20 bytes raw) | Pass session hash to auth |
| +0x1E864 + 7 | JNE @ +0x1E86B | 0x75 | 0xEB | JNE → JMP (force healthy auth path in `+0x1E760`) |
| +0x22BBD | JZ | 0x74 0x05 | 0x90 0x90 | NOP out diagnostic JZ |
| +0x1F1B5 + 4 | Profile port immed | 0xC814 | `profileServerPort` (2B LE) | Redirect profile port |
| +0x1E95C OR +0x1F781 + 7 | Profile port immed | 0xC814 | `profileServerPort` | Redirect (first of 2 matches) |
| +0x457BB (intended) | JGE @ +0x457BB | 0x7D | (would be 0xEB) | Tick-killer disable — pattern doesn't match |
| +0x743D8+n*0x80 | Title strings (10 entries, 0x80 each) | JP strings | EN strings | Localize titles |
| `s_polConnection` (pattern-found) | polConnection object | — | memset 0, write enc buf ptr @ +0x48 | Initialize polConnection before CoCreate |

### Detours hooks (main.cpp)

| API hooked | Purpose re: polcore |
|-----------|---------------------|
| gethostbyname | Redirect pp000.pol.com / ffxi00.pol.com → local |
| send | Inject session hash into XIFF lobby commands |
| recv | pass-through |
| connect | pass-through |
| CreateFileA | Redirect polcore's message file I/O to local dir |
| FindFirstFileA | Redirect message dir scans |
| MoveFileA | Redirect unread→read transitions |

### CallerB init pattern

`friend.cpp` uses pattern `\x56\xE8\x00\x00\x00\x00\x8B\xF0\x85\xF6\x7D\x02\x5E\xC3` and only accepts matches within 0x100 bytes BEFORE the resolved CallerB pump.

### Polcore disk vs runtime

Polcore on-disk has a `POL1` section (255 KB) which is the original packed code. The runtime dump captures the unpacked `.text` (407 KB). RE/disasm against on-disk polcore fails — always dump from running process.

## Call Graphs

### CallerA (Keepalive) — `+0x1E580`
```
CallerA() [+0x1E580]
├── acquire_lock [+0x1ABA00]
├── get_free_slot [+0x1EBA0]
├── slot[0] = 1
├── auth_builder [+0x1EA00]
│   ├── mask_gen [+0x19D40]  → reads session_keys [+0xAA848/4C], conn_type_keys [+0x404A88/8C]
│   └── result_writer [+0x19E20]
└── setup_connection(slot, conn_type=5, param=0) [+0x1FF20]
    └── memzero(slot+0x318, 8) [+0x126B0]
└── release_lock [+0x1ABA40]
```

### CallerB (Friend List) — init `+0x22210`, pump `+0x22260`
```
CallerB_init() [+0x22210]
├── get_free_slot [+0x1EBA0]
├── slot[0] = 1
├── auth_builder [+0x1EA00]
└── setup_connection(slot, 8, 0x1000) [+0x1FF20]

CallerB_pump(slot) [+0x22260]                    — driven per-frame by xiloader worker thread
├── slot_validity_check [+0x1EBD0]
├── case 0: clear counters; memset Array1 [+0x403080] entries low bit; clear bits in status [+0x405800/+0x405820]
├── case 1: TCP_SM(slot) [+0x1F0F0]
│   ├── DNS resolve [+0xFF40] OR copy sockaddr [+0x404AB8]
│   ├── connect [+0x903A0]
│   ├── init_pkt_build [+0x1F390]              — buf[0]=0, buf[1]=¬crypto, buf[4:6]=1
│   ├── send Init 0x28 bytes [+0x91100]
│   ├── recv Init ACK [+0x91170]
│   ├── send Pre-Auth 0x18 bytes [+0x90DC0]
│   └── recv Pre-Auth response [+0x90E30]      — sets slot+0xB8 (server acctid)
├── case 2: Auth_SM(slot, 1, 3, 0) [+0x1F4D0]
│   ├── auth_pkt_build(slot, 1, 3, 0) [+0x1F5E0]
│   │   ├── conn-key-mix [+0x1A050]
│   │   ├── config-mix [+0x1A670] — uses [+0x404A94]
│   │   └── write [+0x18910]
│   ├── BF encrypt [+0x63EF0] (if crypto)
│   ├── send 0x28 bytes [+0x91100]
│   └── recv response 0x28 bytes [+0x91170]
├── case 3: recv_auth_response [+0x1F690]       — handles server discovery side effect
├── case 4: flist request setup [+0x1FAB0]
├── case 5: recv flist chunk [+0x1F800]
├── case 6: friend list parser
│   ├── for each entry (0x68 bytes): write to Array1 [+0x403080]
│   │   ├── Array1[idx*0x68 + 0]   |= 1                  (online flag)
│   │   ├── Array1[idx*0x68 + 0x18] = 15-byte name
│   │   └── Array1[idx*0x68 + 0x10/+0x14] |= packed bits (game type, zone)
│   └── for each entry: write to status table [+0x405820]
├── case 7: send ack [+0x1FAD0]
└── case 8: cleanup
    ├── [+0x28F0]
    ├── [+0x34F0] called twice (FFXiMain handoff)
    └── close [+0x1FBD0]
```

### CallerC (Notification / Befriend) — init `+0x28330`
```
CallerC() [+0x28330]
├── acquire_lock [+0x1ABA00]
├── get_free_slot [+0x1EBA0]
├── slot[0] = 1
├── auth_builder [+0x1EA00]
└── setup_connection(slot, conn_type=8, param=0) [+0x1FF20]
└── release_lock [+0x1ABA40]

CallerC_driver(slot) [+0x1E5D0]
├── acquire_lock + slot_validity_check
├── case 0: clear counters
├── case 1: TCP_SM [+0x1F0F0]
├── case 2: Auth_SM(slot, 4, 7, 0x40) [+0x1F4D0]
├── case 3: send 0x40 bytes [+0x1F970]
├── case 4: recv response [+0x1F690]
└── case 5: close [+0x1FBD0]
└── release_lock
```

### NotificationPickup — init `+0x25B50`, driver `+0x25D10`, pump `+0x25B90`
```
NotificationPickup_init [+0x25B50]
└── lock + [+0x25AD0] + unlock

NotificationPickup_driver(slot, callback) [+0x25D10]
├── acquire_lock
├── notif_slot_check [+0x1EC80] → wraps slot_validity_check [+0x1EBD0]
├── notif_pump [+0x25B90]                        — uses slot+0x0A for outer mode (NOT +0x08)
│   ├── case 0: clear counters
│   ├── case 1: TCP_SM [+0x1F0F0]
│   ├── case 2: Auth_SM(slot, 3, 3, 0x1A0) [+0x1F4D0]   — auth (3,3), 416 bytes
│   ├── case 3: build response (uses mask_gen +0x19D40)
│   ├── case 4: send 0x1A0 [+0x1FA90]
│   ├── case 5: recv [+0x1F690]
│   └── case 6: recv 8-byte size header [+0x1FAB0]
└── release_lock
```

### Friend-List Packet Path (Server → Polcore → FFXiMain)
```
Server → TCP → polcore TCP_SM Pre-Auth response
  ↓ (parsed by recv_auth_response [+0x1F690])
+0x404AB8 sockaddr global is set (IP+port for friend server) ← SERVER DISCOVERY
  ↓
CallerB_init [+0x22210] (xiloader's friend.cpp worker)
  ↓
CallerB_pump [+0x22260] runs through cases 0..7
  ↓
case 6 parser writes to Array1 [+0x403080] and status table [+0x405800/+0x405820]
  ↓
case 8 calls [+0x28F0] and [+0x34F0]×2 — FFXiMain handoff
  ↓
FFXiMain reads from polcore via function table [+0x6FBE8]
  +0x2A0: Array2 reader [+0x23DA0]
  +0x2A4: Array2 writer [+0x23FD0]
  +0x2B4: handle read_entry [+0x1CC40]
  +0x2B8: handle write_entry [+0x1CC80]
  ↓
FFXiMain populate_friend_data [FFXi+0x1E9830] consumes data
  ↓
flistmai render pipeline displays
```

### Notification Callback Path (polcore internal)
```
At any time, code calls set_notif_callback [+0x1B500]
  ↓
+0xAA974 = callback_fn

Polcore queues notifications at +0xAA980 (32 entries × 0x40 bytes)
+0xAAA94 holds count

Periodically, dispatcher [+0x1C600] is called:
  ├── lock +0xAA968
  ├── read +0xAA974 (callback)
  ├── unlock
  ├── for each pending notif: callback(buf[0], buf[4])
  ├── reset count to 0
  └── cleanup [+0x1B900]
```
