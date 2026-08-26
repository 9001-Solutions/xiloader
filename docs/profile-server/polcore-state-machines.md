# Polcore Profile Protocol State Machines

polcore.dll manages profile server TCP connections via a 3-level state machine architecture. All offsets are relative to polcore.dll base unless noted. The `.text` section is packed on disk (RawSize=0) and unpacked at runtime.

## Architecture Overview

```
Outer Callers (CallerA/B/C)
  └─► auth_builder (+0x1EA00) — allocates slot, writes mask
  └─► setup_connection (+0x1FF20) — configures type/param
  └─► Driver (+0x1E5D0) — per-frame tick (CallerC-specific; not truly generic)
        ├─► First SM (+0x1F0F0, 10 states) — TCP connect + Init/ACK/Pre-Auth
        └─► Second SM (+0x1F4D0, 5 states) — Auth build/send/receive
```

## Caller Functions

| Caller | Offset | Mask | Conn Type | Data Size | Behavior |
|--------|--------|------|-----------|-----------|----------|
| CallerA | +0x1E580 | 04,05 | type=5, param=0 | 40B | Keepalive. Lock→get_slot→auth_builder→setup→unlock |
| CallerB | +0x22210 | 04,07 | type=8, param=0x1000 | 64B | Token exchange. get_slot→auth_builder→setup→return. Data contains charname at [1:9] |
| CallerC | +0x28330 | 04,07 | type=8, param=0 | — | Befriend. Lock→get_slot→auth_builder→setup→unlock |

All call the same `auth_builder` (+0x1EA00) and `setup_connection` (+0x1FF20).

CallerA is called from exactly one site: state machine +0x44FCC (bootstrap, before game/addons load). CallerB/C are invoked by xiloader's `friend.cpp` worker thread (CallerB init + driver pump loop).

## Descriptor Array

4 slots × 0x338 (824) bytes at +0x404AD0, ending at +0x4057B0.

`get_free_slot` (+0x1EBA0): scans array, checks slot[0] (mode byte): 0=free, non-zero=occupied. Returns slot index or 0xFFFFFF00 (-256) if full.

### Descriptor Layout

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 1 | In-use / mode byte (0=free) |
| +0x02 | 1 | Connection type byte |
| +0x04 | 4 | Socket handle (SOCKET, -1 when disconnected) |
| +0x08 | 1 | Outer mode (protocol state, 0-6+) |
| +0x09 | 1 | Inner state (TCP SM state, 0-9) |
| +0x0B | 1 | Crypto flag (0=no encryption, non-zero=BF encrypt) |
| +0x0C | 4 | Cleared in init |
| +0x10 | 4 | Cleared in init |
| +0x24 | 20 | Host address struct (sockaddr) |
| +0x26 | 2 | Port (within sockaddr, patched by SetProfileServerPort) |
| +0x38 | 4 | DNS result |
| +0x3C | 4 | Second buffer pointer |
| +0x40 | 4 | Main buffer pointer (Init/Auth packets) |
| +0x44 | 4 | Bytes sent counter 1 |
| +0x48 | 4 | Bytes sent counter 2 |
| +0x50 | 48 | BF key material (NOT written by CreateFriendList — initialized during protocol handshake by inner SM) |
| +0xDE | 1 | Connection enable flag |
| +0x328 | 4 | Data pointer |

## First State Machine (+0x1F0F0)

10 states (0-9), jump table at +0x1F35C. Handles TCP connect + Init/ACK/Pre-Auth exchange. Each call processes one state; caller loops until completion.

Returns: 0 = in progress, >0 = complete, <0 = error.

| State | Function |
|-------|----------|
| 0 | Init: clear counters, set [+0x04]=-1, DNS setup |
| 1 | Check global +0x404AB8, resolve hostname from [+0x02] |
| 2 | TCP connect, set port 0xC814 (51220) |
| 3 | Check connection status |
| 4 | Check connection ready |
| 5 | Build Init (CALL +0x1F390), start sending 40B from [+0x40] |
| 6 | Continue sending, start receiving |
| 7 | Receive ACK (accumulates until 0x28=40B) |
| 8 | Send Pre-Auth (0x18=24B from [+0x3C]) |
| 9 | Receive Pre-Auth Response (0x18=24B, byte[1] must be 0x00, [20:24]→[+0xB8]+[+0x32C]) |

### Init Builder (+0x1F390)

```
buf[0] = 0
buf[1] = 1 if descriptor[0x0B]==0 (no crypto), else 0 (crypto active)
buf[2] = 0
buf[3] = 0
buf[4:6] = 0x0001 (IsFriendInit marker)
buf[6:8] = port value from stack
buf[8:12] = value from stack
buf[0x18:] = linked list data
```

## Second State Machine (+0x1F4D0)

5 states (0-4), jump table at +0x1F5C0. Handles Auth packet build/send/receive. Called from outer callers AFTER first SM completes. Parameters: (descriptor, type1, type2, size).

| State | Function |
|-------|----------|
| 0 | Clear counters, set state=1, fall through |
| 1 | Build Auth (CALL +0x1F5E0), optionally BF-encrypt, set state=2, fall through |
| 2 | Send 40B Auth from [+0x40] via +0x10100, set state=3, return 0 |
| 3 | Receive Auth Response (accumulates until 0x28=40B), return 1 |
| 4 | Done — returns 1 |

### State 1: Crypto Decision

```asm
MOV AL, [ESI+0x0B]   ; crypto flag
TEST AL, AL
JZ skip_encrypt       ; 0 = no encryption
LEA ECX, [ESI+0x50]  ; key material pointer
PUSH 1, ECX, 0x28, EAX, EAX
CALL +0x63EF0        ; BF encrypt
```

`desc+0x50` (key pointer) is NULL for CallerB/C slots because CreateFriendList only initializes it for slot 0. Setting `desc[+0x0B]=0` disables crypto and avoids the BF crash.

## Driver Function (+0x1E5D0)

Per-frame driver: enters critical section, calls +0x1EBD0, processes outer modes 0-5 via jump table.
Signature: `int __cdecl driver(int slot_index)`

Called from main state machine +0x44FCC for CallerA during bootstrap. For CallerB/C, called by xiloader's worker thread in `friend.cpp`.

This driver hardcodes auth (4, 7, 0x40), making it CallerC-specific. CallerB has its own pump at +0x22260; WhoIs and other variants live at distinct addresses (see `polcore-audit.md` §3 "5 distinct driver functions").

## Top-Level State Machine

Dispatcher at +0x4514E. Byte table at +0x452C4 (31 entries, states 11-41 → index 0-7). Jump table at +0x452A4 (8 entries → handler addresses). State variable at [+0x99408].

Key transitions:
- configHandler → state 18
- set_globals_v2 → state 20 (path depends on PlayOnline bootstrap data; xiloader skips this path so the lobby config block is never received and globals stay zero)

### Key Call Sites

| Offset | Action |
|--------|--------|
| +0x443DD | CreateFriendList(0,0,0) — first-time init |
| +0x44BBF | set_globals_v2 with parsed lobby config (NEVER REACHED on xiloader) |
| +0x44FCC | CallerA — fires during PlayOnline bootstrap (before game, before addons) |

## CreateFriendList (+0x1EB00)

Called from state machine at +0x443DD with args (0, 0, 0) — ESI unconditionally zeroed at +0x44392.

Actions (loop over 4 slots, EAX starts at desc_base+0x40, increments by 0x338):
- desc+0x3C = buffer1 (base 0xC558 off polcore .data, +0x208/slot)
- desc+0x40 = buffer2 (base 0xCD78 off polcore .data, +0x398/slot)
- desc+0x328 = buffer3 (base 0xDBD8 off polcore .data, +0x800/slot)
- desc+0x0B = 1 (crypto enabled for ALL 4 slots — not just slot 0)
- Calls +0x2B9C0 and +0x2BA80 (buffer alloc)
- Calls +0x1E930 with 3rd param
- Calls set_globals (+0x1EA60) with params 1 & 2 → null on xiloader → globals stay zero
- Sets init flag [+0xAFBD8]=1 (only runs once)

`desc+0x50` is not written here. BF key material is initialized during the protocol handshake by the inner state machine (LEA [esi+0x50] refs at +0x1F521, +0x1F6FF, +0x1F8A6, +0x1F9DF, +0x1FB05 pass the address to key-init subroutines).

## Sockaddr Global (+0x404AB8)

Must be set in HOST byte order (little-endian). State machine path A copies it to desc+0x24, then `create_connect` byte-swaps to network order for Winsock.

### Writer (+0x1F778)

The sockaddr is written by the inner state machine during protocol processing:
```asm
+0x1F76F  cmp word [+0x404AB8], 0    ; already set?
+0x1F776  jne skip                    ; yes → skip
+0x1F778  mov word [+0x404AB8], 1     ; family marker
+0x1F781  mov word [+0x404ABA], 0xC814; port=51220 (HARDCODED)
+0x1F78A  mov [+0x404ABC], eax        ; IP (from protocol data)
```

The IP (EAX) comes from a byte-reversal loop at +0x1F750 that reads 4 bytes at offset +0x08..+0x0B of received data (big-endian → little-endian). On retail, the profile server IP is embedded in data received from SE's servers. Port is always hardcoded 51220.

### Reader (+0x1F12E)

```asm
+0x1F12E  cmp word [+0x404AB8], 0    ; sockaddr initialized?
+0x1F135  je skip                     ; no → skip (falls through to DNS path)
+0x1F137  push 0x14                   ; memcpy 20 bytes
+0x1F139  lea eax, [esi+0x24]        ; dest = desc+0x24
+0x1F13C  push +0x404AB8             ; src = sockaddr global
+0x1F142  call memcpy
+0x1F14A  mov byte [esi+9], 3        ; advance inner state to 3
```

Written by xiloader's `SetFriendServerSockaddr()` during `friend_system::activate()`.

## Config Data at +0x99288

17-byte structure received from lobby server, written by the setter at +0x46DF0:
```
+0x00: 4B  (dword)
+0x04: 4B  (dword)
+0x08: 4B  (dword)
+0x0C: 4B  (dword)
+0x10: 1B  (byte, read separately as mode/flag at +0x99298)
```

The state machine at +0x44B7F..+0x44BBF decodes this with a random XOR key (ESI), then passes the result to set_globals_v2 (+0x1EAB0). On xiloader, this data is never received → state never reached → globals stay zero.

## Key Addresses

| Address | Purpose |
|---------|---------|
| +0x10040 | send_wrapper: calls WinSock send() |
| +0x10100 | send_invoker: send+recv via +0x10170 |
| +0x10482 | create_connect sockaddr fill (patch site for patchconnect) |
| +0x17830 | Auth data filler 1 |
| +0x19D40 | mask_gen: `session_keys XOR conn_type_keys` |
| +0x19F20 | crypto_processor: derives session keys |
| +0x1F0F0 | First state machine (10 states) |
| +0x1F390 | Init packet builder |
| +0x1F4D0 | Second state machine (5 states) |
| +0x1E580 | CallerA (keepalive) |
| +0x1E5D0 | Driver function (per-frame tick) — CallerC-specific |
| +0x1F5E0 | Auth packet builder |
| +0x1EA00 | auth_builder (slot allocator + mask init) |
| +0x1EA60 | set_globals (session key writer) |
| +0x1EAB0 | set_globals_v2 (conn-type key writer) |
| +0x1EBA0 | get_free_slot |
| +0x1EB00 | CreateFriendList |
| +0x1FF20 | setup_connection |
| +0x22210 | CallerB (token exchange) |
| +0x28330 | CallerC (befriend) |
| +0x44FCC | CallerA call site in state machine |
| +0x63EF0 | BF encrypt/decrypt |
| +0x99408 | State machine current state variable |
| +0x404AB8 | Sockaddr global (20B) |
| +0x404AD0 | Descriptor array start (4 slots × 0x338) |
| +0x4057B0 | Descriptor array end |
| +0xAA848 | Session key 1 |
| +0xAA84C | Session key 2 |
| +0xAAA98 | g_auth_mode block (48B) |
| +0xAFBD8 | CreateFriendList init flag |

## Timing

State machine +0x44FCC fires during PlayOnline bootstrap (before game, before addons load). Addons load after character is in game and cannot hook bootstrap from addon. CallerB/C invoked by xiloader worker thread post-login; they connect with zero globals. Non-zero globals (via set_globals_v2) change slot[+0x02] and break login if set before CoCreateInstance(FFXiEntry).
