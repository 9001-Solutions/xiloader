# POL push channel -- IRC protocol reference

The PlayOnline profile ("pp") service has **two** transports. The binary
request/response protocol on 51220/51222 is documented elsewhere. This file
covers the other one:

> **The push channel is an IRC server.**

It carries live friend online/offline transitions. Without it, friend status is
frozen at whatever CallerB captured when *you* logged in.

This is a from-scratch reference.

---

## 1. Evidence it is IRC

polcore's .rdata string table (0x10073A00-0x10073D00):

    0x10073B0C  "Kicked by same NICK"
    0x10073B28  "ERROR"
    0x10073B30  "IRC%02x"
    0x10073B38  "aiwabeiIklmnostv"     <- IRC user/channel mode letters
    0x10073C4C  "%s %s %d %s :%s"      <- op 2 = USER
    0x10073C64  "QUIT"
    0x10073CA4  "%s %s +o %s -o %s"    <- MODE with operator grants
    0x10073CE0  "%s %s :%s"            <- PRIVMSG form

Command table at **0x10073F48** is the full RFC 1459 list (40 entries,
PASS..ISON). The parallel handler table at **0x10073DA8** shows what polcore
actually implements:

| idx | cmd | handler | idx | cmd | handler |
|-----|-----|---------|-----|-----|---------|
| 5 | QUIT | 0x10017880 | 23 | PRIVMSG | 0x10017EC0 |
| 7 | JOIN | 0x10017910 | 24 | NOTICE | 0x10017F90 |
| 8 | PART | 0x10017A50 | 28 | KILL | 0x10017FC0 |
| 9 | MODE | 0x10017AF0 | 29 | PING | 0x10018030 |
| 10 | TOPIC | 0x10017D40 | 30 | PONG | 0x10018150 |
| 14 | KICK | 0x10017DF0 | 31 | ERROR | 0x10018180 |

Verified live: polcore answers a server PING with `PONG <token>`.

---

## 2. Ports

    polcore dials        proxied to (real server)
    127.0.0.1:51222  ->  127.0.0.1:51322    profile (binary)
    127.0.0.1:51240  ->  127.0.0.1:51340    push (IRC)

xiloader owns the dialled ports so a server restart never drops the socket the
game holds -- see `src/profile_proxy.cpp`. polcore is
unchanged; it still dials 51222/51240.

Port selection is in push SM case 2/3: `conn+0x209 & 8` -> 0xC829,
`& 0x80` -> 0xC82A, else `conn+0x2A8` if non-zero, else **0xC828 (51240)**.

---

## 3. Framing

**Lines are CRLF-terminated in both directions.**

polcore's own format strings end `\t\t\t\t\r\n`. This bit us: replying with a
bare CR leaves every line unparsed and the state machine stalls at sub-state 8
with no error. Send CRLF.

---

## 4. Bring-up

Two gates stand between a fresh client and a working channel.

### 4.1 The router is latched

`pol_msg_router` (polcore+0x44A50) drives everything from state
`DAT_10099408`. On a fresh client it reads **-0x2C04**: case 0 set it when
`DAT_10099C80` was still 0 on the first tick, and a negative state matches no
case in the switch, so it can never re-enter. An ordering race, not a failure.

`pol_set_conn_config` (**polcore+0x448A0** -- note, not 0x448C8, which is past
the prologue; published in polcore's function table at index 814) fixes both
gates at once: it sets `DAT_10099414 = mode` and RESETS `DAT_10099408`
(to 0x12 for modes 1/3). State 0x11 otherwise short-circuits to 0x1E whenever
`DAT_10099414 == 0`.

Full chain once unlatched:

    0x12 -> 0x13   set_globals_v2 (FUN_1001EAB0)
         -> 0x14/0x15   resolve pp host from DAT_10099299
         -> 0x16   connect (FUN_10013EA0), handler table DAT_10099420
         -> 0x17   drives the push SM FUN_100140E0
         -> 0x18..0x1D -> 0x1E   connected / idle

### 4.2 The key generator is compiled out

Push SM case 5 calls `FUN_10047E40(fd, 1, &conn[0x39E4])` to populate a key
struct, then advances **only if `conn+0x39F0` is non-NULL**. In this build
`FUN_10047E40` is `33 C0 C3` (`xor eax,eax; ret`) -- a shared "not implemented"
stub filling 13+ slots of the function table. So the SM parks at sub-state 5
forever.

xiloader supplies the material itself (`pol_push_provide_keys`):

    conn+0x39EC  int  length = 16
    conn+0x39F0  ptr  buffer A   <-- the gate
    conn+0x39F8  u32  mask A = 0
    conn+0x39E6  u16  ready = 1

Two landmines:

- **Buffer A must come from polcore's heap** (`_malloc` at polcore+0x51B95).
  The SM frees it with polcore's `_free` (0x10051C58, seen at polcore+0x141A1).
- **Do NOT populate buffer B** (`conn+0x39F4`) or its mask (`0x39FC`).
  `FUN_10013A80` already allocates and derives them; overwriting leaks that
  allocation and corrupts polcore's derivation.
- **Do NOT detour `FUN_10047E40`** -- it is shared by unrelated callers.

The "masks" are XOR-obfuscated pointers, not masks: the serializer reads from
`(mask ^ buf)`. Mask 0 makes it read the buffer itself.

### 4.3 Session-ready flag

`FUN_10013A80` (any connection creation) calls `FUN_10019BB0()`, which sets
`DAT_100AA8C8 = 0`. The friend path tests it at polcore+0x1EBF6 and returns
**-0x203**, surfacing as the **-5136** abort -- so bringing the push channel up
silently kills friend_status for the rest of the session.

xiloader snapshots the flag before bring-up and restores it after
(`pol_session_ready_restore`). This is also the push SM's own case-0x0C gate
(`FUN_10019BC0() != 0`), so restoring it lets the SM complete as well.

---

## 5. Registration handshake

    C->S  USER x 8 * :<47-char session token>
    S->C  :pol.com 001 x :Welcome ...
    S->C  :pol.com 002/003/004 ...
    S->C  :pol.com 422 x :MOTD File is missing

Numerics `pol_irc_recv_dispatch` (polcore+0x15E80) acts on:

| numeric | effect |
|---------|--------|
| 300 (while sub-state 8) | derive session key from 3rd token (46 chars), init cipher, `conn+0x209 \|= 0x44` -- unlocks op 0x28 AND switches sends to the ENCRYPTED path |
| 422 | sub-state -> 0x0C |
| 433 | error, sub-state 0x0B |
| 001 | accepted (copies 0xC0 bytes if that length) |
| >399 other than 422 | error, sub-state 0x0E |

Sending **422** alone completes registration in plaintext, because only 300
sets the encryption bit. Sub-state **0x0C is the steady listening state**, not
a stall -- advancing to 0x0D runs teardown.

---

## 6. Status delivery

    :<prefix> NOTICE <nick> :<payload>

Two things are easy to get wrong:

**Target must be a well-formed polcore nick** -- `'U'` followed by 8 base-36
digits (`FUN_1001A390` writes the `0x55` 'U' at `buf[-1]`). polcore decodes the
target and the NOTICE handler **skips the message entirely if it decodes to
zero**, so a plain target like `x` is silently ignored. It need NOT be the
player's own nick; any non-zero-decoding value works. The sender prefix is
irrelevant.

**NOTICE, not PRIVMSG.** Both route through `pol_irc_msg_to_channel`
(polcore+0x17EF0):

    if (*target == '#')  cb2(payload, target, ...)     // channel
    else                 cb1(payload, decoded_nick, ...) // private

but they pass different callback pairs:

    PRIVMSG -> conn+0x340, conn+0x348   both NULL -> inert
    NOTICE  -> conn+0x344, conn+0x34C   conn+0x344 IS status_update_dispatch

So status reaches polcore only via NOTICE addressed to a NICK.

---

## 7. Payload codec

`FUN_100078A0` is a custom-alphabet base64: 4 chars -> 3 bytes, MSB-first.
Alphabet from polcore's char->value table at **0x10065D64**:

    TSG8IncW3HFKokOg79qzeCmZs2yBYEQVAUxR5rbwi4P@jMDLtpvad0f_J1hlN6uX

Implemented in `tools/profile-server/pol_b64.py`, verified byte-identical
against polcore's own decoder in a live process.

---

## 8. Record formats

`status_update_dispatch` (polcore+0x1B6F0) parses the first **96 chars** into a
72-byte record, then branches.

Common gates (all required, or the record is dropped silently):

    +0x42 u16  bit 0 set
    +0x3E u16  (val & 0xF80) == 0xF80    <- NOT 0x880; that is the parser's
                                            own separate check at +0x1B640
    +0x1C u8   friend index, < 0xC8
    +0x30 u32  timestamp hi   } strictly NEWER than the pair polcore holds
    +0x34 u32  timestamp lo   } at entry+0x10/+0x14, else ignored

Identity, checked against the friend polcore has at that index:

    +0x00 u32  accid_lo ^ 0x67891133
    +0x04 u32  accid_hi ^ 0x1C273E45

`FUN_1001A080` is a plain XOR against those keys **and the filename IV**, while
the client stores `identity = accid ^ IV` (`FUN_10019D40` is also just XOR with
the IV). **The IV cancels** -- encode with the raw accid and the server never
needs to know it.

### Branch A -- status only

Taken when `record[0x1B] != 0`. Calls
`FUN_100250B0(&record[0x10], index, ts_hi, ts_lo)` -> `FUN_1001ECB0`:

    +0x10 u8   connection state -> entry+0x08 bits 11-12
    +0x11 u8   2 = ONLINE, 1 = OFFLINE  (bits 13-15 = (val-1) & 7)
    +0x12 u8   bit0 -> entry+0x08 bit 16; bits1-3 -> bits 17-19; 7 matches CallerB
    +0x14 u16  game type -> entry+0x0C bits 1-10; 1 = FFXI (drives the XI icon)

Writes ONLY bit-fields. **No name, no zone, no sub-entry** -- a friend pushed
this way renders online but blank.

### Branch B -- the whole row (use this)

Taken when `record[0x1B] == 0` **and** `record[0x1A] == 0` **and**
`record[0x19] & 1` **and** `0 < record[0x38] < 0x158`.

`record[0x38]` is the **character count of a second payload** appended directly
after the 96-char base record (polcore reads it at `base + 0x60`). It decodes
to a block whose **first byte is a presence bitmask**; each set bit appends a
fixed-size field, in this order, starting at offset 8:

| bit | size | field | destination |
|-----|------|-------|-------------|
| 0x01 | -- | apply base record's status bytes | via `FUN_1001EE40` |
| 0x02 | 16B | status record | **routes to `FUN_10029650` instead -- keep CLEAR** |
| 0x04 | 8B | type word | status table +0x00 |
| 0x08 | 16B | sub-entry | entry+0x18 + (idx&7)*0x10, **bit 0 set** |
| 0x10 | 16B | name (15B) | Array2 entry+0xA0 |
| 0x20 | 104B | struct blob (0x32 used) | status table +0x1C; **zone at +0x14** |
| 0x40 | rest | display name (0x17) | status table +0x04 |

then calls `FUN_100250F0(status, index, ts_hi, ts_lo, type, sub, name15,
blob50, dispname23)`.

Built by `build_status_notice_rich()` in `pol_b64.py`.

**Why branch B matters:** the sub-entry it writes is what
`FUN_03ED77A0` gates the in-game render on:

    *(u16*)(entry + 0x1A + ((entry[0x08] >> 17) & 7) * 0x10) == 1

Without it, `populate_friend_data` categorises the friend online but skips the
character name, zone and XI icon. Those normally come from the CallerB snapshot
taken at *your* login, which never refreshes -- so a friend who logs in later
renders blank. Branch B refreshes all of it.

Note the sub-entry cannot reliably be delivered via the friend_status (2,3)
record instead: `FUN_1001EEB0` only copies sub-entries when its caller passes
`is_new`, computed as `(entry[0x10] | entry[0x14]) == 0` -- and those two dwords
are the timestamps a status push writes, so after the first push the window is
closed permanently.

---

## 9. Receive is pumped separately

Neither the router nor the push SM reads the socket. `polcore+0x45480` (real
entry; +0x45495 is past the prologue) is the receive pump, gated on
`DAT_103DF7F8 != 0` and `DAT_1009924C == 1` (set by router state 0x17). It
walks `FUN_10015C30 -> FUN_100164E0 -> pol_irc_recv_dispatch` and handles **one
message per call**.

xiloader calls `FUN_10015C30(slot)` **directly** rather than the outer pump:
the outer one releases polcore's global lock (`FUN_10047FE0`) and re-takes it
around the receive, which from the worker thread breaks mutual exclusion with
the friend state machines.

`FUN_10015B10` is the SEND flush, not receive -- easy to misread.

---

## 10. Verified end to end

Real second client logging in, no simulated sessions:

    t+0    CharB's client logs in
    t+~1s  server pushes a branch-B NOTICE
    t+3s   flags = 0x00172006, gate = 0x0001,
           status table = 0x41 + display name, zone = 0x409A

/flist renders **"NickB in DragonAery"** with the XI icon -- the account
nickname + zone + icon format documented in `friend-list-ui.md`.

## The status-change notification callback (pol+0xAA974)

`status_update_dispatch` (polcore+0x1B71C) decodes every pushed status record
and then calls a function pointer held at `polcore+0xAA974`:

    (*cb)(2, entry)      friend/status entry updated
    (*cb)(1, text)       text payload
    (*cb)(0, record)     base record
    (*cb)(uVar11, data)  uVar11 in {2,4,5,6} for the branch-B classes

Convention is `__cdecl(int opcode, void* data)` -- confirmed by the stock
handler being a bare `RET`, not `RET 8`. Getting this wrong corrupts polcore's
stack.

**Stock polcore installs `FUN_1004F4E0` here, which is a bare `RET`.** The
client receives the push, decodes it, updates its own state, and then notifies
nobody. This is the root cause of the "pushed data is invisible until something
else ticks the client" behaviour, and the reason a polling worker was needed at
all -- it is the same compiled-out subsystem as the push key generator
(`FUN_10047470` / `FUN_100474E0`, neighbours of the shared `FUN_10047E40`
not-implemented stub).

FFXi never registers here: probing the slot immediately before writing it reads
zero on every launch, and the only WRITE xref is polcore's own registrar
`FUN_1001B500`, called from `pol_msg_router`.

xiloader installs a real handler (`Mine_PolStatusNotify`) and re-asserts it from
the worker, because `pol_msg_router` reinstalls the stub during router
progression -- a single write at bring-up does not stick. The handler runs on
polcore's dispatch thread while `status_update_dispatch` holds its critical
section, so it only sets a flag; the worker does the sync.

Verified 1:1 -- every server push produces exactly one opcode-2 callback:

    15:24:13.491 accid 1007 OFFLINE  ->  15:24:13 opcode 2
    15:24:28.786 accid 1007 ONLINE   ->  15:24:28 opcode 2
    15:24:35.659 accid 1000 ONLINE   ->  15:24:35 opcode 2


## Status pushes are index-addressed -- re-announce when the friend set changes

A status NOTICE targets a friend by **index**, so the client drops it if its
friend array has no such slot yet. Creating a friendship mid-session races the
client's `friend_status` refresh: the push goes out first, is discarded, and the
poller's change-detection cache then reads "already ONLINE" and never
re-announces. The friend shows offline indefinitely.

Observed exactly: push at 17:00:47, client's friend_status refresh at 17:01:08,
and `Array2[1]+0x8` stuck at 0x00000006 instead of 0x00072006 -- the online bits
(0x00072000) come from the push channel, NOT from friend_status.

The poller therefore tracks the set of friend account ids and clears its status
cache whenever that set changes, re-announcing every slot on the next poll.
