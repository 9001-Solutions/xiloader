# Message send path (compose -> polcore -> profile server)

RE'd 2026-09-02 against validated dumps: FFXiMain base `0x04A50000`,
polcore base `0x10000000`. Addresses below are LIVE for those bases; subtract
the base for an RVA.

The receive half (notification pickup, msg files on disk, inbox enumeration,
mark-as-read) is covered in `inbox-msg-system.md`, `message-list.md` and
`native-mark-read.md`. This document covers the SEND half, which was previously
undocumented.

## 1. Payload format

`polcore+0x1A8E0` packs the outgoing message body:

    FUN_1001a8e0(str1, str2, blob_len, blob_ptr, out) -> total_len

      str1  copied until NUL, max 0x80  (128)   -- subject
      0x07  separator byte
      str2  copied until NUL, max 0xFFF (4095)  -- body
      0x00  terminator
      blob  optional, memcpy'd, length capped at 0x100000

So the wire body is literally `subject \x07 body \0 [blob]`. This matches the
`str1\x07str2\0[blob]` note in `native-mark-read.md`.

**polcore's caps are not the effective limits** -- see section 3.

## 2. polcore submit

`polcore+0x1BE00` (reached via COM vtable slot `+0x444`):

- rejects unaligned handles (`param_1 & 7`) and a busy flag at `+0x43`
- resolves the destination host, falling back to the literal
  `s_127_0_0_1_C816` -- **0xC816 = 51222**, i.e. the profile server port
- hashes the account id via `FUN_10019D40` when
  `(*(u16*)(handle+0x3E) & 0xF80) == 0x880`
- hands off to `FUN_10027500` to queue the send

The resulting wire packet is the 0x198-byte BF-encrypted body-upload frame
already documented in `native-mark-read.md` (op `0x16`).

## 3. FFXi builder -- the real limits

`FFXi+0x0F2F80` (`FUN_04b42f80`):

    FUN_04b42f80(this, subject, body, blob_ptr, blob_len, subject_maxlen)

- `subject_maxlen` is clamped to `0x32` = **50 chars**, and every caller passes
  exactly `0x32`
- `body` length is clamped to **300** (`if (300 < len) len = base + 0x12D`)
- allocates `total + 0x58`, 8-byte aligns it, stores the aligned base at
  `this+0xA0` and the payload area at `this+0xA4` (= base + 0x48)
- sanitises both strings (`FUN_04b42800` subject, `FUN_04b428c0` body) then
  calls the packer thunk

**Effective limits are subject <= 50 and body <= 300**, far below polcore's
128/4095 caps. Enforce the FFXi limits server-side; anything longer than the
client can produce should be treated as suspect.

## 4. FFXi -> polcore vtable thunks

FFXi reaches polcore through a table of thunks, each
`mov eax,[0x04EA6A2C]; jmp [eax+slot]`, where `0x04EA6A2C` holds the polcore
interface pointer:

| thunk        | slot    | role                          |
|--------------|---------|-------------------------------|
| `0x04D5FEDE` | `+0x440`| buffer packer                 |
| `0x04D5FEE9` | `+0x444`| post_built / submit           |
| `0x04D5FEF4` | `+0x448`| poll_status (pump the SM)     |
| `0x04D5FF15` | `+0x454`| cancel / cleanup              |

The table runs from `0x04D5FE86` (slot `+0x40C`) to `0x04D5FF36` (slot
`+0x460`) with an 11-byte stride. Note these are `jmp`, not `call`: they are
tail-call thunks, so they have no direct callers and do not appear in xrefs.

## 5. Submit wrappers and the slot pool

Five sibling wrappers each build then dispatch:

    FFXi+0x0F3460, +0x0F3520, +0x0F36C0, +0x0F3790, +0x0F3990

Each sets a busy flag at `state[0x416]`, stashes callback/context at
`state[0x412..0x414]`, calls the builder with `subject_maxlen = 0x32`, then
dispatches through `FUN_04b431e0` with an op-table pointer
(`PTR_LAB_04db20d0` for the first). This mirrors the friend-system submit
plumbing in `inbox-msg-system.md`.

Requests come from a pool: up to `0x1D` (29) slots of `0x1060` bytes each,
allocated by `FUN_04b420c0`.

## 6. Open questions before implementing

*(Answered -- see section 7.)*
- Whether the server must persist the uploaded body itself or whether polcore
  also writes the sender's `s/a` copy locally (it does so for befriend -- an
  outgoing copy appeared at `msg/<accid>/s/a/` with polcore's own subject
  text, so the same may hold here).
- The server currently has `send_friend_message()` but only uses it for
  accept/decline system messages; there is no handler for an inbound
  body-upload carrying a user-composed message.


## 7. Which wrapper sends a message to a friend

**`FFXi+0x0F3460` (op table `0x04DB20D0`).** It is the only one that resolves
the recipient from the friend list.

Each wrapper dispatches a distinct NULL-terminated SM phase table:

| wrapper       | op table     | family | distinguishing phase |
|---------------|--------------|--------|----------------------|
| `FFXi+0x0F3460` | `0x04DB20D0` | send | `0x04B445F0` resolve-by-friend-index |
| `FFXi+0x0F3520` | `0x04DB2128` | send | `0x04B447E0` lookup-by-account-id    |
| `FFXi+0x0F3990` | `0x04DB2158` + `0x04DB21A0` | send + enumerate | both |
| `FFXi+0x0F36C0` | `0x04DB21E8` | enumerate | `0x04B45B60` |
| `FFXi+0x0F3790` | (none pushed) | -- | calls the builder twice |

`0x04B44F90` (the submit/poll phase driving vtable slots `+0x444`/`+0x448`,
retrying up to 0x3D times) appears in every table, so they all transmit. The
recipient-resolution phase is what separates them:

- **`0x04B445F0`** calls `FUN_04b46b40(id, 1, buf)`, which walks polcore's two
  friend tables -- 200 entries via thunk `0x04D5FAB3`, then 100 via
  `0x04D5FAC9`, each with 8 sub-entries at `+0x1A` stride 8. These are the same
  two tables polcore's own friend SM uses (`DAT_100B40D8` / `DAT_100AFC18` in
  `FUN_10024170`). On a hit it copies a 16-byte name and stores the recipient's
  8-byte account id to `state+0x38`/`+0x3C`.
  **This is "pick a friend from the list and message them".**

- **`0x04B447E0`** instead takes the account id as INPUT
  (`FUN_04b46d20(accid_lo, accid_hi, ...)`) and only refreshes the display
  name -- i.e. the recipient is already known (reply, or send to a
  non-friend account).

- **`0x04B45A60` / `0x04B45B60`** enumerate rather than address a recipient:
  they iterate via `FUN_04b44200` (returns 0x17/0x18 per item) and compare
  account ids at `state+0x58`/`+0x5C` against `+0x60`/`+0x64`. These are the
  receive/list side, not send.

Implementation consequence: a server handling an inbound body-upload gets the
recipient as an 8-byte account id in the polcore frame (hashed via
`FUN_10019D40` when the flag word says so -- section 2), NOT as a character
name. Resolve the target by account id.


## 8. Receive side: where the body ACTUALLY comes from (open question)

The send half works: compose -> polcore announces `O/m/<filename>` + size ->
client uploads `subject <0x07> body <0x00>` in the tail after our response ->
server persists it. Verified end to end.

The RECEIVE half renders the wrong body, and the cause is ours:

`bridge_msgrec_to_notif_queue` (friend.cpp) leaves `nm.body` empty because the
msgrec wire carries no body, and `write_msg_file` then FABRICATES one:

    std::string body(nm.subject);   // subject reused as body text "for now"
    body += '';
    body += globals::g_Username;    // the LOCAL account's name

So every received message renders as `subject <0x07> <own charname>`. With an
empty subject that is `<0x07><own charname>` -- which is exactly the "ghost"
message. **The ghosts and the wrong message body are the same stub**, not two
separate defects.

### Why the obvious fixes do not work

- **The per-record pad is not a body channel.** `msgrec_recv_pump`
  (polcore+0x276E0) case 8 decodes only the first `0x60` bytes of each `0x108`
  wire block (`FUN_100078A0`, the base64 decoder) and advances by `0x108`. The
  remaining `0xA8` is never read. Tested live: filling it changed nothing.
- **There is no room in the entry.** The record is `0x48` bytes fully
  allocated (accid, msg_id, type, timestamp, sender[16], subject[14], flag),
  with 8 reserved bytes. A 300-char body does not fit.
- **Serving the body on click-to-read cannot work either.** Opening a message
  produces NO server traffic at all -- confirmed across 66 ops with zero
  body-fetches. polcore does not fetch on open.

### What the native path requires

`msgrec_recv_pump` only decodes records: it neither writes a file nor starts a
body fetch. polcore does have a msg-file subsystem --
`FUN_1003D480` initialises it (8 slots of 0x118) and registers `FUN_1003E241`
as its worker via `FUN_100417C8(handler, ctx, ctx, 0x2000)`, and that worker
calls the `WriteFile` wrapper `msg_file_write` (polcore+0x423C0) -- but what
DRIVES that subsystem is not yet traced. Finding the trigger is the remaining
work before xiloader can stop writing msg files itself.
