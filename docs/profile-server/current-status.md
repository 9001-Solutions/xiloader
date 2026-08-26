# Profile Server — Current State

Reference for the friend/messaging integration that runs natively against polcore + FFXiMain.

## Pipeline

```
Server -> CallerB -> Array 1 (polcore+0x403080)
                    |
                    v  do_array_sync() in friend.cpp
                Array 2 (polcore+0xB40D8)
                    |
                    v  func_table+0x29C → polcore+0x23DA0
                Store 3 (FFXiMain friend data object)
                    |
                    v  populate_friend_data
                /flist display
```

## Two transports

The pp service speaks **two** protocols, and both are now in use:

| Port (dialled) | Proxied to | Protocol | Carries |
|----------------|-----------|----------|---------|
| 51222 | 51322 | binary Init/Auth/Data | friend list, messages, befriend |
| 51240 | 51340 | **IRC** (CRLF lines) | live online/offline status |

The push channel is a real IRC server -- polcore implements JOIN/PART/MODE/
PRIVMSG/NOTICE/PING/PONG/QUIT/KICK/TOPIC/KILL/ERROR. Live friend status is
delivered as an IRC `NOTICE` carrying an encoded record. Full spec:
**`pol-push-irc-protocol.md`**.

Without the push channel, friend status is frozen at whatever CallerB captured
at login -- whoever logs in first never sees the other come online.

## Profile-server proxy

xiloader owns the ports polcore dials and forwards to the real server 100
above them (`src/profile_proxy.cpp`, started from `friend_system::bootstrap`).

polcore connects to the profile server directly from inside the game process,
so before the proxy a server restart killed a socket the GAME owned and FFXi
dropped the player to "POL-0008 Connection terminated or not available". The
proxy never closes the client-facing socket: on an outage it holds it open and
silent, buffers client->server data (1MB cap) and reconnects with exponential
backoff (250ms -> 5s).

If it cannot bind 51222/51240 it warns and falls back to a direct connection --
outages become fatal again. Running the Python server on 51222 instead of 51322
silently reintroduces the old failure.

Verified: ~80s outage under a live client with no error screen and no relaunch,
followed by ~18h unattended uptime.

`do_array_sync()` replaces the native per-frame function (FFXiMain build skew makes the old +0x448A0 RVA stale). The native per-frame ran only during PlayOnline bootstrap; xiloader's worker thread reproduces its post-CallerB work at gameplay time.

## Connection Discovery

`recv_auth_response (polcore+0x1F690)` parses Pre-Auth response and writes the friend-server sockaddr to `polcore+0x404AB8` (family=1, port=51220, IP from response). After this, CallerB/C connect directly without DNS.

Polcore's error cleanup zeros `polcore+0x404AB8`. The xiloader worker thread re-writes it on every reconnect attempt when `s_consecutive_failures > 0`.

## Friend Worker State Machine

| State | Action |
|-------|--------|
| 0 WAITING | Wait for FFXiMain.dll + Store 3 + 5s settle. Apply FFXiMain patches. |
| 1 READY | Call CallerB init. Disable BF crypto on allocated slot. Re-write sockaddr if previously failed. |
| 2 PUMPING | Pump CallerB driver until slot freed (`desc[0]=0`). On completion: `do_array_sync()` + `write_handle_array()`. |
| 3 ARRAY_SYNC | Wait for Store 3 populated (friend count > 0). |
| 4 SYNC | `do_sync_status()`: write status table, enrich Store 3, call `populate_friend_data`, write handle array. |
| 5 STEADY | Run `gate_keeper()` per-frame. After 1800 frames, cycle to READY for keepalive refresh. |

Reconnection backoff: 30s, 60s, 120s, 240s, capped at 5 min (`MAX_BACKOFF_TICKS=18000`). 0-synced CallerB completion is treated as failure.

## Auth Modes

`02 04 05 00 ...` (degraded) is the default xiloader mask — predictable, server-extractable, not retail-equivalent.

Healthy mode (Auth[0]=0x01) requires both `SetAuthMode` patches (instances #1 and #2). Server skips DegradedAuthResp. Mask is character-name-derived.

Retail-mode masks need lobby-supplied crypto seed via `set_globals_v2`. State at polcore+0x44BBF that calls it is never reached on xiloader because the lobby config block is never received. Calling `set_globals_v2` before `CoCreateInstance(FFXiEntry)` breaks login.

## CallerB Mode Flow (small lists)

Mode 5 recvs all records. Mode 6 processes → Array 1. Remaining=0 → mode 5 skips to mode 8. Mode 7 never reached for lists < ~19 friends. Mode 8 runs post-processing (polcore+0x228F0): only remaps sub-indices, does NOT copy Array 1 → Array 2. Mode 8 then: counter setter (polcore+0x234F0) → event close (polcore+0x2BB00) → connection cleanup (polcore+0x1FBD0). No notification to FFXiMain. No Array 2 write.

`xiloader` calls CallerB init (polcore+0x23440) and driver (polcore+0x23460) directly from the worker thread.

## Friend List Categorization

`populate_friend_data (FFXiMain+0x1E9830)` runs 5 sequential checks per Store 3 entry:

| Check | Test | Result |
|-------|------|--------|
| 1 | `entry[0x98] & 1` | invalid → skip |
| 2 | `entry[0xF8]` non-zero | cat 2 (type 3) |
| 3 | `entry[0x08] & 0x10000000` (bit 28) | cat 3 (type 4, pending) |
| 4 | `(entry[0x08] & 0xE000) == 0x8000` (bit 15 exact) | cat 4 (type 7, ignored) |
| 5 | `(entry[0x08] >> 13) & 7` | 1-3 = cat 0 ONLINE/type 1, 0 = cat 1 OFFLINE/type 2 |

Two display arrays: 0x54/entry at `flistmai+0x5C`, 0x88/entry at `flistmai+0x60`. Type byte in second_array[i][0] determines display section.

Bit 13 (0x2000) is set natively by status processing from the 0xA8-stride array (polcore+0xAE528). xiloader's `do_array_sync()` sets it directly (server bit 16 → client bit 13). Zone data set by `do_sync_status()`.

## Notification Overlay (Sub F + tick caller + Sub D)

The native notification tick system runs stably with polcore's code under this patch set. Display rendering is stubbed; the framework is operational.

### Apply order

Patch Sub F to `ret-1` FIRST, set struct fields, restore Sub F LAST.

1. `pol+0x457BB`: `0x7D` → `0xEB` (JGE→JMP, skip tick-killer) — 1 byte
2. `pol+0x454CC`: `75 09` → `90 90` (NOP JNE, bypass dispatch_mode check) — 2 bytes
3. `pol+0x9924C` = 1 (tick_enable)
4. `pol+0x99250` = 0 (struct_index)
5. `struct[0x208] = 0x0E`, `struct[0x209] = 0x55`, `struct[0x33C] = 1`
6. `struct[0x20C] = -1` (safe display stub — pol+0x165F0 returns 0 immediately)
7. `struct[0x334] = 0` (safe pol+0x168D0 — clears +0x338, returns)
8. `struct+0x24D0` = ring buffer stub in `struct[1]` (zeroed indices = empty buffer = return 1)
9. `pol+0xAA974` = `FFXiMain+0xF2750` (callback_ptr)

### Tick flow (pol+0x45480)

```
Sub D callback dispatch (pol+0x1C600) — fires every frame
CALL Sub F (pol+0x15C30) — display path
if Sub F returns 0:
  CALL Sub G (pol+0x15560) → returns struct+0x33C
  if 0 → POL-1024 error
  if non-zero → EBP = value, continue
```

### POL-1024 fix

When Sub F returns 0, the tick caller invokes Sub G which returns `struct+0x33C`. If 0, the tick sets error code -1024 ("POL-1024"). Fix: `struct+0x33C = 1`.

### Callback chain

`Sub D → FFXiMain+0xF2750 → FFXiMain+0xF2680` fires every frame. Notification manager at `FFXiMain+0x4DE900` exists and processes entries (counter at `this+0x08` increments).

## Notification Icon (Pulsing S:/R: Upper-Right)

Filesystem-driven by per-frame scan of `PlayOnlineViewer\pub\home01\msg\r\b\` (unread messages). Dismiss moves file to `r\a\`. Modifying DWORD count fields in polcore notification structures has no display effect.

### Notification data structures

`pol+0x3E9190`, stride `0x3A00` — three identical structures within larger 0x3A00-stride blocks (3 POL sessions). Each contains three vector entries:

- Entry 0: `{ptr, count=8, max=8}` — message notification IDs (encrypted DWORDs)
- Entry 1: `{ptr, count=1, max=1}` — mail notification
- Entry 2: `{ptr, count=8, max=8}` — unknown

Metadata caches populated during NotificationPickup. NOT the display data source.

### Message cache directory

```
PlayOnlineViewer\pub\home01\msg\
  r\                    received messages
    a\                  read/archived
    b\                  unread (count drives notification icon)
```

Each file: 18-48 bytes. Body example: `Friend registration declined\x07\x00`.

## Native Bootstrap Connection Sequence

| Order | Caller | Auth | Purpose |
|-------|--------|------|---------|
| 1 | CallerA | (04,05) | Keepalive, 1-3 connections, ~10s apart. Returns server IP → writes sockaddr global. |
| 2 | ShortAuth | (01,0b) | Session setup, 1-4 connections, ~20s after CallerA. |
| 3 | CallerB | (01,03) | Friend list download. |

CallerA sends `Auth[0]=0x02` (degraded) despite `SetAuthMode` patches. `SetAuthMode` instance #1 patches the second SM auth builder; CallerA uses a different code path.

ShortAuth (01,0b) and CallerB (01,03) both use the peek-based second SM (polcore+0x1F4D0), NOT the blocking SM (polcore+0x1E4D0). The server must NOT send AuthResponse before the client sends Data.

CallerB does not fire natively — observed exclusively from xiloader worker thread. Root cause: ShortAuth Status response content prevents the state machine from proceeding.

## BF Crypto Disabled

`desc[0x0B]=0` for all 4 polcore descriptor slots. Polcore's BF callsites gate on this byte. `desc+0x50` BF key material is uninitialized because key material is populated by the inner SM during the protocol handshake; `CreateFriendList` only sets `crypto=1`, never the key bytes.

The 0xA8-stride status array (polcore+0xAE528) is empty on xiloader. Retail populates it via the status update protocol. `do_sync_status()` writes the status table directly.

## set_globals_v2 Constraint

Calling `set_globals_v2` before `CoCreateInstance(FFXiEntry)` causes the session keys to interfere with the login process. The state-machine code at polcore+0x44BBF that calls `set_globals_v2` with lobby data is never reached on xiloader because the lobby config block does not exist.
