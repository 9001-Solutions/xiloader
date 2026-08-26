# Friend List UI — Display Behavior

## Sections

The native /flist UI has four sections:

1. **Online** — friends currently connected
2. **Offline** — friends not connected
3. **Pending** — friend requests awaiting confirmation
4. **Ignore** — blocked accounts

## Display Format

### Offline / Pending / Ignore

Account nickname only (plain text).

### Online — Logging In

Friend has started login but is not yet in-game.

- Online icon (left)
- Account nickname
- XI icon (right)

### Online — In-Game

- Online icon (left)
- Account nickname
- XI icon (right)
- Server name (e.g. `<Fenrir>`)

## Server Name

| Source | Behavior |
|--------|---------|
| Production (LSB) | Current zone, fallback to LSB server config (server name setting) |
| Python profile test server | Current zone, hardcoded `<Horizon>` fallback |

## Data Pipeline

```
Server → CallerB → Array 1 (polcore+0x403080)
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

## Array 2 Entry Layout (0xB0 bytes)

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | friend ID lo (account ID) |
| +0x04 | 4 | friend ID hi |
| +0x08 | 4 | flags lo (bit 16 = online) |
| +0x0C | 4 | flags hi |
| +0x98 | 4 | status (bit 0 = valid) |
| +0xA0 | 15 | display name (account nickname) |

## XI Icon Injection

Native `populate_friend_data` calls the game icon setter at FFXiMain+0x1E95E0, but `flags_hi` is 0 at call time because the native bridge does not set it. `gate_keeper()` in `friend.cpp` injects the XI icon (type=2) directly into render buffers for category==5 (online) entries. Icon pointer resolves via `flistmai+0x8C` (double-deref to icon array, FFXI icon at index 0).
