# Friend list data flow — server to /flist render

End-to-end trace of how friend records reach the FFXi `/flist` display, with
the four polcore SMs that touch friend data and the two FFXi pull paths.

## Storage layout (polcore)

| Address          | Stride | Role                                                  |
|------------------|--------|-------------------------------------------------------|
| `polcore+0x403080`| 0x68   | **Array1** — raw friend records from CallerB's bulk download |
| `polcore+0xB40D8` | 0x2C   | **Array2** — live friend records (THIS is what FFXi reads) |
| `polcore+0xAFC18` | 0x2C   | Parallel linkshell/blacklist array                    |
| `polcore+0x405820`| 0x28   | Friend status table (64 entries × 0x28) — written by CallerB; read by WhoIs to compute subindex |
| `polcore+0x405800`| 0x28   | Adjacent table for sub-entry status flags             |
| `polcore+0x3F06CC`| 0x3098 | World list (4 worlds × 0x3098) — written by `FUN_045AA520` from `(4,5,0x28)` SM result globals; consumed by world-list / search UI, NOT by `/flist` |
| `polcore+0xAC528..0xAC54C`| — | Scattered WhoIs result globals (online flag, account index, etc.) |
| `polcore+0x7541C..0x75428`| — | More WhoIs result globals (subindex, count-1) |
| `polcore+0xAC550` | —     | 10-second cooldown gate for slot_validity_check       |
| `DAT_0463CA58`    | bitmap| Friend slot occupancy bitmap (200 friends + 100 linkshell) |
| `DAT_0463CA80`    | u32   | `friend_status_recv_pump` completion flag             |

## Storage layout (FFXi)

| Address                   | Role                                              |
|---------------------------|---------------------------------------------------|
| `DAT_04AEE768`            | Friend manager pointer (= `&DAT_04AD9648` after `lobby_join_state_machine_init`) |
| `DAT_04AEE768 + 0xA90 + idx*0x100`| Per-friend buffer (300 max). Populated lazily by `FUN_046F79E0` via `ixff_get_inbox_entry` |
| `DAT_04AEE768 + 0x830`    | Visible-friend count (set by `FUN_046F69E0`)      |
| `DAT_04AEE768 + 0x832 + idx*2`| Visible-friend index table (used by `FUN_046F6B00`) |
| `DAT_04AEE768 + 0x132`    | Working count during rebuild                      |

## The four polcore SMs that touch friend data

### 1. CallerB / `polcore_friendlist_download_sm` (auth `1,3`)
- Init: `polcore+0x22210`
- Pump: `polcore+0x22260` (wraps `world_list_recv_pump`)
- Lock-wrapped thunk: `polcore+0x255A0` (function-table slot `+0x298`)
- Bulk friend list download. Runs ONCE at game-start. Populates Array1; xiloader's `do_array_sync()` then bridges Array1 → Array2.

### 2. `friend_status_recv_pump` (auth `2,3`) — **the live-status updater**
- Init: `polcore+0x240C0` (`FUN_045A40C0`)
- Pump: `polcore+0x237F0`
- Init lock-thunk: `polcore+0x25580` (slot `+0x294`)
- Pump lock-thunk: `polcore+0x255C0` (slot `+0x290`)
- Server pushes `N × 0xA8`-byte records. Polcore writes them DIRECTLY to Array2 via `FUN_0459EEB0`. After completion, the bitmap at `DAT_0463CA58` is finalized and FFXi handoff (`FUN_045A34F0`) fires.
- This is what xiloader needs to drive periodically for `/flist` to reflect live status. See `friend-status-update-pump.md`.

### 3. WhoIs `polcore_session_refresh_sm` (auth `4,6,0x18`)
- Driver SM: `polcore+0x1D490`
- Init: `polcore+0x1D400` (jmp trampoline at `+0x1D480`, slot `+0x304`)
- Pump thunk: `polcore+0x1D7D0` (slot `+0x308`)
- Single-account lookup. Caller writes target accid into 24B request body; server returns 128B status. Polcore writes the result into ~10 scattered "result" globals at `+0xAC528..0xAC54C` and `+0x7541C..0x75428`, plus optionally subindex from reading the friend status table.
- These result globals are used by per-name lookup helpers (whois-by-charname, search). They do NOT update Array2, so WhoIs alone has no effect on `/flist` rendering.

### 4. `(4,5,0x28)` SM `FUN_0459DB90`
- Driver SM: `polcore+0x1DB90`
- Auth `(4,5,0x28)` — same auth class as CallerA keepalive
- Sends 40B body, recvs 32B response
- On state change (compared against current globals), calls `FUN_045AA520(acct_index, zone_id, world_index)` which updates the world list at `+0x3F06CC` (4 worlds × 0x3098 stride)
- The world list at `+0x3F06CC` is consumed by world/search UI but NOT by `/flist`. So this SM also doesn't affect friend list rendering.

### Other writers
- `FUN_045A2D00` (`+0x22D00`) — per-friend remove. Clears the matched status entry at `+0x405820`. Called during friend deletion.
- `FUN_0459C9D0` (`+0x1C9D0`) — clear/reset all status table entries. Called on init/cleanup.

## FFXi pull paths

### Friend manager population
1. `lobby_join_state_machine_init` (`FFXi+0xEFFD0`) — allocates `DAT_04AEE768 = &DAT_04AD9648` (one-shot at lobby join)
2. `populate_friend_data` (`FFXi+0x1FAC00`) — main render loop:
   - Calls `FUN_046F69E0` to rebuild the visibility index from each entry's `+0x98` flag
   - Calls `FUN_046F79E0(idx, dst)` per friend, which dispatches to `ixff_get_inbox_entry(idx, dst)`
3. `ixff_get_inbox_entry` (`FFXi+0xF1610`) is a function-pointer thunk:
   ```
   (**(code **)(DAT_04A65A24 + 0x29C))(idx, dst)
   ```
   `DAT_04A65A24` is FFXi's pointer to polcore's function table. Slot `+0x29C` resolves to `polcore+0x23DA0` — the Array2 reader. It copies the Array2 entry at `idx * 0x2C` into `dst` (which is the per-friend buffer at `DAT_04AEE768+0xA90+idx*0x100`).
4. `populate_friend_data` reads status flags from the freshly-pulled buffer:
   - `entry+0x98 & 1` — slot occupied
   - `entry+0x0C` bits — sub-flag for "type 5 vs type 6" (full vs minimal display)
   - `entry+0x08 & 0x10000` — online flag
   - `entry+0x08 >> 0x11 & 7` — sub-entry index

### Implication
**Array2 IS the source of truth for `/flist` rendering.** No status-table caching, no FFXi-side staleness — every render does a fresh function-table pull from polcore. Anything that updates Array2 will be visible in the next `/flist` open.

## Why WhoIs doesn't update `/flist`

WhoIs writes to scattered globals (`+0xAC528`, `+0xAC540`, `+0x754xx`) that are read by polcore's WHOIS-RESULT lookup helpers (`whois.charname`, `search.byname`, etc.). It never touches Array2.

Therefore: even with WhoIs running cleanly and returning correct data, `/flist` will show stale friend status frozen at the CallerB snapshot from game-start. To get live status into `/flist`, drive `friend_status_recv_pump` (auth `(2,3)`) instead — it writes Array2 directly.

## Why CallerB re-pump caused duplicate rows historically

xiloader memory note `feedback_native_polcore_only` and the `do_array_sync` design comment in `friend.cpp` flag that periodic CallerB caused dup rows because the dynamic slot allocator picked a different slot than the inline insert path. That's a CALLERB-specific issue: CallerB wholesale replaces Array1, then sync rewrites Array2. Race conditions with parallel inserts (befriend response) caused dups.

`friend_status_recv_pump` is different: it writes records to Array2 by their `record[2]` index — same record always lands at the same slot, idempotent, no slot allocator race.

## Implementation gotcha (cross-cutting)

Server must NOT send a 40B AuthResponse for any auth class downstream of
`recv_body_sm`: `(2,3)`, `(2,6)`, `(3,1)`, `(3,3)`, `(4,6)`. Sending one
shifts polcore's recv stream by 40 bytes and breaks all downstream parsing.

Only CallerA `(4,5)` and CallerC `(4,7)` tolerate the orphan AuthResponse
because they drain-and-close without reading further.
