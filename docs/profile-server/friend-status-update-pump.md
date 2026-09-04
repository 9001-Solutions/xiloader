# Friend status update pump -- `friend_status_recv_pump (2,3)`

The native polcore mechanism for refreshing the FFXi friend list with current
online/offline/zone status. Distinct from CallerB (the initial bulk download
at game-start) and from WhoIs (per-name lookup).

This SM is what populates polcore's Array2 with live friend records that
FFXi then reads through the function-table on every `populate_friend_data`
render.

## Polcore symbols (image base `0x04580000`)

| RVA      | Role                                                         |
|----------|--------------------------------------------------------------|
| `+0x237F0`| `friend_status_recv_pump` -- the SM (cases 0..8)             |
| `+0x240C0`| Init `FUN_045A40C0(void)` -- allocates slot, counts occupied bitmap entries, sets up state, returns slot index |
| `+0x25580`| Init lock-wrapped thunk -- function-table slot `+0x294`      |
| `+0x255C0`| Pump lock-wrapped thunk -> `friend_status_recv_pump` -- function-table slot `+0x290` |
| `+0x1EEB0`| `FUN_0459EEB0` -- friend record inserter (writes to Array2)  |
| `+0x23CF0`| `FUN_045A3CF0(table, idx, op)` -- bitmap manager at `DAT_0463CA58`. op=2 = read bit |

## Function-table slots

Polcore's function table at `polcore+0x6FBE8` (returned by `GetCommonFunctionTable`):

| Slot     | Target                                                       |
|----------|--------------------------------------------------------------|
| `+0x290` | `+0x255C0` -- pump thunk for `friend_status_recv_pump`        |
| `+0x294` | `+0x25580` -- init thunk for `FUN_045A40C0`                   |
| `+0x298` | `+0x255A0` -- orchestrator thunk -> `polcore_friendlist_download_sm` (different SM) |
| `+0x29C` | `+0x23DA0` -- `ixff_get_inbox_entry` Array2 reader (called by FFXi per friend on render) |
| `+0x2A0` | `+0x23FD0` -- Array2 writer                                   |

## SM cases (`friend_status_recv_pump @ +0x237F0`)

| Case | Action |
|------|--------|
| 0    | Init counters: zero `slot+0x44`, `slot+0x48`; set `slot+0xC0 = -1`; memzero bitmap area at `+0x3CA58` (0x26 bytes); advance |
| 1    | `polcore_connect_sm` -- TCP handshake |
| 2    | `polcore_send_ixff_header_sm(slot, 2, 3, 0)` -- Auth `(2,3)` with body_size=0 |
| 3    | `polcore_drain_sm` -- recv 24B AuthConfirm |
| 4    | `FUN_0459FAB0(slot, 8, 0)` -- recv 8B size header. First dword = N (server's reported friend count). Stored at `slot+0xC0` (and `slot+0xD8`). |
| 5    | `polcore_recv_body_sm(slot, N*0xA8 capped at 0x7E0, 0, buf)` -- recv up to ~12 records per pump. Loops back to case 5 until all N records arrived. |
| 6    | For each `0xA8`-byte record in the recv buffer:<br>  - `FUN_0459F090(record)` validates checksum/sentinel -- error closes slot with `-0x140D`<br>  - If `record[0] & 0x10` -> write to `&DAT_0462FC18 + idx*0x2C` (linkshell/blacklist array)<br>  - Else -> write to `&DAT_046340D8 + idx*0x2C` (Array2)<br>  - `FUN_045A3CF0(table_flag, idx, 1)` -- set bitmap occupancy bit<br>  - `FUN_0459EEB0(record, dst, is_new)` -- copy record into Array2 entry |
| 7    | `FUN_0459FAD0(slot)` -- recv 4B sum-of-dwords trailer (CRC validated) |
| 8    | - `FUN_045A3BE0(&DAT_046340D8, 0)` -- finalize Array2<br>- `FUN_045A3BE0(&DAT_0462FC18, 1)` -- finalize linkshell array<br>- Iterate Array2: for each entry, call `FUN_045A3D60(idx)` and update entry+0x98 occupancy bit<br>- `FUN_045A34F0(1, slot+0x328 buf, 0, 0)` -- FFXi handoff (linkshell pass)<br>- `FUN_045A34F0(0, slot+0x328 buf, 0, 0)` -- FFXi handoff (friend pass)<br>- Set `DAT_0463CA80 = 1` (completion flag)<br>- Close slot |

## Data flow end-to-end

```
1. xiloader worker thread
       v
   call slot +0x294 (init) -> FUN_045A40C0(void) -> returns slot index
       v
   loop slot +0x290 (pump) until status==1
       v
2. polcore TCP -> server
       send Auth(2,3,0)
       recv AuthConfirm + 8B size header (count N) + N*0xA8 records + 4B CRC
       v
3. polcore writes Array2 entries (+0xB40D8, stride 0x2C) and linkshell array (+0xAFC18)
       v
4. FFXi populate_friend_data
       calls FUN_046F69E0 (rebuilds visibility index from each entry+0x98)
       calls FUN_046F79E0(idx, dst) per friend
       which calls ixff_get_inbox_entry -> function-table slot +0x29C
       which calls polcore +0x23DA0 (Array2 reader)
       writes friend data into FFXi friend manager at DAT_04AEE768+0xA90+idx*0x100
       v
5. populate_friend_data renders /flist from the freshly-pulled buffer
```

## Wire format

```
C->S Init                  (40B, std)
S->C ACK                   (24B)
C->S Auth (2,3) body=0     (40B header, no body)
S->C AuthConfirm           (24B; param=TBD by server)
S->C size header           (8B: [u32_le N][u32_le ?])
S->C records               (N x 0xA8 bytes, batched up to 12 per recv)
S->C trailer               (4B sum-of-dwords over preceding bytes)
```

The 0xA8-byte record format is consumed by `FUN_0459EEB0` (friend record
inserter). It writes to Array2 entry at `record[2] * 0x2C` offset
(or to the parallel linkshell array if `record[0] & 0x10`).

The on-the-wire AuthResponse 40B is NOT consumed by
`polcore_send_ixff_header_sm` -- same gotcha as `(3,3)`, `(2,6)`, `(3,1)`,
`(4,6)`. Server must skip the AuthResponse send for `(2,3)` auth.

## Distinction from WhoIs `(4,6,0x18)`

WhoIs is a single-account lookup that populates scattered "result" globals
at `+0xAC528`/`+0xAC540`/`+0x754xx` for use by per-name lookup helpers
(whois-by-charname, etc.). It does NOT update Array2, so it does NOT affect
`/flist` rendering.

`friend_status_recv_pump` is the bulk live-status updater that DOES write
Array2, which IS what `/flist` reads from. This is the SM xiloader needs to
drive periodically for live friend status updates.
