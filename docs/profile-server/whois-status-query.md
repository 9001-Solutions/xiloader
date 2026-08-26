# WhoIs / friend status query — `(4,6,0x18)`

The native polcore mechanism for refreshing a single friend's online status
and name lookup data without re-running the full friend-list pump.

The friend list is populated once at game-start by CallerB (`(1,3)` 32B SM
at `polcore+0x22210` / `+0x22260`), which yields a snapshot of all friends
with their status at that moment. WhoIs is the per-friend update path.

## Polcore symbols (image base `0x04580000`)

| RVA       | Role                                                              |
|-----------|-------------------------------------------------------------------|
| `+0x1D400`| WhoIs init body. Allocates slot, runs `auth_builder`, calls `setup_connection(slot, conn_type=6, 0)`, zeroes 0x18B buffer at `*(slot+0x328)`. Returns slot index (or negative on failure). |
| `+0x1D480`| JMP trampoline into `+0x1D400`. The address polcore stores in its function table at slot `+0x304`. |
| `+0x1D490`| WhoIs driver SM. `int __cdecl(slot_idx)` — pumped until it returns 1 (done). 7 SM states; jump table at `+0x1D7B0..+0x1D7CC`. |
| `+0x1D7D0`| Driver thunk. 1-arg pass-through to `+0x1D490`. Stored in polcore's function table at slot `+0x308`. |

## Function-table exposure

Polcore exposes WhoIs to its consumers through the function-table at
`polcore+0x6FBE8` (returned by `GetCommonFunctionTable`):

- Slot `+0x304` → `+0x1D480` (init thunk)
- Slot `+0x308` → `+0x1D7D0` (driver thunk)

## SM cases

Jump table at `+0x1D7B0..+0x1D7CB`:

| Case | RVA       | Role                                                        |
|------|-----------|-------------------------------------------------------------|
| 0    | `+0x1D4E0`| Init counters / state++                                     |
| 1    | `+0x1D4EB`| TCP handshake SM (`+0x1F0F0`)                               |
| 2    | `+0x1D51A`| Auth SM `(4, 6, 0x18)` (`+0x1F4D0`). Literal triple at `+0x1D51A` (`6A 18 6A 06 6A 04`). |
| 3    | `+0x1D54F`| Send 0x18B body                                             |
| 4    | `+0x1D589`| Drain 24B AuthConfirm (`+0x1F690`)                          |
| 5    | `+0x1D5D7`| Recv 128B with `param_3=1` (CRC-validated). Response buffer at `*(slot+0x328)`. Receives 24B instead of 128B if `slot+0xC8` is non-zero (init zeroes it). |
| 6    | `+0x1D64D`| Parse 128B response → write 11+ result globals. `result[6]==0` → `+0x7541C = -1` (not found) and `+0x75424 = 4`. Otherwise reads `result[0x76] & 1` (online flag → `+0xAC528`), `result[+4..+8]`, etc. |

The outer dispatcher at `+0x1D490` calls `slot_validity_check (+0x1EBD0)` on
every pump. That helper enforces a 10-second cooldown gate at
`polcore+0xAC550`: during cooldown it returns 0 (not negative) and the
dispatcher takes its `JLE` exit without entering the case body.

## Output globals

Result fields touched by case 6 (per `polcore-audit.md` "Other Globals"):

| RVA          | Purpose                                       |
|--------------|-----------------------------------------------|
| `+0xAC528`   | Result flag (low byte = WhoIs result flag)    |
| `+0xAC540`   | Online flag / acctid lo                       |
| `+0xAC54C`   | `pbVar3[3] == 1` flag                         |
| `+0xAAAC8`   | Result byte (from result+0x07)                |
| `+0xAAB20`   | Result dword (from result+0x0C)               |
| `+0xAAB24`   | Result dword (from result+0x08)               |
| `+0x7541C`   | Account index (-1 if invalid)                 |
| `+0x75420`   | Subindex (computed from status table)         |
| `+0x75424`   | Count-1                                       |
| `+0x75428`   | Result word (from result+4)                   |

The status table at `+0x405820` (64 entries × 0x28 stride) holds the
per-friend cache that `populate_friend_data` (FFXi-side) reads when it
re-renders flistmai.

## Calling contract

```
slot = WhoIs_init();           // polcore+0x1D480, returns slot or -1
if (slot < 0) bail;

// Caller writes the query parameters into slot fields here.
// Init zeroes slot+0xC8 / +0xCC / +0xCD and the 0x18B buffer at *(slot+0x328).

while (driver(slot) != 1) {    // polcore+0x1D7D0, pump until status=1
    /* yield */
}
// Result globals are now updated.
```

## Wire format

```
C→S Init           (40B, std)
S→C ACK            (24B)
C→S Auth (4,6)     (40B header advertising body=0x18)
S→C AuthResponse   (40B; standard for this auth class)
C→S Data[0]        (24B query body)
S→C AuthConfirm    (24B)
S→C Status         (124B payload + 4B sum-of-dwords trailer; trailer
                    is validated by polcore_recv_body_sm with param_3=1)
```

The CRC accumulator at `desc+0x10` is zeroed by `polcore_connect_sm` case 0
and is not touched by `polcore_drain_sm`, so it is 0 when WhoIs case 5
calls `polcore_recv_body_sm`. The 4B trailer is therefore the sum of the
124B payload only.
