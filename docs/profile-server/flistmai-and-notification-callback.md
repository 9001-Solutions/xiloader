# flistmai and Polcore Notification Callback

This documents the FFXi-side friend system state and the polcore<->FFXi notification callback chain. RE'd via static Ghidra analysis of FFXiMain.dll and polcore.dll, cross-verified against live in-game memory via fdiag.

## Build skew correction (critical)

Two FFXi offsets in `src/friend.cpp` were stale and need updating:

| Constant | Stale | Correct |
|---|---|---|
| `OFF_FLISTMAI_PTR` | `0x62E9E4` | `0x62FB5C` |
| `OFF_POPULATE_FN`  | `0x1E9830` | `0x1EAC00` |

The stale `0x62E9E4` reads zeros (uninitialized .data), which produced the misleading log line `flistmai = NULL -- feature using this will be silent no-op` for months.

## flistmai object

| Field | Address | Description |
|---|---|---|
| Pointer slot | `FFXi+0x62FB5C` (`DAT_04C3FB5C`) | 32-bit pointer to the flistmai instance |
| Object size | 0xAC bytes | Allocated by `flistmai_ctor (FFXi+0x1EAEC0)` via `operator_new` |
| `+0x00` | vtable | `PTR_FUN_04948D78` (= `FFXi+0x338D78`) |
| `+0x08` | gate field | Read by `FUN_048107C0` to decide whether to close `menu_titlehan` |
| `+0x50` | slot count | `-1` after ctor; populated to `slots+6` by `populate_friend_data` |
| `+0x5C` | render array ptr | NULL after ctor; allocated by populate as `(slots+6) x 0x54` bytes |
| `+0x60` | display array ptr | NULL after ctor; allocated by populate as `(slots+6) x 0x88` bytes |
| `+0x84` | color/font handle | Set by `flistmai_menu_open` |
| `+0x8C` | icon array indirect | Used by `populate_friend_data` |
| `+0xA4..0xA8` | bucket-hide flags | One byte per category (0..4); 0 = visible |

Live state in our build (read from the live process):

| Field | Value | Meaning |
|---|---|---|
| flistmai pointer | `0x15BC8AE0` | Allocated |
| `+0x00` (vtable) | `0x047A8D78` | Matches expected `FFXi_base + 0x338D78` |
| `+0x08` | `0x00000000` | Gate field unset |
| `+0x50` | `0xFFFFFFFF` (-1) | Slot count uninitialized -- populate_friend_data has NOT run |
| `+0x5C` | `0x00000000` | Render array not allocated |
| `+0x60` | `0x00000000` | Display array not allocated |

## Allocation chain

```
WinMain (FFXi+0x15700)
 +- FUN_046259D0 (CoInitialize)
     +- FUN_04626230
         +- FUN_04611520 (window setup, then game-init loop)
             +- FUN_04620D20 (state machine)
                 +- FUN_047E0CF0 (widget bootstrap, runs once)
                     +- flistmai_ctor (FFXi+0x1EAEC0)
                         +- this+0x00 = PTR_FUN_04948D78 (vtable)
                         +- this+0x50 = -1
                         +- allocates 4 sub-objects:
                         |  +- DAT_04C3FB60 (size 0x60, vtable PTR_FUN_04948DE8)
                         |  +- DAT_04C3FB64 (size 0x14, vtable PTR_FUN_04948D30)
                         |  +- DAT_04C3FB68 (size 0x1C, vtable PTR_FUN_04948CE8)
                         |  +- DAT_04C3FB6C (size 0x1C, vtable PTR_FUN_04948CA0)
                         +- stores result at DAT_04C3FB5C
```

The widget bootstrap `FUN_047E0CF0` runs unconditionally as part of the FFXi UI init, alongside `chat_obj`, `msg_obj`, all menus, font tables, etc. flistmai is therefore guaranteed allocated by the time the user can input commands.

## populate_friend_data

`FUN_047FAC00` at FFXi+0x1EAC00. `__thiscall(this=flistmai, openByte)`. Behavior:

1. Resets menu fields at `this+0x3C/0x44/0x45`.
2. Calls `FUN_046F7120` to clear flag fields on the friend system table (`DAT_04AEE768+0x1C4`, `+0x3C8`).
3. Calls `FUN_046F6AC0` to re-sort the friend index (scans 300 slots, rebuilds index at `DAT_04AEE768+0x832`, quicksorts).
4. Reads `*(short*)(DAT_04AEE768+0x132)` = count of occupied slots.
5. **Sets `this+0x50 = slots + 6`** (this is the value flip from -1 to a real count; +6 for header/footer rows).
6. If `this+0x5C == NULL`: allocates render array `operator_new((slots+6) x 0x54)`.
7. If `this+0x60 == NULL`: allocates display array `operator_new((slots+6) x 0x88)`.
8. Sets `this+0x54 = 0` (active row counter).
9. Iterates `slots-1` times, reading entries from `DAT_04AEE768 + 0xA90 + index[i] x 0x100`:
   - Skips if `entry[0x98] & 1 == 0` (occupied bit unset).
   - Categorizes into 5 buckets (0=online, 1=offline, 2=LS members, 3=incoming request, 4=other pending).
   - Inserts category divider rows on first-of-bucket.
   - Populates display row at `this+0x60 + active_count*0x88` with charname, job, level, online status badge.
   - Increments `this+0x54`.
10. Calls `FUN_04806B50(this+0x5C, this+0x54, 1)` (UI commit).
11. If zero iterations: writes "No friends" placeholder string.

**Idempotent** -- never deallocates buffers; only allocates if NULL. Re-running just refills.

**Bails-on-empty behavior:** even with zero friends in `DAT_04AEE768`, populate sets `this+0x50 = 6` and allocates buffers. So calling populate with empty Array1 IS safe and DOES initialize flistmai.

## populate_friend_data callers

| Address | Function | Trigger |
|---|---|---|
| `FFXi+0x1EB190` | `flistmai_menu_open` | UI event: user opens "menu friend" via hotkey or `/friendlist`. Calls populate, then sets up resource fields, then opens the actual UI window via `FUN_0476E1E0("menu friend", 1, 0)`. |
| `FFXi+0x1EB2B0` | `flistmai_toggle_hidden_repopulate` | UI event: user toggles a hide-bucket checkbox on a category divider row. Toggles `this+0xA4+bucket_idx`, then re-runs populate. |

There is **no** "auto-call on startup" trigger and **no** call from a CallerB completion handler. Populate is purely lazy/UI-driven. Until the user opens the friend list menu, flistmai stays uninitialized.

## DAT_04AEE768 (FFXi-side friend table)

Populated by the FFXi friend system state machine (`FUN_04700150`, driven by per-frame pump `FUN_046E9870`). State progression:
- State 7: connect to friend server
- State 8: download friend list
- State 9: write entries to `DAT_04AEE768[0xA90 + i*0x100]` with `entry[0x98] |= 1`

Polcore CallerB pumper (running from xiloader's worker thread in `friend.cpp`) writes to **polcore Array1** (polcore+0x403080), which is a **separate** table. There is no native bridge in FFXi from polcore Array1 to `DAT_04AEE768[]` -- the FFXi state machine populates `DAT_04AEE768` independently by speaking to the friend server through its own connection.

In our build, the FFXi state machine's connect/download likely fails (the profile server doesn't speak the exact protocol the state machine expects, or the connection is misrouted). `DAT_04AEE768` stays empty, and populate produces an empty list.

## Polcore notification callback chain

| Symbol | Address | Role |
|---|---|---|
| `notif_register_cb` | `pol+0x1B500` (FUN_0459B500) | Sets `DAT_0462A974 = arg`; vtable+0x480 |
| `notif_register_cb2` | `pol+0x1B610` (FUN_0459B610) | Sets `DAT_0462A970 = arg` (secondary) |
| `notif_enqueue` | `pol+0x1C570` (FUN_0459C570) | Append to queue (returns 1 silently if cb is NULL); max 4 entries |
| `notif_drain` | `pol+0x1C600` (FUN_0459C600) | Iterates queue, invokes `(*cb)(arg1, arg2)` per entry; called per polcore Tick |
| `notif_dispatcher` | `pol+0x1B6F0` (FUN_0459B6F0) | Master inbound packet handler; can directly invoke cb (bypassing queue) when `DAT_0462AA90 != 0` |
| `notif_force_drain` | `pol+0x1C530` (FUN_0459C530) | Sets `DAT_0462AA84 = 1` to wake drain on next Tick |
| `is_cb_null` | `pol+0x1B520` (FUN_0459B520) | Predicate |

| Global | Address | Description |
|---|---|---|
| Primary callback ptr | `pol+0xAA974` (`DAT_0462A974`) | Function pointer |
| Secondary callback ptr | `pol+0xAA970` (`DAT_0462A970`) | Function pointer |
| Queue base | `pol+0xAA980` (`DAT_0462A980`) | 4 entries x 0x40 bytes |
| Queue depth | `pol+0xAAA94` (`DAT_0462AA94`) | 0..4 |
| Dispatch mode | `pol+0xAAA90` (`DAT_0462AA90`) | 0 = enqueue, 1 = direct call |
| Force-drain flag | `pol+0xAAA84` (`DAT_0462AA84`) | 1 = drain on next Tick |
| Crypto enable | `pol+0xBCA80` (`DAT_0463CA80`) | 0 = plaintext (our case) |

**Live state confirmation (read from the live process):**

| Address | Value | Meaning |
|---|---|---|
| `pol+0xAA974` | `0x04562750` | = FFXi+0xF2750 = `display_cb`. **Real callback IS registered.** |
| `pol+0xAA970` | `0x00000000` | Secondary callback NULL |

The "FFXi only registers NULL" hypothesis from earlier diagnostic was wrong. FFXi DOES register `display_cb` at startup. Our hook only saw NULL writes because it attached AFTER the initial registration.

`display_cb` (FFXi+0xF2750) is the notification overlay's `add_notif` function -- it produces the floating S:/R: pulse on screen.

## Callback invocation signature

`void __cdecl cb(uint32_t type, void* data)`

Drain pseudocode (`FUN_0459C600`):
```c
mutex_acquire(&DAT_0462A968);
cb = DAT_0462A974;
mutex_release(&DAT_0462A968);
if (DAT_0462AA94 != 0) {
    if (cb != NULL) {
        for (i = 0; i < DAT_0462AA94; i++) {
            (*cb)(queue[i].arg1, queue[i].arg2);
        }
    }
    DAT_0462AA94 = 0;
}
FUN_045AB900(cb);  // friend-record event sweeper
```

## Notification types

| Type | Source | data layout | Meaning |
|---|---|---|---|
| 0 | `notif_dispatcher` direct | ptr to 0x60-byte parsed packet header | Generic friend-server packet processed |
| 1 | `notif_dispatcher` direct | ptr to `{char primary[0x80], char secondary[0x80]}` | Friend-server text/system message |
| 2 | `notif_dispatcher` (encrypted + clear paths) | `(void*)friend_index` cast (0..199) | Friend status changed (presence/zone) |
| 3 | `FUN_045A6870 case 0xD` + `notif_dispatcher` (cat 0x480) | ptr into `DAT_049706C0` records array | Friend record fully resolved/updated |
| 4 | `FUN_045A8FB0`/`FUN_045A9340` case 5 + `notif_dispatcher` (cat 0xF80/0xC0) | ptr to 8B `{u32 charname_lo, u32 charname_hi}` | Befriend request delivered (recipient side) |
| 5 | `notif_dispatcher` + `FUN_045AB900` synthetic | ptr to `{u32 charname_lo, u32 charname_hi, int extra}` | Friend table entry added/promoted |
| 6 | `FUN_045A6150 case 0xD` + `notif_dispatcher` | ptr to 8B charname key | Befriend request rejected/declined |

## Polcore tables that types 0/2/3 reference

These are populated by polcore BEFORE the callback fires:
- `DAT_046340D8` (pol+0xB40D8) -- 200 x 0xB0 friend status table
- `DAT_0497C920` (pol+0x3FC920) -- 200 x 0x84 nickname/zone secondary table
- `DAT_049706C0` (pol+0x3F06C0) -- 4 x friend records (0xC26 dwords each)

## What display_cb (FFXi+0xF2750) actually does

It dispatches notifications to the on-screen S:/R: overlay (the floating pulse for sent/received messages). It does NOT populate `DAT_04AEE768` or trigger `populate_friend_data`. So even with the callback registered, the friend list state stays as it is -- the callback is for visual notification only.

## Vtable thunk map (FFXi -> polcore COM vtable)

Discovered during this investigation. FFXi `0x0491F8XX..0x0491FFXX` range contains thunks of the form `(**(code**)(DAT_04A65A24 + 0xN))()`. Sample of confirmed slots:

| FFXi thunk | vtable offset | Used for |
|---|---|---|
| `FUN_0491F8D0` | +0x1F8 | (called by `dismiss_op1_send`) |
| `FUN_0491FDE2` | +0x470 | msg-queue formatter (vtable+0x470) |
| `FUN_0491FDED` | +0x474 | msg-queue formatter |
| `FUN_0491FE0E` | **+0x480** | **notif callback registrar** |
| `FUN_0491FE2F` | +0x48C | filename decoder |
| `FUN_049208E2` | +0xE88 | `polcore_thunk_msgq_poll` |
| `FUN_049208ED` | +0xE8C | `polcore_thunk_msgq_rescan` |

Full table (~100 thunks) in agent investigation notes.
