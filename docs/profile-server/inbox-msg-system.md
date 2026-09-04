# FFXi Inbox & Message-Type System

Reference for FFXi's PlayOnline Messages tab, the icon-type column, and the click-to-open menus. All addresses use FFXiMain runtime base `0x04610000`.

The icon type in the inbox row is not read from the on-disk filename byte `+0x30`. It comes from `param_2` of `inbox_row_callback (FFXi+0x200420)`, invoked by polcore's friend-server response handler. The type travels in the friend-server response packet bytes, not the file. The on-disk msg file is read only for the body when the user clicks a row. The icon-type -> label table is at `type_str_table (FFXi+0x384178)`, 8B stride. Mapping function is `type_to_idx (FFXi+0x2005D0)`. Clicking a row dispatches into `msg_process_handler (FFXi+0x200910)`, which selects between two display formats and two sub-menu objects based on the table_index returned by `type_to_idx`.

## Type -> label table

Table at `type_str_table (FFXi+0x384178)`, 8 bytes per entry, 13 entries:

| Idx | Offset | Label  | Meaning |
|----:|-------:|--------|---------|
| 0   | 0x384178 | `[NRM]` | regular message |
| 1   | 0x384180 | `[FWT]` | "Friend Waiting" -- incoming friend request |
| 2   | 0x384188 | `[FOK]` | "Friend OK" -- your request was accepted |
| 3   | 0x384190 | `[FNO]` | "Friend NO" -- your request was declined |
| 4-9 | 0x384198..0x3841C0 | `[GRP]` | group/linkshell-related |
| 10  | 0x3841C8 | `[KNK]` | unknown |
| 11  | 0x3841D0 | `[OTR]` | unknown |
| 12  | 0x3841D8 | `[OTR]` | unknown |

## Icon label table -- VERIFIED from the 2026-08-31 client

Read directly from a validated dump (FFXiMain base 0x04A50000). The label table
is at **RVA 0x385180**, 8-byte stride; `type_to_idx` is **RVA 0x200650** and the
accessor `label = table + idx * 8` is at RVA 0x200630.

NOTE: earlier revisions of this file cited the table at RVA 0x384178. That is
stale by 0x1008 and lands in unrelated binary data on the current client.

| idx | label   | | idx | label   |
|----:|---------|-|----:|---------|
| 0   | `[NRM]` | | 7   | `[GRP]` |
| 1   | `[FWT]` | | 8   | `[GRP]` |
| 2   | `[FOK]` | | 9   | `[GRP]` |
| 3   | `[FNO]` | | 10  | `[KNK]` |
| 4   | `[GRP]` | | 11  | `[OTR]` |
| 5   | `[GRP]` | | 12  | `[SYS]` |
| 6   | `[GRP]` | | 13  | `menu`  |

Full `type_to_idx` switch, verbatim:

| type | idx | label | type | idx | label |
|-----:|----:|-------|-----:|----:|-------|
| 0    | 0   | NRM   | 15   | 5   | GRP   |
| 1    | 1   | FWT   | 16   | 6   | GRP   |
| 3    | 10  | KNK   | 17   | 7   | GRP   |
| 9    | 2   | FOK   | 18   | 8   | GRP   |
| 10   | 3   | FNO   | 19   | 9   | GRP   |
| 14   | 4   | GRP   | 30   | 12  | SYS   |

Anything not listed falls through to idx 11 = `[OTR]`.

**type 1 = FWT = incoming friend request; type 9 = FOK = request accepted.**

## Type-int -> table index -- `type_to_idx (FFXi+0x2005D0)`

| Type-int | Table idx | Label |
|---------:|----------:|-------|
| 0  | 0  | `[NRM]` |
| 1  | 1  | `[FWT]` |
| 3  | 10 | `[KNK]` |
| 9  | 2  | `[FOK]` |
| 10 | 3  | `[FNO]` |
| 14 | 4  | `[GRP]` |
| 15 | 5  | `[GRP]` |
| 16 | 6  | `[GRP]` |
| 17 | 7  | `[GRP]` |
| 18 | 8  | `[GRP]` |
| 19 | 9  | `[GRP]` |
| 30 | 12 | `[OTR]` |
| else | 11 | `[OTR]` |

The icon-string lookup is `icon_string (FFXi+0x2005B0)` (2-line wrapper):
```c
char* icon_string(int type) {
    return type_table[type_to_idx(type)];   // table + idx*8
}
```

## Inbox plumbing

### Bootstrap -- `inbox_register (FFXi+0x2002F0)`

Allocates the render array (stride 0x54) at `msg_obj+0x68` and the data array (stride 0x50) at `msg_obj+0x6C`. Capacity is determined by `inbox_capacity (FFXi+0x706DD0)` (a friend-system query) plus a 7-row safety pad.

If called with `(param_2=0, param_3=0)` -> registers `inbox_row_callback` via `inbox_register_callback (FFXi+0x707310)` for network-driven population.

If called with non-zero `param_2/param_3` -> calls `inbox_register_alt (FFXi+0x707350)` directly (alternate path, not used in normal inbox open).

### Open -- `full_init (FFXi+0x200710)`

Inbox-open user-action handler. Calls `inbox_register(msg_obj, 0, 0)`, then opens the visible menu via:
- `show_menu("menu    msglist", 1, 0)` -- the inbox list
- `show_menu("menu    titlehan", 1, 0)` -- the title bar (conditional)

`show_menu` is `FFXi+0x76E1E0`.

### Per-row callback -- `inbox_row_callback (FFXi+0x200420)`

Signature: `(msg_obj, icon_type, NULL_or_sentinel, ?, source_struct)`.

When called with `param_3 == NULL` (build mode):
1. Allocate fresh render+data slot via `alloc_slot (FFXi+0x200180)`.
2. Copy header from `source_struct[0..1]` to render slot.
3. Copy timestamp from `source_struct[6]+0x34` to render slot `+0x4C`.
4. Copy sender from `source_struct[2]` to render slot `+0x10`.
5. Copy subject from `source_struct[3]` to render slot `+0x20`.
6. Look up icon string: `data_slot[+0x48] = icon_string(icon_type)`.
7. Format date: `format_date (FFXi+0x7D8B00)` -> string -> render slot `+0x30`.
8. Wire display columns 1-4 (sender, recipient, icon, date) via `wire_columns (FFXi+0x804650)`. The "subject" field in the file is not shown in the inbox listing -- it appears only in the body view when a row is clicked.
9. Append + sort row into render array via `append_sorted (FFXi+0x2001E0)`.

The `icon_type` (param_2) is the only place icon information enters the row. It comes from polcore's deserialization of the friend-server response.

### Sort key

Rows in the render array are sorted by `*(int*)(dentry + 0x4C)` ascending -- the timestamp written at step 3.

### Teardown -- `inbox_teardown (FFXi+0x2007C0)`

Hides 3 (or 4 with titlehan) menus on inbox close:
- `menu msglist` -- main inbox
- `menu mes1rcv` -- regular body display
- `menu mes2frnd` -- friend-request dialog

The two sub-menu names map to two distinct sub-menu objects allocated by `event_handler_init`.

### Inbox constructor -- `event_handler_init (FFXi+0x1FEB30)`

Allocates three globals the click-handler later dispatches between:

| Global | Size | Vtable | Role |
|--------|-----:|--------|-------------|
| `DAT_04C3FF94` | 0x78 | `&PTR_FUN_04949BE0` | main `msg_obj` (the manager) |
| `DAT_04C3FF98` | 0x68 | `&PTR_FUN_04949B90` | sub-menu A (`mes1rcv`) |
| `DAT_04C3FF9C` | 0x68 | `&PTR_FUN_04949B40` | sub-menu B (`mes2frnd`) |

## Click handler -- `msg_process_handler (FFXi+0x200910)`

Invoked when the user presses Enter on an inbox row.

Args: `(msg_obj, icon_type_packed_low16, mode, ?, source_struct)`.

Behavior:
1. If `mode != 0`: special path (close menu / cancel). No row display.
2. Compute `table_idx = type_to_idx(icon_type)`.
3. If `table_idx == 11` (`[OTR]`): call `otr_handler (FFXi+0x739CD0)` and return -- OTR messages have a fully separate handler.
4. Format `"From: <sender>"` line into a buffer (`s_From___s_04994258` template).
5. Switch by `table_idx`:
   - **Cases 0, 7, 10, 12** (NRM, type=17 GRP, KNK, OTR-12): build `"Title: <subject>"` + `"Message: <body>"` from `source_struct[4]` and `source_struct[5]`. Standard regular-message display.
   - **Default** (FWT=1, FOK=2, FNO=3, GRP idx 4-9): build a different format using a `s_Title__04994238` template. Friend-event display.
6. Both branches converge on opening a sub-menu via:
   ```c
   open_submenu(*source_struct, source_struct[1], source_struct[6], table_idx);
   ```
   The `*source_struct` deref is the vtable pointer of the target sub-menu object (`DAT_04C3FF98` or `DAT_04C3FF9C`). Choice is determined by `source_struct[0]` -- the friend-server response specifies which sub-menu opens for each row, by writing one of the two sub-menu objects' addresses into the source struct's first field.

## Sub-menu open -- `open_submenu (FFXi+0x1FFC90)`

`__thiscall` on a sub-menu object. Stuffs args into the obj at `+0x14..+0x1C`, copies 0x12 dwords of the source struct into `obj+0x20..+0x67`, then calls `(**(code**)(obj_vtable + 0x44))()` -- vtable[0x11].

That vtable method shows the appropriate menu (`mes1rcv` or `mes2frnd`) and binds the row data into its widgets. The two sub-menu objects have different vtables (`PTR_FUN_04949B90` vs `PTR_FUN_04949B40`), so the same `open_submenu` opens whichever menu the friend-server picked.

## source_struct shape

```
[0]  uint32  sub-menu picker (0=mes1rcv regular, 1=mes2frnd friend)
[1]  uint32  unix timestamp
[2]  char*   sender charname (15 chars + null)
[3]  char*   recipient charname (15 chars + null)
[4]  uint32  unknown (NULL in observed rows)
[5]  uint32  body text ptr (NULL in observed rows; the body is delivered with the msgrec record and written to the msg file, never fetched on click)
[6]  void*   ptr to struct with `+0x34` timestamp (redundant with [1])
[7]  void*   heap ptr (purpose unknown)
[8..0x1F] (eight dwords) inline copy of decoded filename bytes [0x00..0x1F]:
         [0x20] = sender_accid (post-decrypt)
         [0x24] = msg_id (post-decrypt -- was at filename +0x04)
         [0x28] = recipient_accid (post-decrypt)
         [0x2C] = unused
         [0x30..0x3F] = sender charname inline (16B)
[0x40..0x47] more filename bytes (subject region from filename +0x20)
```

`source_struct` is a static global at one fixed address (e.g. `0x004FE9E4` in our session). It is reused for every row -- populated, callback fires, populated again for next row. Don't cache the pointer; copy out the data.

### Field sources

- `[0]` (sub-menu picker): from filename byte `+0x30` (msg_type). Rows where the written filename had `msg_type=0` get `source_struct[0]=0`, rows with `msg_type=1` get `source_struct[0]=1`. Polcore reads our msg_type byte for sub-menu selection, not for the inbox icon column.
- `[1]` (timestamp): from filename byte `+0x34` (the unix epoch we write).
- `[2]` (sender): from filename `+0x10` (16-char sender nickname).
- `[3]` (recipient): from filename `+0x08` (decrypted recipient accid -> looked up to charname). Polcore performs the lookup. This is column 2 of the inbox listing -- not the message subject.
- `[5]` (body): NULL during inbox listing. Polcore fetches the body from disk when the user clicks (the read-message phase, "Downloading data" UI text).
- `param_2` (icon type): extracted from the filename. The friend-system per-frame tick `friend_per_frame (FFXi+0x102B20)` reads it as `(*(ushort*)(filename + 0x3E) & 0xF80) >> 7` -- a 5-bit field at bits 7-11 of the ushort at filename `+0x3E`.

### Filename `+0x3E/+0x3F` flags ushort

Layout (bits, ushort little-endian):
```
bit 15 (=0x8000)  "valid" flag -- always set in retail
bits 11..7        icon-type index (input to type_to_idx)
bits 6..0         unknown (likely other flags)
```

Decoded retail files:

| File | bytes (3E,3F) | ushort | type | label |
|------|---------------|-------:|----:|-------|
| Syra friend req | `80 80` | `0x8080` | 1 | `[FWT]` |
| "Friend declined" | `00 85` | `0x8500` | 10 | `[FNO]` |
| FFXI sysmsg | `00 80` | `0x8000` | 0 | `[NRM]` |
| Atoyaka req 2 | `00 84` | `0x8400` | 8 | `[OTR]` (default in switch) |

The conditional in the filename decoder `filename_decoder (polcore+0x1B640)`: `if ((decoded[0x3E word] & 0xF80) != 0x880) decrypt block 1`. Setting type=17 (the only value where `(N<<7) == 0x880`) makes polcore skip decrypting the recipient accid field -- used for system messages with no encrypted recipient. Don't use 17 for normal types.

`build_msg_filename_data` writes `+0x3E/+0x3F = ((msg_type & 0x1F) << 7) | 0x8000`, which makes `[FWT]`/`[FOK]`/etc. icons render correctly without needing the friend-server response path.

## Friend-system submit / state-machine plumbing

Multiple submit paths land in different state machines, each with its own op-code and callback layout. All ultimately go through `friend_inner_send (FFXi+0x103150)` which stores the SM ptr at `+0x105C` of a friend-state struct and runs phases on subsequent ticks via the per-frame friend driver.

| Submit fn | Inner | SM ptr | Callback offset | Op |
|-----------|-------|--------|----------------:|---:|
| `inbox_register_callback (FFXi+0x707310)` | `FFXi+0x702490 -> FFXi+0x703A50` | `&PTR_LAB_0497129C` | `state[+0x415]` | (no op-code arg) |
| `decline_submit (FFXi+0x707430)` | `FFXi+0x702440 -> FFXi+0x703350` | `&PTR_LAB_04971278` | `state[+0x414]` | `0x19` |
| `dismiss_submit (FFXi+0x707150)` | `unified_submit (FFXi+0x702210)` | (different) | (different) | `10` |
| `befriend_submit (FFXi+0x707520)` | `unified_submit (FFXi+0x702210)` | (different) | (different) | befriend |

Both SM pointers `0x0497129C` and `0x04971278` resolve to the same function `friend_op_state_dispatcher (FFXi+0x704400)` -- a tiny switch returning phase codes (0x16=init-done, 0x17=increment-counter, 0x15/6/0=other). The actual network send happens in the per-frame driver which reads `state[+0x105C]` (SM ptr), invokes the SM fn for the next phase, and dispatches the registered callback when the response arrives.

`DAT_04AEE900` is the friend-system manager struct pointer. `+0x0A` = current inbox row count (clamped to 200). Populated by the network response deserializer (writers at `friend_resp_write_a (FFXi+0x707570)` and `friend_resp_write_b (FFXi+0x701AE0)`).

### Per-frame friend driver -- `friend_per_frame (FFXi+0x102B20)`

Reads SM ptr at `state[+0x105C]`, runs SM[counter] until phase returns 0x16 (init done) or non-0x17. On completion (SM returns NULL/0):

- If `state[+0x104C]` (callback A) is set, calls it: `(*cb)(ctx, 0, 0, optional_arg)`.
- Else if `state[+0x1050]` (callback B) is set, calls it with the icon type extracted as `(*(ushort*)(state[+0xA0]+0x3E) & 0xF80) >> 7`.

This feeds `inbox_row_callback` for inbox population, and similar callbacks for body delivery.

## Polcore notification queue (+0xAA980)

Polcore has its own internal notification queue distinct from FFXiMain's notification overlay. FFXi's friend-system reads from this queue when:

- The user clicks an inbox row to open the body (`mes2frnd` / `mes1rcv`).
- A friend-server response completes for any submitted friend-system op.
- A friend status change arrives.

If the queue is empty (or not populated for a given click), FFXi displays the "Downloading data" placeholder.

### Queue layout

| Symbol | Address | Purpose |
|--------|---------|---------|
| `DAT_0462A968` | global | dispatch lock |
| `DAT_0462A974` | global | registered callback fn ptr (set via `notif_register (polcore+0x1B500)`) |
| `DAT_0462A980` | global | queue base (4 entries x 0x40 bytes) |
| `DAT_0462AA94` | global | pending entry count (max 4) |

Each entry (0x40 bytes):
```
+0x00 (4B)  type code (1, 3, 6, ...)
+0x04 (4B)  data ptr (either inline at +0x08 or external buffer)
+0x08..0x3F inline data buffer (up to 0x38 bytes copied here when external
            param_3 > 0 in the enqueuer)
```

### Enqueue / dispatch

- **Enqueue**: `notif_enqueue (polcore+0x1C570)` `(uint32_t type, void* data, int len)`
  - If `len > 0`: copies up to `min(len, 0x38)` bytes from `data` into the inline buffer and stores the inline addr in slot+0x04.
  - If `len < 0`: stores `data` directly in slot+0x04 (external pointer).
  - If `data == NULL`: slot+0x04 = 0.
  - Returns 0 if queue full, 1 otherwise.
- **Dispatch**: `notif_dispatch (polcore+0x1C600)` -- drains the queue, calling the registered callback `(*callback)(slot[0], slot[4])` for each entry, then resets count to 0.

### Producers

| Function | Type queued | Op |
|----------|------------|-----|
| `friend_status_enq (polcore+0x26150)` | type=6 | "friend status change" -- 8 bytes from slot+0xD30 |
| `body_upload_sm (polcore+0x1A6870)` | type=3 | body download -- variable-size body buffer |

### Body-download flow -- `body_upload_sm (polcore+0x1A6870)`

State machine triggered by FFXi -> polcore vtable -> `polcore+0x1BF00` -> `polcore+0x1A7550` -> `body_upload_sm`:

| Phase | Action |
|------:|--------|
| 0-2   | clear counters, TCP setup (`polcore+0x1F0F0`) |
| 3     | `Auth_SM(slot, 3, 1, slot[+0x9C]+0x19C)` -- auth type **(3,1)**, size from filename data |
| 4     | Build 0x198-byte request packet in slot's output buffer: |
|       |   `+0x00..+0x01` 2 bytes from slot+0xD28/+0xD29 (msg_type bytes from filename) |
|       |   `+0x08..+0x0F` 64-bit hash from `polcore+0x19D40(slot+0xC0, slot+0xC4)` |
|       |   `+0x10..+0x18F` 0x17F bytes copied from slot+0xD8 (filename data) |
|       |   `+0x190..+0x193` 4-byte field from slot+0xD20 |
|       |   `+0x194..+0x197` 4-byte field from slot+0xD1C |
| 5     | Send 0x198 bytes via `polcore+0x1FA90(slot, 0x198, 0)` |
| 6-7   | Setup BF crypto context for response decryption |
| 8-9   | Receive size info (4 bytes via `polcore+0x11100`/`polcore+0x11170`) |
| 10-11 | Receive 4-byte chunks (per-chunk decrypt via `polcore+0x63EF0`) |
| 12    | `polcore+0x1F690` -- recv response final |
| 13    | Enqueue type-3 notification: `notif_enqueue(3, body_ptr, 0xFFFFFFFF)` |

### Click flow in this build

In our build the click does not run through `body_upload_sm`. The path:

1. User Enter on inbox row -> menu framework dispatches event.
2. `msg_click_submit_v3 (FFXi+0x2008D4)` fires:
   ```c
   framework_callback_register(in_EAX[0], in_EAX[1], in_EAX[2], param_1, msg_process_handler);
   ```
   This registers `msg_process_handler` as the click-completion callback.
3. Submit chain: `framework_callback_register (FFXi+0xF7490)` -> `framework_callback_register_inner (FFXi+0xF23F0)` -> `friend_submit_inner (FFXi+0xF32D0)` -> `friend_inner_send(FFXi+0xF3150, &PTR_LAB_04971268)` -- same generic SM as everything else.
4. The per-frame friend driver `friend_per_frame (FFXi+0x102B20)` eventually fires the registered callback. Its inner block:
   ```c
   if (state[+0x1050] != 0) {
       ...prepare local_184/local_180/local_17c from slot+0xA0+0x30/0x34/0x10...
       ...iterate friend lists (FFXi+0x91F949 x100, FFXi+0x91F933 x200)
          to find sender match in caches, populating param_1+0x78 if found...
       iVar4 = polcore_body_lookup_thunk(slot[+0xA0], slot[+0xA4], local_buf_0x80);
       if (iVar4 == 0) { puVar7 = NULL; uVar6 = 0x10; }     // mode=16
       else            { puVar7 = &local_184; uVar6 = 0; }   // mode=0
       (**(code**)(state[+0x1050]))(state[+0x1048], type, uVar6, 0, puVar7);
   }
   ```
5. Callback (`msg_process_handler`) is called with:
   - `mode = uVar6` -- 0 if `polcore_body_lookup_thunk` succeeded, 0x10 if it failed.
   - `src = puVar7` -- non-NULL only if `polcore_body_lookup_thunk` succeeded.
6. `msg_process_handler(mode=0)` builds chat lines + opens mes2frnd via `open_submenu`. `mode=0x10` exits silently.

### `polcore_body_lookup_thunk (FFXi+0x91FD53)`

```c
void polcore_body_lookup_thunk(void) {
    (**(code **)(DAT_04A65A24 + 0x43C))();  // thunk through polcore obj field
}
```

Thin thunk through `DAT_04A65A24 + 0x43C` -- a function pointer stored as a member of the polcore COM object (`DAT_04A65A24` is FFXi's cached polcore object pointer, set by `polcore_obj_init (FFXi+0x625700)`).

Looks up the message body (by filename) in polcore's local cache. Returns 0 if not found, non-zero (with body data written to the output buffer) if found. The cache is populated by polcore's file-load + decryption pipeline.


