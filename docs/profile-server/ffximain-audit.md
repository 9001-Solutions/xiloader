# FFXiMain Audit — Click-to-Read, Friends, Messaging, Notifications

Reference for FFXiMain.dll's friend/message/notification subsystems. FFXiMain base `0x04610000`; conversion `addr_in_ghidra = 0x04610000 + RVA`.

Function code addresses are stable across LSB builds. String, global, and per-frame/SM RVAs may shift between builds — stale RVAs are tracked in the local build-skew notes.

## Click-to-Read Core

### `event_dispatcher (FFXiMain+0x2000B0)` — `0x048100B0`

```
CMP WORD [ESP+4], 5         ; if event_type != 5, early-out
JNE +0x7B
MOVSX ECX, WORD [ESP+8]     ; ECX = sub_type
DEC ECX → JZ body_display   ; sub_type 1
DEC ECX → JZ detail_view    ; sub_type 2
DEC ECX → JNZ skip          ; sub_type != 3 → skip; else: refresh

sub_type 1 path:
  ECX = [+0x62FF90] chat_obj (verify != 0)
  PUSH msg_obj+0x30, +0x24, +0x20, +0x1C, +0x18  ; type_str_table, sel, vis, rendered, max
  CALL +0x1FFB20 (body_display)
  PUSH "mes2frnd" string @ +0x3841F4
  ECX = window_manager @ +0x5EDD10
  CALL +0x15E7A0 (show_element)
  RET 8
```

- chat_obj at `[+0x62FF90]`
- msg_obj fields +0x18 (max_items), +0x1C (rendered), +0x20 (visible), +0x24 (selected), +0x30 (type_str_table)
- `body_display +0x1FFB20`, `detail_view +0x1FFBB0`, `refresh +0x1FFE10`
- `show_element +0x15E7A0`
- `mes2frnd` string at `+0x3841F4`
- `window_manager` at `+0x5EDD10`
- `RET 8` (cleanup 2 WORD args)

### `body_display (FFXiMain+0x1FFB20)` — `0x0480FB20`

`__thiscall body_display(chat_obj, max, rendered, vis, sel, type_str_table_ptr)`

- Checks rebuild_flag at `+0x62FFA0`; non-zero → `error_report(0x7A)` and bail
- Writes chat_obj fields:
  - +0x1E0 = max_items
  - +0x14 = 7 (mode)
  - +0x1D4 = sel
  - +0x1E4 = rendered
  - +0x1D0 = visible
  - +0x188 = strncpy(type_str_table, 0x10) (16-byte copy)
- Calls `show_menu("menu msgline ", 1, 0)` via `+0x176E1E0`

### `event_handler_init (FFXiMain+0x1EB30)` — `0x0480EB30`

Lazy-init for three objects:
- `+0x62FF94` (msg_obj): allocates 0x78 bytes, calls `msg_obj_init (FFXiMain+0x200690)`, vtable `+0x339C28`
- `+0x62FF98` (undocumented): 0x68 bytes, vtable `+0x339B90`
- `+0x62FF9C` (event_handler): 0x68 bytes, vtable `+0x339B40`

### Event handler vtable — `+0x339B40` → `0x04949B40`

Entry 6 (offset +0x18) at `0x04949B58` → reads `event_dispatcher (+0x2000B0)`

### `MsgProcess (FFXiMain+0x200910)` — `0x04810910`

Enter callback. Zero direct CALL xrefs; single DATA xref at `+0x2008D9` (PUSH of its address inside `msg_register_callback`). Invoked indirectly via the framework callback dispatch when Enter fires on the scroll list. The `Mine_MsgProcess` bypass in `friend.cpp` is the correct architecture because xiloader skips the PlayOnline bootstrap that initializes the framework dispatch state.

### `msg_register_callback (FFXiMain+0x2008A0)` — `0x048108A0`

```
__thiscall register(msg_obj):
  if (rebuild_flag at +0x62FFA0) {
    error_report(+0x577150, 0x7A);
    return AL=0;
  }
  scroll_entry = scroll_list_lookup(msg_obj);  ; FFXiMain+0x200140
  if (!scroll_entry || !scroll_entry[+0x48]) return;

  PUSH msg_obj                            ; arg6 (callback context)
  PUSH MsgProcess @ +0x200910             ; arg5 (callback fn)
  PUSH scroll_entry+0x0C                  ; arg4
  PUSH scroll_entry+0x08                  ; arg3
  PUSH scroll_entry+0x04                  ; arg2
  PUSH scroll_entry[0]                    ; arg1
  CALL framework_callback_register        ; FFXiMain+0xF7490
  ADD ESP, 0x18
```

DATA xref at `0x04949C84` shows `msg_register_callback` is itself in msg_obj's vtable at offset `0x5C` from the vtable base. Calling `msg_obj->vt[N]()` triggers re-registration.

### `scroll_list_lookup (FFXiMain+0x200140)` — `0x04810140`

`__thiscall lookup(msg_obj)`. Validates `msg_obj+0x50 >= 0` AND `msg_obj+0x68 != 0` (sub-object pointer). Calls `idx_compute (FFXiMain+0x6C30)` twice. Returns `*(msg_obj+0x68 + idx*0x54 + 0x48)`. Scroll list entries are 0x54 bytes wide; field +0x48 is the registered callback slot.

### `idx_compute (FFXiMain+0x6C30)` — `0x04806C30`

`__fastcall idx_compute(msg_obj)`. Reads `msg_obj+0x08` (scroll mgr sub-object); if NULL, returns -1. Returns `*(short)(sub_obj+0x4C) - 1 + *(short)(msg_obj+0x1E)`. `msg_obj+0x1E` and `sub_obj+0x4C` are cursor/scroll position fields.

### `framework_callback_register (FFXiMain+0xF7490)` — `0x04707490`

Gates on `[+0x4DE900]` (notification manager pointer) being non-zero. If gate passes, calls `framework_callback_register_inner (FFXiMain+0xF23F0)` with the same 5+ args. If gate fails, returns 2.

`OFF_NOTIF_MGR_PTR = +0x4DE900`. If the notification manager isn't initialized, callback registration silently fails and Enter on the Messages tab doesn't dispatch.

### Globals

| RVA | Ghidra | Purpose |
|-----|--------|---------|
| `+0x62FF90` | 0x04C3FF90 | chat_obj ptr |
| `+0x62FF94` | 0x04C3FF94 | msg_obj ptr |
| `+0x62FF98` | 0x04C3FF98 | Unknown obj (vtable +0x339B90, 0x68 bytes) |
| `+0x62FF9C` | 0x04C3FF9C | event_handler ptr |
| `+0x62FFA0` | 0x04C3FFA0 | rebuild_flag |
| `+0x4DE900` | 0x04AEE900 | notification mgr ptr |
| `+0x577150` | 0x04B87150 | error/log object |
| `+0x5EDD10` | 0x04BFDD10 | window manager (inline obj) |

## UI Element Strings

Cluster around `+0x3730xx-+0x3731Cx`. Each string has 2 matches in the dump.

| String | RVA |
|--------|------|
| `flistmai` | `+0x373068` |
| `flmes` | `+0x373094` |
| `msgline` | `+0x373144` |
| `msglist` | `+0x373170` |
| `mes2frnd` | `+0x3731C8` (also `+0x3841F4`) |

## Message List Rendering

### `bind_render_array (FFXiMain+0x1F6B50)` — `0x04806B50`

`__thiscall(render_obj, count_ptr, count16, refresh_flag)`. Sets `render_obj+0x38 = count_ptr`, `+0x20 = count16`, `+0x22 = clamp(count16-max, 0)`. Adjusts `+0x1E` (cursor) if it exceeds new max. Calls `+0x1F61E0`, syncs `render+0x24` from sub-obj (msg_obj+0x08) field +0x4C.

### `full_init (FFXiMain+0x200710)` — `0x04810710`

`__thiscall(this, a, b, c)` `RET 0x0C` (3 stack args). Reads from `+0x47D8760(1)` result `+0x44C`, `+0x12C`. Sets msg_obj fields: `+0x70=val`, `+0x34=val`, `+0x74=val`, `+0x49=1` (active), `+0x16=5` (mode), `+0x26=0x10` (16). Sets `msg_obj+0x30 = +0x38416C` (type_str_table). Calls `register_menus (FFXiMain+0x2002F0)`; on success calls `show_menu("menu msglist ", 1, 0)` and conditionally `show_menu("menu titlehan ", 1, 0)`.

### `type_str_table (FFXiMain+0x38416C)` — `0x0499416C`

6-byte header `00 00 03 00 4E 00 9E 00 D7 00 2C 01`, then 8-byte entries: `[NRM]`, `[FWT]`, `[FOK]`, `[FNO]`, `[GRP]`, `[GRP]`, `[GRP]`, ...

## Notification Overlay

### `add_notif (FFXiMain+0xF2680)` — `0x04702680`

```
PUSH EBX; MOV EBX, ECX; PUSH EBP; PUSH ESI
MOV EDX, [EBX+0x1C]   ; mgr+0x1C = sub-object
PUSH EDI
MOV EDI, [ESP+0x14]   ; arg1 = notification buf
MOV EAX, EDX; TEST EAX, EAX; JZ +0x2A
```
`__thiscall(mgr, buf48)` with sub-object at `mgr+0x1C`.

### `display_cb (FFXiMain+0xF2750)` — `0x04702750`

```
MOV ECX, [+0x4DE900]    ; OFF_NOTIF_MGR_PTR
TEST ECX, ECX; JZ +0x12   ; bail if uninit
MOV EAX, [ESP+4]; TEST EAX, EAX; JNZ +0x0A
MOV EAX, [ESP+8]; PUSH EAX
CALL -0xEC                 ; tail-call display routine
RET
```
Same gate as `framework_callback_register`.

## Newly Discovered

### Functions

| RVA | Ghidra | Role |
|-----|--------|------|
| `event_handler_init (+0x1EB30)` | 0x0480EB30 | Lazy initializer for msg_obj, +0x62FF98 obj, event_handler |
| `msg_obj_init (+0x200690)` | 0x04810690 | msg_obj allocator/initializer (vtable +0x339C28) |
| `idx_compute (+0x6C30)` | 0x04806C30 | Cursor index computer |

### Globals

| RVA | Purpose |
|-----|---------|
| `+0x62FF98` | Undocumented 3rd object (vtable +0x339B90, 0x68 bytes) |
| `+0x577150` | Error/log singleton ptr |
| `+0x339B90` | Vtable for unknown +0x62FF98 object |
| `+0x339C28` | msg_obj vtable |
| `+0x384208` | "menu msgline " string |
| `+0x384224` | "menu msglist " string |
| `+0x380FE4` | "menu titlehan " string |
| `+0x4B87478` | Flag controlling whether titlehan menu opens with msglist |

## Call Graphs

### Click-to-Read flow (when working)
```
[user presses Enter on Messages tab entry in scroll list]
         ↓
[FFXiMain framework input loop]
         ↓
[lookup callback for current scroll list entry, slot at scroll_list[+0x48]]
         ↓
[invoke registered Enter callback]
         ↓
MsgProcess [+0x200910]   ← HOOKED by Mine_MsgProcess
         ↓
event_handler [+0x62FF9C]->vtable[6] (= dispatcher)
         ↓
event_dispatcher [+0x2000B0] (event_type=5, sub_type=1)
         ├── chat_obj [+0x62FF90] checked
         ├── body_display [+0x1FFB20] (chat, max, rendered, vis, sel, type_str_table)
         │     ├── rebuild_flag check [+0x62FFA0]
         │     ├── populate chat_obj fields (+0x14, +0x1D0..+0x1E4, +0x188)
         │     └── show_menu("menu msgline ", 1, 0)
         └── show_element("mes2frnd", window_manager [+0x5EDD10])
              opens "mes2frnd" sub-menu (Reply/Ignore/Leave Unread/Exit)
```

### Registration flow (one-time setup)
```
msg_obj is created (lazy init at event_handler_init [+0x1EB30], allocates 0x78B, vtable +0x339C28)
         ↓
msg_register_callback [+0x2008A0] is invoked on msg_obj
         ├── checks rebuild_flag [+0x62FFA0]
         ├── scroll_list_lookup(msg_obj) [+0x200140] → returns scroll_list_entry
         ├── PUSH (entry[0], entry+0x4, entry+0x8, entry+0xC, MsgProcess, msg_obj)
         └── CALL framework_callback_register [+0xF7490]
              ├── GATE: [+0x4DE900] (notif_mgr_ptr) must be non-zero
              └── framework_callback_register_inner [+0xF23F0] (actual storage)
```

### Notification Display flow
```
notif_mgr_ptr [+0x4DE900] (initialized by FFXiMain bootstrap)
         ↓
add_notif [+0xF2680] called with mgr + notification buf48
         ├── reads mgr+0x1C (sub-object)
         └── enqueues notification
         ↓
display_cb [+0xF2750] (called per-frame or on-demand)
         ├── checks notif_mgr_ptr non-zero
         └── invokes display routine
```
