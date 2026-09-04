# Message List (Communication > Friend List > Messages)

The Messages table displays friend notifications in columns: From, To, Type, Date. Separate system from /flist.

Messages persist as **files on disk**, not in memory. The filesystem is the persistence layer.

## Retail Flow

1. NotifPickup (polcore auth 03,03) delivers notification data.
2. polcore writes message body files to `PlayOnlineViewer\pub\homeNN\msg\r\b\`.
3. Per-frame function scans `msg\r\b\` directory; file count = notification icon number.
4. User opens Messages tab -> `full_init` creates a task (state machine).
5. Task iterates files in `msg\r\b\`, calls `message_insert` per file.
6. `message_insert` writes sender/recipient/date/type to render/data arrays.
7. Tab close frees arrays. Reopen re-scans files and rebuilds.
8. Click-to-read reads file body, displays in chat log.
9. Read message: file moves from `r\b\` (unread) to `r\a\` (read).

## xiloader Implementation

- Write message body files to `msg\r\b\` with properly encoded filenames.
- Hook `CreateFileA` to redirect `msg\r\b\` paths to a local directory.
- Game's own `full_init` task handles display (no manual array injection).
- Click-to-read and notification overlay work natively.

## Filesystem Layout

```
<install_folder>\pub\homeNN\msg\r\b\<encoded_filename>   (received, unread)
<install_folder>\pub\homeNN\msg\r\a\<encoded_filename>   (received, read)
<install_folder>\pub\homeNN\msg\s\b\<encoded_filename>   (sent, unread)
```

- `install_folder` from registry `HKLM\SOFTWARE\PlayOnlineUS\InstallFolder\1000`
- `homeNN` per-account directory (home00, home01, etc.)
- `r` = received, `s` = sent
- `a` = read, `b` = unread

### File body format

```
<body_text><0x07><recipient_charname><0x00>
```

Body text: ASCII or Shift-JIS. `0x07` separates body from recipient name.

## Filename Encoding

### Alphabet (polcore .rdata 0x10065DE0)

```
TSG8IncW3HFKokOg79qzeCmZs2yBYEQVAUxR5rbwi4P@jMDLtpvad0f_J1hlN6uX
```

Standard base64 mechanics (3 bytes -> 4 chars, big-endian bit packing) with a custom alphabet. `T` = value 0 = padding.

### Decode table (polcore .rdata 0x10065D64)

256 bytes mapping each byte value to its 0-63 index. `0xFF` = invalid.

### Filename structure (96 chars encoding 72 bytes)

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 8 | Sender account hash |
| +0x08 | 8 | Recipient account hash |
| +0x10 | 16 | Sender nickname (null-padded) |
| +0x20 | 16 | Subject text (null-padded) |
| +0x30 | 4 | Flags/type |
| +0x34 | 4 | Timestamp (unix LE) |
| +0x38 | 16 | Metadata (length, sub-type, flags) |

## NotifPickup (polcore auth 03,03)

Dedicated init/driver pair separate from CallerA/B/C.

| Function | Offset | Signature |
|----------|--------|-----------|
| Init wrapper | polcore+0x25B50 | `int __cdecl(data_ptr, byte0, enc_lo, enc_hi, byte1)` |
| Driver wrapper | polcore+0x25D10 | `int __cdecl(slot, &output)`, returns 1 when done |

- `data_ptr` (arg1) MUST be a valid pointer to >=383 bytes (driver memcpy's it into the 416B packet)
- Auth (03,03) with buffer size 416 hardcoded in driver
- Driver auto-frees slot on completion
- Mode byte at `desc[0x0A]` (not 0x08)
- 7 modes (0-6); mode 7 = done

## Object Layout

### Globals

| Global | Purpose |
|--------|---------|
| `[FFXi+0x62FF94]` | Messages table (vtable +0x339C28) |
| `[FFXi+0x62FF90]` | Chat message display (vtable +0x339BE0) |
| `[FFXi+0x62EE1C]` | Unused (zero xrefs in .text) |

### msg_obj fields

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | vtable (+0x339C28) |
| +0x08 | 4 | ui_element (set by game on tab open, NULL on close) |
| +0x14 | 2 | inner_switch |
| +0x16 | 2 | column_count (5) |
| +0x18 | 2 | max_items (15) |
| +0x1C | 4 | rendered_count |
| +0x20 | 2 | visible_count |
| +0x30 | 4 | type_str_table (+0x38416C) |
| +0x38 | 4 | display_ptr (= +0x68) |
| +0x54 | 4 | count |
| +0x58 | 4 | saved arg1 from full_init |
| +0x5C | 4 | saved arg2 from full_init |
| +0x60 | 4 | saved arg3 from full_init |
| +0x68 | 4 | render_arr (stride 0x54, freed on tab close) |
| +0x6C | 4 | data_arr (stride 0x50, freed on tab close) |
| +0x74 | 4 | descriptor ptr (ephemeral, NOT a linked list) |

### Functions

| Address | Name | Signature |
|---------|------|-----------|
| FFXi+0x200710 | full_init | `__thiscall(a1,a2,a3)`, RET 0x0C |
| FFXi+0x1FEF10 | message_insert | `__thiscall(icon_type,source)`, RET 8 |
| FFXi+0x2002F0 | array_builder | `__thiscall(a1,a2,a3)`, RET 0x0C |
| FFXi+0x1F4650 | display_text | ECX=entry, `__stdcall(col,pos,data,color)`, RET 0x10 |
| FFXi+0x1FF690 | chat_insert | `__thiscall(data1,data2,type)`, RET 0x0C |
| FFXi+0x200420 | rebuild_consumer | checks `+0x64` flag, re-calls builder |
| FFXi+0x1F63E0 | vt[1] | `__thiscall()` |

## Notification Handlers

Jump table at FFXi+0x1EB642 -- four handlers dispatched by the listener at `[FFXi+0x62E9F8]` vtable+0x18.

| Entry | Address | Action |
|-------|---------|--------|
| 0 | FFXi+0x1EB53E | Body display: format + vtable[9] call |
| 1 | FFXi+0x1EB5B0 | `chat_insert` on `[FFXi+0x62FF90]` (opens input) |
| 2 | FFXi+0x1EB5EB | `full_init` on `[FFXi+0x62FF94]` + create task |
| 3 | FFXi+0x1EB61D | Event handler |

### Handler 0: Body Display (FFXi+0x1EB53E)

Native click-to-read path:

1. Read body text from `event_data+0x3C`.
2. `sprintf(buf, "%s %s ", "/tell", body)` using format at FFXi+0x36E9B0.
3. Load display controller from `[FFXi+0x62F218]`.
4. Call `vtable[9]` (offset 0x24) with `__thiscall(display_obj, formatted_text)`.
5. Show "flmes" element via wm function at FFXi+0x15E7A0.

The display controller at `[FFXi+0x62F218]` is a POL text output object (vtable at FFXi+0x2F6A98). It is NOT the chat_obj at `[FFXi+0x62FF90]`.

### Handler 1: chat_insert (FFXi+0x1EB5B0)

Opens the POL chat input field ("msgline" element). Not for displaying body text.

1. Check rebuild flag at `[FFXi+0x62FFA0]` -- if set, early return.
2. Store `arg1->chat_obj+0x1D0`, `arg2->+0x1D4`, `arg3->+0x1D8`.
3. Set `chat_obj+0x14` (inner_switch) = 1.
4. Call `show_menu("menu    msgline ", vis=1, 0)` on wm at FFXi+0x5EDD10.
5. RET 0x0C.

### Handler 2: full_init (FFXi+0x1EB5EB)

Calls `full_init` on msg_obj `[FFXi+0x62FF94]`. Creates the file-scanning task.

## UI Element Names (8-byte padded, parent+child compound)

| Address | Name | Purpose |
|---------|------|---------|
| FFXi+0x380FD0 | `menu    flmes   ` | Notification display panel |
| FFXi+0x380FE4 | `menu    titlehan` | Title handler |
| FFXi+0x384208 | `menu    msgline ` | Chat input field |
| FFXi+0x384224 | `menu    msglist ` | Messages table scroll list |
| FFXi+0x3841E0 | `menu    mes1rcv ` | Message receive panel 1 |
| FFXi+0x3841F4 | `menu    mes2frnd` | Friends message panel 2 |

## Display Controller

| Global | Value | Purpose |
|--------|-------|---------|
| `[FFXi+0x62F218]` | POL text display obj | Body text output |

vtable at FFXi+0x2F6A98. Method at offset 0x24 (vtable[9]): `__thiscall(this, text_string)` -- displays text in POL chat area.

## Window Manager

Inline object at FFXi+0x5EDD10. Used by `show_menu` and element activation functions.

| Function | Address | Signature |
|----------|---------|-----------|
| show_menu (3-arg) | FFXi+0x15E1D4 | `__thiscall(wm, name16, vis, unk)` |
| show_menu (3-arg) | FFXi+0x15E1E0 | `__thiscall(wm, name16, vis, unk)` |
| show_element (1-arg) | FFXi+0x15E7A0 | `__thiscall(wm, name16)` |

## Data Entry Format (stride 0x50)

```
+0x00: uint32    flag = 2
+0x10: 16 bytes  sender (null-terminated)
+0x20: 16 bytes  recipient (null-terminated)
+0x30: 16 bytes  date (format "M/DD/YY H:MM:SSam")
+0x48: uint32    type string pointer
```

## Render Entry Format (stride 0x54)

```
+0x00: 8 bytes  positions = { 0x00, 0x25, 0x25, 0x01, 0x01, 0x00, 0x00, 0x00 }
+0x08: 32 bytes colors[0-7] = ALL 0x80808080
+0x2C: uint32   data_ptr[1] = &data_entry+0x10 (sender)
+0x30: uint32   data_ptr[2] = &data_entry+0x20 (recipient)
+0x34: uint32   data_ptr[3] = type string pointer
+0x38: uint32   data_ptr[4] = &data_entry+0x30 (date)
+0x48: uint32   data_entry_link
```

## Count Fields

When injecting directly (not via filesystem):

```
msg_obj+0x1C = count   ; rendered row count
msg_obj+0x20 = count   ; visible count
msg_obj+0x54 = count   ; internal count
```

## Type String Table

At FFXi+0x384180, 8 bytes per entry:

| Offset | String |
|--------|--------|
| FFXi+0x384180 | `[NRM]` |
| FFXi+0x384188 | `[FOK]` |
| FFXi+0x384190 | `[FNO]` |

## Colors

`0x80808080` = normal (retail). `0xFFFFFFFF` = bold.
