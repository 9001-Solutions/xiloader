# Native Mark-as-Read Flow

End-to-end RE of the inbox dismiss path. Marking a message as read in the inbox runs through a polcore-side state machine that copies the file from `/msg/r/b/<file>` to `/msg/r/a/<file>` and deletes the source. Op-0x19 dismiss is intentionally local — no wire packet is sent.

## Click flow

1. User selects Read on `mes2frnd` row.
2. `inbox_action_dispatcher (FFXi+0xFFFE0)` routes action 4 to `dismiss_outer (FFXi+0xF7430)` with op_code `0x19`.
3. `dismiss_outer` invokes the polcore-queue SM via `friend_inner_send (FFXi+0xF3150)`.
4. `polcore_queue_sm_driver (FFXi+0xF4170)` runs through op-table `FFXi+0x361278`:
   - op[1] = `dismiss_op1_send (FFXi+0xF59D0)` — iterates the polcore queue to locate the matching entry.
   - op[2] = `dismiss_op2_handler (FFXi+0xF5590)` — opens and reads `/msg/r/b/<file>`.
   - op[3] — writes `/msg/r/a/<file>`.
5. Polcore calls `DeleteFileA` on `/msg/r/b/<file>` after the copy.
6. `dismiss_completion_callback (FFXi+0x1FFD60)` fires with `result=0`. It clears `DAT_04C3FFA0`, plays a sound, and sets the row read flag at `DAT_04C3FF94+0x64 = 1`.
7. Next inbox refresh re-enumerates `/msg/r/b/`; the dismissed file is no longer present, so the row is excluded and the inbox rebuilds without it.

## Local file move requirement

`Mine_DeleteFileA` must redirect `\msg\` paths to the local msg directory (matching `Mine_MoveFileA` / `Mine_CreateFileA` / `Mine_FindFirstFileA`).

Without the redirect, polcore deletes against the original POL path that does not exist on disk, the call silently fails, and the file stays in `/b/` — which causes the next inbox enumeration to re-render the row.

## Key offsets

| Symbol | Address | Role |
|--------|---------|------|
| `inbox_action_dispatcher` | FFXi+0xFFFE0 | Inbox menu action dispatch (Reply/Ignore/Read) |
| `dismiss_outer` | FFXi+0xF7430 | Outer wrapper; gated on `DAT_04AEE900 != 0` |
| `friend_inner_send` | FFXi+0xF3150 | Common inner sender (chokepoint for all friend ops) |
| `polcore_queue_sm_driver` | FFXi+0xF4170 | Polcore-queue SM driver |
| `dismiss_op1_send` | FFXi+0xF59D0 | op[1]: polcore queue iterator |
| `dismiss_op2_handler` | FFXi+0xF5590 | op[2]: file-IO SM (open + read source) |
| `dismiss_completion_callback` | FFXi+0x1FFD60 | Fires on SM completion |
| `body_upload_sm` | polcore+0x1A6870 | Body-upload SM (used by other ops, not op-0x19) |
| `polcore_msg_format_writer` | polcore+0x1C8BE0 | Buffer formatter — `str1\x07str2\0[blob]` payload |
| `friend_conn_state` | FFXi+0x4DE900 (`DAT_04AEE900`) | Friend connection state pointer; submits early-return 2 if NULL |

## Polcore COM vtable slots

`DAT_04A65A24` (FFXi) holds the polcore COM vtable pointer `0x1006FBE8`. In the static dump (polcore base `0x04580000`) this is RVA `+0x6FBE8`.

| Slot   | Polcore RVA | Function                                              |
|--------|-------------|-------------------------------------------------------|
| +0x440 | `+0x1A8E0`  | Buffer packer — builds `str1\x07str2\0[blob]` payload |
| +0x444 | `+0x1ABA0`  | `polcore_vt444_post_built` — submit, allocates slot + kicks body-upload SM |
| +0x448 | `+0x1ABC0`  | `polcore_vt448_poll_status` — pumps SM forward        |
| +0x454 | `+0x1AC00`  | Cancel/cleanup                                        |
| +0x470 | `+0x1C8BE0` | `polcore_msg_format_writer`                           |

## Op codes

Op-0x19 is the dismiss op_code dispatched by `inbox_action_dispatcher` for action 4 (Read). Local — no TCP packet.

Op-0x16 is a body-upload (different op_table, different submit chain). It produces wire traffic via `body_upload_sm`. Unrelated to dismiss.

## CallerC descriptor offsets (body_upload_sm)

CallerC descriptor table at polcore `+0x404AD0`, stride `0x338`, 4 slots.

| Slot offset   | Field                                          |
|---------------|------------------------------------------------|
| `+0x040`      | output_buf_ptr (deref → wire packet)           |
| `+0x0C0`      | account ID lo                                  |
| `+0x0C4`      | account ID hi                                  |
| `+0x0CC`      | size_param                                     |
| `+0x0D0`      | op_code                                        |
| `+0x0D8`      | body content (0x17F bytes)                     |
| `+0x258`      | msg_type byte 0                                |
| `+0x259`      | msg_type byte 1                                |

## Wire packet layout (body_upload_sm, 0x198 bytes, BF-encrypted)

| Offset           | Source                          | Content                                |
|------------------|---------------------------------|----------------------------------------|
| `+0x00..0x01`    | slot+0x258..0x259               | msg_type bytes                         |
| `+0x08..0x0F`    | hash of slot+0xC0..0xC4         | 64-bit account hash                    |
| `+0x10..0x18F`   | slot+0xD8                       | Body: `str1\x07str2\0[padding]`        |
| `+0x190..0x193`  | slot+0xD0                       | op_code                                |
| `+0x194..0x197`  | slot+0xCC                       | size_param                             |
