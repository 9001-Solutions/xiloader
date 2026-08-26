# Polcore Title String Table

Polcore.dll ships a 10-entry title string table at RVA `0x743D8` used to label friend/group notification messages (e.g., "Let's be friends!", "Friend registration accepted"). The on-disk file contains Japanese-only strings; retail clients overwrite this table with English at runtime. xiloader skips the PoL bootstrap path that performs the overwrite, so without intervention the in-game UI shows JP titles even on US/EN installs. `friend.cpp::PatchPolcoreTitles()` writes the EN strings into the table during `friend_system::bootstrap()`, gated by `g_EnableFriends`.

## Table Layout

- **RVA:** `0x743D8` (in `.data` section)
- **Disk file offset:** `0xF7D8` in `viewer/com/polcore.dll`
- **Stride:** 128 bytes per entry
- **Count:** 10 entries
- **Encoding (on disk):** Shift-JIS

| Idx | Offset  | JP (on disk)              | EN (retail patches in)                 | Msg code |
|-----|---------|---------------------------|----------------------------------------|----------|
| 0   | +0x000  | 友達になろうよ！           | Let's be friends!                       | 0x01     |
| 1   | +0x080  | フレンド登録承諾           | Friend registration accepted            | 0x09     |
| 2   | +0x100  | フレンド登録拒否           | Friend registration declined            | 0x0A     |
| 3   | +0x180  | 削除しました               | Deleted                                 | 0x0B     |
| 4   | +0x200  | 削除してください           | Please delete.                          | 0x0C     |
| 5   | +0x280  | グループに参加しませんか！ | Would you like to join a friend group?  | 0x0E     |
| 6   | +0x300  | グループ参加承諾           | Group registration accepted             | 0x0F     |
| 7   | +0x380  | グループ参加拒否           | Group registration declined             | 0x10     |
| 8   | +0x400  | グループ除名               | Removed from friend group               | 0x12     |
| 9   | +0x480  | グループ解散               | Friend group disbanded                  | 0x13     |

## Access Pattern

Four call sites in polcore `.text` index the table with the same instruction sequence:

```asm
SHL EAX, 7          ; entry_index * 128
ADD EAX, 0x100743D8 ; preferred-base address; PE relocation patches at load
```

Sites: `polcore+0x1ADB3, +0x1AE30, +0x1B16E, +0x1B2CB`.

### Getter Function (polcore+0x1ADA0)

```c
void get_title(int idx, char* dst) {
    if (idx >= 10) return;
    strncpy_s(dst, 0x7F, (char*)0x100743D8 + idx * 128, _TRUNCATE);
}
```

## Message-Code → Title-Index Lookup

Immediately following the title array (polcore+0x748D8) is an 8-byte-per-entry lookup that maps incoming network message type codes to title indices:

```
+0x748D8: FF FF FF FF / 00 00 00 00   sentinel
+0x748E0: 01 / 00                     code 0x01 → title 0  (Let's be friends!)
+0x748E8: 09 / 01                     code 0x09 → title 1  (Friend registration accepted)
+0x748F0: 0A / 02                     code 0x0A → title 2  (Friend registration declined)
+0x748F8: 0B / 03                     code 0x0B → title 3  (Deleted)
+0x74900: 0C / 04                     code 0x0C → title 4  (Please delete.)
+0x74908: 0E / 05                     code 0x0E → title 5  (Would you like to join a friend group?)
+0x74910: 0F / 06                     code 0x0F → title 6  (Group registration accepted)
+0x74918: 10 / 07                     code 0x10 → title 7  (Group registration declined)
+0x74920: 12 / 08                     code 0x12 → title 8  (Removed from friend group)
+0x74928: 13 / 09                     code 0x13 → title 9  (Friend group disbanded)
```

Plus an unrelated EN string at `polcore+0x74930`: `"Would you like to be friends?"` (alternate prompt phrasing — not part of the table).

## Implementation

`src/friend.cpp::PatchPolcoreTitles()`:

1. Skip unless `g_Language == English`. JP players need the original strings; EU players load `polcoreeu.dll` (layout not RE'd).
2. `GetModuleHandleA("polcore.dll")` — table is accessed via runtime base + RVA.
3. `VirtualProtect(table, 1280, PAGE_READWRITE, ...)` — defensive; `.data` is RW by default.
4. For each of the 10 entries: `memset(slot, 0, 128)` then `memcpy(slot, en, strlen(en)+1)`. Zeroing first avoids residual-byte tails.
5. Restore protection.

Called from `friend_system::bootstrap()`.

## Diagnostic Commands

To verify in a live process via the fdiag/fdiag2 Ashita addon:

```
/fdiag dumpcode 0x743D8 512   # dump entries 0-3
/fdiag dumpcode 0x74558 512   # dump entries 3-6
/fdiag dumpcode 0x74758 512   # dump entries 7-9 + lookup table
/fdiag findref polcore.dll polcore.dll+0x743D8 30   # show all 4 read sites
```
