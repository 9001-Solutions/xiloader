# account_id hydration chain

How the player's account_id reaches FFXi's character struct field
`[*DAT_04AEED90 + 0x3C388]`. All FFXiMain addresses use image base
`0x04610000`.

## Two source paths

### Path A -- POL XML (retail-only; doesn't fire in our bypass)

```
POL CLI args ("-globaluniqueno=N")
  -> parse_pol_xml_boot_params (FFXi+0x1021E0)
        writes  *(int*)(DAT_04AEFAE8 + 0x15C) = parsed acct_id
        @ FFXi+0x102B37 (case "-uniqueno")
        @ FFXi+0x102B66 (case "-globaluniqueno")
  -> enter_lobby_after_xml_parse (FFXi+0x103260)
  -> lobby_join_state_machine_init (FFXi+0xEFFD0, mode=1)
        sets DAT_04AEE768[0x47] = 7
  -> lobby_join_state_machine_tick (FFXi+0xF0150) state 7
  -> stage_pol_xml_account_id_then_init_char (FFXi+0xF98D0)
        iVar3 = *(int*)(DAT_04AEFAE8 + 0x15C)
        if (iVar3 == 0) iVar3 = DAT_04AEE768[0x2D]   // fallback
  -> character_record_init_from_pol_xml (FFXi+0x109D50)
        WRITE: *(int*)(struct + 0x3C388) = param_5  @ FFXi+0x109DC5
```

This path is gated on POL launching FFXi with command-line args. Our bypass
never invokes it. Confirmed at runtime: a hook on FFXi+0x109D50 never fired.

### Path B -- zone packet cmd 10 (this fires in our bypass)

```
LSB zone server sends cmd 10 "PlayerSetup"
  -> ec_recv (polcore export, BF-decrypts zone stream)
  -> per_frame_active_character_tick (FFXi+0xFA020)
  -> drive_active_character_tick (FFXi+0xF9BF0)
  -> zone_packet_dispatcher (FFXi+0xFA460)
        cmd_id = (*(ushort*)body) & 0x1FF
        handler = [DAT_04AEED8C + 0x44720 + cmd_id*4]
        (cmd 10 -> character_record_full_init_from_login_packet)
  -> character_record_full_init_from_login_packet (FFXi+0xFAB90)
        WRITE: *(uint32_t*)(struct + 0x3C388) = *(uint32_t*)(packet_body + 4)
                @ FFXi+0xFAD73
        WRITE: strncpy(struct + 0x3C39C, packet_body + 0x84, 0x10)  // charname
        + ~150 other field copies from packet body
```

**This is what populates `+0x3C388` in our build.** The value comes directly
from `packet_body[4..7]` of cmd 10. If the LSB zone server writes `1` in that
field, FFXi's character struct reads `1`.

## Writers of `+0x3C388` (complete enumeration)

Pattern-scan for `0x0003C388` (immediate `88 c3 03 00`) yielded 33 instruction
sites; only 2 are writes (`MOV [reg+0x3C388], reg`):

| FFXi VA      | Function                                          | Source         |
|--------------|---------------------------------------------------|----------------|
| `0x04709DC5` | `character_record_init_from_pol_xml` (path A)     | param_5        |
| `0x0470AD73` | `character_record_full_init_from_login_packet` (B)| packet[+4]     |

There are **no `MOV imm32` writes** to this offset. Nothing hard-codes `1`.
The `1` we observed is whatever the LSB zone server sends in cmd 10 body+4.

## Allocator for the character struct

`char_pool_alloc_and_register_handlers @ FFXi+0xF77E0` initialises the pool
from the static BSS block at `DAT_04F8EF60` (`0x44CA4` bytes). No
`operator_new`. `DAT_04AEED90` is set to the first slot, all fields initially
zero. Same function calls `register_all_zone_packet_handlers` (FFXi+0xF99C0)
which fills the cmd-10 dispatch slot.

## Readers of `+0x3C388` (notable)

| Function                                                | RVA           | Role                                                                |
|---------------------------------------------------------|---------------|---------------------------------------------------------------------|
| `befriend_dialog_callback`                              | `0x79FE0`     | Compares against `iVar2[0x18]` to skip self-befriend.               |
| `propagate_local_id_to_party_ls_friend_blacklist`       | `0xE87F0`     | Copies to 4 subsystem self-records: `+0x57E4`, `+0x60A8`, `+0x696C`, `+0x7230`. |
| `build_local_player_record`                             | `0xE8A40`     | Copies into derived array entry at `+0x14`.                          |
| `FUN_046FC290` (action packet builder)                  | `0xEC290`     | Embeds in outgoing action packet `+0xC` (cmd 0xD8).                 |
| `FUN_0473ADD0` (interaction eligibility)                | `0x12ADD0`    | Cases 10/0x10: target eligibility (kick/dismiss/invite).            |
| `FUN_048079F0` (chat/tell handler)                      | `0x1F79F0`    | Suppresses own messages.                                             |
| Various subsystem propagation sites within `0xE87F0`    | ...             | Mirror id into party/linkshell/friend/blacklist self-record.        |

31 read sites total. Anything self-recognition related uses this field.

## polcore-side audit

polcore image searched for `0x3C388` immediate and POL-related strings
(`globaluniqueno`, `uniqueno`, `param.xml`, `BootParam`, `polonline`):
**zero hits**. polcore is a transport/COM layer and does **not** propagate
account_id to FFXi. The account_id lives in either the POL XML CLI args
(retail) or the zone server's cmd 10 packet (everyone else, including us).

## Integration points (ranked)

### 1. LSB zone server -- fix cmd 10 packet (recommended; truly native)

The zone server is the authoritative source for cmd 10 body+4. Make it write
the correct account_id. **No client patch, no detour.** This is what the
field's contract says happens, and it's the same mechanism retail-non-POL
characters would use.

LSB code lives in `<lsb>/src/map/packets/` -- find the
"char update" / "send player init" packet builder for the active character
zone-in flow.

### 2. xiloader -- seed `[DAT_04AEFAE8 + 0x15C]` before state 7 (path A mimic)

If we additionally need path A to work (e.g. for some bypass mode that
doesn't get a cmd 10 packet), write our `g_AccountId` to
`[*DAT_04AEFAE8 + 0x15C]` after auth completes. The state machine then reads
it via `stage_pol_xml_account_id_then_init_char` and the rest of path A runs
unchanged. Caveat: only effective if `lobby_join_state_machine_init(mode=1)`
is invoked and reaches state 7, which we have not verified.

### 3. (Reject) Detour `character_record_full_init_from_login_packet`

Hooking the writer to substitute the value papers over the upstream bug. Use
only as a last resort.

### 4. (Reject) Patch the field directly in worker thread

Earlier attempt; broke the data-download SM by writing during init. Even
properly timed it would mask, not fix, the root cause.

## Renames committed in Ghidra (FFXiMain)

| Address      | New name                                         |
|--------------|--------------------------------------------------|
| `0x04709D50` | `character_record_init_from_pol_xml`             |
| `0x047098D0` | `stage_pol_xml_account_id_then_init_char`        |
| `0x047097E0` | `char_pool_alloc_and_register_handlers`          |
| `0x0470A460` | `zone_packet_dispatcher`                         |
| `0x0470AB90` | `character_record_full_init_from_login_packet`   |
| `0x0470C210` | `register_zone_packet_handler`                   |
| `0x047099C0` | `register_all_zone_packet_handlers`              |
| `0x047121E0` | `parse_pol_xml_boot_params`                      |
| `0x046F8A40` | `build_local_player_record`                      |
| `0x046F87F0` | `propagate_local_id_to_party_ls_friend_blacklist`|
| `0x046FFFD0` | `lobby_join_state_machine_init`                  |
| `0x04700150` | `lobby_join_state_machine_tick`                  |
| `0x04713260` | `enter_lobby_after_xml_parse`                    |
| `0x0470A020` | `per_frame_active_character_tick`                |
| `0x04709BF0` | `drive_active_character_tick`                    |

## Cmd 10 packet body layout (partial)

```
+0x00  uint16  cmd_word: low 9 bits = cmd_id (=10), high 7 bits = size_in_dwords
+0x04  uint32  account_id              -> char_record + 0x3C388
+0x42  uint16  (zone/related)          -> char_record + 0x40D74
+0x84  char[16] charname               -> char_record + 0x3C39C
... 100+ further field copies handled by character_record_full_init_from_login_packet
```

`character_record_full_init_from_login_packet` (FFXi+0xFAB90) is a ~350-line
struct copy; the full layout can be derived by reading every write inside it
if needed.
