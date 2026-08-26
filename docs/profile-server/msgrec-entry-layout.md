# msgrec entry layout — xiloader/server contract

The 0x48-byte entry that polcore's `msgrec_recv_pump` (+0x276E0) decodes into
the entry array (one per notification record, stride 0x50 when init's
`stride_flag=0`). The first 8 bytes are XOR-encrypted by polcore's session
mask; the remaining bytes are stored as raw plaintext (because we set the
flag word to 0x0880, which makes polcore skip the conditional block-1 XOR).

This layout is a **xiloader/profile-server convention** — polcore itself
treats entries[0x10..0x47] as opaque bytes; only entry[0..7] (the token /
primary key) and entry[0x3E..0x3F] (the flag word) have polcore-defined
semantics.

| Offset | Size | Field             | Notes                                            |
|--------|------|-------------------|--------------------------------------------------|
| 0x00   | 8    | token             | u64. XOR-encrypted by polcore on receive. Set to a unique notification ID (e.g. msg_id padded). |
| 0x08   | 8    | reserved          | Zero. Skipped from XOR because flag word == 0x0880. |
| 0x10   | 4    | from_accid        | u32 LE. Sender's account ID.                    |
| 0x14   | 4    | msg_id            | u32 LE. Server-assigned notification ID.        |
| 0x18   | 1    | msg_type          | u8. 1=accept, 9=friend-request, 10=decline, etc. (LSBN-compatible codes) |
| 0x19   | 3    | reserved          | Zero.                                            |
| 0x1C   | 4    | created_at        | u32 LE. Unix timestamp.                         |
| 0x20   | 16   | sender_name       | ASCII, null-padded, 15 chars max + null.        |
| 0x30   | 14   | subject_prefix    | ASCII, null-padded, 13 chars max + null.        |
| 0x3E   | 2    | flag_word         | u16 LE. **Must be 0x0880** to skip block-1 XOR. |
| 0x40   | 8    | reserved          | Zero. Reserved for future extension.            |
| 0x48 (end) |      |                   |                                                  |

## Constraints

- `flag_word` (0x3E..0x3F) MUST be 0x0880. Any other value triggers polcore's
  conditional XOR on entry[8..0xF], which would scramble the `from_accid` /
  `msg_id` fields.
- `token` (0x00..0x07) is XOR'd through `derive_iv(session_token_8b)`; the
  server must compute the encryption mask from the connection's session token.
- All multi-byte integers are little-endian.
- Strings are null-terminated ASCII; sender_name max 15 chars, subject_prefix
  max 13 chars.

## Wire framing

Each entry occupies 0x108 bytes on the wire (with leading + trailing zero
padding around the 0x60-byte custom-base64 chunk). See
`memory/project_msgrec_recv_pump.md` for the full SM trace.

## Client decode

xiloader's `pump_msgrec_recv` reads `s_msgrec_buf` after polcore completes the
SM, decodes each 0x50-byte entry into the same shape as
`s_cached_messages` (currently sourced from LSBN), and the existing native
msg-object injection takes over. This lets us retire the LSBN HTTP-style
bypass while keeping the proven UI bridge.
