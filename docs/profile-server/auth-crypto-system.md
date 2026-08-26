# Profile Server Auth & Crypto

Profile server (port 51220) uses XOR-mask encoding for packet headers.

## XOR Mask Protocol

```
1. Store Init packet (40B plaintext)
2. Receive Auth (40B)
3. mask[0:12] = Auth[0:12] XOR Init[0:12]
4. Decode all C2S packet headers [0:12] with mask
5. Encode all S2C packet headers [0:12] with mask
```

### Encoding rules

- Init: plaintext (no encoding)
- ACK: plaintext `[0x81, 0x00*19, counter_LE_4B]`
- Auth: `encoded[0:12] = plaintext[0:12] XOR mask`; `[12:24]` = token; `[24:40]` = encrypted
- All subsequent packets: `[0:12]` XOR mask, `[12+]` varies by packet type

### Mask byte breakdown (per-account)

| Byte | Source |
|------|--------|
| mask[0] | constant per account (e.g. e48b→0x54, 3a6a→0x28) |
| mask[1] | `account_base1 XOR (seq XOR 3)` |
| mask[2] | `account_base2 XOR opcode` |
| mask[3] | constant per account |
| mask[4] | varies (constant for same account+op except op=0x01) |
| mask[5] | varies (low bit flips, mostly 2 values per account) |
| mask[6:12] | constant per account |

On xiloader (degraded mode), mask is `02 04 05 00 ...` — predictable, functional, not retail.

## Auth Builder Global Chain

```
Lobby Server -> session config data -> polcore memory
                                        |
                                        v
crypto_processor (polcore+0x19F20):  input_data -> session_keys [polcore+0xAA848/4C]
                                                              |
                                                              v
auth_builder (polcore+0x1EA00):  session_keys XOR conn_type_keys -> mask bytes
                                  [polcore+0xAA848/4C]  [polcore+0x404A88/8C]
```

### mask_gen (polcore+0x19D40)

```asm
MOV EAX, [polcore+0xAA848]   ; session key 1
MOV EDX, [ESP+4]             ; arg1 = conn_type key 1
MOV ECX, [ESP+8]             ; arg2 = conn_type key 2
XOR EAX, EDX                 ; result_low = session ^ conn_type
MOV EDX, [polcore+0xAA84C]   ; session key 2
XOR EDX, ECX                 ; result_high = session ^ conn_type
RET                          ; returns EAX:EDX
```

### auth_builder (polcore+0x1EA00)

Reads conn-type keys from `[polcore+0x404A88]` and `[polcore+0x404A8C]`, calls mask_gen, then calls polcore+0x19E20 to write results to slot. Zeros: `slot[0x01]=0xFF`, `slot[0x08/09/14]=0`, `slot[0x38]=-1`. Timer at `slot[0x330]`.

### Key Global Addresses

| Address | Size | Written By | Content |
|---------|------|------------|---------|
| polcore+0xAA848 | 4 | crypto_processor (polcore+0x19F20) | Session key 1 |
| polcore+0xAA84C | 4 | crypto_processor (polcore+0x19F20) | Session key 2 |
| polcore+0x404A88 | 4 | set_globals/v2 | Connection-type key 1 |
| polcore+0x404A8C | 4 | set_globals/v2 | Connection-type key 2 |
| polcore+0x404A94 | 15 | set_globals | Config data (from lobby) |
| polcore+0xAAA98 | 48 | SetAuthMode | g_auth_mode block |

### xiloader state

- Session keys: 0 (NULL input to crypto_processor)
- Conn-type keys: 0 (set_globals_v2 state never reached)
- Result: mask is always `02 04 05 00 ...` (degraded defaults)

## polcore Auth Modes

Two instances of the auth-mode setter:

| Instance | RVA | Role | Patch |
|----------|-----|------|-------|
| #1 | polcore+0x01E86D | Controls Auth packet building (Auth[0]) | `JNE` → `JMP` |
| #2 | polcore+0x022BBD | Forces healthy internal mode | `JE` (`74 05`) → `NOP NOP` (`90 90`) |

Instance #2 byte pattern:

```
74 05 C6 07 01 EB 03 C6 07 02
   JE +5  MOV [EDI],0x01  JMP +3  MOV [EDI],0x02
```

### g_auth_mode block (polcore+0xAAA98, 48B)

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | mode DWORD (0=cleared, 1=healthy, 2=degraded) |
| +0x04 | 1 | sentinel byte |
| +0x05 | 16 | mask16 (reversed NOTed character name) |
| +0x15 | 20 | mask20 (session hash, written by SetAuthMode from g_SessionHash) |
| +0x29 | 6 | extra6 (degraded mode only) |

`SetAuthMode` writes character name as mask16 with reversed-NOT: `~name[0]` at `+0x14`, `~name[1]` at `+0x13`, etc.

### Healthy vs Degraded

| Aspect | Degraded (Auth[0]=0x02) | Healthy (Auth[0]=0x01) |
|--------|------------------------|------------------------|
| When | Unpatched client | Both instances patched (xiloader default) |
| Server response | DegradedAuthResp (144B) | Skip DegradedAuthResp |
| Mask | Predictable `02 04 05 ...` | Character-name-derived |

## polConnection XOR Behavior

polConnection (0x68 bytes at pattern-scanned address; `+0x48` → malloc'd 0x1000 buffer) provides XOR key material for `Auth[4:20]`, NOT `Auth[0:4]`.

```
polConn[0x00:0x04] -> XOR'd into Auth[4:7]
polConn[0x04:0x08] -> XOR'd into Auth[8:11]
polConn[0x08:0x0C] -> XOR'd into Auth[12:15]
polConn[0x0C:0x10] -> XOR'd into Auth[16:19]
```

`Auth[0:4]` (mode prefix) is unaffected by polConnection. On xiloader, polConnection is zero — no XOR effect.

## AuthConfirm Plaintext Structure

```
[0]    = 0x81 (type marker)
[1]    = seq (connection sequence: 1, 2, 3)
[2]    = op (0x0B=status, 0x06=befriend, 0x01=confirm, 0x00=notif, 0x02=pickup, 0x0D=delete)
[3]    = 0x00
[4:6]  = param (server-chosen, e.g. 0x0029 for status)
[6:8]  = acctid_lo (2 bytes)
[8:12] = Init[8:12] XOR server_IP_LE
[12:24]= session token (plaintext, NOT mask-encoded)
```

Bytes 9-11 = constant `01 59 81` across all accounts.
