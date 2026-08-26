# Python Test Server

Source: `tools/profile-server/profile_test_server.py`.

Threaded TCP server implementing the profile protocol. Handles degraded and healthy mode connections. Logs all packets to JSON.

## Running

```bash
cd <packet_dumps>
python profile_test_server.py [PORT]
```

Default port: 51222. Set `PROFILE_SERVER_IP` env var for AuthConfirm IP computation (default: `127.0.0.1`).

`ffxi_blowfish.py` ships in the same directory for BF-OFB support (disabled — see `bf-key-research.md`).

## Protocol Flow

### Degraded mode (Auth[0]=0x02)

```
C→S: Init (40B plaintext)
S→C: ACK (24B plaintext)
C→S: Auth (40B)
S→C: DegradedAuthResp (144B)
C→S: Data (40-416B, varies by type)
S→C: AuthConfirm (24B) + Status (32-128B)
Server FIN
```

### Healthy mode (Auth[0]=0x01)

```
C→S: Init (40B plaintext)
S→C: ACK (24B plaintext)
C→S: Auth (40B)
                                  (skip DegradedAuthResp)
C→S: Data
S→C: AuthConfirm (24B) + Status
Server FIN
```

## Connection Detection

First 40B determines connection type:

- **Direct** (from polcore): Init marker `0x0001` at bytes `[4:6]` → Init starts at byte 0
- **Proxied** (from xiloader): no marker → first 20B = credential header (4B account_id + 16B session_hash), next 20B + 20B more = Init

## Mask Extraction

```python
wire_mask = Auth[0:12] XOR Init[0:12]
```

## Response Structures

### DegradedAuthResp (144B)

```
[0:4]   = 0x00000028 (40)         Auth packet size
[4:8]   = status_size (0x20=32 for keepalive)
[8:12]  = SERVER_IP_LE
[12:144]= zeros
```

### AuthConfirm (24B, mask-encoded header)

```
[0]    = 0x81
[1]    = seq (from Auth[1])
[2]    = op (from Auth[2])
[3]    = 0x00
[4:6]  = param (lookup table by (seq,op))
[6:8]  = acctid_lo
[8:12] = Init[8:12] XOR server_IP_LE
[12:24]= session token (plaintext, NOT mask-encoded)
```

### Param Table

| (seq, op) | Param | Type |
|-----------|-------|------|
| (0x04, 0x05) | 0x0009 | Post-game keepalive |
| (0x04, 0x06) | 0x0099 | POL-stage status |
| (0x04, 0x07) | 0x0049 | POL-stage initial auth |
| (0x01, 0x0b) | 0x0029 | Befriend/flist |
| (0x07, 0x0c) | 0x0011 | Quick validation |

## Logging

Each connection writes a JSON file to `<packet_dumps>/server_logs/` containing connection ID, account ID, session hash, mask, token, ACK counter, and a full packet log with timestamps, directions, labels, and hex.
