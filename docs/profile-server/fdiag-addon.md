# fdiag Addon — Friend System Diagnostic Tool

Ashita addon for runtime inspection and manipulation of polcore profile-protocol internals. Diagnostic tool; not required for friend system operation.

Source: `tools/profile-server/fdiag.lua`.

## HTTP API

LuaSocket listener on port **18780**.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ping` | GET | Health check |
| `/reload` | GET | Reload addon |
| `/exec?cmd=COMMAND` | GET | Execute fdiag command, return output |
| `/cmd?cmd=ASHITA_CMD` | GET | Execute arbitrary Ashita command |

```bash
curl "http://localhost:18780/exec?cmd=desc"
curl "http://localhost:18780/exec?cmd=callB"
```

## Commands

### Memory Inspection

| Command | Description |
|---------|-------------|
| `/fdiag all` | Dump everything (polconn, modetbl, friend, desc, polcore, functbl, authdata) |
| `/fdiag desc` | Dump connection descriptor array (4 active slots) |
| `/fdiag dumpslot N` | Hex dump full slot N (824 bytes) |
| `/fdiag polconn` | Dump polConnection object (0x68 bytes) |
| `/fdiag modetbl` | Dump FFXiMain mode table (14 entries × 4B) |
| `/fdiag friend` | Dump friend connection manager + sub-objects |
| `/fdiag connmgr` | Dump FFXiMain connection manager + slot table |
| `/fdiag polcore` | Dump polcore sections and profile server port |
| `/fdiag authdata` | Show g_auth_mode and mask data |
| `/fdiag authblock` | Raw hex dump of g_auth_mode 48B block |
| `/fdiag readabs ADDR [len]` | Hex dump any absolute memory address |
| `/fdiag dumpcode OFFSET [size]` | Hex dump polcore code at offset |

### Auth/Crypto

| Command | Description |
|---------|-------------|
| `/fdiag patch` | Set g_auth_mode=1 (healthy) + write character name as mask |
| `/fdiag unpatch` | Restore g_auth_mode=2 (degraded) |
| `/fdiag setbyte OFF VAL` | Write byte at g_auth_mode+OFF |
| `/fdiag setglobals [V1 V2]` | Dump/set auth-builder globals at polcore+0x404A88/8C |
| `/fdiag setglobals2` | Call set_globals_v2 to derive connection-type keys from crypto seed |
| `/fdiag patchauth2` | Patch instance #2 (JE→NOP NOP, force healthy path) |

### Connection Management

| Command | Description |
|---------|-------------|
| `/fdiag callA` | Invoke CallerA (polcore+0x1E580, keepalive type=5) |
| `/fdiag callB` | Invoke CallerB (polcore+0x22210, token type=8, param=0x1000) |
| `/fdiag callC` | Invoke CallerC (polcore+0x28330, befriend type=8) |
| `/fdiag tickslot N` | Call per-slot driver (polcore+0x1E5D0) once |
| `/fdiag connect [port]` | CallerB + write sockaddr + tickslot atomically |
| `/fdiag enable N` | Enable descriptor slot N (`+0xDE=1`) |
| `/fdiag clone S D [mode]` | Copy host/config from slot S to D with buffer allocation |

### Code Patching

| Command | Description |
|---------|-------------|
| `/fdiag patchlogin` | Install cave at polcore+0x44FCC that calls CallerA+B+C during bootstrap |
| `/fdiag readcave [addr]` | Read diagnostic values from patchlogin cave |
| `/fdiag patchconnect` | Patch create_connect to use slot sockaddr |
| `/fdiag patchconnect2` | Extended: sockaddr fix + WSAEWOULDBLOCK handling |
| `/fdiag unpatchconnect` | Restore original bytes at polcore+0x10482 |

### Scanning

| Command | Description |
|---------|-------------|
| `/fdiag scan` | Search polcore .text for Auth-related patterns |
| `/fdiag scanauth` | Broad search for `MOV BYTE [EDI], 0x02` |
| `/fdiag scanrefs` | Find all refs to g_auth_mode block |
| `/fdiag scanvt` | Scan FFXiMain .data for friend manager vtable |
| `/fdiag scanaddr OFFSET` | Find all refs to polcore+offset |
| `/fdiag findcall OFFSET` | Find all CALL instructions to polcore+offset |
| `/fdiag findauth` | Scan for `C6 07 01/02` patterns |

### Monitoring

| Command | Description |
|---------|-------------|
| `/fdiag watch` | Poll friend manager, report state changes |
| `/fdiag watch stop` | Stop watching |

### Other

| Command | Description |
|---------|-------------|
| `/fdiag file` | Write dump to file |
| `/fdiag functbl` | Dump polcore function table |
| `/fdiag friendwide` | Dump wider region around friend manager address |
| `/fdiag testsock [port] [nb]` | Create fresh socket, test connect to 127.0.0.1 |

## Pump Mechanism

Per-frame pump installed via `d3d_present` hook drives connection slots through the state machine. Required when CallerB/C is invoked from the addon — the driver function (polcore+0x1E5D0) needs per-frame calls to advance through TCP states.

State variables: `pump_active`, `pump_slot`, `pump_count`, `pump_max` (default 600 frames = ~10s at 60fps).

### POL push channel (added 2026-08-23)

| Command | Description |
|---------|-------------|
| `/fdiag polstate` | Dump POL router state (DAT_10099408/414/C80/244/940C/250) + push buffer + conn+0x208 |
| `/fdiag setconnconf [mode]` | Call pol_set_conn_config(mode, cfg) at polcore+0x448A0 -- unlatches the router |
| `/fdiag pumprouter [n]` | Step pol_msg_router n times, stopping on a negative (terminal) state |

**WARNING:** `pumprouter` past router state 0x16 has killed the client. State
0x17 drives the push SM concurrently with the friend SMs the xiloader worker is
already pumping, and they share connection-slot state. Use `polstate` freely
(read-only); treat the other two as destructive.

Note the push SM indexes by channel: state and buffers live at
`base + chan*0x3A00`, and the router's channel is `DAT_10099250`, which was 1 --
not 0 -- in testing. Reading channel 0 shows stale values.
