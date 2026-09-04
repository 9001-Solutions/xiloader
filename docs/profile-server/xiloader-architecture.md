# xiloader Architecture (Profile Server Integration)

Source: `src/friend.cpp`, `src/friend.h`, `src/profile_proxy.cpp`.

## Profile-server proxy (src/profile_proxy.cpp)

Started from `friend_system::bootstrap` BEFORE `SetFriendServerConfig`, so it
owns the ports polcore is about to dial:

    127.0.0.1:51222  ->  127.0.0.1:51322   profile (binary)
    127.0.0.1:51240  ->  127.0.0.1:51340   push (IRC)

polcore connects to the profile server directly from inside the game process,
so an outage on that socket is fatal to the client (POL-0008). The proxy holds
the client-facing socket open across outages, buffers client->server data and
reconnects with exponential backoff. polcore needs no changes -- it keeps
dialling 51222/51240. Falls back to a direct connection if the bind fails.

## POL push channel (live friend status)

The friend system uses two transports: the binary protocol for the friend list
and messages, and an **IRC** channel on 51240 for live online/offline
transitions. Driven by `pump_pol_push()` from the friend worker; runs whenever
`--friends` is on (`--no-pol-push` disables it for diagnosis).

Bring-up unlatches polcore's router (`pol_set_conn_config`), supplies the key
material polcore's own compiled-out generator would have produced
(`pol_push_provide_keys`), and restores the session-ready flag that connection
setup clears. Receive is pumped explicitly via `FUN_10015C30(slot)`.

Protocol details: **`pol-push-irc-protocol.md`**.

## Bootstrap Sequence

xiloader orchestrates polcore.dll + FFXiMain.dll initialization:

1. `CoCreateInstance(polcore)` -- get `IPolCoreCom` interface
2. `SetParamInit` + `lpCommandTable` -- standard polcore init
3. `SetProfileServerPort` -- configure profile server port
4. `friend_system::bootstrap(polcore)`:
   1. `SetAuthMode` -- patches 2 instances in polcore, writes g_auth_mode + session hash
   2. `SetFriendServerConfig` -- writes config string to polcore+0xA30DC, clears flags
   3. Write sockaddr IP early (127.0.0.1 BE to polcore+0x404ABC)
   4. `AuthModeMonitor` thread -- watches g_auth_mode, re-patches if overwritten
   5. `CreateFriendList` -- initializes descriptor array + callbacks
   6. Disable BF crypto -- `desc[+0x0B]=0` for all 4 slots
5. `CoCreateInstance(FFXiEntry)` -- load FFXiMain.dll
6. `GameStart` -- enter game loop
7. After lobby login, `friend_system::activate()`:
   1. `SetFriendServerSockaddr` -- writes family+port+IP to polcore+0x404AB8
   2. Set friend system enable gate (polcore+0x99C80 = 1)
   3. `friend_system::init()` -- reset state machine
   4. `FriendWorkerThread` -- drives `on_frame()` at ~60Hz

## SetAuthMode Patches

Two patches in polcore force healthy auth mode. Full detail in `auth-crypto-system.md`.

| Instance | RVA | Patch |
|----------|-----|-------|
| #1 | polcore+0x01E86D | `JNE` (`0x75`) -> `JMP` (`0xEB`) |
| #2 | polcore+0x022BBD | `JE` (`0x74 0x05`) -> `NOP NOP` (`0x90 0x90`) |

Instance #2 byte pattern: `74 05 C6 07 01 EB 03 C6 07 02`.

## SetFriendServerConfig

Writes config string to polcore+0xA30DC, clears associated flags. On xiloader this is a minimal config (no POL login session data exists).

## polConnection

- Pattern scan: `8B0D????????8B4148508B` -- reads `[ecx+0x48]` (0x1000 buffer ptr)
- Object: 0x68 bytes at scanned address
- Buffer: malloc'd 0x1000 bytes at offset +0x48
- On xiloader: zeroed (no XOR key material)

## on_send Hook

`friend_system::on_send()` hooks Winsock `send()`:

- Init packets (40B, marker `0x0001` at `[4:6]`): inject account ID into `[6:12]` if zeros
- Auth packets (40B, `[12:24]` zeros on Init-seen sockets): inject session token into `[12:24]`
- Logs auth mode (retail `0x33/0x28/0x2E` vs degraded `0x02`)
- Does NOT modify Auth[0] -- controlled by polcore SetAuthMode patches

## Friend Worker State Machine

`friend_system::activate()` starts a worker thread that drives `on_frame()` at ~60Hz.

| State | Name | Action |
|-------|------|--------|
| 0 | WAITING | Wait for FFXiMain.dll + Store 3 allocation + 5s settle. Apply FFXiMain patches (NOP type-5 check, NOP populate guards). |
| 1 | READY | Call CallerB init (polcore+0x23440). Disable BF crypto on allocated slot. |
| 2 | PUMPING | Pump CallerB driver (polcore+0x23460) per-frame until slot freed (`desc[0]=0`). On completion: `do_array_sync()` + `write_handle_array()`. |
| 3 | ARRAY_SYNC | Wait for Store 3 to be populated (friend count > 0). |
| 4 | SYNC | Run `do_sync_status()`: write status table, enrich Store 3 entries, call `populate_friend_data`, write handle array. |
| 5 | STEADY | Run `gate_keeper()` per-frame (XI icon injection, deferred populate). After 30s (1800 frames), cycle back to READY for keepalive refresh. |

### Key Functions

| Function | Purpose |
|----------|---------|
| `do_array_sync()` | Copy Array 1 (64x104B) -> Array 2 (200x176B); map accid, flags, nickname; enforce bit 13 (0x2000) for online entries |
| `gate_keeper()` | Patch Store 3 entries (flags, zone, XI icon flags); inject XI icon (type=2) into render buffers for category==5 entries |
| `do_sync_status()` | Write polcore status table (0x84-stride); enrich Store 3 via polcore enrich (polcore+0x23E60); call `populate_friend_data` |
| `write_handle_array()` | Populate handle entries with encoded account IDs + charnames for the display text getter chain |

## Network Integration

`friend_system::activate()` is called from `PolDataComm` (`network.cpp`) after successful lobby login. Defers friend system activation until the game has a valid session.

CallerB does not fire natively. The xiloader worker thread invokes CallerB init/driver directly to download the friend list.

## Direct vs Proxied Connections

| Mode | Description |
|------|-------------|
| Proxied | Through xiloader proxy. 20B credential header (4B account_id + 16B session_hash) prepended to first send. |
| Direct | polcore connects directly to profile server. No credential header. Server detects via Init marker at `[4:6]=0x0001`. |

CallerA (keepalive) goes through xiloader proxy. CallerB/C connections from the worker thread connect directly via the sockaddr global.
