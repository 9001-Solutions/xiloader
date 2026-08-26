# FFXi search-server query path

How FFXi resolves a typed charname to an account_id during `/befriend`,
`/sea`, the friend-request dialog, etc. All FFXiMain addresses use image base
`0x04610000`.

## TL;DR

Search queries are **client-side**: FFXi opens its own TCP socket directly to
the search server (port 54002 in our setup), bypassing polcore. xi_search may
use ZMQ IPC to consult map server for online-player data, but that's its
internal detail; the FFXi→xi_search hop is plain TCP.

In our build the search-server endpoint (`DAT_04ABD8B4` IP / `DAT_04ABD8B8`
port) is **zero** because the LSB lobby login response doesn't populate the
fields FFXi reads (`DAT_04AEE768 + 0x13808` IP / `+0x1380C` port). The dialog
tries to `connect()` to `0.0.0.0:0`, fails silently, the dialog hangs without
any rows, and when the user accepts anyway, `befriend_submit` runs with
`rec[5]=0` and the polcore submit dies with `result_code=5` ("Unable to send.
(5)").

## Native chain (when working)

```
/befriend NAME
  └─> befriend_chat_handler (FFXi+0x79F50)
       │ Builds a stack-allocated dialog descriptor; copies typed name to it.
       └─> befriend_descriptor_init (FFXi+0x113D60)            (zero descriptor)
       └─> befriend_descriptor_clear_search_list_flag (0x1179E0) (clears bit 2)
       └─> befriend_descriptor_set_typed_name (0x117530)        (name → desc+0xC)
       └─> befriend_show_confirm_dialog (0xF1A50)
            │ tick=dialog_tick_simple_confirm (0xF1DA0)
            │ close=dialog_close_callback   (0xF1F20)
            ▼
[every frame, dialog_system_tick (0x1037C0) drives the dialog]
  dialog_tick_simple_confirm (0xF1DA0)
    └─> search_query_send_by_criteria (0xE8B20)
         │ Builds raw IXFF packet on the search-server TCP socket
         │ (FFXi-owned, not polcore):
         │   [0x00] uint32 total_size
         │   [0x04] uint32 'IXFF' magic = 0x46465849
         │   [0x08] uint16 size
         │   [0x0A] uint8  flags = 0x80
         │   [0x0B] uint8  type  = 0  (TCP_SEARCH_ALL)
         │   [0x0C] uint16 0
         │   [0x0E] uint16 0
         │   [0x10] bit-packed criteria via search_pack_criteria_bits
         │           (5-bit len prefix + 7-bit chars per name byte)
         └─> Per-context callback at ctx+0x18 enqueues to
             search_server_thread (0xE83E0) which does socket/connect/send.
            ▼
xi_search responds with packed rows.
  dialog_close_callback (0xF1F20) parses incoming rows and
  stores them at dialog+0x20.
            ▼
User clicks a row.
  befriend_dialog_callback (0x79FE0) fires with selected row.
    └─> befriend_submit (0x1FF550) with row
         │ rec[5] = resolved account_id_hi (real value, not 0!)
         │ rec[6] = packed (zone, world, lo16)
         └─> polcore vt+0x33C/vt+0x340 submit chain
              (already documented in befriend-ixff-wire-format.md)
```

## Connection initialisation

`search_server_thread @ FFXi+0xE83E0` is a worker thread spawned at FFXi
startup by `search_server_ctx_create @ FFXi+0xE8350` (`malloc(0x9E8)` then
`CreateThread`). The thread state machine reads `ctx+0x460` (state index),
processes connect/send/recv via direct ws2_32 imports.

The connect destination is set by `search_server_connect @ FFXi+0xE89E0`,
which is invoked by `dialog_open_callback @ FFXi+0xF15D0`. That callback
reads:
- IP from `DAT_04ABD8B4`
- Port from `DAT_04ABD8B8`

Those globals are populated by `search_server_set_endpoint @ FFXi+0xF1650`,
called from `search_server_login_sm @ FFXi+0xFE000` case 6, which itself runs
when the master friend SM (`friend_master_sm_tick @ FFXi+0xEA610`) reaches
state 3 with a valid lobby login response in `DAT_04AEE768`.

The lobby response source fields (per character slot, stride `0x8C`):
- `DAT_04AEE768 + 0x13824 + slot*0x8C` — search IP (big-endian)
- `DAT_04AEE768 + 0x13828 + slot*0x8C` — search port (htons)

A globally-cached pair is also expected at:
- `DAT_04AEE768 + 0x13808` — current search IP
- `DAT_04AEE768 + 0x1380C` — current search port

## Why it doesn't work in our build

The LSB lobby login response doesn't write the search-server IP/port into the
response payload that FFXi parses. Result chain:

1. `friend_master_sm_tick` runs but `case 3` data sources are zero.
2. `search_server_login_sm` reads zeros.
3. `search_server_set_endpoint` writes zeros to `DAT_04ABD8B4/B8`.
4. `dialog_open_callback` calls `search_server_connect(ctx, 0, 0)`.
5. `search_server_thread` calls `connect()` to `0.0.0.0:0` → instant fail.
6. State machine resets quietly; `dialog_tick_simple_confirm`'s
   `search_query_send_by_criteria` returns 1 every tick (no progress).
7. Dialog never displays rows. User accepts the empty stack descriptor.
8. `befriend_submit` runs with `rec[5]=0`, polcore submits malformed packet,
   server times out, `cat=10 msg=0x70 args=[5]` displayed.

## Wire protocol

Search packets are RAW IXFF (no Blowfish, no polcore). Builders observed:

| Sender                                  | Type | Purpose                                |
|-----------------------------------------|------|----------------------------------------|
| `search_query_send_by_criteria` 0xE8B20 | 0    | TCP_SEARCH_ALL — name/job/level filter |
| `FUN_046E8CA0`                          | 1    | account_id → character lookup          |
| `FUN_046E8DA0`                          | 8    | group list                             |
| `FUN_046E8E70`                          | 2    | RPT short (size 0x24)                  |
| `FUN_046E8F30`                          | 2    | RPT long (size 0x414)                  |
| `FUN_046E9010`                          | 5/6/0x15 | auction-related                    |

The initial handshake before any query is a 16-byte type-0x10 IXFF "hello"
built by `FUN_046E88E0`.

The criteria packer (`search_pack_criteria_bits @ FFXi+0x1140A0`) bit-packs:
- 5-bit length prefix (case 0 = NAME)
- 7-bit per char for the name field
- Other criteria types: 1=JOB, 2=LEVEL_LO, 3=NATION, 4=LEVEL_RANGE, 5=RACE,
  6=ZONE, 7=LEVEL_RANGE_ALT, 0x10=RANK
- Optional 32-bit appendix fields keyed by descriptor flag bits 0x800/
  0x80000/0x100000/0x1000/0x1000000/0x20000

LSB's `xi_search` (`src/search/search_handler.cpp`) already implements this
unpacking format — see lines 605..616 for the name extraction.

## Why not LSB-internal IPC?

In retail FFXi, the search query is opened by the CLIENT directly. xi_search
may IPC with map (via ZMQ in LSB) to look up online players, but that's
an xi_search implementation detail. The FFXi→search hop is plain TCP, and
that's the hop that's broken in our build.

## The fix (LSB-side, two parts)

### 1. LSB lobby/view server — inject search endpoint into login response

The login response packet (parsed by FFXi's `FUN_046FFC40` reading
`DAT_04AEE768 + 0x13824` IP / `+0x13828` port per slot) must carry the
search-server endpoint. In our setup that's `127.0.0.1:54002`.

Find the LSB code that builds this response (likely under
`src/login/`/`src/world/view_session*` or similar). Add the search endpoint
field to the per-character payload.

### 2. xi_search server — accept FFXi's hello + handle name lookups for offline targets

xi_search already runs on port 54002 and parses bit-packed names. Verify:
- Initial 16-byte type-0x10 IXFF "hello" is accepted (handshake before any
  query).
- `TCP_SEARCH_ALL` (type 0) with a name filter returns a row even when the
  target is OFFLINE. Current code paths join `accounts_sessions` to require
  online presence (`src/search/data_loader.cpp:245-256`); for our use case
  we need to also accept offline matches by querying `chars` directly.
- Response format matches what `dialog_close_callback @ FFXi+0xF1F20`
  expects (row layout to be derived from that decompile if needed).

After both fixes, the entire native chain works:
- `/befriend NAME` → search query → row with real account_id → dialog selects
  → `befriend_submit` → polcore IXFF befriend opcode 0x0B class 1 with valid
  identity → server completes the friendship.

## Renamed / annotated functions in Ghidra

| Address      | Name                                                 |
|--------------|------------------------------------------------------|
| `0x04713D60` | `befriend_descriptor_init`                           |
| `0x047179E0` | `befriend_descriptor_clear_search_list_flag`         |
| `0x04717530` | `befriend_descriptor_set_typed_name`                 |
| `0x046F1AF0` | `dialog_framework_open`                              |
| `0x046F1DA0` | `dialog_tick_simple_confirm`                         |
| `0x046F1F20` | `dialog_close_callback`                              |
| `0x046F1560` | `dialog_setup_callback`                              |
| `0x046F15D0` | `dialog_open_callback`                               |
| `0x046F1600` | `dialog_phase1_callback`                             |
| `0x047037C0` | `dialog_system_tick`                                 |
| `0x046E8B20` | `search_query_send_by_criteria`                      |
| `0x047140A0` | `search_pack_criteria_bits`                          |
| `0x04714080` | `search_pack_criteria_default`                       |
| `0x046E9010` | `search_query_send_v1` (auction-related)             |
| `0x046E8350` | `search_server_ctx_create`                           |
| `0x046E83E0` | `search_server_thread`                               |
| `0x046E89E0` | `search_server_connect`                              |
| `0x046F1650` | `search_server_set_endpoint`                         |
| `0x046FE000` | `search_server_login_sm`                             |
| `0x046EA610` | `friend_master_sm_tick`                              |
| `0x046EB030` | `friend_master_sm_set_state`                         |
| `0x046FD680` | `search_server_connection_sm` (LOBBY 54001)          |

## Globals

| Address      | Role                                                  |
|--------------|--------------------------------------------------------|
| `0x04ABD8B0` | search-server context pointer (set by ctx_create)      |
| `0x04ABD8B4` | **search-server IP (zero in our build)**               |
| `0x04ABD8B8` | **search-server port (zero in our build)**             |
| `0x04AEE768` | network/server config struct root                      |
| `0x04AEE768 + 0x13800` | current-server IP (lobby response)            |
| `0x04AEE768 + 0x13804` | current-server port                          |
| `0x04AEE768 + 0x13808` | search-server IP (lobby response source)     |
| `0x04AEE768 + 0x1380C` | search-server port                            |
| `0x04AEE768 + 0x13824 + slot*0x8C` | search IP per char slot          |
| `0x04AEE768 + 0x13828 + slot*0x8C` | search port per char slot         |
