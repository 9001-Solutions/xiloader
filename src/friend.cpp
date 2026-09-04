/* Friend system: bootstrap, send hook, state machine. Worker thread drives
 * on_tick() at ~60Hz. */

#include "defines.h"
#include "console.h"
#include "functions.h"

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <string>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <vector>

#include "friend.h"
#include "profile_proxy.h"

namespace globals {
    extern xiloader::Language g_Language;
    extern bool               g_IsRunning;
    extern uint32_t           g_AccountId;
    extern std::string        g_Username;
    extern char               g_SessionHash[16];
    extern bool               g_EnablePolPush;
}

static const char* polcore_module()
{
    return (globals::g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
}

/* Polcore offsets -- resolved at runtime via signature scanning. Defaults are
 * fallbacks for the current known version. */
static uint32_t OFF_CALLERB_INIT          = 0x22210;
static uint32_t OFF_CALLERB_PUMP          = 0x22260;
static uint32_t OFF_CALLERC_INIT          = 0x28330;
static uint32_t OFF_GENERIC_DRIVER        = 0x1E5D0;
static uint32_t OFF_DESC_ARRAY            = 0x404AD0;
static constexpr uint32_t OFF_DESC_STRIDE = 0x338;
static uint32_t OFF_ARRAY1                = 0x403080;
static uint32_t OFF_ARRAY2                = 0x0B40D8;
static uint32_t OFF_HANDLE                = 0x405800;
static uint32_t OFF_HANDLE_INDEX          = 0x07541C;
static uint32_t OFF_STATUS_TABLE          = 0x3FC920;
static uint32_t OFF_ENRICH_FN             = 0x23E60;
static uint32_t OFF_SOCKADDR              = 0x404AB8;

/* The real profile server sits this far above the ports polcore dials, so the
 * proxy can own 51222/51240 without colliding with it. */
/* Ports this client claimed. Several clients share a machine, so each gets
 * its own pair -- polcore is pointed at these rather than at fixed ports. */
static uint16_t s_proxyProfilePort = 51222;
static uint16_t s_proxyPushPort    = 51240;
static bool     s_proxyActive      = false;
static uint32_t OFF_DONE_FLAG             = 0x99240;
static uint32_t OFF_INIT_FLAG             = 0xAFBD8;
static uint32_t OFF_ENABLE_GATE           = 0x99C80;

/* POL push connection -- the transport for live friend status updates.
 * polcore delivers online/offline transitions as type-0x1F notification
 * records on a persistent connection opened by pol_msg_router state 0x16.
 * On xiloader that SM is never driven (no native per-frame caller during
 * gameplay) and its config block is empty, so the connection is never made
 * and /flist keeps whatever CallerB captured at login. We seed the target
 * and pump the SM ourselves. */
static uint32_t OFF_POL_MSG_ROUTER = 0x44A50;
static uint32_t OFF_POL_SM_STATE   = 0x99408;
/* Obfuscated host buffer consumed by state 0x14. 66 bytes; the length lives
 * at +0x41 (FUN_10047370 passes src[0x41] as the length). */
static constexpr uint32_t OFF_POL_HOST_BUF    = 0x99299;
static constexpr uint32_t OFF_POL_KEY_BLOB    = 0x99288;
static constexpr uint32_t OFF_POL_CONN_HANDLE = 0x99250;
static uint32_t OFF_DONE_FLAG2            = 0x99244;

/* POL push channel.
 *
 * pol_set_conn_config is the ONLY way to unlatch the router: it sits at
 * -0x2C04 from an ordering race on its first tick (DAT_10099C80 still 0), and
 * a negative state matches no case in its switch, so it can never re-enter.
 * The function starts at 0x448A0, not 0x448C8 -- the latter is the body past
 * the prologue. Published in polcore's own function table at index 814. */
static constexpr uint32_t OFF_POL_SET_CONN_CONFIG = 0x448A0;
/* Router mode gate (DAT_10099414); non-zero moves state 0x11 -> 0x12. */
static constexpr uint32_t OFF_POL_ROUTER_MODE = 0x99414;

/* polcore's CRT allocator pair. The push SM frees the key buffer with
 * CALL 0x10051C58 (observed at polcore+0x141A1), so the buffer MUST come from
 * polcore's heap -- allocating it with xiloader's CRT corrupts the heap on the
 * SM's next teardown through case 2/3. */
static constexpr uint32_t OFF_POL_MALLOC = 0x51B95;
/* Per-connection receive; safe to call holding the normal locks. */
static constexpr uint32_t OFF_POL_RECV_CONN = 0x15C30;
/* FUN_10014650(slot, 1) -- tears a connection slot down. */
static constexpr uint32_t OFF_POL_CONN_RELEASE = 0x14650;

/* NOTE: clearing these from the worker does NOT prevent the POL-0008 error
 * screen. FFXi polls for the error every frame while this thread ticks far
 * more slowly, so the clear always loses the race -- and it then wipes the
 * error state, which makes diagnosing the real surfacing path harder. Tried
 * and reverted 2026-08-24. FUN_100458D0 reads DAT_10099254 but is NOT in
 * polcore's published function table, so it is not how FFXi learns of the
 * failure; that path is still unidentified. */

/* The ONE piece of shared state the push channel steals from the friend system.
 *
 * DAT_100AA8C8 is polcore's "session ready" flag:
 *   FUN_10019BA0() sets it 1   (called from status_update_dispatch)
 *   FUN_10019BB0() sets it 0   (called from FUN_10013A80, i.e. EVERY time a
 *                               connection is created)
 *   FUN_10019BC0() reads it
 *
 * The friend path tests it at polcore+0x1EBF6 and bails with -0x203 (-515) when
 * it is zero, which surfaces as the -5136 abort. So creating the push
 * connection at router state 0x16 clears it and every friend operation fails
 * from then on -- permanently, because only a status update would set it back.
 *
 * Verified live: poking it back to 1 on a wedged client restored friend_status
 * and WhoIs immediately.
 *
 * NOT caused by set_globals_v2 (proven innocent by stepping the router: friends
 * stayed healthy through state 0x13), nor by connection-slot contention, nor by
 * router state -- all tested and excluded. */
static constexpr uint32_t OFF_POL_SESSION_READY = 0xAA8C8;

/* polcore's message-filename IV. */
static constexpr uint32_t OFF_POL_IV_LO = 0xAA848;
static constexpr uint32_t OFF_POL_IV_HI = 0xAA84C;

static uint32_t s_session_ready_saved = 0;
static bool     s_session_ready_taken = false;

static void pol_session_ready_snapshot(uint8_t* base)
{
    s_session_ready_saved = *(uint32_t*)(base + OFF_POL_SESSION_READY);
    s_session_ready_taken = true;
}

/* Put the flag back if the push bring-up cleared it. */
static bool pol_session_ready_restore(uint8_t* base)
{
    if (!s_session_ready_taken || s_session_ready_saved == 0)
        return false;
    uint32_t* p = (uint32_t*)(base + OFF_POL_SESSION_READY);
    if (*p != 0)
        return false;
    DWORD prot = 0;
    if (!VirtualProtect(p, 4, PAGE_READWRITE, &prot))
        return false;
    *p = s_session_ready_saved;
    VirtualProtect(p, 4, prot, &prot);
    return true;
}

typedef int (__cdecl* FnPolMsgRouter)(void);
typedef int (__cdecl* FnPolRecvConn)(int);

/* Connection-slot array; each channel is a 0x3A00-byte record. */
static constexpr uint32_t OFF_POL_CONN_ARRAY  = 0x3E58A0;
static constexpr uint32_t POL_CONN_STRIDE     = 0x3A00;
/* Fields, relative to a channel record. */
static constexpr uint32_t CONN_STATE      = 0x208;  /* u8  */
static constexpr uint32_t CONN_FLAGS      = 0x209;  /* u8  */
static constexpr uint32_t CONN_KEY_READY  = 0x39E6; /* u16, polcore sets to 1 */
static constexpr uint32_t CONN_KEY_LEN    = 0x39EC; /* i32 */
static constexpr uint32_t CONN_KEY_BUF    = 0x39F0; /* ptr, THE case-5 gate  */
static constexpr uint32_t CONN_KEY_BUF_B  = 0x39F4; /* ptr */
static constexpr uint32_t CONN_KEY_MASK_A = 0x39F8; /* u32 */
/* Port override read by push SM case 2/3; 0 means use the default 0xC828. */
static constexpr uint32_t CONN_PORT_OVERRIDE = 0x2A8;

/* OFF unless --pol-push. Driving this SM past state 0x16 has killed the client
 * three times: the push SM runs concurrently with the friend SMs the worker
 * already pumps, and they share connection-slot state. */
static bool s_pol_push_enabled = false;
static bool s_seeded = false;
/* Bring-up retry budget. Small and delayed: retrying hard during zone-in is
 * what has killed the client before. */
static constexpr int   POL_PUSH_FAST_RETRIES   = 3;
static constexpr DWORD POL_PUSH_RETRY_DELAY_MS = 5000;
static constexpr DWORD POL_PUSH_SLOW_RETRY_MS  = 30000;
static int   s_push_retries  = 0;
static DWORD s_push_retry_at = 0;

/* Declared here (not further down) so the early push bring-up, which runs
 * during bootstrap before the usual init, can populate it. */
static uint8_t* s_polBase = nullptr;

static uint32_t OFF_TICK_KILLER_JGE = 0x457BB;
static uint32_t OFF_CALLBACK_PTR    = 0xAA974;
static uint32_t OFF_STRUCT_INDEX    = 0x99250;
static uint32_t OFF_NOTIF_STRUCT    = 0x3E58A0;
static uint32_t OFF_TICK_ENABLE     = 0x9924C;
static uint32_t OFF_DISPATCH_MODE   = 0x9941C;

/* NotificationPickup -- separate init/driver pair in polcore for auth (03,03). */
static uint32_t OFF_NOTIF_PICKUP_INIT   = 0x25B50;  /* int __cdecl(a1,a2,a3,a4,a5) */
static uint32_t OFF_NOTIF_PICKUP_DRIVER = 0x25D10;  /* int __cdecl(slot, &output), returns 1 when done */

/* msgrec_recv_pump -- second (3,3) 416B SM that fetches notification records
 * after notif_pump returns count > 0. Same wire opcode/length as notif_pump,
 * disambiguated server-side by body[0x190..0x191]. See
 * memory/project_msgrec_recv_pump.md for the SM trace. */
static uint32_t OFF_MSGREC_RECV_INIT    = 0x27660;  /* int __cdecl(entry_arr, count, stride_flag) */
static uint32_t OFF_MSGREC_RECV_DRIVER  = 0x276E0;  /* int __cdecl(slot), returns 1 when done */

/* WhoIs / friend-status query -- (4,6,0x18) SM. Per-friend status refresh
 * exposed via polcore's function-table slots +0x304/+0x308. See
 * docs/profile-server/whois-status-query.md. */
static uint32_t OFF_WHOIS_INIT          = 0x1D480;  /* int __cdecl(void), returns slot or -1 */
static uint32_t OFF_WHOIS_DRIVER        = 0x1D7D0;  /* int __cdecl(slot), returns 1 when done */

/* friend_status_recv_pump -- bulk live-status SM (Auth (2,3), body=0). Server
 * pushes N*0xA8 records that polcore writes DIRECTLY to Array2 (the source of
 * truth /flist reads). Only path that updates online status post-game-start.
 * See docs/profile-server/friend-status-update-pump.md. */
static uint32_t OFF_FRIEND_STATUS_INIT  = 0x240C0;  /* int __cdecl(void), returns slot or -1 */
static uint32_t OFF_FRIEND_STATUS_DRIVER = 0x237F0; /* int __cdecl(slot), returns 1 when done */
/* DAT_0463CA80 -- completion flag set when case 8 finalize fires. Extracted
 * by scanning forward from FRIEND_STATUS_DRIVER for `89 3D <imm32> E9`. */
static uint32_t OFF_FRIEND_STATUS_DONE   = 0xBCA80;

/* MsgProcess (FFXi+0x200910): scroll-list framework Enter handler. Native path
 * reads event data from caller stack slots that the missing PlayOnline
 * bootstrap leaves uninitialized in private servers. HandleMessageClick
 * bypasses MsgProcess and invokes the event dispatcher at +0x2000B0 with
 * params drawn from msg_obj/globals that ARE populated locally. */
static uint32_t OFF_MSG_PROCESS       = 0x200910;

/* Filename decoder magic constants (polcore vtable+0x70074, FUN_0459B6D0). The
 * decoder base64-decodes 96 chars -> 72 bytes, then triple-XORs blocks 0/1 with
 * these magics and a session IV at polcore +0xAA848/+0xAA84C. The IV is only
 * set when polcore inits with a non-NULL accid; LSB passes NULL so the IV
 * stays (0,0). Mirroring the XOR locally lets polcore's decode produce the
 * intended plaintext accids from filenames written by xiloader. */
static constexpr uint32_t POL_FNAME_XOR_LO = 0x67891133;
static constexpr uint32_t POL_FNAME_XOR_HI = 0x1C273E45;
/* FUN_0480F550 -- friend-system submit. __thiscall(chat_obj, uint8_t* src, uint8_t).
 * Copies 72 bytes from src to chat_obj+0x184, calls FUN_04707520. */
static uint32_t OFF_FRIEND_SUBMIT     = 0x1FF550;
/* FUN_0480F450 -- friend-system error callback. Registered by 4 different
 * submit functions. arg3 = result code (0=success, 1=special, else error
 * dispatched via msg_id 0x6F => "Failed to send reply. (NN)"). */
static uint32_t OFF_FRIEND_ERR_CB     = 0x1FF450;
/* FUN_04702210 -- friend-system network submit chokepoint. __thiscall, 10 stack
 * args, ret 0x28. Returns 0x10 if `this+0x20` is NULL (no conn). */
static uint32_t OFF_FRIEND_REAL_SEND  = 0xF2210;
/* FUN_0480FBB0 -- Reply/Ignore handler for some other menu (op code 0x16).
 * Never fires for the inbox Read action; left hooked for visibility. */
static uint32_t OFF_DISMISS_SUBMIT     = 0x1FFBB0;
/* msg_dismiss_action_v2 (FFXi+0x80FFE0) -- inbox menu-action handler.
 * __thiscall(this, menu_group, action_id). menu_group==5 (mes1rcv inbox):
 *   action 1 = Reply (FUN_0480F6F0); 2 = Ignore (FUN_0480FCD0);
 *   action 4 = READ -> friend_dismiss_submit_outer(..., 0x19). */
static uint32_t OFF_MSG_DISMISS_ACTION = 0x1FFFE0;
/* friend_dismiss_submit_outer (FFXi+0xF7430) -- Read submit wrapper. Returns 2
 * when conn (DAT_04AEE900) is NULL, else the inner SM status (0 = queued). */
static uint32_t OFF_DISMISS_OUTER      = 0xF7430;
/* DAT_04AEE900 (FFXi RVA 0x4DE900) -- friend connection state pointer. NULL
 * causes FUN_04707150 / 04707310 / 04707350 to early-return 2. Resolved at
 * runtime from FRIEND_CONN_TEARDOWN's first instruction imm32. */
static uint32_t OFF_FRIEND_CONN_STATE  = 0x4DE900;
/* polcore FUN_0459B6D0 -- filename/entry decoder. Called by vtable+0x48C thunk
 * inside dismiss_op1_send to extract per-entry fields for the match check
 * against dismissal target (type, ts, from_accid, msg_id). */
static uint32_t OFF_POL_FILENAME_DECODER = 0x1B6D0;  /* thunk; body at +0x1B640 */

/* dismiss_op1_send (FFXi+0xF59D0) -- op[1] of dismiss op_table FFXi+0x361278
 * AND of body-fetch op_table FFXi+0x361268. Body-fetch produces wire traffic;
 * dismiss doesn't. The branch lives inside the polcore vtable+0x1F8 call. */
static uint32_t OFF_DISMISS_OP1_SEND   = 0xF59D0;
/* polcore_queue_sm_driver (FFXi+0xF4170) -- shared queue-walking SM driver.
 * __cdecl(self, state, *entry_out, *err_out). case 0 inits + calls
 * polcore_msgq_rescan_trigger via vtable+0xE8C; case 1 yields entries;
 * case 2 closes slot; case 3 status. */
static uint32_t OFF_POLCORE_QUEUE_SM_DRIVER = 0xF4170;
/* dismiss_completion_callback (FFXi+0x1FFD60) -- fires when the dismiss SM
 * completes. Sets DAT_04C3FFA0=0, plays sound, sets read flag at
 * DAT_04C3FF94+0x64. */
static uint32_t OFF_DISMISS_COMPLETION_CB = 0x1FFD60;
/* dismiss_op2_handler (FFXi+0xF5590) -- op[2] of dismiss op_table 0x361278.
 * Drives FUN_04703F60 file-IO SM (open + read /b/<filename>). Only fires if
 * SM advances state 1->2. */
static uint32_t OFF_DISMISS_OP2_HANDLER = 0xF5590;
/* FUN_04707570 -- friend conn TEARDOWN. Sets DAT_04AEE900 = 0. Called from
 * FUN_046275C0 during shutdown phase. Resolved at runtime. */
static uint32_t OFF_FRIEND_CONN_TEARDOWN = 0xF7570;
/* FUN_04707550 -- friend conn state initializer. Sets DAT_04AEE900 if NULL,
 * allocs 2 receive slots via FUN_04701A40. Called from FUN_046FFFD0 ->
 * FUN_04713260 -> FUN_047121E0, gated on FUN_046EBD10 && FUN_046EBB30 &&
 * !FUN_046E9240(0). One of those guards fails in the LSB build. */
static uint32_t OFF_FRIEND_CONN_INIT   = 0xF7550;
/* FUN_046FFFD0 -- friend system initializer. Allocs DAT_04AEE768 (~86KB),
 * copies account/strings into it, calls FUN_04707550. */
static uint32_t OFF_FRIEND_SYS_INIT    = 0xEFFD0;
/* FUN_04703150 -- common inner sender invoked by every submit that registers a
 * callback at +0x104C. __thiscall(this, op_table_ptr), ret 4. Dispatches by
 * the virtual at *op_table[0]: 0x17 retry, 0x16 OK, else fail (0x10). */
static uint32_t OFF_FRIEND_INNER_SEND = 0xF3150;
/* FUN_04728A00 -- error/notification message dispatcher.
 * __cdecl(int category, int id) -- looks up + shows message by category+id. */
static uint32_t OFF_SHOW_ERROR        = 0x118A00;
/* FUN_04737AA0 -- per-line chat append. __thiscall on the chat log object at
 * [FFXi+0x577150]. Args (msg_str, &flags, 0, 1, 0) -- flags low byte is the
 * channel (MsgProcess uses 0x12). First instruction is a JMP to a polcore
 * thunk; Detours relocates the rel32 so trampoline forwarding is safe. */
static uint32_t OFF_CHAT_APPEND       = 0x127AA0;
static constexpr uint32_t OFF_CHAT_LOG_PTR      = 0x577150;

/* FUN_0480FC90 -- opens mes1rcv or mes2frnd sub-menu (vtable[+0x44]). */
static uint32_t OFF_FC90 = 0x1FFC90;

/* inbox_row_callback (FFXi+0x200420) -- invoked once per inbox row by the
 * friend-system network response handler. param_2 = icon type;
 * param_5 = source_struct pointer. Resolved at runtime; OFF_MSG_OBJ_NATIVE
 * and OFF_INBOX_INIT_DONE both extracted from this function's first 12 bytes. */
static uint32_t OFF_INBOX_ROW_CALLBACK = 0x200420;

static uint32_t OFF_MSG_OBJ_NATIVE = 0x62FF94;   /* native msg_obj global */
/* Store 3 container pointer. Resolved at runtime from the entry accessor
 * (see resolve_ffximain_offsets); the old hardcoded 0x4DD600 reads NULL on
 * builds after 2026-07, which silently disabled do_sync_status entirely. */
static uint32_t OFF_STORE3_PTR    = 0x4DF770;
/* DAT_04C3FB5C in this build. Stale 0x62E9E4 (Δ-0x1178) was reading
 * uninitialized .data and producing the misleading "flistmai NULL" warning. */
static uint32_t OFF_FLISTMAI_PTR  = 0x62FB5C;
/* FUN_047FAC00 in old build. New client moved this -- resolved at runtime
 * via signature scan in resolve_ffximain_offsets. */
static uint32_t OFF_POPULATE_FN   = 0x1EAC00;
/* full_init (inbox-panel initializer) and the two show_menu vis-flag
 * immediates inside it. Resolved by resolve_ffximain_offsets; the defaults
 * are the 2026-05-11 build values. Patched 6A 01 -> 6A 00 to suppress
 * auto-open of the inbox panel when ensure_native_msg_obj fires it. */
static uint32_t OFF_FULL_INIT       = 0x200790;
static uint32_t OFF_FULL_INIT_VIS1  = 0x200809;
static uint32_t OFF_FULL_INIT_VIS2  = 0x200824;
/* PTR_FUN_04948D78 -- flistmai vtable. Used to verify the resolved flistmai
 * pointer hasn't shifted again under build skew. */

/* Resource provider table -- DAT_04C3F328 in this build. 18 dwords; each is
 * a pointer to a resource handle table. Initialized once at engine startup
 * by FUN_047D8480 via FUN_047E0CF0 (the global menu init). flistmai_menu_open
 * indexes RES[1] (windowps), RES[2] (keytops3), RES[5] (menu/contents). */
static constexpr uint32_t OFF_RES_TABLE       = 0x62F328;
/* DAT_04990FA0 -- short[9], indices into RES[2]->table for flistmai+0x68..+0x88 */
static constexpr uint32_t OFF_KEYTOPS_IDX_9   = 0x380FA0;
/* DAT_04990FC4 -- short[5], indices into RES[1]->table for flistmai+0x90..+0xA0 */
static constexpr uint32_t OFF_WINDOWPS_IDX_5  = 0x380FC4;
/* DAT_04990F90 -- short[7], column x-offsets, pointer stored at flistmai+0x30 */
static constexpr uint32_t OFF_COL_OFFSETS     = 0x380F90;
static uint32_t OFF_DISPLAY_CB    = 0xF2750;
/* Same address as OFF_FRIEND_CONN_STATE -- resolved via the teardown anchor. */
#define OFF_NOTIF_MGR_PTR OFF_FRIEND_CONN_STATE
static uint32_t OFF_ADD_NOTIF_FN  = 0xF2680;  /* resolved via OFF_DISPLAY_CB anchor */

/* /befriend chat command handler. __cdecl(input_buf, "/servmes", id=0xD).
 * Bails with -id if iRam04a8c488 != 2 (token count must be 2). On success
 * pops a Yes/No confirm dialog; the dialog's callback (FFXi+0x79FE0) then
 * calls into the friend submit chain. */
static uint32_t OFF_FFXI_BEFRIEND_HANDLER = 0x79F50;
/* Token count global (iRam04a8c488). Set by get_chat_mode in the dispatcher
 * just before calling the handler. */
static uint32_t OFF_FFXI_TOKEN_COUNT      = 0x47C488;
/* Tokenized servmes buffer the handler sees. */
static constexpr uint32_t OFF_FFXI_SERVMES_BUF      = 0x353DF0;
/* Token pointer array (PTR_DAT_049641F0). [0]=cmd, [1]=arg1, etc. The handler
 * reads [1] for the target charname. */
static uint32_t OFF_FFXI_TOKEN_PTRS       = 0x3541F0;
/* DAT message display function (FUN_04762DD0). __cdecl(category, msg_id, ...).
 * Befriend "Unable to send. (N)" emits with category=10, msg_id=0x70 from
 * befriend_response_callback. Catches every localized message displayed. */
static uint32_t OFF_FFXI_DAT_MSG_THUNK    = 0x152DD0;

/* Befriend submit (FFXi+0x1FF550 = befriend_submit). Called from the dialog
 * callback or friend-list menu after the user confirms a target. Walks the
 * chain into polcore via vt+0x33C/vt+0x340. If this never fires after
 * /befriend, the chat dialog never selected a target. */
/* OFF_FFXI_BEFRIEND_SUBMIT -- same function as OFF_FRIEND_SUBMIT; alias kept for clarity. */
#define OFF_FFXI_BEFRIEND_SUBMIT OFF_FRIEND_SUBMIT
/* Befriend op-table state-2 callback (FFXi+0xF49F0 = befriend_op_send).
 * __cdecl(slot, advance). Polled by friend_op_slot_pump; emits the polcore
 * submit calls (vt+0x33C/0x340) and reads the response (vt+0x344). Return
 * value becomes result_code passed to befriend_response_callback. */
static uint32_t OFF_FFXI_BEFRIEND_OP_SEND = 0xF49F0;

/* Native character record initializer (FFXi+0x109D50 = FUN_04709D50).
 * __cdecl, 10 args. Writes param_5 (account_id) to character struct +0x3C388.
 * Caller chain: FUN_047132E0 -> FUN_04700150 (state 7) -> FUN_047098D0 ->
 * FUN_04709D50. param_5 is read from DAT_04AEFAE8+0x15C, populated by
 * FUN_047121E0 from POL XML "globaluniqueno". Since we bypass POL XML, the
 * intermediate buffer holds a placeholder (1). The hook substitutes
 * g_AccountId so the native code path writes the real value to the struct,
 * which the friend dialog gate (befriend_dialog_callback) and downstream
 * befriend submit then read correctly. */
static uint32_t OFF_FFXI_CHAR_RECORD_INIT = 0xF9D50;

/* Inbox enumerator FUN_048102F0 -- called by full_init (FFXi+0x200710) to scan
 * msg/r/b/, fire inbox_row_callback per file, and populate msg_obj's
 * render+data arrays. Gated by DAT_04C3FFA0 (FFXi+0x62FFA0) so it runs once
 * per init; reset that byte to force re-enumeration after deleting a stale
 * msg file. __thiscall(msg_obj, a2, a3, a4) where a2/a3/a4 mirror
 * msg_obj+0x58/+0x5C/+0x60. */
static uint32_t OFF_INBOX_ENUM_FN     = 0x2002F0;  /* resolved at runtime */
static uint32_t OFF_INBOX_INIT_DONE   = 0x62FFA0;
typedef bool (__thiscall* FnInboxEnum)(void* msg_obj, uint32_t a2, uint32_t a3, uint32_t a4);

/* SEH-isolated thunk: __try cannot live in a function with C++ object
 * unwinding (C2712). Returns 1 on success, 0 on SEH exception. */
static int call_inbox_enum_seh(uint8_t* ffxiBase, void* msg_obj,
    uint32_t a2, uint32_t a3, uint32_t a4)
{
    __try
    {
        *(uint8_t*)(ffxiBase + OFF_INBOX_INIT_DONE) = 0;
        FnInboxEnum fn = (FnInboxEnum)(ffxiBase + OFF_INBOX_ENUM_FN);
        fn(msg_obj, a2, a3, a4);
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

static constexpr uint32_t OFF_TYPE5_CHECK = 0x0E751D;
static constexpr uint32_t OFF_POP_CHECK1  = 0x1E9A0F;
static constexpr uint32_t OFF_POP_CHECK2  = 0x1E9A1C;

/* Timing constants (1 tick = ~16ms, ~60 ticks/sec) */
static constexpr int KEEPALIVE_TICKS    = 1800;
static constexpr int PUMP_TIMEOUT       = 3000;
static constexpr int SETTLE_TICKS       = 300;
static constexpr int EARLY_FAIL_TICKS   = 120;
static constexpr int MAX_BACKOFF_TICKS  = 18000;

/* Fixed 12-byte friend session token shared with the profile server. Retail
 * receives this from POL during login; xiloader uses a deterministic constant. */
static const unsigned char s_FriendToken[12] = {
    0x76, 0xCE, 0xAB, 0x6D, 0xC6, 0xFD, 0x04, 0xC9, 0x92, 0xBE, 0x35, 0xF4
};

static volatile DWORD* s_pAuthMode = nullptr;

static uint16_t s_FriendPort = 0;
static volatile bool s_FriendActive = false;

struct FriendSocketState {
    bool init_seen;
    bool auth_rewritten;
};
static std::map<SOCKET, FriendSocketState> s_FriendSockets;
static std::mutex s_FriendSocketsMtx;

static std::string get_local_msg_dir();

struct BefriendRequest {
    std::string charname;
    std::string nickname;
};
static int  s_callerC_slot    = -1;
static int  s_callerC_pumps   = 0;
static bool s_callerC_active  = false;
static bool s_callerC_is_notification = false; /* true = notification pickup, false = befriend */
static char s_befriend_target_charname[16] = {};
static char s_befriend_target_nickname[16] = {};
static std::queue<BefriendRequest> s_befriend_queue;
static std::mutex s_befriend_mtx;

/* write_msg_file pipeline. Replace with native polcore
 * NotificationResponse-driven msg-file writing once that path is online. */
struct NotifMessage {
    uint32_t from_accid;
    uint32_t msg_id;     /* server-side DB id (24-bit); 0 for friend requests */
    uint8_t  msg_type;   /* icon_type: 0=NRM, 9=FOK, 10=FNO */
    char     sender[16];
    char     subject[16];
    char     body[128];
    /* Filename written to disk (96-char custom-base64). Captured at write
     * time so cleanup can DeleteFileA the exact name -- recomputing uses a
     * fresh time(NULL) at +0x34 and yields a different encoding. */
    char     filename[100];
    /* Unix timestamp embedded into filename bytes +0x34..+0x37, used by
     * inbox_row_callback to suppress rows polcore re-emits from its in-memory
     * notification queue (polcore+0xAA980) after a b/->a/ move. */
    uint32_t timestamp;
};
static std::queue<NotifMessage> s_notif_queue;
static std::mutex s_notif_mtx;

/* Mirror of injected notifications so other code paths (HandleMessageClick,
 * indicator sync) can resolve a row index back to its source message. */
static std::vector<NotifMessage> s_cached_messages;

/* Cap on injected messages. >7 entries in render_arr/data_arr corrupts the
 * heap (ntdll fault 0x525ea ~10s post-inject) because the game reallocates
 * these arrays on tab rebuild at a size smaller than msg_obj+0x18
 * (max_items=15) implies, and the per-tick re-sync walks past the new bound. */
static constexpr int MAX_CACHED_MESSAGES = 7;

/* Session-level dedup: prevents writing the same msg file twice per session. */
static std::set<std::string> s_injected_keys;
static int s_pending_notif_count = 0;  /* pending-notification count -- drives overlay badge */

static std::string make_message_key(const NotifMessage& nm)
{
    char buf[80];
    wsprintfA(buf, "%u:%u:%u:%.15s", nm.from_accid, nm.msg_type, nm.msg_id, nm.subject);
    return std::string(buf);
}

static void InjectFriendAccountId(char* buf)
{
    uint16_t low = static_cast<uint16_t>(globals::g_AccountId & 0xFFFF);
    buf[6]  = static_cast<char>(low & 0xFF);
    buf[7]  = static_cast<char>((low >> 8) & 0xFF);
    buf[8]  = static_cast<char>(0xA2);
    buf[9]  = static_cast<char>(0x37);
    buf[10] = static_cast<char>(0x1A);
    buf[11] = static_cast<char>(0x4B);
}

static void InjectFriendToken(char* buf, int offset)
{
    std::memcpy(buf + offset, s_FriendToken, 12);
}

static bool SetAuthMode(const std::string& username)
{
    const char* module = polcore_module();

    auto patternAddr = (DWORD)xiloader::functions::FindPattern(
        module,
        (BYTE*)"\x83\x3D\x00\x00\x00\x00\x02\x75\x39\xC6\x07\x02",
        "xx????xxxxxx");

    if (patternAddr == 0)
    {
        xiloader::console::output(xiloader::color::warning, "SetAuthMode: pattern not found in %s (non-fatal)", module);
        return false;
    }

    DWORD authModeAddr = *(DWORD*)(patternAddr + 2);
    s_pAuthMode = (volatile DWORD*)authModeAddr;

    memset((void*)authModeAddr, 0, 48);
    *(DWORD*)authModeAddr = 1;

    size_t len = username.size();
    if (len > 16) len = 16;
    uint8_t* maskBase = (uint8_t*)(authModeAddr + 0x05);
    for (size_t i = 0; i < 16; i++)
    {
        uint8_t ch = (i < len) ? (uint8_t)username[i] : 0;
        maskBase[15 - i] = ~ch;
    }

    xiloader::console::output_to_channel("friend", "SetAuthMode: g_auth_mode=%d, mask='%s'",
        *s_pAuthMode, username.c_str());

    uint8_t* mask20Base = (uint8_t*)(authModeAddr + 0x15);
    std::memcpy(mask20Base, globals::g_SessionHash, 16);

    /* Auth builder: JNE -> JMP so it always produces a healthy Auth. */
    BYTE* jneAddr = (BYTE*)(patternAddr + 7);
    DWORD oldProtect = 0;
    if (VirtualProtect(jneAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        *jneAddr = 0xEB;
        VirtualProtect(jneAddr, 1, oldProtect, &oldProtect);
    }

    /* Instance #2: JE -> NOP NOP. */
    auto pat2Addr = (DWORD)xiloader::functions::FindPattern(
        module,
        (BYTE*)"\x74\x05\xC6\x07\x01\xEB\x03\xC6\x07\x02",
        "xxxxxxxxxx");
    if (pat2Addr != 0)
    {
        BYTE* found = (BYTE*)pat2Addr;
        DWORD oldProt2 = 0;
        if (VirtualProtect(found, 2, PAGE_EXECUTE_READWRITE, &oldProt2))
        {
            found[0] = 0x90;
            found[1] = 0x90;
            VirtualProtect(found, 2, oldProt2, &oldProt2);
        }
    }

    return true;
}

static bool SetFriendServerConfig(const std::string& ip, uint16_t port)
{
    const char* module = polcore_module();
    HMODULE hMod = GetModuleHandleA(module);
    if (hMod == NULL) return false;

    char* configAddr = (char*)((DWORD)hMod + 0xA30DC);
    char configStr[64] = {};
    snprintf(configStr, sizeof(configStr), "%s:%04X", ip.c_str(), port);
    memcpy(configAddr, configStr, strlen(configStr) + 1);

    xiloader::console::output_to_channel("friend", "SetFriendServerConfig: \"%s\"", configStr);

    *(volatile DWORD*)((DWORD)hMod + OFF_DONE_FLAG) = 0;
    *(volatile DWORD*)((DWORD)hMod + OFF_INIT_FLAG) = 0;

    return true;
}

static bool SetFriendServerSockaddr(const std::string& ip, uint16_t port)
{
    HMODULE hMod = GetModuleHandleA(polcore_module());
    if (hMod == NULL) return false;

    uint8_t* addr = (uint8_t*)((DWORD)hMod + OFF_SOCKADDR);

    unsigned int a, b, c, d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return false;
    uint32_t ipBE = (a << 24) | (b << 16) | (c << 8) | d;

    *(uint16_t*)(addr + 0) = 1;
    *(uint16_t*)(addr + 2) = port;
    *(uint32_t*)(addr + 4) = ipBE;

    xiloader::console::output_to_channel("friend",
        "SetFriendServerSockaddr: %s:%d", ip.c_str(), port);
    return true;
}

static DWORD WINAPI AuthModeMonitorThread(LPVOID)
{
    while (s_pAuthMode == nullptr)
        Sleep(100);

    DWORD lastValue = *s_pAuthMode;

    while (globals::g_IsRunning)
    {
        Sleep(50);
        if (s_pAuthMode == nullptr) continue;

        DWORD currentValue = *s_pAuthMode;
        if (currentValue != lastValue)
        {
            xiloader::console::output(xiloader::color::warning,
                "AuthModeMonitor: g_auth_mode CHANGED %d -> %d, re-patching to 1.",
                lastValue, currentValue);
            *(DWORD*)s_pAuthMode = 1;
            lastValue = 1;
        }
        else
        {
            lastValue = currentValue;
        }
    }
    return 0;
}

static DWORD WINAPI FriendWorkerThread(LPVOID)
{
    xiloader::console::output_to_channel("friend", "FriendSys: worker thread started");

    while (globals::g_IsRunning)
    {
        friend_system::on_tick();
        Sleep(16);
    }

    xiloader::console::output_to_channel("friend", "FriendSys: worker thread stopped");
    return 0;
}

/* Overwrites polcore.dll's JP friend/group title string table with EN
 * equivalents. Retail patches these at runtime; xiloader skips POL bootstrap
 * so the patch is applied directly. */
static void PatchPolcoreTitles()
{
    if (globals::g_Language != xiloader::Language::English)
        return; /* JP keeps original strings; EU uses polcoreeu.dll (layout not RE'd). */

    HMODULE hMod = GetModuleHandleA("polcore.dll");
    if (!hMod)
        return;

    static const char* const titles[10] = {
        "Let's be friends!",
        "Friend registration accepted",
        "Friend registration declined",
        "Deleted",
        "Please delete.",
        "Would you like to join a friend group?",
        "Group registration accepted",
        "Group registration declined",
        "Removed from friend group",
        "Friend group disbanded",
    };

    constexpr DWORD TITLE_TABLE_RVA = 0x743D8;
    constexpr DWORD STRIDE          = 0x80;
    constexpr DWORD COUNT           = 10;

    char* table = (char*)hMod + TITLE_TABLE_RVA;

    DWORD oldProtect = 0;
    if (!VirtualProtect(table, STRIDE * COUNT, PAGE_READWRITE, &oldProtect))
        return;

    for (DWORD i = 0; i < COUNT; ++i)
    {
        char* slot = table + i * STRIDE;
        memset(slot, 0, STRIDE);
        memcpy(slot, titles[i], strlen(titles[i]) + 1);
    }

    VirtualProtect(table, STRIDE * COUNT, oldProtect, &oldProtect);
}

/* Diagnostic: dump polcore's published function table.
 *
 * The POL connection router (pol_msg_router) is latched in its case-0 error
 * state (-0x2C04) because DAT_10099C80 was still 0 on its first tick; a
 * negative state matches no case in its switch, so it can never re-enter.
 * pol_set_conn_config (polcore+0x448C8) is what resets the state AND sets the
 * router mode + host config, but its only Ghidra xref is a false positive from
 * the 0x1043xxxx runtime-code region, so the real entry point has to be found
 * at runtime. GetCommonFunctionTable is polcore's own published surface.
 *
 * Read-only: this walks the table and logs it, it does not call through it. */
static void dump_polcore_function_table(IPOLCoreCom* polcore)
{
    HMODULE hPC = GetModuleHandleA(polcore_module());
    if (hPC == nullptr || polcore == nullptr)
        return;

    /* SEH-isolated thunks: __try cannot live in a function that needs C++
     * object unwinding (C2712), which the logging calls below require. */
    auto invoke_get_table = [](IPOLCoreCom* pc, unsigned long** out) -> HRESULT {
        __try {
            return pc->GetCommonFunctionTable(out);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return E_FAIL;
        }
    };
    auto safe_read = [](unsigned long* t, int i, uintptr_t* out) -> bool {
        __try {
            *out = (uintptr_t)t[i];
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    };

    unsigned long* table = nullptr;
    HRESULT hr = invoke_get_table(polcore, &table);

    if (FAILED(hr) || table == nullptr)
    {
        xiloader::console::output_to_channel("friend",
            "PolFnTable: GetCommonFunctionTable hr=0x%08X table=%p", (unsigned)hr, table);
        return;
    }

    const uintptr_t base = (uintptr_t)hPC;
    const uintptr_t end  = base + 0x451000;

    xiloader::console::output_to_channel("friend",
        "PolFnTable: base=0x%08X table=%p", (unsigned)base, table);

    for (int i = 0; i < 256; i++)
    {
        uintptr_t v = 0;
        if (!safe_read(table, i, &v))
            break;
        if (v == 0)
            continue;
        if (v < base || v >= end)
            continue;

        const uint32_t rva = (uint32_t)(v - base);
        const char* tag = "";
        if (rva == 0x448C8) tag = "  <== pol_set_conn_config";
        else if (rva == 0x46E50) tag = "  <== set_pp_host";
        else if (rva == 0x1EAB0) tag = "  <== set_globals_v2";
        else if (rva == 0x44A50) tag = "  <== pol_msg_router";
        else if (rva == 0x140E0) tag = "  <== push_sm";

        xiloader::console::output_to_channel("friend",
            "PolFnTable: [%3d] polcore+0x%05X%s", i, rva, tag);
    }
}

static void pol_obfuscate(uint8_t* dst, const uint8_t* plain, int len);
static bool pol_push_provide_keys(int chan);

/* Release connection slots left latched in a terminal state.
 *
 * polcore has only THREE slots (OFF_POL_CONN_ARRAY, stride POL_CONN_STRIDE)
 * and FUN_10013A80 refuses a new connection once all are taken. Slot 0 is
 * routinely found at state 0x0E (terminal error) with the in-use bit still
 * set -- a leak that silently costs a third of the pool. Only states 0x0B and
 * 0x0E are released; those are the SM's dead ends. */
static void release_leaked_conn_slots(uint8_t* base)
{
    typedef int (__cdecl* FnConnRelease)(int, int);
    auto release = [](uint8_t* b, int slot) -> int {
        __try {
            auto fn = (FnConnRelease)(b + OFF_POL_CONN_RELEASE);
            return fn(slot, 1);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return INT32_MIN;
        }
    };

    for (int i = 0; i < 3; i++)
    {
        uint8_t* conn = base + OFF_POL_CONN_ARRAY + (uint32_t)i * POL_CONN_STRIDE;
        const uint8_t st = *(conn + CONN_STATE);
        const uint8_t fl = *(conn + CONN_FLAGS);
        if ((fl & 1) == 0)
            continue;
        if (st != 0x0B && st != 0x0E)
            continue;
        const int rc = release(base, i);
        xiloader::console::output_to_channel("friend",
            "PolPush: released leaked conn slot %d (was state=0x%02X flags=0x%02X) rc=%d -> state=0x%02X flags=0x%02X",
            i, st, fl, rc, *(conn + CONN_STATE), *(conn + CONN_FLAGS));
    }
}

/* Bring the push channel up BEFORE the friend system initialises.
 *
 * Order matters: with the friend system established first, bringing push up
 * afterwards wedges friend_status permanently for the rest of the session
 * (router state 0x13 runs set_globals_v2, which rewrites shared session
 * crypto). Running push first lets the friend system derive its keys from the
 * post-push state instead of having them invalidated underneath it.
 *
 * Blocking, with a hard cap -- it must never stall world entry. */
static void bring_up_pol_push_early(uint8_t* base)
{
    if (!globals::g_EnablePolPush || base == nullptr)
        return;

    if (s_polBase == nullptr)
        s_polBase = base;

    release_leaked_conn_slots(base);

    int32_t* state = (int32_t*)(base + OFF_POL_SM_STATE);

    uint8_t host_plain[] = "127.0.0.1";
    const int host_len = (int)sizeof(host_plain);
    uint8_t* hbuf = base + OFF_POL_HOST_BUF;
    DWORD prot = 0;
    if (VirtualProtect(hbuf, 0x42, PAGE_READWRITE, &prot))
    {
        memset(hbuf, 0, 0x42);
        pol_obfuscate(hbuf, host_plain, host_len);
        hbuf[0x41] = (uint8_t)host_len;
        VirtualProtect(hbuf, 0x42, prot, &prot);
    }

    DWORD gp = 0;
    if (VirtualProtect(base + OFF_POL_ROUTER_MODE, 4, PAGE_READWRITE, &gp))
    {
        *(uint32_t*)(base + OFF_POL_ROUTER_MODE) = 1;
        VirtualProtect(base + OFF_POL_ROUTER_MODE, 4, gp, &gp);
    }
    *state = 0x12;

    auto step = [](uint8_t* b, int chan) -> int {
        __try {
            if (chan < 0)
            {
                ((FnPolMsgRouter)(b + OFF_POL_MSG_ROUTER))();
            }
            else
            {
                auto recv = (FnPolRecvConn)(b + OFF_POL_RECV_CONN);
                recv(chan);
            }
            return 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return -1;
        }
    };

    for (int i = 0; i < 400; i++)
    {
        if (step(base, -1) != 0)
        {
            xiloader::console::output(xiloader::color::error,
                "PolPush: router raised during early bring-up -- disabling");
            return;
        }

        const int chan = (int)*(uint32_t*)(base + OFF_POL_CONN_HANDLE);
        if (chan >= 0 && chan < 8)
        {
            uint8_t* conn = base + OFF_POL_CONN_ARRAY + (uint32_t)chan * POL_CONN_STRIDE;
            if (*(conn + CONN_STATE) == 5 && *(uint32_t*)(conn + CONN_KEY_BUF) == 0)
                pol_push_provide_keys(chan);
            step(base, chan);
            if (*(conn + CONN_STATE) == 0x0C)
            {
                s_seeded = true;
                s_pol_push_enabled = true;
                xiloader::console::output(xiloader::color::success,
                    "PolPush: channel registered before friend init (chan %d, %d steps)", chan, i);
                return;
            }
        }
        if (*state < 0)
            break;
        Sleep(25);
    }

    xiloader::console::output(xiloader::color::warning,
        "PolPush: early bring-up did not reach sub-state 0x0C (router=0x%X)", (unsigned)*state);
    s_seeded = true;
}

void friend_system::bootstrap(IPOLCoreCom* polcore)
{
    SetAuthMode(globals::g_Username);
    /* Stand the profile-server proxy up before pointing polcore anywhere.
     *
     * polcore dials the profile server directly from inside the game process,
     * so when that server goes away the socket the GAME owns dies and FFXi
     * drops the player to "POL-0008 Connection terminated or not available"
     * (traced to the vtable method at FFXi+0x23BCE0 posting category-8 DAT
     * messages the instant the socket closes).
     *
     * The proxy owns the ports polcore dials (51222 profile, 51240 push) and
     * forwards to the real server 100 ports up. The client-facing socket is
     * held open across an outage and the proxy reconnects with backoff, so a
     * profile-server restart is invisible to the game.
     *
     * If the bind fails -- most likely the profile server is still sitting on
     * the old ports -- fall through to connecting directly, which is the old
     * behaviour: live status works, but an outage is fatal. */
    {
        static char greet[128] = {};
        _snprintf_s(greet, _TRUNCATE, "PASS acct:%u\r\n",
                    (unsigned)globals::g_AccountId);

        xiloader::console::output_to_channel("friend",
            "ProfileProxy: identifying push channel as account %u",
            (unsigned)globals::g_AccountId);

        if (xiloader::profile_proxy::start("127.0.0.1",
                                           51222, 51322,
                                           51240, 51340,
                                           &s_proxyProfilePort, &s_proxyPushPort,
                                           greet))
        {
            s_proxyActive = true;
        }
        else
        {
            s_proxyProfilePort = 51322;   /* talk to the server directly */
            s_proxyPushPort    = 51340;
            xiloader::console::output(xiloader::color::warning,
                "ProfileProxy: not started -- connecting directly, a profile-server "
                "outage will drop the client");
        }
    }

    SetFriendServerConfig("127.0.0.1", s_proxyProfilePort);

    dump_polcore_function_table(polcore);

    PatchPolcoreTitles();

    /* Must be the port the proxy actually bound, not the 51222 base: on a
     * fast relaunch 51222 is still held and bind_free falls back to 51223+.
     * A stale 51222 here points polcore at a dead port and every slot-0 SM
     * (NotifPickup, friend_status, WhoIs) aborts with status -33. */
    s_FriendPort = s_proxyProfilePort;
    HMODULE hPC = GetModuleHandleA(polcore_module());
    if (hPC)
    {
        uint8_t* addr = (uint8_t*)((DWORD)hPC + OFF_SOCKADDR);
        *(uint32_t*)(addr + 4) = 0x7F000001; /* 127.0.0.1 BE */
    }

    CreateThread(NULL, 0, AuthModeMonitorThread, NULL, 0, NULL);

    /* Release dead connection slots. polcore has only three and routinely
     * leaks slot 0 at state 0x0E with the in-use bit still set. */
    if (hPC)
        release_leaked_conn_slots((uint8_t*)hPC);

    /* DO NOT bring the push channel up here.
     *
     * Tried 2026-08-23 (bring_up_pol_push_early, kept below for reference):
     * registering push before the friend system works -- "channel registered
     * before friend init (chan 0, 6 steps)" -- but the client then never gets
     * past "Connect: new destination ...:54001" and never reaches the lobby.
     * polcore's filename IV changes from 0 to 1 across the call, i.e. the
     * bring-up rewrites session crypto that LOGIN itself depends on. This is
     * the failure current-status.md documents for calling set_globals_v2
     * before CoCreateInstance(FFXiEntry); router state 0x13 runs it.
     *
     * So the ordering fix trades a broken friend list for a broken login. The
     * conflict has to be solved by isolating the push channel's session state,
     * not by resequencing. */

    xiloader::console::output_to_channel("friend",
        "FriendSys: calling polcore->CreateFriendList()...");
    polcore->CreateFriendList();
    xiloader::console::output_to_channel("friend",
        "FriendSys: CreateFriendList() returned");

    /* Initialize polcore's friend message-queue. polcore+0x2E850 walks queue
     * slots from polcore+0xBE0F8 (stride 0x228) and sets the ready flag at
     * polcore+0xBE998 to 1. Without this, polcore_msgq_rescan_trigger
     * (polcore+0x1F0D0) returns -10242 immediately, which propagates through
     * polcore_thunk_msgq_rescan (FFXi+0x49208ED) back into
     * polcore_queue_sm_driver, ending in "Failed to send reply. (20)".
     * Retail runs this init from a polcore COM bootstrap that LSB skips. */
    if (hPC)
    {
        /* SEH-isolated thunk: keeps __try out of the C++-unwinding caller. */
        auto invoke_qinit = [](DWORD handle) -> uint32_t {
            __try {
                typedef void (__cdecl* FnFriendQueueInit)();
                auto qinit = (FnFriendQueueInit)(handle + 0x2E850);
                qinit();
                return *(uint32_t*)(handle + 0xBE998);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return 0xDEADC0DE;
            }
        };
        uint32_t ready_flag = invoke_qinit((DWORD)hPC);
        if (ready_flag == 0xDEADC0DE)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: polcore queue init crashed");
        }
        else
        {
            xiloader::console::output_to_channel("friend",
                "FriendSys: polcore queue init returned, ready=%u", ready_flag);
        }

        /* Expected (0, 0) -- polcore inits with NULL accid via FUN_045C4390
         * -> FUN_0459EB00(0,0,0). Non-zero indicates an unknown path set it. */
        uint32_t fn_iv_lo = *(uint32_t*)((uint8_t*)hPC + OFF_POL_IV_LO);
        uint32_t fn_iv_hi = *(uint32_t*)((uint8_t*)hPC + OFF_POL_IV_HI);
        xiloader::console::output_to_channel("friend",
            "FriendSys: polcore filename IV = (lo=0x%08X, hi=0x%08X)", fn_iv_lo, fn_iv_hi);
    }

    /* Purge stale message files from prior runs -- count_msg_files() otherwise
     * returns the cumulative count and polcore shows hundreds of leftovers. */
    {
        std::string dir = get_local_msg_dir() + "\\r\\b";
        std::string pattern = dir + "\\*";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
        int purged = 0;
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                {
                    std::string path = dir + "\\" + fd.cFileName;
                    if (DeleteFileA(path.c_str()))
                        purged++;
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
        if (purged > 0)
        {
            xiloader::console::output_to_channel("friend",
                "FriendSys: purged %d stale msg files from %s", purged, dir.c_str());
        }
    }

    /* Disable BF crypto on all 4 descriptor slots. CreateFriendList enables
     * it but the BF context is uninitialized in our flow. */
    if (hPC)
    {
        for (int i = 0; i < 4; i++)
        {
            uint8_t* desc = (uint8_t*)((DWORD)hPC + OFF_DESC_ARRAY + i * OFF_DESC_STRIDE);
            desc[0x0B] = 0;
        }
    }
}

void friend_system::activate()
{
    if (s_FriendActive || s_FriendPort == 0)
        return;
    s_FriendActive = true;
    SetFriendServerSockaddr("127.0.0.1", s_FriendPort);

    HMODULE hMod = GetModuleHandleA(polcore_module());
    if (hMod != NULL)
    {
        uint8_t* base = (uint8_t*)(DWORD)hMod;
        *(uint32_t*)(base + OFF_ENABLE_GATE) = 1;
        *(volatile uint32_t*)(base + OFF_DONE_FLAG2) = 1;

        /* Pin the friend sockaddr. polcore+0x201B0 memsets DAT_04984AB8
         * (friend sockaddr) to zero on every negative slot result from
         * polcore_slot_teardown. Once wiped, the friend SM falls into the
         * DNS-resolve path that uses the slot-init port baked at pol+0x1F1B5,
         * which SetProfileServerPort patches to the polsock relay port -- so
         * friend ops dial the lobby relay instead of the profile server and
         * accept fails with op[4]=5. Replacing the prologue with RET (0xC3)
         * makes the wipe a no-op. */
        const uint32_t OFF_NUKE_FRIEND_ADDR = 0x201B0;
        uint8_t* nuke_fn = base + OFF_NUKE_FRIEND_ADDR;
        DWORD oldProtect = 0;
        if (VirtualProtect(nuke_fn, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            *nuke_fn = 0xC3;
            VirtualProtect(nuke_fn, 1, oldProtect, &oldProtect);
        }

        xiloader::console::output_to_channel("friend",
            "Friend system enabled: gate=1, done_flag=1, sockaddr=127.0.0.1:%d, "
            "nuke_friend_addr NOP'd",
            s_FriendPort);

        friend_system::init();
        CreateThread(NULL, 0, FriendWorkerThread, NULL, 0, NULL);
    }
}

bool friend_system::is_active()
{
    return s_FriendActive;
}

void friend_system::on_send(SOCKET s, const char* buf, int len)
{
    if (!s_FriendActive)
        return;

    /* Inject target into BefriendRequest (304B) packets from CallerC.
     * Layout convention: [24:39] = target charname, [40:55] = nickname. */
    if (len == 304 && s_callerC_active && s_befriend_target_charname[0] != 0)
    {
        char* mbuf = const_cast<char*>(buf);
        memcpy(mbuf + 24, s_befriend_target_charname, 15);
        memcpy(mbuf + 40, s_befriend_target_nickname, 15);
        xiloader::console::output_to_channel("friend",
            "FriendSys: injected target '%s' nick='%s' into BefriendRequest",
            s_befriend_target_charname, s_befriend_target_nickname);
    }


    if (len != 40)
    {
        std::lock_guard<std::mutex> lk(s_FriendSocketsMtx);
        auto it = s_FriendSockets.find(s);
        return;
    }

    bool isInit = (buf[0] == 0 && buf[1] == 1 && buf[2] == 0 && buf[3] == 0 &&
                   (uint8_t)buf[4] == 0x01 && buf[5] == 0x00);

    if (isInit)
    {
        {
            std::lock_guard<std::mutex> lk(s_FriendSocketsMtx);
            s_FriendSockets[s] = { true, false };
        }

        if (globals::g_AccountId != 0 &&
            buf[6] == 0 && buf[7] == 0 && buf[8] == 0 &&
            buf[9] == 0 && buf[10] == 0 && buf[11] == 0)
        {
            InjectFriendAccountId(const_cast<char*>(buf));
        }
    }
    else
    {
        std::lock_guard<std::mutex> lk(s_FriendSocketsMtx);
        auto it = s_FriendSockets.find(s);
        if (it != s_FriendSockets.end() && it->second.init_seen && !it->second.auth_rewritten)
        {
            uint8_t mode = (uint8_t)buf[0];

            if (mode == 0x33 || mode == 0x28 || mode == 0x2E)
            {
                xiloader::console::output_to_channel("friend",
                    "Friend Auth: RETAIL mode 0x%02X", mode);
            }
            else if (mode == 0x02)
            {
                static bool s_degraded_logged = false;
                if (!s_degraded_logged)
                {
                    xiloader::console::output(xiloader::color::warning,
                        "Friend Auth: degraded 0x%02X (subsequent occurrences suppressed)", mode);
                    s_degraded_logged = true;
                }
            }
            it->second.auth_rewritten = true;

            if (globals::g_AccountId != 0 &&
                buf[12] == 0 && buf[13] == 0 && buf[14] == 0 && buf[15] == 0 &&
                buf[16] == 0 && buf[17] == 0 && buf[18] == 0 && buf[19] == 0 &&
                buf[20] == 0 && buf[21] == 0 && buf[22] == 0 && buf[23] == 0)
            {
                InjectFriendToken(const_cast<char*>(buf), 12);
            }
        }
    }
}

enum {
    STATE_WAITING = 0,
    STATE_READY,
    STATE_PUMPING,
    STATE_ARRAY_SYNC,
    STATE_SYNC,
    STATE_STEADY,
};

static int  s_state                = STATE_WAITING;
static int  s_tick_counter         = 0;
static int  s_pump_slot            = -1;
static int  s_pump_count           = 0;
static bool s_resync_pending       = false;
static bool s_ui_was_ready         = false;
static bool s_populate_pending     = false;
static int  s_wait_ticks           = 0;
static bool s_patches_applied      = false;
static int  s_consecutive_failures = 0;
static int  s_backoff_ticks        = 0;
static int  s_inner_state_snapshot = -1;

/* Resolved once in STATE_WAITING -> STATE_READY. */
static uint8_t* s_ffxiBase = nullptr;

/* Bypasses native MsgProcess and calls the event dispatcher at +0x2000B0 with
 * (event_type=5, sub_type=1). Dispatcher reads display params from msg_obj and
 * opens the mes2frnd sub-menu. Invoked from the naked Enter hook. */
static void __cdecl HandleMessageClick()
{
    if (s_ffxiBase == nullptr)
        return;

    uint32_t msg_ptr = *(uint32_t*)(s_ffxiBase + OFF_MSG_OBJ_NATIVE);
    if (msg_ptr == 0)
        return;

    uint8_t* obj = (uint8_t*)(uintptr_t)msg_ptr;
    uint16_t selected = *(uint16_t*)(obj + 0x24);
    uint32_t count    = *(uint32_t*)(obj + 0x54);

    xiloader::console::output_to_channel("friend",
        "HandleMessageClick: msg_obj=0x%08X sel=%u count=%u", msg_ptr, selected, count);

    {
        uint32_t diag_render = *(uint32_t*)(obj + 0x68);
        uint32_t diag_data   = *(uint32_t*)(obj + 0x6C);
        if (diag_render != 0 && diag_data != 0)
        {
            for (uint32_t i = 0; i < count && i < 8; i++)
            {
                uint8_t* r = (uint8_t*)(uintptr_t)(diag_render + i * 0x54);
                uint32_t linked_dentry = *(uint32_t*)(r + 0x48);
                uint32_t arith_dentry  = diag_data + i * 0x50;
                const char* linked_sender = (linked_dentry != 0)
                    ? (const char*)(uintptr_t)(linked_dentry + 0x10) : "(null)";
                const char* arith_sender = (const char*)(uintptr_t)(arith_dentry + 0x10);
                xiloader::console::output_to_channel("friend",
                    "  diag row %u: rentry[+0x48]=0x%08X sender='%.16s' | arith[%u]=0x%08X sender='%.16s'",
                    i, linked_dentry, linked_sender, i, arith_dentry, arith_sender);
            }
        }
    }

    /* msg_obj+0x24 selected is one higher than the actual dentry index, so
     * valid range is [1..count]. selected==count means dentry[count-1]. */
    if (selected == 0 || selected > count)
    {
        xiloader::console::output(xiloader::color::warning,
            "  selected(%u) out of range (count=%u), skipping", selected, count);
        return;
    }

    uint32_t data_arr   = *(uint32_t*)(obj + 0x6C);
    uint32_t render_arr = *(uint32_t*)(obj + 0x68);
    const char* body = nullptr;
    const char* sender = nullptr;
    uint32_t dentry_addr = 0;
    uint32_t dentry_idx = (selected > 0) ? (uint32_t)(selected - 1) : 0;

    if (render_arr != 0 && dentry_idx < 15)
    {
        uint8_t* rentry = (uint8_t*)(uintptr_t)(render_arr + dentry_idx * 0x54);
        dentry_addr = *(uint32_t*)(rentry + 0x48);
    }
    /* Fallback: if render_arr lookup failed, compute from data_arr. */
    if (dentry_addr == 0 && data_arr != 0 && dentry_idx < 15)
    {
        dentry_addr = data_arr + dentry_idx * 0x50;
    }

    if (dentry_addr != 0)
    {
        uint8_t* dentry = (uint8_t*)(uintptr_t)dentry_addr;
        sender = (const char*)(dentry + 0x10);
        uint32_t body_ptr = *(uint32_t*)(dentry + 0x08);
        if (body_ptr != 0)
            body = (const char*)(uintptr_t)body_ptr;
        xiloader::console::output_to_channel("friend",
            "  dentry=0x%08X body='%.60s' sender='%.16s'", dentry_addr, body, sender);
    }

    /* Clear rebuild_flag. Some mes2frnd actions (e.g. Leave Unread) leave it
     * set, blocking subsequent Enter with "Cannot do that action while
     * processing another PlayOnline message." */
    *(uint8_t*)(s_ffxiBase + 0x62FFA0) = 0;

    /* Mirror retail MsgProcess: emit Title/From/Message lines to the chat log
     * so the user has a persistent record alongside the action menu. */
    if (dentry_addr != 0 && sender != nullptr)
    {
        uint8_t* dentry = (uint8_t*)(uintptr_t)dentry_addr;
        const char* subj = (const char*)(uintptr_t)*(uint32_t*)(dentry + 0x40);
        if (subj == nullptr)
            subj = (const char*)(dentry + 0x10);  /* fall back to sender if no subj ptr */

        uint32_t chat_log_obj = *(uint32_t*)(s_ffxiBase + OFF_CHAT_LOG_PTR);
        if (chat_log_obj != 0)
        {
            typedef bool (__thiscall* FnChatAppend)(void*, const char*, const void*, int, int, int);
            auto chatAppend = (FnChatAppend)(s_ffxiBase + OFF_CHAT_APPEND);
            uint16_t flags = 0x0012;   /* chat channel byte; matches MsgProcess */
            char line[256];

            auto emit = [&](const char* fmt, const char* val) {
                if (val == nullptr || *val == '\0') return;
                _snprintf_s(line, sizeof(line), _TRUNCATE, fmt, val);
                __try { chatAppend((void*)(uintptr_t)chat_log_obj, line, &flags, 0, 1, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    xiloader::console::output(xiloader::color::error,
                        "  chatAppend crashed (0x%08X)", GetExceptionCode());
                }
            };

            /* Resolve subject via the cached message at the same selected
             * index. Slot 0 is the help template; messages occupy 1..N. */
            char subj_buf[16] = {};
            int idx = (int)((uintptr_t)dentry_addr - (uintptr_t)*(uint32_t*)(obj + 0x6C)) / 0x50;
            if (idx >= 0 && idx < (int)s_cached_messages.size() + 1)
            {
                int cache_idx = idx - 1;
                if (cache_idx >= 0 && cache_idx < (int)s_cached_messages.size())
                {
                    const NotifMessage& nm = s_cached_messages[cache_idx];
                    emit("Title: %s", nm.subject);
                    emit("From: %s",  nm.sender);
                    emit("Message: %s", nm.body);
                }
                else
                {
                    emit("From: %s", sender);
                    emit("Message: %s", body ? body : "");
                }
            }
            else
            {
                emit("From: %s", sender);
                emit("Message: %s", body ? body : "");
            }
            xiloader::console::output_to_channel("friend",
                "  chat log printed (idx=%d, sender='%.16s')", idx, sender);
        }
        else
        {
            xiloader::console::output(xiloader::color::warning,
                "  chat log obj null (FFXi+0x%X)", OFF_CHAT_LOG_PTR);
        }
    }

    /* Emulate retail MsgProcess Enter path: on action==1 it calls FFXi+0x1FFC90
     * on the event_handler at [+0x62FF9C], which copies 72 bytes from arg3 into
     * event_handler+0x20..+0x67 and invokes vt[+0x44] to show_menu("mes2frnd").
     * dentry layout matches retail's arg3 (sender at +0x10, 16B ASCII), so
     * passing dentry copies the sender into event_handler+0x30 where the
     * accept-flow nickname input reads its default. */
    uint32_t event_handler_ptr = *(uint32_t*)(s_ffxiBase + 0x62FF9C);

    if (event_handler_ptr == 0 || dentry_addr == 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "  event_handler=0x%08X dentry=0x%08X -- falling back to plain show_menu",
            event_handler_ptr, dentry_addr);
        typedef void (__thiscall* FnShowMenu)(void* wm, const char* name, int, int);
        auto showMenu = (FnShowMenu)(s_ffxiBase + 0x15E1E0);
        void* wm = (void*)(s_ffxiBase + 0x5EDD10);
        const char* mes2frnd = (const char*)(s_ffxiBase + 0x3841F4);
        __try { showMenu(wm, mes2frnd, 1, 0); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    else
    {
        /* Call +0x1FFC90(event_handler, dentry[0], dentry[4], dentry_ptr, type_code).
         * 5th arg is the normalized message type from FUN_048105D0 (raw 0->0
         * NRM, 1->1, 9->2 FOK, 10->3 FNO, ...), stored at event_handler+0x14
         * (menu SM cursor). Passing the dentry index here advances mes2frnd
         * straight into a sub-state; type_code keeps it at the initial
         * Reply/Ignore/Leave Unread/Exit prompt. */
        uint32_t type_code = 0;
        {
            int idx = (int)((uintptr_t)dentry_addr - (uintptr_t)*(uint32_t*)(obj + 0x6C)) / 0x50;
            int cache_idx = idx - 1;
            if (cache_idx >= 0 && cache_idx < (int)s_cached_messages.size())
            {
                uint8_t mt = s_cached_messages[cache_idx].msg_type;
                /* Mirror FUN_048105D0 for the values we use. */
                switch (mt) {
                    case 0:  type_code = 0; break;
                    case 1:  type_code = 1; break;
                    case 9:  type_code = 2; break;
                    case 10: type_code = 3; break;
                    default: type_code = 0; break;
                }
            }
        }
        typedef void (__thiscall* FnHandleEvent)(void*, uint32_t, uint32_t, uint32_t, uint32_t);
        auto handleEvent = (FnHandleEvent)(s_ffxiBase + 0x1FFC90);
        uint32_t arg1 = *(uint32_t*)(uintptr_t)dentry_addr;
        uint32_t arg2 = *(uint32_t*)(uintptr_t)(dentry_addr + 4);
        __try
        {
            handleEvent((void*)(uintptr_t)event_handler_ptr, arg1, arg2, dentry_addr, type_code);
            xiloader::console::output_to_channel("friend",
                "  +0x1FFC90(event_handler, 0x%08X, 0x%08X, dentry=0x%08X, type=%u) returned OK",
                arg1, arg2, dentry_addr, type_code);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            xiloader::console::output(xiloader::color::error,
                "  +0x1FFC90 crashed (0x%08X)", GetExceptionCode());
        }
    }
}

/* Accept op_table entries (FFXi+0x361220). Each is a state-machine method
 * `fn(this, arg)`; one is registered at friend_mgr+0x1050 and polled by the
 * FFXi per-frame loop. */
struct AcceptOpHookSlot {
    uint32_t rva;
    const char* tag;
    void* real;
};
static AcceptOpHookSlot s_accept_op_hooks[] = {
    { 0xF4400, "op[0] state-dispatcher", nullptr },
    { 0xF5AD0, "op[1]",                  nullptr },
    { 0xF5660, "op[2]",                  nullptr },
    { 0xF4750, "op[3]",                  nullptr },
    { 0xF4BB0, "op[4]",                  nullptr },
    { 0xF4EC0, "op[5]",                  nullptr },
    { 0xF4F00, "op[6]",                  nullptr },
    { 0xF5000, "op[7]",                  nullptr },
};
typedef int (__cdecl* FnAcceptOp)(uint32_t, uint32_t, uint32_t, uint32_t);
/* Per-slot trampolines so each hooks a distinct address. */
#define ACCEPT_OP_TRAMP(N) \
    static int __cdecl Mine_AcceptOp_##N(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4) { \
        int r = ((FnAcceptOp)s_accept_op_hooks[N].real)(a1, a2, a3, a4); \
        xiloader::console::output_to_channel("friend", \
            "AcceptOp[%d %s]: a1=0x%08X a2=0x%08X -> %d (0x%X)", \
            N, s_accept_op_hooks[N].tag, a1, a2, r, r); \
        return r; \
    }
ACCEPT_OP_TRAMP(0) ACCEPT_OP_TRAMP(1) ACCEPT_OP_TRAMP(2) ACCEPT_OP_TRAMP(3)
ACCEPT_OP_TRAMP(4) ACCEPT_OP_TRAMP(5) ACCEPT_OP_TRAMP(6) ACCEPT_OP_TRAMP(7)
#undef ACCEPT_OP_TRAMP

/* Polcore slot allocator (FUN_0459EBA0). Returns slot index (0..3) or negative. */
static uint32_t OFF_POL_SLOT_ALLOC = 0x1EBA0;

/* Polcore registrar (FUN_0459FF20). Per-op init's final call: binds op_type
 * (desc+0x323) and timeout (desc+0x326). __cdecl(desc, op_type, timeout). */
static uint32_t OFF_POL_REGISTRAR  = 0x1FF20;

/* Polcore pumper-gate hook (FUN_0459EBD0). Every per-slot pumper enters here
 * to check active+timeout. __cdecl(char* desc, int slot). Pumper RVA map:
 *   0x1DB90 (4,5) CallerA keepalive    0x1E5D0 (4,7) CallerC notif pickup
 *   0x22260 (1,3) CallerB flist bulk    0x23100 (1,B) ShortAuth
 *   0x24170 (2,6) BefriendRequest      0x27250 (3,2) Confirmation
 *   0x20BB0 (5,4) accept-class         0x210E0 (5,3) accept-class */
static uint32_t OFF_POL_PUMP_GATE = 0x1EBD0;

/* Polcore notification queue enqueuer FUN_0459C570 -- type-3/4/5/6 enqueue
 * chokepoint. __cdecl(uint32_t type, void* data, int len). */
static uint32_t OFF_POL_NOTIF_ENQUEUE = 0x1C570;

/* Polcore notification callback registrar FUN_0459B500 -- sets DAT_0462A974,
 * the callback that FUN_0459C600 dispatches queue entries to. */
static uint32_t OFF_POL_NOTIF_CB_REG = 0x1B500;

/* Real handler for polcore's status-change notification slot (pol+0xAA974).
 *
 * status_update_dispatch (polcore+0x1B71C) decodes every pushed status record
 * and then calls this slot as __cdecl(opcode, data) -- opcode 2 is "friend
 * entry updated", 1 is a text payload, 0/3/4/5/6 are other record classes.
 * Stock polcore installs FUN_1004F4E0 here, which is a bare RET: the client
 * decodes the push, updates its own state, and tells FFXi nothing. That stub
 * is why a polling worker was needed to notice pushed data at all.
 *
 * Runs on polcore's dispatch thread while status_update_dispatch holds its
 * critical section -- do NOT sync, allocate, or log from here. Flag only; the
 * worker does the work.
 *
 * Convention is __cdecl, confirmed by the stub being RET rather than RET 8.
 * Getting this wrong corrupts polcore's stack. */
static void __cdecl Mine_PolStatusNotify(int opcode, void* data)
{
    (void)opcode;
    (void)data;
    s_resync_pending = true;
}

/* Polcore body-fetch driver FUN_045A7550 -- fires on click-to-read body
 * fetch. __cdecl(int slot). */
static uint32_t OFF_POL_BODY_FETCH_DRIVER = 0x27550;


/* /befriend chat command handler hook (FFXi+0x79F50). Logs the token count
 * (iRam04a8c488), the servmes buffer, and the token pointers. The handler
 * bails to "Unable to send. (5)" when token count != 2. */
typedef int (__cdecl* FnBefriendHandler)(void* buf, const char* servmes, int id);
static FnBefriendHandler Real_BefriendHandler = nullptr;
static int __cdecl Mine_BefriendHandler(void* buf, const char* servmes, int id)
{
    uint32_t token_count = 0;
    char servmes_buf[64] = {};
    char tok0[32] = {}, tok1[32] = {};
    __try {
        token_count = *(uint32_t*)(s_ffxiBase + OFF_FFXI_TOKEN_COUNT);
        const char* sm = (const char*)(s_ffxiBase + OFF_FFXI_SERVMES_BUF);
        for (int i = 0; i < 63 && sm[i]; i++) servmes_buf[i] = sm[i];
        const char** tp = (const char**)(s_ffxiBase + OFF_FFXI_TOKEN_PTRS);
        if (tp[0]) for (int i = 0; i < 31 && tp[0][i]; i++) tok0[i] = tp[0][i];
        if (tp[1]) for (int i = 0; i < 31 && tp[1][i]; i++) tok1[i] = tp[1][i];
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    xiloader::console::output_to_channel("friend",
        "BefriendHandler: id=0x%X token_count=%u servmes='%s' tok[0]='%s' tok[1]='%s'",
        id, token_count, servmes_buf, tok0, tok1);

    int r = Real_BefriendHandler ? Real_BefriendHandler(buf, servmes, id) : -id;
    xiloader::console::output_to_channel("friend",
        "BefriendHandler: returned %d (0x%X)", r, r);
    return r;
}

/* befriend_submit (FFXi+0xFF550). __thiscall(this, record_ptr, caller_id).
 * Called by befriend_dialog_callback (caller_id=1) and befriend_dispatch_caller
 * (caller_id=0) after target selection. If this fires, the dialog DID select
 * a target. If we see the chain go through here, downstream polcore SM is
 * the next thing to investigate. */
typedef void (__thiscall* FnBefriendSubmit)(void* self, uint32_t* record, uint32_t caller_id);
static FnBefriendSubmit Real_BefriendSubmit = nullptr;
static void __fastcall Mine_BefriendSubmit(void* self, void* /*edx*/,
                                           uint32_t* record, uint32_t caller_id)
{
    uint32_t r5 = 0, r6 = 0, r0 = 0, r1 = 0;
    __try {
        if (record) {
            r0 = record[0];
            r1 = record[1];
            r5 = record[5];
            r6 = record[6];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    xiloader::console::output_to_channel("friend",
        "BefriendSubmit: this=0x%08X caller_id=%u rec[0]=0x%08X rec[1]=0x%08X rec[5]=0x%08X rec[6]=0x%08X",
        (uint32_t)(uintptr_t)self, caller_id, r0, r1, r5, r6);
    if (Real_BefriendSubmit) Real_BefriendSubmit(self, record, caller_id);
}

/* character_record_init hook (FUN_04709D50). Substitutes g_AccountId for the
 * placeholder value when FFXi populates its character struct from POL XML.
 * Without this, [DAT_04AEED90 + 0x3C388] gets a placeholder (1) because the
 * POL XML parser (FUN_047121E0) didn't run in our bypass flow. */
typedef int (__cdecl* FnCharRecordInit)(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
    uint32_t a5, uint32_t a6, uint32_t a7, uint32_t a8, uint32_t a9, uint32_t a10);
static FnCharRecordInit Real_CharRecordInit = nullptr;
static int s_char_init_log_count = 0;
static int __cdecl Mine_CharRecordInit(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
    uint32_t a5, uint32_t a6, uint32_t a7, uint32_t a8, uint32_t a9, uint32_t a10)
{
    /* a5 is the account_id parameter that gets written to +0x3C388 inside the
     * function. If POL bypass left it as the placeholder, override with our
     * known account_id from the auth handshake. */
    uint32_t orig = a5;
    if (globals::g_AccountId != 0 && (a5 == 0 || a5 == 1))
    {
        a5 = globals::g_AccountId;
    }

    if (s_char_init_log_count < 4)
    {
        s_char_init_log_count++;
        char name[17] = {};
        if (a6) {
            __try {
                for (int i = 0; i < 16 && ((const char*)a6)[i]; i++) name[i] = ((const char*)a6)[i];
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        xiloader::console::output_to_channel("friend",
            "CharRecordInit[%d]: idx=%u acct=%u->%u name='%s'",
            s_char_init_log_count, a1, orig, a5, name);
    }

    return Real_CharRecordInit ? Real_CharRecordInit(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) : 0;
}

/* befriend_op_send (FFXi+0xF49F0). State-2 callback in op-table 0x04971188.
 * Calling convention: __cdecl(slot, advance) -- both args read from stack;
 * function ends with bare RET (caller-clean). DO NOT use __thiscall here:
 * the function-pointer table dispatch in friend_op_slot_pump invokes it
 * via cdecl (PUSH advance, PUSH slot, CALL [tbl]).
 * Return value: 0 = continue, 0x16 = wait, 0x17 = advance state, terminal
 * (5/8/0xB/etc) = error code passed to befriend_response_callback. */
typedef uint32_t (__cdecl* FnBefriendOpSend)(void* slot, uint32_t advance);
static FnBefriendOpSend Real_BefriendOpSend = nullptr;
static int s_op_send_log_count = 0;
static uint32_t __cdecl Mine_BefriendOpSend(void* slot, uint32_t advance)
{
    uint32_t r = Real_BefriendOpSend ? Real_BefriendOpSend(slot, advance) : 0xFFFFFFFF;
    /* Log terminal states (non-0x16, non-0x17, non-0) and the first few
     * polls so we can see SM lifecycle without flooding. Dump the slot's
     * befriend identity fields so we know what target FFXi is submitting. */
    bool terminal = (r != 0 && r != 0x16 && r != 0x17);
    if (terminal || s_op_send_log_count < 4) {
        s_op_send_log_count++;
        uint8_t  retry  = 0;
        uint16_t pollct = 0;
        uint32_t acct_hi = 0, packed = 0, handle = 0;
        __try {
            retry   = *(uint8_t*) ((uint8_t*)slot + 0x12);
            pollct  = *(uint16_t*)((uint8_t*)slot + 0x10);
            handle  = *(uint32_t*)((uint8_t*)slot + 0xC);
            acct_hi = *(uint32_t*)((uint8_t*)slot + 0x38);
            packed  = *(uint32_t*)((uint8_t*)slot + 0x3C);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        xiloader::console::output_to_channel("friend",
            "BefriendOpSend[%d]: slot=0x%08X advance=%u -> 0x%X%s "
            "| acct_hi=0x%08X packed=0x%08X handle=0x%08X retry=%u poll=%u",
            s_op_send_log_count, (uint32_t)(uintptr_t)slot, advance, r,
            terminal ? " (TERMINAL)" : "",
            acct_hi, packed, handle, retry, pollct);
    }
    return r;
}

/* polcore_send_body_sm hook (polcore+0x1F970). __cdecl(desc, size, type,
 * body_ptr). Sub-state machine for the body-send phase (4 sub-states:
 * setup -> encrypt -> send -> poll). Log on first sub-state (state 0) so we
 * see the body just before encryption.
 *
 * Sizes we care about:
 *   0x018 (24B)  -- befriend handshake body
 *   0x1A0 (416B) -- NotificationPickup body (CallerC notification SM) */
static uint32_t OFF_POL_SEND_BODY_SM = 0x1F970;
typedef int (__cdecl* FnPolSendBodySm)(void* desc, uint32_t size, uint32_t type, void* body);
static FnPolSendBodySm Real_PolSendBodySm = nullptr;
static int __cdecl Mine_PolSendBodySm(void* desc, uint32_t size, uint32_t type, void* body)
{
    if (body == nullptr) {
        return Real_PolSendBodySm ? Real_PolSendBodySm(desc, size, type, body) : 0;
    }

    uint8_t state = 0xFF;
    __try { state = *(uint8_t*)((uint8_t*)desc + 0x9); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    (void)state;
    return Real_PolSendBodySm ? Real_PolSendBodySm(desc, size, type, body) : 0;
}

/* Befriend submit outer (FFXi+0xF6FD0 = FUN_04706FD0). Gates on DAT_04AEE900;
 * forwards to FUN_047021B0 -> FUN_04703560 -> inner_send(op_table 0x1010F4).
 * Called by the /befriend chat handler with op_code=0x13. */
static uint32_t OFF_FFXI_BEFRIEND_OUTER = 0xF6FD0;
typedef uint32_t (__cdecl* FnBefriendOuter)(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
    uint32_t a5, uint32_t a6, uint32_t a7, uint32_t a8, uint32_t a9);
static FnBefriendOuter Real_BefriendOuter = nullptr;
static uint32_t __cdecl Mine_BefriendOuter(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
    uint32_t a5, uint32_t a6, uint32_t a7, uint32_t a8, uint32_t a9)
{
    void* ret_ip = _ReturnAddress();
    uint32_t ret_rva = (uint32_t)((uintptr_t)ret_ip - (uintptr_t)s_ffxiBase);
    uint32_t conn = s_ffxiBase ? *(uint32_t*)(s_ffxiBase + OFF_FRIEND_CONN_STATE) : 0;
    xiloader::console::output_to_channel("friend",
        "BefriendOuter: caller=FFXi+0x%X conn=0x%08X args=[%08X %08X %08X %08X %08X %08X %08X %08X %08X]",
        ret_rva, conn, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    uint32_t r = Real_BefriendOuter ? Real_BefriendOuter(a1, a2, a3, a4, a5, a6, a7, a8, a9) : 0xFF;
    xiloader::console::output_to_channel("friend",
        "BefriendOuter: returned %u (0x%X)", r, r);
    return r;
}

/* Befriend op_table submit (FFXi+0xF3560 = FUN_04703560). Inner submit:
 * checks busy flag at self+0x416, calls FUN_04702EF0 to alloc the BefriendRequest
 * payload buffer (returns 0x10 if malloc fails), then calls inner_send with
 * op_table 0x1010F4. */
static uint32_t OFF_FFXI_BEFRIEND_INNER = 0xF3560;
typedef uint32_t (__thiscall* FnBefriendInner)(void* self, uint32_t seq, uint16_t flag,
    void* charname_ptr, uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7, int a8, int a9,
    uint32_t a10, uint32_t a11);
static FnBefriendInner Real_BefriendInner = nullptr;
static uint32_t __fastcall Mine_BefriendInner(void* self, void* /*edx*/, uint32_t seq, uint16_t flag,
    void* charname_ptr, uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7, int a8, int a9,
    uint32_t a10, uint32_t a11)
{
    uint16_t busy = 0;
    char target[16] = {};
    __try {
        busy = *(uint16_t*)((uint8_t*)self + 0x416 * 4);
        if (charname_ptr)
            memcpy(target, charname_ptr, 15);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    xiloader::console::output_to_channel("friend",
        "BefriendInner: this=0x%08X busy=%u target='%s' flag=0x%X a8=%d a9=%d",
        (uint32_t)(uintptr_t)self, busy, target, flag, a8, a9);
    uint32_t r = Real_BefriendInner
        ? Real_BefriendInner(self, seq, flag, charname_ptr, a4, a5, a6, a7, a8, a9, a10, a11)
        : 0xFF;
    xiloader::console::output_to_channel("friend",
        "BefriendInner: returned %u (0x%X)", r, r);
    return r;
}

/* Polcore BefriendRequest driver (polcore+0x24170). Per-slot pumper for the
 * 14-mode befriend state machine: TCP connect -> auth (2,6) -> send 0x130-byte
 * BefriendRequest -> recv response -> parse 0xA8-stride friend records -> close.
 * Native per-frame pump dispatches into this when desc[+0x322]=2,
 * desc[+0x324]=6 matches. If no PolBefriendDriver entry appears in the log
 * after /befriend is typed, the per-frame pump never fired for this slot. */
static uint32_t OFF_POL_BEFRIEND_DRIVER = 0x24170;

/* FUN_0459EEB0(record, friend_table_entry, is_new) -- central insert/update
 * for polcore friend table at +0xB40D8. Writes record to entry+0xA0 (15B
 * name) plus flag bits.
 *
 * FUN_045A3CF0(table_flag, index, op) -- bitmap manager for friend-slot
 * occupancy at DAT_0463CA58. op=1 set, op=0 clear, op=2 read. */
static uint32_t OFF_POL_FRIEND_INSERTER = 0x1EEB0;
static uint32_t OFF_POL_BITMAP_OP       = 0x23CF0;

/* polcore_slot_teardown FUN_0459FBD0 -- called at the end of every slot op
 * with the result code (1 = success, negative = error). */
static uint32_t OFF_POL_SLOT_TEARDOWN = 0x1FBD0;

static bool send_acpt_request(const char* target_charname, const char* nickname);

/* FUN_04707550 hook -- DAT_04AEE900 setter. */
typedef uint32_t (__cdecl* FnFriendConnInit)(void);
static FnFriendConnInit Real_FriendConnInit = nullptr;
static uint32_t __cdecl Mine_FriendConnInit(void)
{
    uint32_t before = s_ffxiBase ? *(uint32_t*)(s_ffxiBase + OFF_FRIEND_CONN_STATE) : 0;
    void* ret_ip = _ReturnAddress();
    uint32_t ret_rva = s_ffxiBase ? (uint32_t)((uintptr_t)ret_ip - (uintptr_t)s_ffxiBase) : 0;
    xiloader::console::output_to_channel("friend",
        "FriendConnInit (FUN_04707550): caller=FFXi+0x%X DAT_04AEE900 before=0x%08X",
        ret_rva, before);
    uint32_t r = Real_FriendConnInit ? Real_FriendConnInit() : 0;
    uint32_t after = s_ffxiBase ? *(uint32_t*)(s_ffxiBase + OFF_FRIEND_CONN_STATE) : 0;
    xiloader::console::output_to_channel("friend",
        "FriendConnInit returned %u, DAT_04AEE900 after=0x%08X", r, after);
    return r;
}

/* FUN_04707570 hook -- friend conn teardown (clears DAT_04AEE900). */
typedef uint8_t (__cdecl* FnFriendConnTeardown)(uint32_t arg);
static FnFriendConnTeardown Real_FriendConnTeardown = nullptr;
static uint8_t __cdecl Mine_FriendConnTeardown(uint32_t arg)
{
    void* ret_ip = _ReturnAddress();
    uint32_t ret_rva = s_ffxiBase ? (uint32_t)((uintptr_t)ret_ip - (uintptr_t)s_ffxiBase) : 0;
    uint32_t before = s_ffxiBase ? *(uint32_t*)(s_ffxiBase + OFF_FRIEND_CONN_STATE) : 0;
    xiloader::console::output(xiloader::color::warning,
        "FriendConnTeardown (FUN_04707570): caller=FFXi+0x%X arg=%u DAT_04AEE900 before=0x%08X",
        ret_rva, arg, before);
    uint8_t r = Real_FriendConnTeardown ? Real_FriendConnTeardown(arg) : 1;
    uint32_t after = s_ffxiBase ? *(uint32_t*)(s_ffxiBase + OFF_FRIEND_CONN_STATE) : 0;
    xiloader::console::output(xiloader::color::warning,
        "FriendConnTeardown returned %u, DAT_04AEE900 after=0x%08X", r, after);
    return r;
}

/* Signature-based offset resolution. Finds anchor functions by unique byte
 * patterns, then extracts data addresses from instruction operands. Falls
 * back to hardcoded defaults on failure. */
static bool resolve_polcore_offsets(uint8_t* base)
{
    const char* mod = polcore_module();
    uint32_t baseAddr = (uint32_t)(uintptr_t)base;
    int resolved = 0;
    bool ok_pump = false, ok_init = false, ok_enrich = false;
    bool ok_drv  = false, ok_callerC = false, ok_tick = false, ok_tickkill = false;
    bool ok_tick_enable = false;

    /* CallerB pump: PUSH ECX; MOV ECX,[ESP+8]; PUSH EBP; MOV EAX,ECX; PUSH ESI;
     * SHL EAX,4; ADD EAX,ECX; PUSH EDI; PUSH ECX; LEA EAX,[EAX*2+EAX];
     * LEA EDX,[ECX+EAX*2]; LEA ESI,[EDX*8+desc_array] */
    DWORD pump = xiloader::functions::FindPattern(mod,
        (const unsigned char*)"\x51\x8B\x4C\x24\x08\x55\x8B\xC1\x56\xC1\xE0\x04\x03\xC1\x57\x51",
        "xxxxxxxxxxxxxxxx");
    if (pump)
    {
        OFF_CALLERB_PUMP = pump - baseAddr;
        OFF_DESC_ARRAY   = *(uint32_t*)(pump + 0x19) - baseAddr;
        OFF_SOCKADDR     = OFF_DESC_ARRAY - 0x18;
        ok_pump = true;
        resolved++;

        /* CallerB init is immediately before pump (PUSH ESI; CALL; MOV ESI,EAX) */
        DWORD init = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\xE8\x00\x00\x00\x00\x8B\xF0\x85\xF6\x7D\x02\x5E\xC3",
            "x?????xxxxxxxx");
        if (init && init < pump && (pump - init) < 0x100)
        {
            OFF_CALLERB_INIT = init - baseAddr;
            ok_init = true;
            resolved++;
        }
    }

    /* Enrich function: PUSH EBX; MOV EBX,[ESP+8]; CMP EBX,0xC8; JB +7; MOV EAX,-0x1C07; POP EBX; RET */
    DWORD enrich = xiloader::functions::FindPattern(mod,
        (const unsigned char*)"\x53\x8B\x5C\x24\x08\x81\xFB\xC8\x00\x00\x00\x72\x07\xB8\xF9\xE3\xFF\xFF\x5B\xC3",
        "xxxxxxxxxxxxxxxxxxxx");
    if (enrich)
    {
        OFF_ENRICH_FN    = enrich - baseAddr;
        OFF_ARRAY2       = *(uint32_t*)(enrich + 0x2A) - baseAddr;
        OFF_STATUS_TABLE = *(uint32_t*)(enrich + 0x6B) - baseAddr;
        ok_enrich = true;
        resolved++;
    }

    /* CallerC-specific driver (hardcodes auth (4,7,0x40)). Disambiguator: only
     * CallerC's driver calls the Auth SM with (4, 7, 0x40), compiled as
     * `6A 40 6A 07 6A 04`. Find that, then scan back to the prologue. */
    {
        const char* auth_sig = "\x6A\x40\x6A\x07\x6A\x04";
        DWORD auth_call = xiloader::functions::FindPattern(mod, (const unsigned char*)auth_sig, "xxxxxx");
        DWORD drv = 0;
        if (auth_call)
        {
            /* Walk backward up to 0x200 bytes for the prologue: 53 56 57 8B 7C 24 10 8B C7 */
            for (int back = 6; back < 0x200; back++)
            {
                uint8_t* p = (uint8_t*)(auth_call - back);
                if (p[0] == 0x53 && p[1] == 0x56 && p[2] == 0x57 &&
                    p[3] == 0x8B && p[4] == 0x7C && p[5] == 0x24 && p[6] == 0x10 &&
                    p[7] == 0x8B && p[8] == 0xC7)
                {
                    drv = (DWORD)p;
                    break;
                }
            }
        }
        if (drv)
        {
            OFF_GENERIC_DRIVER = drv - baseAddr;
            ok_drv = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: CallerC driver pattern FAILED to resolve (auth_sig found=%d)", auth_call != 0);
        }
    }

    /* CallerC init. CallerA (+0x1E580) and CallerC (+0x28330) have byte-
     * identical prologues; the disambiguator is the trailing setup_connection
     * conn_type arg (CallerA=5, CallerC=8). Pattern ends in `\x6A\x00\x6A\x08`
     * (PUSH 0; PUSH 8) to match only CallerC. */
    DWORD callerC = xiloader::functions::FindPattern(mod,
        (const unsigned char*)"\x56\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xF0\x85\xF6\x7C\x2A"
                              "\xC1\xE0\x04\x03\xC6\x57\x8D\x04\x40\x8D\x0C\x46\x8D\x3C\xCD"
                              "\x00\x00\x00\x00\x57\xC6\x07\x01\xE8\x00\x00\x00\x00\x6A\x00\x6A\x08",
        "x?????x????xxxxxxxxxxxxxxxxxxxxx????xxxxx????xxxx");
    if (callerC)
    {
        OFF_CALLERC_INIT = callerC - baseAddr;
        ok_callerC = true;
        resolved++;
    }
    else
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: CallerC init pattern FAILED to resolve (would silently route befriend to CallerA)");
    }

    /* Tick function entry: MOV EAX,[guard]; CMP EAX,EDI; JNE +8; ...
     * The imm32 at offset +1 is OFF_DONE_FLAG (the SM done-flag the tick
     * function reads at entry). Extract it for free. */
    DWORD tick = xiloader::functions::FindPattern(mod,
        (const unsigned char*)"\xA1\x00\x00\x00\x00\x3B\xC7\x75\x08\xB8\x01\x00\x00\x00\x5F\x59\xC3\x53\x55\x56\x57",
        "x????xxxxxxxxxxxxxxxx");
    if (tick)
    {
        ok_tick = true;
        OFF_DONE_FLAG = *(uint32_t*)(tick + 1) - baseAddr;
        /* DONE_FLAG2 and STRUCT_INDEX live in the same polcore SM state struct
         * as DONE_FLAG; they're sibling fields at +4 and +0x10. This layout
         * has been stable across every retail build observed so far. If a
         * future client reshuffles, the misbehaviour will be very loud (the
         * tick will fail to start), so a hardcoded relative offset is safer
         * than risking a silent miss-match. */
        OFF_DONE_FLAG2   = OFF_DONE_FLAG + 0x04;
        OFF_STRUCT_INDEX = OFF_DONE_FLAG + 0x10;
        /* Scan the tick function for the enable-gate read of tick_enable.
         * Two encodings across builds:
         *   New (ffximain-69F0846A / polcore 2026-07-02):
         *     BD 01 00 00 00   MOV EBP, 1
         *     A1 <imm32>       MOV EAX, [tick_enable]
         *     3B C5            CMP EAX, EBP        -> imm32 at +6
         *   Old:
         *     83 3D <imm32> 01 CMP DWORD [tick_enable], 1  -> imm32 at +2
         * The old "83 3D ..01" scan misfires on the new build because the only
         * remaining 83 3D is CMP [dispatch_mode], 3, so match both forms. */
        for (int i = 20; i < 0x200; i++)
        {
            uint8_t* p = (uint8_t*)(tick + i);
            uint32_t addr = 0;
            if (p[0] == 0xBD && p[1] == 0x01 && p[2] == 0x00 && p[3] == 0x00 &&
                p[4] == 0x00 && p[5] == 0xA1 && p[10] == 0x3B && p[11] == 0xC5)
                addr = *(uint32_t*)(p + 6) - baseAddr;   /* MOV EBP,1; MOV EAX,[m]; CMP EAX,EBP */
            else if (p[0] == 0x83 && p[1] == 0x3D && p[6] == 0x01)
                addr = *(uint32_t*)(p + 2) - baseAddr;   /* CMP DWORD [m], 1 */
            else
                continue;
            if (addr > 0x90000 && addr < 0xA0000)
            {
                OFF_TICK_ENABLE = addr;
                ok_tick_enable = true;
                break;
            }
        }
        if (!ok_tick_enable)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: tick_enable scan FAILED (no enable-gate encoding "
                "matched in tick_fn) -- overlay tick would use a stale offset");
        }

        /* JGE tick-killer near the end of the function. Layout:
         * `7D <disp> 81 FD ED FB FF FF` (JGE THEN CMP -1043). */
        bool tk_found = false;
        for (int i = 0x100; i < 0x400; i++)
        {
            uint8_t* p = (uint8_t*)(tick + i);
            /* 7D ?? = JGE +disp; 81 FD ED FB FF FF = CMP EBP, -1043 */
            if (p[0] == 0x7D && p[2] == 0x81 && p[3] == 0xFD &&
                p[4] == 0xED && p[5] == 0xFB && p[6] == 0xFF && p[7] == 0xFF)
            {
                OFF_TICK_KILLER_JGE = (uint32_t)(tick + i) - baseAddr;
                tk_found = true;
                ok_tickkill = true;
                resolved++;
                break;
            }
        }
        if (!tk_found)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: tick-killer JGE pattern FAILED to resolve (patch will not be applied)");
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: tick function entry pattern FAILED to resolve");
    }

    /* HANDLE + HANDLE_INDEX -- referenced together by the polcore handle-table
     * reset function (FUN_0459C9D0 in old build). The unique signature is
     * the sequence `MOV ECX, HANDLE; MOV EDX, -0x20; ADD ESP, 8; SUB EDX,
     * ECX; MOV ESI, alias_table; MOV EDI, 0x40` -- bytes
     * `B9 ?? ?? ?? ?? BA E0 FF FF FF 83 C4 08 2B D1 BE ?? ?? ?? ?? BF 40`.
     * The -0x20 + 0x40 literals are this function's fingerprint. HANDLE
     * is the imm32 of the leading MOV ECX. HANDLE_INDEX is set by a
     * later `C7 05 ?? ?? ?? ?? FF FF FF FF` (MOV [imm32], -1) within
     * the same function -- scan forward up to 0x100 bytes for the first
     * match. */
    bool ok_handle = false, ok_handle_idx = false;
    {
        DWORD h = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xB9\x00\x00\x00\x00\xBA\xE0\xFF\xFF\xFF"
                                  "\x83\xC4\x08\x2B\xD1\xBE\x00\x00\x00\x00"
                                  "\xBF\x40\x00\x00\x00",
            "x????xxxxxxxxxxx????xxxxx");
        if (h)
        {
            OFF_HANDLE = *(uint32_t*)(h + 1) - baseAddr;
            ok_handle = true;
            resolved++;
            /* The handle-table-reset function does `OR EBX, -1` early then
             * either `MOV [HANDLE_INDEX], EBX` (89 1D ...) or
             * `MOV [HANDLE_INDEX], -1` (C7 05 ... FF FF FF FF). The first
             * matching write within the function is HANDLE_INDEX. */
            for (int i = 0x18; i < 0x100; i++)
            {
                uint8_t* p = (uint8_t*)(h + i);
                if (p[0] == 0x89 && p[1] == 0x1D)
                {
                    OFF_HANDLE_INDEX = *(uint32_t*)(p + 2) - baseAddr;
                    ok_handle_idx = true;
                    resolved++;
                    break;
                }
                if (p[0] == 0xC7 && p[1] == 0x05 &&
                    p[6] == 0xFF && p[7] == 0xFF &&
                    p[8] == 0xFF && p[9] == 0xFF)
                {
                    OFF_HANDLE_INDEX = *(uint32_t*)(p + 2) - baseAddr;
                    ok_handle_idx = true;
                    resolved++;
                    break;
                }
            }
        }
        if (!ok_handle)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: HANDLE pattern FAILED to resolve");
        }
        else if (!ok_handle_idx)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: HANDLE_INDEX scan from HANDLE anchor FAILED");
        }
    }

    /* ENABLE_GATE -- read by the polcore SM dispatch entry (FUN_045C4630 in
     * old build). Function layout: `MOV EAX, [DONE_FLAG2]; TEST EAX, EAX;
     * JNZ rel32; MOV EAX, [ENABLE_GATE]; MOV [DONE_FLAG2], 1; SUB EAX, 0`.
     * Bytes: `A1 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? A1 [ENABLE_GATE]
     * C7 05 ?? ?? ?? ?? 01 00 00 00 83 E8 00`. The leading
     * `MOV/TEST/JNZ rel32; MOV imm32; MOV [imm32], 1; SUB EAX, 0` chain
     * is unique to this dispatch entry. */
    bool ok_engate = false;
    {
        DWORD eg = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x85\xC0\x0F\x85\x00\x00\x00\x00"
                                  "\xA1\x00\x00\x00\x00\xC7\x05\x00\x00\x00\x00"
                                  "\x01\x00\x00\x00\x83\xE8\x00",
            "x????xxxx????x????xx????xxxxxxx");
        if (eg)
        {
            OFF_ENABLE_GATE = *(uint32_t*)(eg + 14) - baseAddr;
            ok_engate = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: ENABLE_GATE pattern FAILED to resolve");
        }
    }

    /* INIT_FLAG -- read+zeroed by the polcore session-finalizer
     * (FUN_0459EB80 in old build). Tiny function: `MOV EAX, [INIT_FLAG];
     * TEST EAX, EAX; JZ +0x14; CALL imm; CALL imm; MOV [INIT_FLAG], 0;
     * RET`. Bytes `A1 ?? ?? ?? ?? 85 C0 74 14 E8 ?? ?? ?? ?? E8 ?? ?? ??
     * ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C3`. The exact `74 14` plus the
     * two zero-arg CALLs make this signature unique. */
    bool ok_init_flag = false;
    {
        DWORD ifl = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x85\xC0\x74\x14\xE8\x00\x00\x00\x00"
                                  "\xE8\x00\x00\x00\x00\xC7\x05\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\xC3",
            "x????xxxxx????x????xx????xxxxx");
        if (ifl)
        {
            OFF_INIT_FLAG = *(uint32_t*)(ifl + 1) - baseAddr;
            ok_init_flag = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: INIT_FLAG pattern FAILED to resolve");
        }
    }

    /* NOTIF_STRUCT -- friend-notification global state array. Referenced by
     * the polcore notification init function (FUN_04593610 in old build).
     * The function loads ESI = NOTIF_STRUCT + 0x20A (since it streams
     * through entries at +0x20A stride from a base), then `LEA EAX,
     * [ESI - 0x20A]` recovers the base. Bytes
     * `A1 ?? ?? ?? ?? 85 C0 75 ?? 53 56 33 DB BE ?? ?? ?? ??
     *  8D 86 F6 FD FF FF`. The `-0x20A` displacement (`F6 FD FF FF`) is
     * the unique fingerprint -- no other polcore function uses this
     * delta. Subtract 0x20A from the MOV ESI imm32 to get NOTIF_STRUCT. */
    bool ok_notif_struct = false;
    {
        DWORD ns = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x00\x53\x56\x33\xDB"
                                  "\xBE\x00\x00\x00\x00"
                                  "\x8D\x86\xF6\xFD\xFF\xFF",
            "x????xxx?xxxxx????xxxxxx");
        if (ns)
        {
            OFF_NOTIF_STRUCT = *(uint32_t*)(ns + 14) - baseAddr - 0x20A;
            ok_notif_struct = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: NOTIF_STRUCT pattern FAILED to resolve");
        }
    }

    /* ARRAY1 -- referenced by the alias-table sweep function FUN_045A28F0.
     * Prologue is highly distinctive: `83 EC 40 B9 10 00 00 00 83 C8 FF
     * 33 D2 53 55 56 57 8D 7C 24 10 F3 AB B9 [ARRAY1+0x10]`. The first
     * `B9 10 00 00 00` (MOV ECX, 0x10) is the rep-stosd count; the second
     * `B9 [imm32]` after the stosd loop loads ARRAY1+0x10. Subtract 0x10
     * to get ARRAY1 itself. */
    bool ok_array1 = false;
    {
        DWORD a = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x83\xEC\x40\xB9\x10\x00\x00\x00\x83\xC8\xFF"
                                  "\x33\xD2\x53\x55\x56\x57\x8D\x7C\x24\x10"
                                  "\xF3\xAB\xB9",
            "xxxxxxxxxxxxxxxxxxxxxxxx");
        if (a)
        {
            OFF_ARRAY1 = *(uint32_t*)(a + 0x18) - baseAddr - 0x10;
            ok_array1 = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: ARRAY1 pattern FAILED to resolve");
        }
    }

    /* DISPATCH_MODE -- global SM dispatch-mode word read by the friend
     * teardown handler (FUN_045C4550 in old build) to decide whether to
     * run friend cleanup. Function signature: `PUSH ESI; PUSH EDI; XOR
     * EDI,EDI; PUSH EDI; CALL imm32; PUSH EDI; CALL imm32; MOV EAX,
     * [DISPATCH_MODE]; ADD ESP,8; CMP EAX,2; MOV ESI,1; JL ?? ; CMP
     * EAX,3; JG`. The "in range [2,3]?" check (`83 F8 02 BE 01 00 00 00
     * 7C ?? 83 F8 03 7F`) is unique to this function. We anchor on the
     * MOV EAX,[imm32] immediately before that check and read its imm32. */
    bool ok_dispatch = false;
    {
        DWORD anchor = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x83\xC4\x08\x83\xF8\x02\xBE\x01\x00\x00\x00"
                                  "\x7C\x00\x83\xF8\x03\x7F",
            "xxxxxxxxxxxx?xxxx");
        if (anchor)
        {
            /* MOV EAX, [imm32] is 5 bytes immediately before anchor:
             * `A1 ?? ?? ?? ??`. */
            uint8_t* p = (uint8_t*)(anchor - 5);
            if (p[0] == 0xA1)
            {
                OFF_DISPATCH_MODE = *(uint32_t*)(p + 1) - baseAddr;
                ok_dispatch = true;
                resolved++;
            }
        }
        if (!ok_dispatch)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: DISPATCH_MODE pattern FAILED to resolve "
                "(anchor_found=%d)", anchor != 0);
        }
    }

    /* friend_status_recv_pump (Auth (2,3,0)) -- unique anchor is the case-2
     * call to polcore_send_ixff_header_sm with (slot, A=2, B=3, body=0).
     * cdecl pushes RTL: push 0 (or push EBX when EBX==0), push 3, push 2,
     * push ESI, call rel32. Bytes `6A 03 6A 02 56 E8 ?? ?? ?? ??` are unique
     * across polcore -- no other SM uses (2,3,*) auth. Walk back for the
     * shared slot-SM prologue `51 8B 4C 24 08 53 8B C1 56`.
     *
     * (Old build had the function at +0x237F0; signature anchor at +0x88
     *  into the function body.) */
    bool ok_fs_drv = false;
    {
        DWORD anchor = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x6A\x03\x6A\x02\x56\xE8",
            "xxxxxx");
        DWORD drv = 0;
        if (anchor)
        {
            for (int back = 6; back < 0x200; back++)
            {
                uint8_t* p = (uint8_t*)(anchor - back);
                if (p[0] == 0x51 && p[1] == 0x8B && p[2] == 0x4C &&
                    p[3] == 0x24 && p[4] == 0x08 && p[5] == 0x53 &&
                    p[6] == 0x8B && p[7] == 0xC1 && p[8] == 0x56)
                {
                    drv = (DWORD)p;
                    break;
                }
            }
        }
        if (drv)
        {
            OFF_FRIEND_STATUS_DRIVER = drv - baseAddr;
            ok_fs_drv = true;
            resolved++;

            /* Piggyback: scan forward in the SM body (cases 0..8 ~0xC00B
             * bytes typical) for the case-8 completion-flag store:
             * `83 C4 28 89 3D <imm32> E9`. The unusual `add esp, 0x28`
             * stack cleanup (after FUN_0459FBD0 with many args) immediately
             * precedes the `mov [completion_flag], EDI` we need. */
            for (int fwd = 0x100; fwd < 0x800; fwd++)
            {
                uint8_t* p = (uint8_t*)(drv + fwd);
                if (p[0] == 0x83 && p[1] == 0xC4 && p[2] == 0x28 &&
                    p[3] == 0x89 && p[4] == 0x3D && p[9] == 0xE9)
                {
                    OFF_FRIEND_STATUS_DONE = *(uint32_t*)(p + 5) - baseAddr;
                    resolved++;
                    break;
                }
            }
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_status_recv_pump (2,3,0) pattern FAILED to resolve "
                "(anchor_found=%d)", anchor != 0);
        }
    }

    /* friend_status_recv_pump INIT (FUN_045A40C0) -- unique anchor inside the
     * function body: `PUSH 0x1000; PUSH 0xD; PUSH ESI; CALL <register>` =
     * `68 00 10 00 00 6A 0D 56 E8 ?? ?? ?? ??`. The 0x1000 body-buffer + 0xD
     * dispatch-code combination is specific to this init's slot setup. Walk
     * back for the distinctive prologue `53 55 33 ED E8` (push EBX; push EBP;
     * xor EBP,EBP; call slot_alloc). */
    bool ok_fs_init = false;
    {
        /* Slot-alloc wrapper prologue: `PUSH EBX; PUSH EBP; XOR EBP, EBP;
         * CALL slot_alloc; MOV EBX, EAX; TEST EBX, EBX; JGE +3; POP EBP;
         * POP EBX; RET; MOV EAX, EBX; PUSH ESI; SHL EAX, 4`. */
        DWORD init = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x53\x55\x33\xED\xE8\x00\x00\x00\x00"
                                  "\x8B\xD8\x85\xDB\x7D\x03\x5D\x5B\xC3"
                                  "\x8B\xC3\x56\xC1\xE0\x04",
            "xxxxx????xxxxxxxxxxxxxxx");
        if (init)
        {
            OFF_FRIEND_STATUS_INIT = init - baseAddr;
            ok_fs_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_status init (FUN_45A40C0) pattern FAILED to resolve");
        }
    }

    /* WhoIs / session_refresh_sm DRIVER body (FUN_0459D490). Auth (4,6,0x18)
     * -- unique across polcore. RTL pushes: 0x18, 6, 4, slot. Bytes
     * `6A 18 6A 06 6A 04 56 E8 ?? ?? ?? ??`. Walk back for prologue
     * `53 56 57 8B 7C 24 10 8B C7`. NOTE: existing OFF_WHOIS_DRIVER = 0x1D7D0
     * pointed at a thin trampoline; we target the body directly. Updates the
     * signed-call sites in pump_whois() which use FnWhoIsDriver(slot).
     *
     * Old build: body @ +0x1D490, trampoline @ +0x1D7D0. We resolve body. */
    bool ok_whois_drv = false;
    {
        DWORD anchor = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x6A\x18\x6A\x06\x6A\x04\x56\xE8",
            "xxxxxxxx");
        DWORD drv = 0;
        if (anchor)
        {
            for (int back = 8; back < 0x200; back++)
            {
                uint8_t* p = (uint8_t*)(anchor - back);
                if (p[0] == 0x53 && p[1] == 0x56 && p[2] == 0x57 &&
                    p[3] == 0x8B && p[4] == 0x7C && p[5] == 0x24 &&
                    p[6] == 0x10 && p[7] == 0x8B && p[8] == 0xC7)
                {
                    drv = (DWORD)p;
                    break;
                }
            }
        }
        if (drv)
        {
            OFF_WHOIS_DRIVER = drv - baseAddr;
            ok_whois_drv = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: WhoIs driver (4,6,0x18) pattern FAILED to resolve "
                "(anchor_found=%d)", anchor != 0);
        }
    }

    /* polcore_befriend_driver (FUN_045A4170) -- 14-state befriend SM (case
     * 0..0xD). Prologue: `SUB ESP,0xC; MOV ECX,[ESP+0x10]; PUSH EBX; MOV
     * EAX,ECX; PUSH ESI; SHL EAX,4; ADD EAX,ECX; PUSH ECX; LEA EAX,[EAX+EAX*2];
     * LEA EDX,[ECX+EAX*2]; LEA EBX,[EDX*8 + DESC_BASE]`. The 0xC stack frame
     * + double-LEA stride math + the 14-case switch later are highly specific. */
    bool ok_befriend_drv = false;
    {
        DWORD bd = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x83\xEC\x0C\x8B\x4C\x24\x10\x53\x8B\xC1\x56"
                                  "\xC1\xE0\x04\x03\xC1\x51\x8D\x04\x40\x8D\x14\x41\x8D\x1C\xD5",
            "xxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (bd)
        {
            OFF_POL_BEFRIEND_DRIVER = bd - baseAddr;
            ok_befriend_drv = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_befriend_driver pattern FAILED to resolve");
        }
    }

    /* polcore_send_body_sm -- body-send sub-SM. Anchor on the unique switch
     * core (read slot+9 sub-state, switch 0..3, jump table):
     *   33 C0              XOR EAX,EAX
     *   8A 46 09           MOV AL, [ESI+9]
     *   83 F8 03           CMP EAX, 3
     *   0F 87 EE 00 00 00  JA +0xEE
     *   FF 24 85 <imm32>   JMP [EAX*4 + table]
     * Build 2026-07-02 (ffximain-69F0846A) dropped the old
     * `56 8B 74 24 08` (PUSH ESI; MOV ESI,[ESP+8]) prologue -- `desc` now
     * arrives live in ESI (ESI-in convention) and the entry moved +5 to the
     * XOR. Old pattern anchored on the prologue and no longer matched. If the
     * old prologue is present (pre-2026-07 builds), back up 5 bytes to the
     * real entry. NOTE: the ESI-in ABI is why the Mine_PolSendBodySm hook is
     * no longer attached (see DetourAttach site). */
    bool ok_send_body = false;
    {
        DWORD sb = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x33\xC0\x8A\x46\x09\x83\xF8\x03"
                                  "\x0F\x87\xEE\x00\x00\x00\xFF\x24\x85",
            "xxxxxxxxxxxxxxxxx");
        if (sb)
        {
            uint8_t* pre = (uint8_t*)(uintptr_t)(sb - 5);
            if (pre[0] == 0x56 && pre[1] == 0x8B && pre[2] == 0x74 &&
                pre[3] == 0x24 && pre[4] == 0x08)
                sb -= 5;   /* older build: entry includes the push-esi prologue */
            OFF_POL_SEND_BODY_SM = sb - baseAddr;
            ok_send_body = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_send_body_sm pattern FAILED to resolve");
        }
    }

    /* polcore_body_fetch_driver (FUN_045A7550) -- wraps body-upload SM
     * (FUN_045A6870) with lock + slot validation + second call to the
     * inner driver. Similar shape to notif_pickup wrapper but disambiguated
     * by JMP displacements (`7E 2D` and `74 1E` vs notif's `7E 32`) and
     * the second validation call. */
    bool ok_body_fetch = false;
    {
        DWORD bf = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x57\xE8\x00\x00\x00\x00\x8B\x7C\x24\x0C\x57\xE8"
                                  "\x00\x00\x00\x00\x8B\xF0\x83\xC4\x04\x85\xF6\x7E\x2D"
                                  "\x57\xE8\x00\x00\x00\x00\x8B\xF0\x83\xC4\x04\x85\xF6"
                                  "\x74\x1E",
            "xxx????xxxxxx????xxxxxxxxxxxx????xxxxxxxx");
        if (bf)
        {
            OFF_POL_BODY_FETCH_DRIVER = bf - baseAddr;
            ok_body_fetch = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_body_fetch_driver pattern FAILED to resolve");
        }
    }

    /* polcore_notif_cb_reg (FUN_0459B500) -- notification callback registrar.
     * Prologue: `PUSH -1; CALL <lock>; MOV EAX,[ESP+8]; ADD ESP,4;
     * MOV [CALLBACK_PTR], EAX; RET`. Stores its arg into the CALLBACK_PTR
     * global. The `6A FF E8 ... 8B 44 24 08 83 C4 04 A3` sequence is unique
     * (push -1 + immediate store-to-global). */
    bool ok_notif_cb_reg = false;
    {
        DWORD cb = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x6A\xFF\xE8\x00\x00\x00\x00\x8B\x44\x24\x08\x83\xC4\x04"
                                  "\xA3\x00\x00\x00\x00\xC3",
            "xxx????xxxxxxxx????x");
        if (cb)
        {
            OFF_POL_NOTIF_CB_REG = cb - baseAddr;
            ok_notif_cb_reg = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_notif_cb_reg pattern FAILED to resolve");
        }
    }

    /* polcore_notif_enqueue (FUN_0459C570) -- notification queue enqueuer.
     * Prologue: `MOV EAX,[CALLBACK_PTR]; TEST EAX,EAX; JNE +6; MOV EAX,1;
     * RET; MOV EAX,[QUEUE_COUNT]; CMP EAX,4; JL +3; XOR EAX,EAX; RET`.
     * The imm32 at offset +1 is OFF_CALLBACK_PTR -- extract for free. */
    bool ok_notif_enq = false;
    {
        DWORD ne = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x06\xB8\x01\x00\x00\x00\xC3"
                                  "\xA1\x00\x00\x00\x00\x83\xF8\x04\x7C\x03\x33\xC0\xC3",
            "x????xxxxxxxxxxx????xxxxxxxx");
        if (ne)
        {
            OFF_POL_NOTIF_ENQUEUE = ne - baseAddr;
            OFF_CALLBACK_PTR      = *(uint32_t*)(ne + 1) - baseAddr;
            ok_notif_enq = true;
            resolved += 2;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_notif_enqueue pattern FAILED to resolve");
        }
    }

    /* polcore_registrar (FUN_0459FF20) -- descriptor registration helper.
     * Prologue clears desc+0x318 (8 bytes), then writes magic constants to
     * struct fields at +0x320 (=0xA), +0x322 (=4), +0x323 (input cl), +0x324
     * (=3), +0x326 (input dx). The specific struct offsets 0x318/0x320/
     * 0x322/0x323/0x324/0x326 are unique to this descriptor setup. */
    bool ok_registrar = false;
    {
        DWORD pr = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x8B\x74\x24\x08\x6A\x08\x8D\x86\x18\x03\x00\x00\x50"
                                  "\xE8\x00\x00\x00\x00\x8A\x4C\x24\x14\x66\x8B\x54\x24\x18"
                                  "\x83\xC4\x08\x66\xC7\x86\x20\x03\x00\x00\x0A\x00",
            "xxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxx");
        if (pr)
        {
            OFF_POL_REGISTRAR = pr - baseAddr;
            ok_registrar = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_registrar pattern FAILED to resolve");
        }
    }

    /* polcore_slot_teardown (FUN_0459FBD0) -- slot cleanup helper. Prologue:
     * `MOV EAX,[ESP+8]; TEST EAX,EAX; JGE +5; CALL <err>; PUSH EBX; PUSH ESI;
     * MOV ESI,[ESP+0xC]; OR EBX,-1; MOV ECX,[ESI+4]; TEST ECX,ECX; JL +0x20;
     * MOVSX EAX, BYTE [ESI+1]; SUB EAX,0; JE +0xB`. The `83 CB FF`
     * (OR EBX,-1) + `0F BE 46 01` (signed byte extend from ESI+1) +
     * `83 E8 00` (sub 0 -- same byte test as JE) is the distinguishing
     * combination. */
    bool ok_slot_td = false;
    {
        DWORD st = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x08\x85\xC0\x7D\x05\xE8\x00\x00\x00\x00"
                                  "\x53\x56\x8B\x74\x24\x0C\x83\xCB\xFF\x8B\x4E\x04"
                                  "\x85\xC9\x7C\x20\x0F\xBE\x46\x01\x83\xE8\x00\x74\x0B",
            "xxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxx");
        if (st)
        {
            OFF_POL_SLOT_TEARDOWN = st - baseAddr;
            ok_slot_td = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_slot_teardown pattern FAILED to resolve");
        }
    }

    /* polcore_pump_gate (FUN_0459EBD0) -- entry validator for SM pumps.
     * Prologue: `MOV EAX,[ESP+8]; PUSH ESI; TEST EAX,EAX; JL bail;
     * CMP EAX,4; JGE bail; MOV ESI,[ESP+8]; CMP BYTE [ESI],0; JNE next;
     * MOV EAX,-0x1410; POP ESI; RET`. The 0..3 slot range check + -0x1410
     * (slot stale) sentinel is unique. */
    bool ok_pump_gate = false;
    {
        DWORD pg = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x08\x56\x85\xC0\x0F\x8C\x9A\x00\x00\x00"
                                  "\x83\xF8\x04\x0F\x8D\x91\x00\x00\x00\x8B\x74\x24\x08"
                                  "\x80\x3E\x00\x75\x07\xB8\xF0\xEB\xFF\xFF\x5E\xC3",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (pg)
        {
            OFF_POL_PUMP_GATE = pg - baseAddr;
            ok_pump_gate = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_pump_gate pattern FAILED to resolve");
        }
    }

    /* polcore_friend_inserter (FUN_0459EEB0) -- Array2 record writer. The
     * core "write record to Array2 entry" function. Prologue: `PUSH ESI;
     * MOV ESI,[ESP+0xC]; PUSH EDI; MOV EDI,[ESP+0xC]; XOR ECX,ECX; MOV EAX,
     * [EDI]; AND EAX, 0x60 (visibility bits); OR EAX,ECX; MOV ECX,[ESI+0x98];
     * JE ...; OR ECX,1; ...; AND ECX,~1; MOV [ESI+0x98],ECX`. The 0x60 mask
     * (visibility) + +0x98 (occupied flag) combination is unique to this
     * Array2 writer. */
    bool ok_inserter = false;
    {
        DWORD fi = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x8B\x74\x24\x0C\x57\x8B\x7C\x24\x0C\x33\xC9\x8B\x07"
                                  "\x83\xE0\x60\x0B\xC1\x8B\x8E\x98\x00\x00\x00\x74\x05"
                                  "\x83\xC9\x01\xEB\x03\x83\xE1\xFE\x89\x8E\x98",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (fi)
        {
            OFF_POL_FRIEND_INSERTER = fi - baseAddr;
            ok_inserter = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_friend_inserter pattern FAILED to resolve");
        }
    }

    /* polcore_slot_alloc (FUN_0459EBA0) -- iterates descriptor array looking
     * for free slot (desc[0]==0). Loop: `XOR EAX,EAX; MOV ECX, desc_base;
     * loop: CMP BYTE [ECX],0; JE found; ADD ECX, 0x338 (stride); INC EAX;
     * CMP ECX, desc_end; JL loop; MOV EAX, -256; RET`. The 0x338 stride
     * literal + -256 sentinel return is unique. */
    bool ok_slot_alloc = false;
    {
        DWORD sa = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x33\xC0\xB9\x00\x00\x00\x00\x80\x39\x00\x74\x14"
                                  "\x81\xC1\x38\x03\x00\x00\x40\x81\xF9\x00\x00\x00\x00"
                                  "\x7C\xEC\xB8\x00\xFF\xFF\xFF\xC3",
            "xxx????xxxxxxxxxxxxxx????xxxxxxxx");
        if (sa)
        {
            OFF_POL_SLOT_ALLOC = sa - baseAddr;
            ok_slot_alloc = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_slot_alloc pattern FAILED to resolve");
        }
    }

    /* polcore_filename_decoder body (FUN_0459B640) -- base64-decodes 96-char
     * msg filenames into 72-byte records, then XOR-decrypts. Prologue checks
     * filename length >= 0x60 (96): `PUSH EDI; MOV EDI,[ESP+0xC]; PUSH EDI;
     * CALL strlen; ADD ESP,4; CMP EAX,0x60; JAE +7; MOV EAX,0xFFFFEC00 (-0x1400);
     * POP EDI; RET`. The 0x60 length check + -0x1400 error code are unique
     * to filename validation. We pattern the body; existing OFF_FILENAME_DECODER
     * pointed at a thin thunk that just forwards to this body -- both have
     * identical (arg1, arg2) cdecl signatures so retargeting works. */
    bool ok_fname_dec = false;
    {
        DWORD fd = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x57\x8B\x7C\x24\x0C\x57\xE8\x00\x00\x00\x00\x83\xC4\x04"
                                  "\x83\xF8\x60\x73\x07\xB8\x00\xEC\xFF\xFF\x5F\xC3",
            "xxxxxxx????xxxxxxxxxxxxxxx");
        if (fd)
        {
            OFF_POL_FILENAME_DECODER = fd - baseAddr;
            ok_fname_dec = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: filename_decoder pattern FAILED to resolve");
        }
    }

    /* polcore_bitmap_op (FUN_045A3CF0) -- friend-occupancy bitmap manager.
     * Prologue:
     *   MOV EAX,[ESP+4]   ; op flag (0/1 for friend/linkshell array)
     *   MOV EDX,[ESP+8]   ; bit index
     *   PUSH ESI
     *   XOR ESI,ESI
     *   TEST EAX,EAX
     *   JE +6
     *   ADD EDX, 0xC8     ; +200 for linkshell range
     *   MOV EAX,[ESP+0x10]; op (0=set,1=clear,2=test)
     *   MOV ECX,EDX
     *   AND ECX,7
     *   SAR EDX,3
     *   SUB EAX,0; JE...
     * The 0xC8 (200 friend slots) + the bit-extraction shifts (and 7, sar 3)
     * + dispatcher on `sub eax,0` are the unique fingerprint. */
    bool ok_bitmap_op = false;
    {
        DWORD bo = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x04\x8B\x54\x24\x08\x56\x33\xF6\x85\xC0\x74\x06"
                                  "\x81\xC2\xC8\x00\x00\x00\x8B\x44\x24\x10\x8B\xCA\x83\xE1\x07"
                                  "\xC1\xFA\x03\x83\xE8\x00\x74\x2B",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (bo)
        {
            OFF_POL_BITMAP_OP = bo - baseAddr;
            ok_bitmap_op = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: polcore_bitmap_op pattern FAILED to resolve");
        }
    }

    /* notif_pickup_driver wrapper (FUN_045A5D10) -- wraps notif_pump body
     * @ +0x25B90 with lock-acquire + slot validation. Caller signature
     * (slot, &output) identical to body. We pattern the wrapper since
     * the existing OFF_NOTIF_PICKUP_DRIVER targets it. Distinctive
     * structure: 2 internal validation calls before forwarding to body:
     * `56 57 E8 [val_lock] 8B 7C 24 0C 57 E8 [slot_validate] 8B F0
     * 83 C4 04 85 F6 7E 32 8B 44 24 10 50 57 E8 [body]`. The cleanup
     * `83 C4 04 85 F6 7E 32 8B 44 24 10 50 57 E8` after the validation
     * call is the wrapper's distinguishing tail. */
    bool ok_notif_drv = false;
    {
        DWORD nd = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x57\xE8\x00\x00\x00\x00\x8B\x7C\x24\x0C\x57\xE8"
                                  "\x00\x00\x00\x00\x8B\xF0\x83\xC4\x04\x85\xF6\x7E\x32"
                                  "\x8B\x44\x24\x10\x50\x57\xE8",
            "xxx????xxxxxx????xxxxxxxxxxxxxxxx");
        if (nd)
        {
            OFF_NOTIF_PICKUP_DRIVER = nd - baseAddr;
            ok_notif_drv = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: notif_pickup_driver wrapper pattern FAILED to resolve");
        }
    }

    /* msgrec_recv_pump body (FUN_045A76E0) -- auth (3,3,0x1A0) bulk msg
     * record receiver. Shares auth class with notif_pump and
     * friendlist_recv_pump, so disambiguate via case-3 literal push:
     * `FUN_04592330(slot+0x10, &DAT_045F53B8, 0x17F)`. The byte sequence
     * `68 [literal_addr] 68 7F 01 00 00` (PUSH imm32; PUSH 0x17F) is the
     * unique fingerprint -- notif_pump and friendlist_recv push a register
     * value here, only msgrec uses a literal. Walk back ~0xE0 bytes for
     * the body prologue `53 56 57 E8` (push EBX/ESI/EDI; call lock). */
    bool ok_msgrec_drv = false;
    {
        /* Classic slot-SM prologue + slot*17 descriptor calc. msgrec is the
         * only (3,3,0x1A0) function in polcore that begins with the lock
         * call (notif_pump body starts with `MOV ECX,[ESP+4]; PUSH EBX`
         * with no lock call). Bytes:
         * `53 56 57 E8 ?? ?? ?? ?? 8B 4C 24 10 8B C1 51 C1 E0 04 03 C1`
         *  = PUSH EBX/ESI/EDI; CALL polcore_lock; MOV ECX,[ESP+0x10];
         *    MOV EAX,ECX; PUSH ECX; SHL EAX,4; ADD EAX,ECX
         * Unique across polcore -- verified one match in both old (+0x276E0)
         * and new (+0x276E0, same RVA) dumps. The earlier (FAIL'd, then
         * crash-loop) pattern resolved to a DIFFERENT function with a
         * NEG/SBB stack-shuffle prologue, which on call corrupted polcore
         * state. */
        DWORD body = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x53\x56\x57\xE8\x00\x00\x00\x00"
                                  "\x8B\x4C\x24\x10\x8B\xC1\x51\xC1\xE0\x04\x03\xC1",
            "xxxx????xxxxxxxxxxxx");
        if (body)
        {
            OFF_MSGREC_RECV_DRIVER = body - baseAddr;
            ok_msgrec_drv = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: msgrec_recv_pump pattern FAILED to resolve");
        }
    }

    /* WhoIs INIT body (FUN_0459D400). Short function: push EBX; push EDI;
     * call lock; call slot_alloc; mov EDI,EAX; xor EBX,EBX; cmp EDI,EBX;
     * jge body. Bytes `53 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 33 DB 3B FB 7D`.
     * Unique combination across polcore -- no other slot allocator caller
     * uses this exact prologue + register sequence.
     *
     * Old build: body @ +0x1D400, trampoline @ +0x1D480. We resolve body. */
    bool ok_whois_init = false;
    {
        DWORD init = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x53\x57\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00"
                                  "\x8B\xF8\x33\xDB\x3B\xFB\x7D",
            "xxx????x????xxxxxxx");
        if (init)
        {
            OFF_WHOIS_INIT = init - baseAddr;
            ok_whois_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: WhoIs init (FUN_45A9D400) pattern FAILED to resolve");
        }
    }

    /* notif_pickup_init (FUN_045A5B50) -- 5-arg trampoline that grabs the
     * polcore lock and forwards all 5 stack args to the inner allocator
     * (FUN_045A5AD0). Distinctive shuffle: pulls [ESP+0x18], [ESP+0x14],
     * [ESP+0x10] into EAX/ECX/EDX, then re-pushes after each subsequent
     * load adjusts ESP. Long-form bytes:
     *  56 E8 ?? ?? ?? ?? 8B 44 24 18 8B 4C 24 14 8B 54 24 10
     *  50 8B 44 24 10 51 8B 4C 24 10 52 50 51 E8
     *
     * FRAGILITY (verified 2026-07-02, ffximain-69F0846A): this shuffle is NOT
     * unique -- a near-identical 5-arg forwarding trampoline exists (rva
     * 0x273B0 in that build; notif_pickup_init is at 0x25B50). FindPattern
     * returns the lowest-address match, so this resolves correctly ONLY
     * because notif_pickup_init sits below the sibling. If a future build
     * reorders them, this silently resolves to the wrong function with no
     * FAIL in the dashboard. To harden: extend the pattern to include the
     * final E8's target (the inner allocator differs between the two) once a
     * build-stable distinguishing byte is found. Until then this is
     * first-match-dependent by design. */
    bool ok_np_init = false;
    {
        DWORD np = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\xE8\x00\x00\x00\x00\x8B\x44\x24\x18"
                                  "\x8B\x4C\x24\x14\x8B\x54\x24\x10\x50"
                                  "\x8B\x44\x24\x10\x51\x8B\x4C\x24\x10"
                                  "\x52\x50\x51\xE8",
            "xx????xxxxxxxxxxxxxxxxxxxxxxxxx?");
        if (np)
        {
            OFF_NOTIF_PICKUP_INIT = np - baseAddr;
            ok_np_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: notif_pickup_init pattern FAILED to resolve");
        }
    }

    /* msgrec_recv_init (FUN_045A7660) -- 3-arg slot allocator. Distinctive
     * tail writes a, b, c into ESI+0xC0/0xC4/0xCC/0xD0 then `MOV [ESI],1`
     * then PUSH 0x1000; PUSH 0xA literal pair (msgrec capacity + class
     * arg). Anchor on the field-write sequence which is unique to this
     * function in polcore, then walk back for the `57 E8 ?? ?? ?? ?? E8`
     * prologue. */
    bool ok_mr_init = false;
    {
        DWORD anchor = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x89\x96\xC0\x00\x00\x00\x89\x86\xC4\x00\x00\x00"
                                  "\x89\x8E\xCC\x00\x00\x00\x89\x86\xD0\x00\x00\x00"
                                  "\xC6\x06\x01",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxx");
        DWORD body = 0;
        if (anchor)
        {
            for (int back = 0x10; back < 0x80; back++)
            {
                uint8_t* p = (uint8_t*)(anchor - back);
                if (p[0] == 0x57 && p[1] == 0xE8 &&
                    p[6] == 0xE8 && p[11] == 0x8B && p[12] == 0xF8)
                {
                    body = (DWORD)p;
                    break;
                }
            }
        }
        if (body)
        {
            OFF_MSGREC_RECV_INIT = body - baseAddr;
            ok_mr_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: msgrec_recv_init pattern FAILED to resolve "
                "(anchor_found=%d)", anchor != 0);
        }
    }

    /* pol_msg_router (polcore+0x44A50) -- the POL connection state machine
     * that opens the push channel carrying friend status notifications.
     * Prologue is distinctive (0x178 stack frame + 4 pushes + the state
     * global read):
     *   81 EC 78 01 00 00  SUB ESP,0x178
     *   53 55 56 57        PUSH EBX,EBP,ESI,EDI
     *   33 FF 57           XOR EDI,EDI; PUSH EDI
     *   E8 rel32           CALL
     *   8B 0D <imm32>      MOV ECX,[sm_state]   <- state global at +20
     *   A1 <imm32>         MOV EAX,[prev_state]
     * Also yields OFF_POL_SM_STATE for free. */
    bool ok_pol_router = false;
    {
        static const unsigned char PR_PAT[] = {
            0x81, 0xEC, 0x78, 0x01, 0x00, 0x00, 0x53, 0x55, 0x56, 0x57, 0x33, 0xFF,
            0x57, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xA1, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x04, 0x3B, 0xC8, 0x74, 0x06,
            0x89, 0x0D, 0x00, 0x00, 0x00, 0x00,
        };
        DWORD pr = xiloader::functions::FindPattern(mod, PR_PAT,
            "xxxxxxxxxxxxxx????xx????x????xxxxxxxxx????");
        if (pr)
        {
            OFF_POL_MSG_ROUTER = pr - baseAddr;
            OFF_POL_SM_STATE   = *(uint32_t*)(pr + 20) - baseAddr;
            ok_pol_router = true;
            resolved += 2;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: pol_msg_router pattern FAILED to resolve");
        }
    }

    /* Per-pattern resolution log -- surfaces silent failures. */
    bool all_ok = ok_pump && ok_init && ok_enrich && ok_drv && ok_callerC &&
                  ok_tick && ok_tick_enable && ok_tickkill && ok_fs_drv && ok_fs_init &&
                  ok_whois_drv && ok_whois_init && ok_notif_drv && ok_msgrec_drv &&
                  ok_bitmap_op && ok_fname_dec && ok_slot_alloc && ok_inserter &&
                  ok_pump_gate && ok_slot_td && ok_registrar && ok_notif_enq &&
                  ok_notif_cb_reg && ok_body_fetch && ok_send_body && ok_befriend_drv &&
                  ok_np_init && ok_mr_init && ok_dispatch &&
                  ok_handle && ok_handle_idx && ok_array1 &&
                  ok_engate && ok_init_flag && ok_notif_struct && ok_pol_router;
    xiloader::console::output(all_ok ? xiloader::color::success : xiloader::color::warning,
        "FriendSys: polcore offsets resolved: pump=%s init=%s enrich=%s drv=%s "
        "callerC=%s tick=%s tick_kill=%s fs_drv=%s fs_init=%s whois_drv=%s "
        "whois_init=%s notif_drv=%s msgrec_drv=%s bitmap_op=%s fname_dec=%s "
        "slot_alloc=%s inserter=%s pump_gate=%s slot_td=%s registrar=%s "
        "notif_enq=%s notif_cb_reg=%s body_fetch=%s send_body=%s befriend_drv=%s "
        "np_init=%s mr_init=%s dispatch=%s handle=%s handle_idx=%s array1=%s "
        "engate=%s init_flag=%s notif_struct=%s pol_router=%s (%d/36)",
        ok_pump       ? "ok" : "FAIL",
        ok_init       ? "ok" : "FAIL",
        ok_enrich     ? "ok" : "FAIL",
        ok_drv        ? "ok" : "FAIL",
        ok_callerC    ? "ok" : "FAIL",
        ok_tick       ? "ok" : "FAIL",
        ok_tickkill   ? "ok" : "FAIL",
        ok_fs_drv     ? "ok" : "FAIL",
        ok_fs_init    ? "ok" : "FAIL",
        ok_whois_drv  ? "ok" : "FAIL",
        ok_whois_init ? "ok" : "FAIL",
        ok_notif_drv  ? "ok" : "FAIL",
        ok_msgrec_drv ? "ok" : "FAIL",
        ok_bitmap_op  ? "ok" : "FAIL",
        ok_fname_dec  ? "ok" : "FAIL",
        ok_slot_alloc ? "ok" : "FAIL",
        ok_inserter   ? "ok" : "FAIL",
        ok_pump_gate  ? "ok" : "FAIL",
        ok_slot_td    ? "ok" : "FAIL",
        ok_registrar     ? "ok" : "FAIL",
        ok_notif_enq     ? "ok" : "FAIL",
        ok_notif_cb_reg  ? "ok" : "FAIL",
        ok_body_fetch    ? "ok" : "FAIL",
        ok_send_body     ? "ok" : "FAIL",
        ok_befriend_drv  ? "ok" : "FAIL",
        ok_np_init       ? "ok" : "FAIL",
        ok_mr_init       ? "ok" : "FAIL",
        ok_dispatch      ? "ok" : "FAIL",
        ok_handle        ? "ok" : "FAIL",
        ok_handle_idx    ? "ok" : "FAIL",
        ok_array1        ? "ok" : "FAIL",
        ok_engate        ? "ok" : "FAIL",
        ok_init_flag     ? "ok" : "FAIL",
        ok_notif_struct  ? "ok" : "FAIL",
        ok_pol_router    ? "ok" : "FAIL",
        resolved);
    return all_ok;
}

/* FFXiMain offsets -- resolved at runtime via signature scanning. Mirrors
 * resolve_polcore_offsets pattern: each block finds an anchor, optionally
 * walks back for a function prologue, and updates the OFF_* constant.
 * Pass/fail dashboard logged at end. */
static bool resolve_ffximain_offsets(uint8_t* base)
{
    const char* mod = "FFXiMain.dll";
    uint32_t baseAddr = (uint32_t)(uintptr_t)base;
    int resolved = 0;


    /* populate_friend_data (FUN_047FAC00) -- __thiscall on flistmai. Prologue
     * is highly unique: `83 EC 14 53 55 56 8B F1 33 DB 57 89 5E 3C C6 46 44
     * 20 C6 46 45 18`. The `C6 46 44 20 C6 46 45 18` writes (set bytes
     * [esi+0x44]=0x20 and [esi+0x45]=0x18) are friend-list specific magic
     * values that won't appear elsewhere. */
    bool ok_populate = false;
    {
        DWORD pop = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x83\xEC\x14\x53\x55\x56\x8B\xF1\x33\xDB\x57"
                                  "\x89\x5E\x3C\xC6\x46\x44\x20\xC6\x46\x45\x18",
            "xxxxxxxxxxxxxxxxxxxxxx");
        if (pop)
        {
            OFF_POPULATE_FN = pop - baseAddr;
            ok_populate = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: populate_friend_data pattern FAILED to resolve");
        }
    }

    /* friend_conn_teardown (FUN_04707570) + OFF_FRIEND_CONN_STATE -- the
     * teardown's first instruction is `MOV ECX, [DAT_04AEE900]; TEST ECX,ECX;
     * JZ +0x1F; PUSH EBX; MOV EBX,[ESP+8]; PUSH EBX; CALL FUN_04701AE0`.
     * Bytes `8B 0D ?? ?? ?? ?? 85 C9 74 1F 53 8B 5C 24 08 53 E8`. The imm32
     * at offset 2 of the match is the absolute address of FRIEND_CONN_STATE,
     * so we resolve both offsets from one anchor. */
    bool ok_teardown = false;
    {
        DWORD td = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x0D\x00\x00\x00\x00\x85\xC9\x74\x1F\x53"
                                  "\x8B\x5C\x24\x08\x53\xE8",
            "xx????xxxxxxxxxxx");
        if (td)
        {
            OFF_FRIEND_CONN_TEARDOWN = td - baseAddr;
            OFF_FRIEND_CONN_STATE    = *(uint32_t*)(td + 2) - baseAddr;
            ok_teardown = true;
            resolved += 2;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_conn_teardown pattern FAILED to resolve");
        }
    }

    /* inbox_row_callback (FFXi+0x200420) -- friend-system network response
     * row handler. Prologue references TWO data globals in its first 12
     * bytes: `51 A1 [OFF_MSG_OBJ_NATIVE] C6 05 [OFF_INBOX_INIT_DONE] 00 56
     * 8B 48 08 85 C9`. push ECX; mov EAX,[m32]; mov byte [m32], 0; push ESI;
     * mov ECX,[EAX+8]; test ECX,ECX. The two imm32s are at offsets +2 and
     * +8 of the match -- we extract both globals + the function entry. */
    bool ok_inbox_row = false;
    {
        DWORD ir = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x51\xA1\x00\x00\x00\x00\xC6\x05\x00\x00\x00\x00\x00"
                                  "\x56\x8B\x48\x08\x85\xC9",
            "xx????xx?????xxxxxx");
        if (ir)
        {
            OFF_INBOX_ROW_CALLBACK    = ir - baseAddr;
            uint32_t msg_obj_addr     = *(uint32_t*)(ir + 2);
            uint32_t inbox_done_addr  = *(uint32_t*)(ir + 8);
            OFF_MSG_OBJ_NATIVE        = msg_obj_addr - baseAddr;
            OFF_INBOX_INIT_DONE       = inbox_done_addr - baseAddr;
            ok_inbox_row = true;
            resolved += 3;  /* function + 2 globals */
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: inbox_row_callback pattern FAILED to resolve");
        }
    }

    /* DAT message display thunk (FUN_04762DD0) -- __cdecl(cat, msg_id, ...).
     * Hook target for befriend error capture. Prologue iterates a 28-entry
     * category table: `56 57 8B 7C 24 0C 33 F6 39 3C F5 ?? ?? ?? ?? 74 14 46
     * 83 FE 1C 72 F1`. The `83 FE 1C` (CMP ESI, 0x1C -- 28 categories) is the
     * uniquely identifying constant. */
    bool ok_dat_msg = false;
    {
        DWORD dm = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x57\x8B\x7C\x24\x0C\x33\xF6\x39\x3C\xF5"
                                  "\x00\x00\x00\x00\x74\x14\x46\x83\xFE\x1C\x72\xF1",
            "xxxxxxxxxxx????xxxxxxxx");
        if (dm)
        {
            OFF_FFXI_DAT_MSG_THUNK = dm - baseAddr;
            ok_dat_msg = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: dat_msg_thunk pattern FAILED to resolve");
        }
    }

    /* /befriend chat command handler (FUN_04689F50) -- bails if token count
     * != 2. Prologue references TWO data globals: `A1 [TOKEN_COUNT] 83 EC 68
     * 83 F8 02 75 76 A1 [TOKEN_PTRS] C6 05 ?? ?? ?? ?? 00 6A 10`. The
     * `mov EAX,[m32]; sub ESP,0x68; cmp EAX,2; jne <bail>` is the token-count
     * gate, followed by mov EAX,[token_ptrs_m32]. Resolves: handler entry,
     * OFF_FFXI_TOKEN_COUNT (offset +1), OFF_FFXI_TOKEN_PTRS (offset +14). */
    bool ok_befriend_hnd = false;
    {
        DWORD bh = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x83\xEC\x68\x83\xF8\x02\x75\x76"
                                  "\xA1\x00\x00\x00\x00\xC6\x05\x00\x00\x00\x00\x00"
                                  "\x6A\x10",
            "x????xxxxxxxxx????xx?????xx");
        if (bh)
        {
            OFF_FFXI_BEFRIEND_HANDLER = bh - baseAddr;
            OFF_FFXI_TOKEN_COUNT      = *(uint32_t*)(bh + 1)  - baseAddr;
            OFF_FFXI_TOKEN_PTRS       = *(uint32_t*)(bh + 14) - baseAddr;
            ok_befriend_hnd = true;
            resolved += 3;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: befriend_handler pattern FAILED to resolve");
        }
    }

    /* friend_conn_init (FUN_04707550) -- initialize-if-NULL pattern: `MOV EAX,
     * [conn_state]; TEST EAX,EAX; JNE +0x10; MOV ECX, conn_state_base;
     * MOV [conn_state], ECX; JMP <inner_init>`. Bytes
     * `A1 ?? ?? ?? ?? 85 C0 75 10 B9 ?? ?? ?? ?? 89 0D ?? ?? ?? ?? E9`.
     * Cross-validates: imm32 at offset +1 should equal the conn-state global
     * we already resolved via teardown. */
    bool ok_conn_init = false;
    {
        DWORD ci = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x10\xB9\x00\x00\x00\x00"
                                  "\x89\x0D\x00\x00\x00\x00\xE9",
            "x????xxxxx????xx????x");
        if (ci)
        {
            OFF_FRIEND_CONN_INIT = ci - baseAddr;
            ok_conn_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_conn_init pattern FAILED to resolve");
        }
    }

    /* MsgProcess (FUN_04810910) -- scroll-list framework Enter handler.
     * Prologue: `MOV EAX,[ESP+0xC]; SUB ESP, 0x1B4; TEST EAX,EAX; PUSH EBP;
     * PUSH ESI; MOV BYTE [INBOX_INIT_DONE], 0; JNE <large rel32>`. The
     * `81 EC B4 01 00 00` (sub esp, 0x1B4 = 436B locals) is a uniquely-large
     * stack frame for this dispatcher. Bytes:
     * `8B 44 24 0C 81 EC B4 01 00 00 85 C0 55 56 C6 05 ?? ?? ?? ?? 00 0F 85`. */
    bool ok_msg_process = false;
    {
        DWORD mp = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x0C\x81\xEC\xB4\x01\x00\x00\x85\xC0\x55\x56"
                                  "\xC6\x05\x00\x00\x00\x00\x00\x0F\x85",
            "xxxxxxxxxxxxxxxx?????xx");
        if (mp)
        {
            OFF_MSG_PROCESS = mp - baseAddr;
            ok_msg_process = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: MsgProcess pattern FAILED to resolve");
        }
    }

    /* character_record_init_from_pol_xml (FUN_04709D50) -- account_id setup
     * during char record init. Hook target for account_id substitution.
     * NOTE: existing const `OFF_FFXI_CHAR_RECORD_INIT = 0x109D50` was OFF
     * by 0x10000 (correct is 0xF9D50); previous hook was pointing into
     * unrelated code. Resolving uniquely fixes this on every build.
     *
     * Prologue: `MOV EAX,[m32]; MOV EDX,[ESP+4]; PUSH EBX; PUSH ESI; MOV ECX,
     * [EAX+0x40E38]; PUSH EDI; CMP EDX,ECX; JAE rel32; MOV ESI,[EAX+EDX*4];
     * MOV ECX, 0x1038C; XOR EAX,EAX; MOV EDI,ESI; MOV [m32], ESI`.
     * The `B9 8C 03 01 00` (mov ecx, 66444 = chars rec size in dwords) is
     * the disambiguating constant. */
    bool ok_char_init = false;
    {
        /* Struct-offset byte and char-record-size constant byte are
         * wildcarded -- both vary by client; the structural shape (load
         * global; arg; SHL-by-2 index into record table; SHL-derived
         * size; bulk-zero) is what makes this signature unique. */
        DWORD ci = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x8B\x54\x24\x04\x53\x56\x8B\x88"
                                  "\x00\x00\x04\x00\x57\x3B\xD1\x0F\x83\x00\x00\x00\x00"
                                  "\x8B\x34\x90\xB9\x00\x03\x01\x00\x33\xC0\x8B\xFE\x89\x35",
            "x????xxxxxxxx??xxxxxxx????xxxx?xxxxxxxxx");
        if (ci)
        {
            OFF_FFXI_CHAR_RECORD_INIT = ci - baseAddr;
            ok_char_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: char_record_init pattern FAILED to resolve");
        }
    }

    /* inbox_enum_fn (FUN_048102F0) -- called by full_init to scan msg/r/b/
     * and populate msg_obj. Gated by `INBOX_INIT_DONE` byte at start.
     * Prologue: `MOV AL, [INBOX_INIT_DONE]; SUB ESP,8; TEST AL,AL; PUSH EBX;
     * PUSH ESI; MOV ESI,ECX; JNE rel32+0x110; PUSH EDI`. Bytes:
     * `A0 ?? ?? ?? ?? 83 EC 08 84 C0 53 56 8B F1 0F 85 10 01 00 00 57`. The
     * specific JNE displacement (0x110) + the byte-read-test-jne pattern is
     * unique to this enumerator's "skip if already done" gate. */
    bool ok_inbox_enum = false;
    {
        DWORD ie = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA0\x00\x00\x00\x00\x83\xEC\x08\x84\xC0\x53\x56\x8B\xF1"
                                  "\x0F\x85\x10\x01\x00\x00\x57",
            "x????xxxxxxxxxxxxxxxx");
        if (ie)
        {
            OFF_INBOX_ENUM_FN = ie - baseAddr;
            ok_inbox_enum = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: inbox_enum_fn pattern FAILED to resolve");
        }
    }

    /* befriend_op_send (FUN_047049F0) -- op-table state-2 callback polled by
     * friend_op_slot_pump. Switch on state 0..3 via jump table at imm32+22.
     * Prologue: `MOV EAX,[ESP+8]; SUB ESP,8; CMP EAX,3; PUSH EBX; PUSH ESI;
     * JA rel32; JMP [EAX*4 + imm32]`. Bytes: `8B 44 24 08 83 EC 08 83 F8 03
     * 53 56 0F 87 89 01 00 00 FF 24 85 ?? ?? ?? ??`. */
    bool ok_op_send = false;
    {
        DWORD os = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x08\x83\xEC\x08\x83\xF8\x03\x53\x56"
                                  "\x0F\x87\x89\x01\x00\x00\xFF\x24\x85",
            "xxxxxxxxxxxxxxxxxxxxx");
        if (os)
        {
            OFF_FFXI_BEFRIEND_OP_SEND = os - baseAddr;
            ok_op_send = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: befriend_op_send pattern FAILED to resolve");
        }
    }

    /* friend_sys_init (FUN_046FFFD0) -- friend system initializer. Allocates
     * DAT_04AEE768 (~86KB friend manager buffer), copies strings/account.
     * Prologue includes early-return-1 on NULL arg, then `MOV EAX,[FRIEND_MGR];
     * TEST EAX,EAX; JNE bail; CMP ESI,1; JL bail; CMP ESI,3; JG bail`.
     * The dual range check `83 FE 01 0F 8C ... 83 FE 03 0F 8F` (arg in 1..3)
     * is the unique fingerprint. */
    bool ok_sys_init = false;
    {
        DWORD si = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x8B\x74\x24\x08\x85\xF6\x75\x04\xB0\x01\x5E\xC3"
                                  "\xA1\x00\x00\x00\x00\x85\xC0\x0F\x85\x00\x00\x00\x00"
                                  "\x83\xFE\x01\x0F\x8C\x00\x00\x00\x00\x83\xFE\x03\x0F\x8F",
            "xxxxxxxxxxxxxx????xxxx????xxxxx????xxxxx");
        if (si)
        {
            OFF_FRIEND_SYS_INIT = si - baseAddr;
            ok_sys_init = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_sys_init pattern FAILED to resolve");
        }
    }

    /* display_cb (FUN_04702750) -- notification display callback. Prologue:
     * `MOV ECX,[CONN_STATE]; TEST ECX,ECX; JE +0x12; MOV EAX,[ESP+4];
     * TEST EAX,EAX; JNE +0xA; MOV EAX,[ESP+8]; PUSH EAX; CALL <add_notif>;
     * RET`. The rel32 call at offset +23 lets us extract OFF_ADD_NOTIF_FN
     * by computing target_abs = (anchor + 28) + rel32. */
    bool ok_display_cb = false;
    {
        DWORD dcb = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x0D\x00\x00\x00\x00\x85\xC9\x74\x12\x8B\x44\x24\x04"
                                  "\x85\xC0\x75\x0A\x8B\x44\x24\x08\x50\xE8\x00\x00\x00\x00\xC3",
            "xx????xxxxxxxxxxxxxxxxxx????x");
        if (dcb)
        {
            OFF_DISPLAY_CB = dcb - baseAddr;
            int32_t rel = *(int32_t*)(dcb + 24);
            uint32_t add_notif_abs = dcb + 28 + rel;
            OFF_ADD_NOTIF_FN = add_notif_abs - baseAddr;
            ok_display_cb = true;
            resolved += 2;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: display_cb pattern FAILED to resolve");
        }
    }

    /* polcore_queue_sm_driver (FUN_04704170) -- queue-walking SM driver,
     * __thiscall(self, state, *entry_out, *err_out). Switch on state 0..3
     * via jump table. Prologue: `MOV EAX,[ESP+4]; PUSH EBX; PUSH ESI;
     * CMP EAX,3; PUSH EDI; MOV ESI,ECX; JA +0x1B0; JMP [EAX*4 + imm32]`.
     * Distinguishable from befriend_op_send by stack-arg offset (4 not 8)
     * and `MOV ESI,ECX` (thiscall this). */
    bool ok_queue_drv = false;
    {
        DWORD qd = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x04\x53\x56\x83\xF8\x03\x57\x8B\xF1"
                                  "\x0F\x87\xB0\x01\x00\x00\xFF\x24\x85",
            "xxxxxxxxxxxxxxxxxxxxx");
        if (qd)
        {
            OFF_POLCORE_QUEUE_SM_DRIVER = qd - baseAddr;
            ok_queue_drv = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: polcore_queue_sm_driver pattern FAILED to resolve");
        }
    }

    /* dismiss_completion_cb (FUN_0480FD60) -- fires when dismiss SM completes.
     * Sets DAT_04C3FFA0=0, clears chat-related state, sets read flag at
     * msg_obj+0x64. The combination of `C6 05 [INBOX_INIT_DONE] 00` (clear
     * the inbox flag), `C6 40 64 01` (set byte at +0x64), and the test
     * structure is uniquely identifying. */
    bool ok_dismiss_cb = false;
    {
        DWORD dc = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x0C\xC6\x05\x00\x00\x00\x00\x00\x85\xC0\x75\x1D"
                                  "\x8B\x44\x24\x04\x8B\x0D\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00"
                                  "\xA1\x00\x00\x00\x00\x85\xC0\x74\x04\xC6\x40\x64\x01",
            "xxxxxx?????xxxxxxxxxx????xx????x????xxxxxxxx");
        if (dc)
        {
            OFF_DISMISS_COMPLETION_CB = dc - baseAddr;
            ok_dismiss_cb = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: dismiss_completion_cb pattern FAILED to resolve");
        }
    }

    /* dismiss_op2_handler (FUN_04705590) -- op[2] file-IO handler. Same +0xC48
     * struct offset as dismiss_op1 (LEA into 3144-byte struct). Prologue:
     * `PUSH ESI; MOV ESI,[ESP+8]; PUSH EDI; MOV EDI,[ESP+0x10]; TEST EDI,EDI;
     * JNE +0x2B; PUSH 0; LEA EAX,[ESI+0xC48]; PUSH 0x200; PUSH EAX; PUSH 7`. */
    bool ok_dismiss_op2 = false;
    {
        DWORD d2 = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x8B\x74\x24\x08\x57\x8B\x7C\x24\x10\x85\xFF\x75\x2B"
                                  "\x6A\x00\x8D\x86\x48\x0C\x00\x00\x68\x00\x02\x00\x00\x50\x6A\x07",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (d2)
        {
            OFF_DISMISS_OP2_HANDLER = d2 - baseAddr;
            ok_dismiss_op2 = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: dismiss_op2_handler pattern FAILED to resolve");
        }
    }

    /* FC90 (FUN_0480FC90) -- opens mes1rcv or mes2frnd sub-menu via vtable[+0x44].
     * Copies 18 dwords (72 bytes) from arg to this+0x20 using `rep movsd`.
     * Distinctive bytes: `8D 78 20 B9 12 00 00 00 ... F3 A5 ... FF 52 44`
     * (lea edi, +0x20; mov ecx, 0x12; rep movsd; call [edx+0x44]). */
    bool ok_fc90 = false;
    {
        DWORD f9 = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x54\x24\x08\x8B\xC1\x8B\x4C\x24\x04\x56\x8B\x74\x24\x10"
                                  "\x89\x48\x18\x8B\x4C\x24\x14\x57\x89\x48\x14\x8D\x78\x20"
                                  "\xB9\x12\x00\x00\x00\x89\x50\x1C\x8B\x10\xF3\xA5\x8B\xC8"
                                  "\xFF\x52\x44\x5F\x5E\xC2\x10\x00",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (f9)
        {
            OFF_FC90 = f9 - baseAddr;
            ok_fc90 = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: FC90 (submenu open) pattern FAILED to resolve");
        }
    }

    /* friend_err_cb (FUN_0480F450) -- friend-system error callback. Dispatches
     * on result code 0/1/else with DAT msg cat=10 msg=0x6F ("Failed to send
     * reply. (NN)"). Prologue: `MOV ECX,[ESP+0xC]; SUB ESP,0x20; MOV EAX,ECX;
     * MOV BYTE [INBOX_INIT_DONE],0; SUB EAX,0; JE +0x34; DEC EAX; JE +0x4E;
     * PUSH ECX; PUSH 0x6F; PUSH 0xA`. The `6A 6F 6A 0A` (push 0x6F msg_id;
     * push 0xA cat) is the befriend-error fingerprint. */
    bool ok_err_cb = false;
    {
        DWORD ec = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x4C\x24\x0C\x83\xEC\x20\x8B\xC1\xC6\x05\x00\x00\x00\x00"
                                  "\x00\x83\xE8\x00\x74\x34\x48\x74\x4E\x51\x6A\x6F\x6A\x0A",
            "xxxxxxxxxxx?????xxxxxxxxxxxxx");
        if (ec)
        {
            OFF_FRIEND_ERR_CB = ec - baseAddr;
            ok_err_cb = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_err_cb pattern FAILED to resolve");
        }
    }

    /* friend_submit (FUN_0480F550) -- friend-system submit (chat_obj, src, type).
     * Prologue starts with `MOV AL, [INBOX_INIT_DONE]; TEST AL,AL; JE +0x10;
     * MOV ECX, [chat_log]; PUSH 0x7A; CALL; RET 8`. The `6A 7A C2 08 00`
     * tail (push 0x7A error msg id; ret 8) is the unique fingerprint. */
    bool ok_friend_submit = false;
    {
        DWORD fs = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA0\x00\x00\x00\x00\x84\xC0\x74\x10\x8B\x0D\x00\x00\x00\x00"
                                  "\x6A\x7A\xE8\x00\x00\x00\x00\xC2\x08\x00",
            "x????xxxxxx????xxx????xxx");
        if (fs)
        {
            OFF_FRIEND_SUBMIT = fs - baseAddr;
            ok_friend_submit = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_submit pattern FAILED to resolve");
        }
    }

    /* friend_real_send (FUN_04702210) -- network submit chokepoint. Returns
     * 0x10 if `this+0x20` is NULL (no conn). Then: increment counter at
     * `this+8` with 0/1 overflow check, forward 10 stack args. Prologue:
     * `MOV EAX,ECX; MOV ECX,[EAX+0x20]; TEST ECX,ECX; JNE +8; MOV EAX,0x10;
     * RET 0x28; INC WORD [EAX+8]; CMP WORD [EAX+8],0; JNE +6;
     * MOV WORD [EAX+8],1`. The 16-bit counter increment-with-overflow at
     * +8 is unique. */
    bool ok_real_send = false;
    {
        DWORD rs = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\xC1\x8B\x48\x20\x85\xC9\x75\x08\xB8\x10\x00\x00\x00\xC2\x28\x00"
                                  "\x66\xFF\x40\x08\x66\x83\x78\x08\x00\x75\x06\x66\xC7\x40\x08\x01\x00",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (rs)
        {
            OFF_FRIEND_REAL_SEND = rs - baseAddr;
            ok_real_send = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_real_send pattern FAILED to resolve");
        }
    }

    /* friend_inner_send (FUN_04703150) -- common inner sender. Writes to
     * thisstruct fields at +0x8 (op_table ptr), +0x105A (status word), and
     * +0x105C (handler pointer). The store-pair at +0x105A/+0x105C (large
     * struct offsets in 4188-byte char struct) is uniquely identifying:
     * `66 89 BE 5A 10 00 00 89 86 5C 10 00 00`. */
    bool ok_inner_send = false;
    {
        DWORD is = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x44\x24\x04\x56\x57\x8B\xF1\x33\xFF\x3B\xC7\x89\x7E\x08"
                                  "\x66\x89\xBE\x5A\x10\x00\x00\x89\x86\x5C\x10\x00\x00\x74\x2C",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (is)
        {
            OFF_FRIEND_INNER_SEND = is - baseAddr;
            ok_inner_send = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: friend_inner_send pattern FAILED to resolve");
        }
    }

    /* dismiss_op1_send (FUN_047059D0) -- op[1] state-2 callback that produces
     * wire traffic. Prologue: `SUB ESP,0x48; PUSH EBX; MOV EBX,[ESP+0x54];
     * PUSH ESI; MOV ESI,[ESP+0x54]; TEST EBX,EBX; JNE +0x24; XOR EAX,EAX;
     * PUSH EDI; LEA EDX,[ESI+0xC48]`. The `8D 96 48 0C 00 00` (LEA into
     * +0xC48 of `this` -- 3144 bytes into a struct) is uniquely large + the
     * surrounding stack frame structure. */
    bool ok_dismiss_op1 = false;
    {
        DWORD d1 = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x83\xEC\x48\x53\x8B\x5C\x24\x54\x56\x8B\x74\x24\x54\x85\xDB"
                                  "\x75\x24\x33\xC0\x57\x8D\x96\x48\x0C\x00\x00",
            "xxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (d1)
        {
            OFF_DISMISS_OP1_SEND = d1 - baseAddr;
            ok_dismiss_op1 = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: dismiss_op1_send pattern FAILED to resolve");
        }
    }

    /* dismiss_submit (FUN_0480FBB0) -- Reply/Ignore handler for op code 0x16.
     * Prologue: `MOV AL, [INBOX_INIT_DONE]; SUB ESP, 0x80; TEST AL,AL;
     * PUSH ESI; MOV ESI,ECX; JE +0x17`. The 0x80 stack frame + byte-test +
     * thiscall this-load discriminate. NOTE: existing OFF was 0x80FBB0
     * (wrong base 0x04000000); correct RVA is 0x1FFBB0. */
    bool ok_dismiss_sub = false;
    {
        DWORD ds = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA0\x00\x00\x00\x00\x81\xEC\x80\x00\x00\x00\x84\xC0\x56\x8B\xF1\x74\x17",
            "x????xxxxxxxxxxxxx");
        if (ds)
        {
            OFF_DISMISS_SUBMIT = ds - baseAddr;
            ok_dismiss_sub = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: dismiss_submit pattern FAILED to resolve");
        }
    }

    /* msg_dismiss_action_v2 (FUN_0480FFE0) -- inbox menu-action handler,
     * `__thiscall(this, menu_group, action_id)`. Prologue:
     *   CMP WORD [ESP+4], 5  ; group 5 = mes1rcv inbox
     *   JNE bail
     *   MOVSX EAX, WORD [ESP+8]  ; action_id
     *   DEC EAX; JE +0x4C      ; action 1 = Reply
     *   DEC EAX; JE +0x41      ; action 2 = Ignore
     *   SUB EAX, 2; JNE bail   ; action 4 = READ
     * NOTE: existing const `OFF_MSG_DISMISS_ACTION = 0x80FFE0` had wrong
     * base (0x04000000 not 0x04610000); correct RVA is 0x1FFFE0. Resolves
     * automatically. */
    bool ok_dismiss_action = false;
    {
        DWORD da = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x66\x83\x7C\x24\x04\x05\x0F\x85\x83\x00\x00\x00"
                                  "\x0F\xBF\x44\x24\x08\x48\x74\x4C\x48\x74\x41\x83\xE8\x02\x75\x64",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (da)
        {
            OFF_MSG_DISMISS_ACTION = da - baseAddr;
            ok_dismiss_action = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: msg_dismiss_action pattern FAILED to resolve");
        }
    }

    /* dismiss_outer (FUN_04707430) -- Read submit wrapper. Same early-return-2
     * shape as befriend_outer but disambiguated by stack arg position:
     * dismiss reads `[ESP+0x18]` (4 stack args) vs befriend's `[ESP+0x24]`
     * (8 stack args). Pattern: `8B 0D [conn_state] 85 C9 75 06 B8 02 00 00
     * 00 C3 8B 44 24 18 8B 54 24 14`. */
    bool ok_dismiss_outer = false;
    {
        DWORD doo = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x0D\x00\x00\x00\x00\x85\xC9\x75\x06\xB8\x02\x00\x00\x00\xC3"
                                  "\x8B\x44\x24\x18\x8B\x54\x24\x14",
            "xx????xxxxxxxxxxxxxxxxxx");
        if (doo)
        {
            OFF_DISMISS_OUTER = doo - baseAddr;
            ok_dismiss_outer = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: dismiss_outer pattern FAILED to resolve");
        }
    }

    /* befriend_inner (FUN_04703560) -- __thiscall inner submit. Prologue:
     * `PUSH ESI; MOV ESI,ECX; CMP WORD [ESI+0x1058],0; JE +9; MOV EAX,3;
     * POP ESI; RET 0x2C`. The 0x1058 struct offset (a busy flag) + return
     * code 3 + RET 0x2C (11 stack args + this) is uniquely specific. */
    bool ok_befriend_inner = false;
    {
        DWORD bi = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x8B\xF1\x66\x83\xBE\x58\x10\x00\x00\x00\x74\x09"
                                  "\xB8\x03\x00\x00\x00\x5E\xC2\x2C\x00",
            "xxxxxxxxxxxxxxxxxxxxxx");
        if (bi)
        {
            OFF_FFXI_BEFRIEND_INNER = bi - baseAddr;
            ok_befriend_inner = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: befriend_inner pattern FAILED to resolve");
        }
    }

    /* befriend_outer (FUN_04706FD0) -- early-return-2-if-conn-null wrapper,
     * forwards 8 stack args + push 3 to inner. Prologue: `MOV ECX,
     * [CONN_STATE]; TEST ECX,ECX; JNE +6; MOV EAX,2; RET; MOV EAX,[ESP+0x24]`.
     * The `75 06 B8 02 00 00 00 C3` early-out (return 2) + immediate
     * arg-forwarding via `8B 44 24 24` is the discriminator. */
    bool ok_befriend_outer = false;
    {
        DWORD bo = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x8B\x0D\x00\x00\x00\x00\x85\xC9\x75\x06\xB8\x02\x00\x00\x00\xC3"
                                  "\x8B\x44\x24\x24",
            "xx????xxxxxxxxxxxxxx");
        if (bo)
        {
            OFF_FFXI_BEFRIEND_OUTER = bo - baseAddr;
            ok_befriend_outer = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: befriend_outer pattern FAILED to resolve");
        }
    }

    /* chat_append (FUN_04737AA0) -- __thiscall per-line chat appender. Prologue
     * (after Detours JMP relocation): `PUSH EBX; PUSH EBP; PUSH ESI; PUSH EDI;
     * MOV EBP,ECX; PUSH 8; PUSH 0; MOV [ESP+0x1C],EBP; CALL rel32; MOV EDI,
     * [ESP+0x864]`. The `8B BC 24 64 08 00 00` (MOV EDI, [ESP+0x864] -- 2148
     * byte stack offset) is a uniquely-large local frame, definitive marker. */
    bool ok_chat_append = false;
    {
        DWORD ca = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x53\x55\x56\x57\x8B\xE9\x6A\x08\x6A\x00\x89\x6C\x24\x1C"
                                  "\xE8\x00\x00\x00\x00\x8B\xBC\x24\x64\x08\x00\x00",
            "xxxxxxxxxxxxxxx????xxxxxxx");
        if (ca)
        {
            OFF_CHAT_APPEND = ca - baseAddr;
            ok_chat_append = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: chat_append pattern FAILED to resolve");
        }
    }

    /* show_error (FUN_04728A00) -- __thiscall(this, msg_id) error/notification
     * dispatcher. Prologue: `PUSH ECX; PUSH ESI; LEA ESI,[ECX+0x14]; PUSH EDI;
     * MOV ECX,ESI; CALL <method>; TEST EAX,EAX; MOV [ESP+8],EAX; JE +0x38`.
     * The `8D 71 14` (LEA into +0x14 sub-object) + `74 38` (specific JE
     * displacement) discriminate. */
    bool ok_show_error = false;
    {
        DWORD se = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x51\x56\x8D\x71\x14\x57\x8B\xCE\xE8\x00\x00\x00\x00"
                                  "\x85\xC0\x89\x44\x24\x08\x74\x38",
            "xxxxxxxxx????xxxxxxxx");
        if (se)
        {
            OFF_SHOW_ERROR = se - baseAddr;
            ok_show_error = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: show_error pattern FAILED to resolve");
        }
    }

    /* OFF_FLISTMAI_PTR -- friend list menu object pointer. Resolved via a
     * function (FUN_048107C0) that loads it as imm32 in its prologue, after
     * an unrelated guard check on another global. Prologue:
     * `A1 [other_global] 56 85 C0 8B F1 74 1F A1 [FLISTMAI_PTR] 85 C0 74 07
     * 8B 48 08 85 C9 75 0F`. The double-`MOV EAX,[m32]; TEST EAX,EAX`
     * pointer-validity check is the discriminator. */
    bool ok_flistmai = false;
    {
        DWORD anchor = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\xA1\x00\x00\x00\x00\x56\x85\xC0\x8B\xF1\x74\x1F"
                                  "\xA1\x00\x00\x00\x00\x85\xC0\x74\x07\x8B\x48\x08\x85\xC9\x75\x0F",
            "x????xxxxxxxx????xxxxxxxxxxx");
        if (anchor)
        {
            OFF_FLISTMAI_PTR = *(uint32_t*)(anchor + 13) - baseAddr;
            ok_flistmai = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: flistmai_ptr pattern FAILED to resolve");
        }
    }

    /* full_init (FUN_04610710 in pre-2026-05-11 builds) -- inbox-panel
     * initializer called by ensure_native_msg_obj. Prologue:
     * `56 8B F1 E8 ?? ?? ?? ?? 6A 01 E8 ?? ?? ?? ?? 8B 00 6A 01 8B 88 4C 04
     * 00 00 89 4E 74`. The `MOV ECX,[EAX+0x44C]; MOV [ESI+0x74],ECX` pair is
     * unique to this function.
     *
     * Within full_init's body, the two show_menu("msglist", vis=1) calls each
     * appear as `6A 00 6A 01 68 imm32 B9 imm32 E8 rel32`. ensure_native_msg_obj
     * patches the `6A 01` immediates to `6A 00` so full_init runs without
     * auto-opening the inbox panel. */
    bool ok_full_init = false;
    {
        DWORD fi = xiloader::functions::FindPattern(mod,
            (const unsigned char*)"\x56\x8B\xF1\xE8\x00\x00\x00\x00\x6A\x01\xE8"
                                  "\x00\x00\x00\x00\x8B\x00\x6A\x01\x8B\x88\x4C\x04"
                                  "\x00\x00\x89\x4E\x74",
            "xxxx????xxx????xxxxxxxxxxxxx");
        if (fi)
        {
            OFF_FULL_INIT = fi - baseAddr;
            int vis_found = 0;
            for (uint32_t off = 0x60; off < 0x140 && vis_found < 2; off++)
            {
                uint8_t* p = (uint8_t*)(uintptr_t)(fi + off);
                if (p[0] == 0x6A && p[1] == 0x00 &&
                    p[2] == 0x6A && p[3] == 0x01 &&
                    p[4] == 0x68 && p[9] == 0xB9 && p[14] == 0xE8)
                {
                    uint32_t site = (fi + off + 3) - baseAddr;
                    if (vis_found == 0)
                        OFF_FULL_INIT_VIS1 = site;
                    else
                        OFF_FULL_INIT_VIS2 = site;
                    vis_found++;
                    off += 0x10;
                }
            }
            if (vis_found == 2)
            {
                ok_full_init = true;
                resolved += 3;
            }
            else
            {
                xiloader::console::output(xiloader::color::error,
                    "FriendSys: full_init vis-patch sites only found %d/2",
                    vis_found);
            }
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: full_init pattern FAILED to resolve");
        }
    }

    /* Store 3 container pointer -- extracted from the entry accessor
     * (FFXi+0xE6B70 in the 2026-07 build):
     *   A1 <imm32>            MOV EAX,[store3_ptr]
     *   66 8B 4C 24 04        MOV CX,[ESP+4]
     *   66 3B 88 30 08 00 00  CMP CX,[EAX+0x830]      ; entry count
     *   ...                   MOVSX EDX,[EAX+ECX*2+0x832] ; index table
     *   C1 E2 08              SHL EDX,8               ; idx * 0x100
     *   8D 84 02 90 0A 00 00  LEA EAX,[EDX+EAX+0xA90] ; entry base
     * The imm32 at +1 is the container pointer. This accessor also documents
     * the container layout do_sync_status depends on (count +0x830, index
     * table +0x832, entry = base + idx*0x100 + 0xA90). */
    bool ok_store3 = false;
    {
        static const unsigned char S3_PAT[] = {
            0xA1, 0x00, 0x00, 0x00, 0x00, 0x66, 0x8B, 0x4C, 0x24, 0x04, 0x66, 0x3B,
            0x88, 0x30, 0x08, 0x00, 0x00, 0x7C, 0x03, 0x33, 0xC0, 0xC3, 0x0F, 0xBF,
            0xC9, 0x0F, 0xBF, 0x94, 0x48, 0x32, 0x08, 0x00, 0x00, 0xC1, 0xE2, 0x08,
            0x8D, 0x84, 0x02, 0x90, 0x0A, 0x00, 0x00, 0xC3,
        };
        DWORD s3 = xiloader::functions::FindPattern(mod, S3_PAT,
            "x????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        if (s3)
        {
            OFF_STORE3_PTR = *(uint32_t*)(s3 + 1) - baseAddr;
            ok_store3 = true;
            resolved++;
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: store3_ptr pattern FAILED to resolve");
        }
    }

    bool all_ok = ok_populate && ok_teardown && ok_inbox_row && ok_dat_msg &&
                  ok_befriend_hnd && ok_conn_init && ok_msg_process &&
                  ok_char_init && ok_inbox_enum && ok_op_send && ok_flistmai &&
                  ok_show_error && ok_chat_append && ok_befriend_outer &&
                  ok_befriend_inner && ok_dismiss_outer && ok_dismiss_action &&
                  ok_dismiss_sub && ok_dismiss_op1 && ok_inner_send &&
                  ok_friend_submit && ok_err_cb && ok_fc90 && ok_dismiss_op2 &&
                  ok_dismiss_cb && ok_queue_drv && ok_display_cb && ok_sys_init &&
                  ok_real_send && ok_full_init && ok_store3;
    xiloader::console::output(all_ok ? xiloader::color::success : xiloader::color::warning,
        "FriendSys: ffximain offsets resolved: populate=%s teardown=%s "
        "inbox_row=%s dat_msg=%s befriend_hnd=%s conn_init=%s msg_proc=%s "
        "char_init=%s inbox_enum=%s op_send=%s flistmai=%s show_err=%s "
        "chat_append=%s befriend_outer=%s befriend_inner=%s dismiss_outer=%s "
        "dismiss_action=%s dismiss_sub=%s dismiss_op1=%s inner_send=%s "
        "friend_submit=%s err_cb=%s fc90=%s dismiss_op2=%s dismiss_cb=%s "
        "queue_drv=%s display_cb=%s sys_init=%s real_send=%s "
        "full_init=%s store3=%s (%d/36)",
        ok_populate       ? "ok" : "FAIL",
        ok_teardown       ? "ok" : "FAIL",
        ok_inbox_row      ? "ok" : "FAIL",
        ok_dat_msg        ? "ok" : "FAIL",
        ok_befriend_hnd   ? "ok" : "FAIL",
        ok_conn_init      ? "ok" : "FAIL",
        ok_msg_process    ? "ok" : "FAIL",
        ok_char_init      ? "ok" : "FAIL",
        ok_inbox_enum     ? "ok" : "FAIL",
        ok_op_send        ? "ok" : "FAIL",
        ok_flistmai       ? "ok" : "FAIL",
        ok_show_error     ? "ok" : "FAIL",
        ok_chat_append    ? "ok" : "FAIL",
        ok_befriend_outer ? "ok" : "FAIL",
        ok_befriend_inner ? "ok" : "FAIL",
        ok_dismiss_outer  ? "ok" : "FAIL",
        ok_dismiss_action ? "ok" : "FAIL",
        ok_dismiss_sub    ? "ok" : "FAIL",
        ok_dismiss_op1    ? "ok" : "FAIL",
        ok_inner_send     ? "ok" : "FAIL",
        ok_friend_submit  ? "ok" : "FAIL",
        ok_err_cb         ? "ok" : "FAIL",
        ok_fc90           ? "ok" : "FAIL",
        ok_dismiss_op2    ? "ok" : "FAIL",
        ok_dismiss_cb     ? "ok" : "FAIL",
        ok_queue_drv      ? "ok" : "FAIL",
        ok_display_cb     ? "ok" : "FAIL",
        ok_sys_init       ? "ok" : "FAIL",
        ok_real_send      ? "ok" : "FAIL",
        ok_full_init      ? "ok" : "FAIL",
        ok_store3         ? "ok" : "FAIL",
        resolved);
    return all_ok;
}

typedef int  (__cdecl*    FnCallerBInit)();
typedef int  (__cdecl*    FnCallerBPump)(int slot);
typedef int  (__cdecl*    FnEnrich)(int a2i, void* entry);
typedef void (__thiscall* FnPopulate)(void* flistmai, int param);
typedef void (__thiscall* FnAddNotification)(void* manager, void* buf48);

static void nop_bytes(uint8_t* addr, int count)
{
    DWORD old;
    if (VirtualProtect(addr, count, PAGE_EXECUTE_READWRITE, &old))
    {
        memset(addr, 0x90, count);
        VirtualProtect(addr, count, old, &old);
    }
}

static bool s_notif_overlay_applied = false;
static uint32_t s_notif_cb_expected = 0;
static bool s_notif_cb_drift_logged = false;

/* FFXiMain add_notification (FFXi+0xF2680) -- __thiscall(manager, buf48), RET 4.
 * Called from the worker thread under SEH protection. */
static uint8_t s_notif_inject_buf[0x48] = {};

static EXCEPTION_POINTERS* s_last_exception = nullptr;
static LONG WINAPI notif_exception_filter(EXCEPTION_POINTERS* ep)
{
    s_last_exception = ep;
    return EXCEPTION_EXECUTE_HANDLER;
}

static void apply_notification_overlay_patches()
{
    if (s_notif_overlay_applied || s_polBase == nullptr || s_ffxiBase == nullptr)
        return;

    /* Tick-killer JGE->JMP patch is currently disabled: the resolver finds the
     * JGE at +0x457BB, but applying the flip stops the notification overlay
     * from rendering. Resolution stays for visibility; flip is not applied. */
    if (OFF_TICK_KILLER_JGE != 0)
    {
        xiloader::console::output_to_channel("friend",
            "NotifOverlay: tick-killer resolved at +0x%06X (patch deferred pending investigation)",
            OFF_TICK_KILLER_JGE);
    }

    uint32_t* tick_enable   = (uint32_t*)(s_polBase + OFF_TICK_ENABLE);
    uint32_t* dispatch_mode = (uint32_t*)(s_polBase + OFF_DISPATCH_MODE);

    if (*tick_enable != 1)
    {
        xiloader::console::output(xiloader::color::warning,
            "NotifOverlay: tick_enable=%d, setting to 1", *tick_enable);
        *tick_enable = 1;
    }

    /* dispatch_mode==3 blocks Sub D via a gate check requiring profile-server
     * sockets that LSB doesn't use; any other value skips the gate. */
    if (*dispatch_mode == 3)
    {
        xiloader::console::output(xiloader::color::warning,
            "NotifOverlay: dispatch_mode=3 (would block Sub D), setting to 0");
        *dispatch_mode = 0;
    }

    int32_t* struct_index = (int32_t*)(s_polBase + OFF_STRUCT_INDEX);
    *struct_index = 0;

    /* Initialize notification struct[0] so Sub F/G don't error out. */
    uint8_t* notif_struct = s_polBase + OFF_NOTIF_STRUCT;
    notif_struct[0x208] = 0x0E;
    notif_struct[0x209] = 0x55;
    *(int32_t*)(notif_struct + 0x20C) = -1;   /* skip socket I/O in Sub F */
    *(int32_t*)(notif_struct + 0x334) = 0;
    *(int32_t*)(notif_struct + 0x33C) = 1;    /* non-zero avoids POL-1024 */
    uint32_t* notif_mgr = (uint32_t*)(s_ffxiBase + OFF_NOTIF_MGR_PTR);
    xiloader::console::output_to_channel("friend",
        "NotifOverlay: notification manager = 0x%08X", *notif_mgr);
    if (*notif_mgr == 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "NotifOverlay: notification manager is NULL -- overlay won't render");
    }

    /* Display-path callback for polcore tick -> Sub D -> FFXiMain. */
    uint32_t* callback_ptr = (uint32_t*)(s_polBase + OFF_CALLBACK_PTR);
    uint32_t cb_target = (uint32_t)(uintptr_t)&Mine_PolStatusNotify;

    /* Does FFXi register this itself? A non-zero value here means the native
     * registration already happened and this write is CLOBBERING it. */
    const uint32_t cb_before = *callback_ptr;
    const char* origin = "zero (no native registration)";
    if (cb_before != 0)
    {
        if (cb_before >= (uint32_t)(uintptr_t)s_ffxiBase &&
            cb_before <  (uint32_t)(uintptr_t)s_ffxiBase + 0x1000000)
            origin = "FFXiMain";
        else if (cb_before >= (uint32_t)(uintptr_t)s_polBase &&
                 cb_before <  (uint32_t)(uintptr_t)s_polBase + 0x100000)
            origin = "polcore";
        else
            origin = "other module";
    }
    xiloader::console::output_to_channel("friend",
        "NotifCBProbe: pol+0x%X was 0x%08X [%s]%s -> writing 0x%08X",
        OFF_CALLBACK_PTR, cb_before, origin,
        (cb_before != 0 && cb_before != cb_target) ? " (CLOBBERING)" : "",
        cb_target);

    *callback_ptr = cb_target;
    s_notif_cb_expected = cb_target;

    s_notif_overlay_applied = true;
    xiloader::console::output_to_channel("friend",
        "NotifOverlay: enabled (struct_idx=0, callback=0x%08X, mgr=0x%08X)",
        cb_target, *notif_mgr);
}

/* Inject a notification and set S:/R: counter values. */
static bool inject_notification(const uint8_t* buf48, uint16_t s_count, uint16_t r_count)
{
    if (s_ffxiBase == nullptr)
        return false;

    uint32_t mgr_addr = *(uint32_t*)(s_ffxiBase + OFF_NOTIF_MGR_PTR);
    if (mgr_addr == 0)
        return false;

    auto addNotif = (FnAddNotification)(s_ffxiBase + OFF_ADD_NOTIF_FN);
    s_last_exception = nullptr;

    __try
    {
        memcpy(s_notif_inject_buf, buf48, 0x48);
        addNotif((void*)(uintptr_t)mgr_addr, s_notif_inject_buf);

        uint8_t* mgr = (uint8_t*)(uintptr_t)mgr_addr;
        uint32_t node_addr = *(uint32_t*)(mgr + 0x1C);
        if (node_addr == 0)
        {
            xiloader::console::output(xiloader::color::error,
                "NotifOverlay: addNotif returned but node list is empty");
            return false;
        }

        *(uint32_t*)(mgr + 0x28) = node_addr;  /* active notification */
        *(uint16_t*)(mgr + 0x0A) = s_count;    /* S: counter */
        *(uint16_t*)(mgr + 0x10) = r_count;    /* R: counter */
        return true;
    }
    __except(notif_exception_filter(GetExceptionInformation()))
    {
        if (s_last_exception && s_last_exception->ExceptionRecord && s_last_exception->ContextRecord)
        {
            auto* ctx = s_last_exception->ContextRecord;
            uint32_t crash_rva = ctx->Eip - (uint32_t)(uintptr_t)s_ffxiBase;
            xiloader::console::output(xiloader::color::error,
                "NotifOverlay: addNotif CRASH at FFXi+0x%06X code=0x%08X",
                crash_rva, s_last_exception->ExceptionRecord->ExceptionCode);
        }
        else
        {
            xiloader::console::output(xiloader::color::error,
                "NotifOverlay: addNotif CRASH (code=0x%08X)", GetExceptionCode());
        }
        return false;
    }
}

static bool enrich_and_clean(FnEnrich enrich_fn, int a2i, uint8_t* ent)
{
    __try
    {
        enrich_fn(a2i, (void*)ent);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: enrich EXCEPTION for a2i=%d (code=0x%08X)",
            a2i, GetExceptionCode());
        return false;
    }

    uint16_t zid_pre = *(uint16_t*)(ent + 0xE0);
    memset(ent + 0xCC, 0, 0x100 - 0xCC);
    *(uint16_t*)(ent + 0xE0) = zid_pre;
    *(uint16_t*)(ent + 0xD8) = zid_pre & 0x3FFF;
    ent[0xFC] = 0x41;
    uint16_t* fhi = (uint16_t*)(ent + 0x0C);
    *fhi = (*fhi & 0xF800) | 0x0002;

    return true;
}

static void write_handle_array()
{
    uint8_t* hnd_base = s_polBase + OFF_HANDLE;
    uint8_t* src_base = s_polBase + OFF_ARRAY1;

    DWORD hp = 0;
    VirtualProtect(hnd_base, 64 * 40, PAGE_READWRITE, &hp);

    /* handle[0] = (account_id << 1) | 1. Game reads handle[0]+0 as uint64 and
     * right-shifts by 1; bit 0 is the valid flag. */
    uint64_t encoded_id = ((uint64_t)globals::g_AccountId << 1) | 1ULL;
    *(uint64_t*)hnd_base = encoded_id;

    if (!globals::g_Username.empty())
    {
        memset(hnd_base + 8, 0, 15);
        size_t len = globals::g_Username.size();
        if (len > 15) len = 15;
        memcpy(hnd_base + 8, globals::g_Username.c_str(), len);
    }

    /* handle_index = 0 so display reads handle[0]. */
    DWORD ip = 0;
    uint8_t* idx_addr = s_polBase + OFF_HANDLE_INDEX;
    uint32_t before = *(uint32_t*)idx_addr;
    VirtualProtect(idx_addr, 4, PAGE_READWRITE, &ip);
    *(uint32_t*)idx_addr = 0;
    VirtualProtect(idx_addr, 4, ip, &ip);
    static bool s_logged_idx = false;
    if (!s_logged_idx)
    {
        s_logged_idx = true;
        xiloader::console::output_to_channel("friend",
            "FriendSys: handle_index at polcore+0x%X: %08X -> 00000000",
            OFF_HANDLE_INDEX, before);
    }

    /* Friend handles at sequential indices 1..63. handle[0..7] is the
     * (account_id << 1) | 1 encoded ID polcore's WhoIs SM uses for the
     * target_accid -> slot reverse lookup. handle[8..22] is the charname. */
    for (int i = 1; i < 64; i++)
    {
        uint8_t* src = src_base + i * 0x68;
        if (!(src[0] & 1)) continue;
        const char* cn = (const char*)(src + 0x18);
        if (cn[0] == 0) continue;
        uint32_t friend_accid = *(uint32_t*)(src + 0x04);
        uint8_t* hnd = hnd_base + i * 40;
        uint64_t encoded = ((uint64_t)friend_accid << 1) | 1ULL;
        *(uint64_t*)hnd = encoded;
        memset(hnd + 8, 0, 15);
        for (int j = 0; j < 15 && cn[j]; j++)
            hnd[8 + j] = cn[j];
    }

    VirtualProtect(hnd_base, 64 * 40, hp, &hp);
}

static void force_free_slot(int slot)
{
    if (slot < 0 || slot >= 4 || s_polBase == nullptr) return;
    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + slot * OFF_DESC_STRIDE;

    SOCKET sock = *(SOCKET*)(desc + 0x04);
    if (sock != 0 && sock != INVALID_SOCKET)
        closesocket(sock);

    *(SOCKET*)(desc + 0x04) = INVALID_SOCKET;
    desc[0x00] = 0;
    desc[0x08] = 0;
    desc[0x09] = 0;
}

static int compute_backoff_ticks(int failures)
{
    if (failures <= 0) return KEEPALIVE_TICKS;
    int backoff = KEEPALIVE_TICKS;
    for (int i = 1; i < failures && backoff < MAX_BACKOFF_TICKS; i++)
        backoff *= 2;
    if (backoff > MAX_BACKOFF_TICKS) backoff = MAX_BACKOFF_TICKS;
    return backoff;
}

/* Replicates the SETUP portion of native flistmai_menu_open (FFXi+0x1EB190)
 * without the UI-thread mutations (FUN_047FB290 + visual menu opens). After
 * this runs, flistmai's color/font/layout fields are valid, populate can be
 * called, and the engine's per-frame draw won't deref NULL handles.
 *
 * Native flistmai_menu_open does:
 *   A) FUN_047FB290        -- UI-mgr "node ready" (SKIP -- touches UI-mgr open list)
 *   B) RES[2] loop -> flistmai+0x68..+0x88     (SETUP -- keytops3 handles)
 *   C) flistmai+0x8C = RES[5]                  (SETUP -- icon array)
 *   D) RES[1] loop -> flistmai+0x90..+0xA0     (SETUP -- windowps handles)
 *   E) RES[1][75] -> flistmai+0x34, +0x64      (SETUP -- text colors)
 *   F) misc layout writes                      (SETUP)
 *   G) populate_friend_data                    (POPULATE)
 *   H) FUN_0476E1E0("menu friend", ...)        (SKIP -- visual open)
 *   I) FUN_0476E1E0("menu titlehan", ...)      (SKIP -- visual open) */
static bool flistmai_setup_resources(uint8_t* fm, uint8_t mode_byte)
{
    uint32_t* res_table = (uint32_t*)(s_ffxiBase + OFF_RES_TABLE);
    uint32_t res2 = res_table[2];   /* menu/keytops3 */
    uint32_t res5 = res_table[5];   /* menu/contents */
    uint32_t res1 = res_table[1];   /* menu/windowps */
    if (res1 == 0 || res2 == 0 || res5 == 0)
    {
        static bool s_logged = false;
        if (!s_logged)
        {
            xiloader::console::output(xiloader::color::warning,
                "FlistmaiSetup: resource table not yet populated "
                "(RES[1]=%08X RES[2]=%08X RES[5]=%08X) -- suppressing further",
                res1, res2, res5);
            s_logged = true;
        }
        return false;
    }

    uint32_t* tbl1 = *(uint32_t**)(uintptr_t)res1;
    uint32_t* tbl2 = *(uint32_t**)(uintptr_t)res2;
    if (tbl1 == nullptr || tbl2 == nullptr)
    {
        xiloader::console::output(xiloader::color::warning,
            "FlistmaiSetup: resource handle tables NULL (tbl1=%p tbl2=%p)",
            tbl1, tbl2);
        return false;
    }

    /* B) Loop 1: 9 dwords from RES[2]->table -> flistmai+0x68..+0x88 */
    const uint16_t* idx9 = (const uint16_t*)(s_ffxiBase + OFF_KEYTOPS_IDX_9);
    uint32_t* dst = (uint32_t*)(fm + 0x68);
    for (int i = 0; i < 9; i++)
        dst[i] = tbl2[idx9[i]];

    /* C) flistmai+0x8C = RES[5] (icon array provider) */
    *(uint32_t*)(fm + 0x8C) = res5;

    /* D) Loop 2: 5 dwords from RES[1]->table -> flistmai+0x90..+0xA0 */
    const uint16_t* idx5 = (const uint16_t*)(s_ffxiBase + OFF_WINDOWPS_IDX_5);
    dst = (uint32_t*)(fm + 0x90);
    for (int i = 0; i < 5; i++)
        dst[i] = tbl1[idx5[i]];

    /* E) flistmai+0x64 (default text color) and +0x34 (current text color)
     *    = RES[1]->table[75] (= 0x12C bytes in) */
    uint32_t text_color = tbl1[75];
    *(uint32_t*)(fm + 0x64) = text_color;
    *(uint32_t*)(fm + 0x34) = text_color;

    /* F) Layout / state fields */
    fm[0x49] = 1;
    *(uint16_t*)(fm + 0x16) = 6;
    *(uint16_t*)(fm + 0x26) = 0x10;
    fm[0x2C] = 4;
    fm[0x2D] = 3;
    *(const uint16_t**)(fm + 0x30) =
        (const uint16_t*)(s_ffxiBase + OFF_COL_OFFSETS);
    *(int8_t*)(fm + 0x58) = (int8_t)mode_byte;

    /* FUN_04806230(0xf): scroll_top=0xF, page_size=clamp(total-0xF, 0).
     * Inlined to avoid a stale callee offset. */
    int16_t total = *(int16_t*)(fm + 0x20);
    int16_t page  = total - 0x0F;
    if (page < 0) page = 0;
    *(int16_t*)(fm + 0x18) = 0x0F;
    *(int16_t*)(fm + 0x22) = page;

    return true;
}

/* Setup-only flistmai initializer. Once-per-session; idempotent on retry.
 * Returns true if flistmai is fully initialized (resources + populate). */
static bool flistmai_init_for_befriend()
{
    static bool s_done = false;
    if (s_done) return true;

    uint32_t flistmai = *(uint32_t*)(s_ffxiBase + OFF_FLISTMAI_PTR);
    if (flistmai == 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "FlistmaiSetup: flistmai pointer NULL -- engine init incomplete");
        return false;
    }

    uint8_t* fm = (uint8_t*)(uintptr_t)flistmai;
    const uint8_t mode_byte = 0;

    if (!flistmai_setup_resources(fm, mode_byte))
        return false;

    typedef void (__thiscall* FnPopulate)(void* flistmai, uint32_t openByte);
    auto populate = (FnPopulate)(s_ffxiBase + OFF_POPULATE_FN);

    __try {
        populate((void*)(uintptr_t)flistmai, mode_byte);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        xiloader::console::output(xiloader::color::error,
            "FlistmaiSetup: populate raised exception, will not retry");
        s_done = true;
        return false;
    }

    uint32_t slot_count = *(uint32_t*)((uintptr_t)flistmai + 0x50);
    uint32_t render_arr = *(uint32_t*)((uintptr_t)flistmai + 0x5C);
    uint32_t display_arr = *(uint32_t*)((uintptr_t)flistmai + 0x60);
    xiloader::console::output_to_channel("friend",
        "FlistmaiSetup: ok -- slot_count=%u render=0x%08X display=0x%08X",
        slot_count, render_arr, display_arr);
    s_done = true;
    return true;
}

static int do_array_sync()
{
    uint8_t* src_base = s_polBase + OFF_ARRAY1;
    uint8_t* dst_base = s_polBase + OFF_ARRAY2;

    DWORD oldProt = 0;
    VirtualProtect(dst_base, 200 * 0xB0, PAGE_READWRITE, &oldProt);

    int sync_count = 0;
    for (int i = 0; i < 64; i++)
    {
        uint8_t* src = src_base + i * 0x68;
        uint8_t* dst = dst_base + i * 0xB0;

        if (src[0] & 1)
        {
            memset(dst, 0, 0xB0);
            memcpy(dst + 0x00, src + 0x04, 4);
            memcpy(dst + 0x08, src + 0x08, 4);
            memcpy(dst + 0x0C, src + 0x0C, 4);
            memcpy(dst + 0x10, src + 0x10, 4);

            uint32_t flags = *(uint32_t*)(dst + 0x08);
            if ((flags & 0x10000) && !(flags & 0x2000))
                *(uint32_t*)(dst + 0x08) = flags | 0x2000;

            memcpy(dst + 0xA0, src + 0x18, 15);
            *(uint32_t*)(dst + 0x98) = 1;

            sync_count++;
        }
    }

    VirtualProtect(dst_base, 200 * 0xB0, oldProt, &oldProt);
    return sync_count;
}

static void gate_keeper()
{
    uint32_t store3_ptr = *(uint32_t*)(s_ffxiBase + OFF_STORE3_PTR);
    if (store3_ptr == 0) return;

    uint16_t s3_count = *(uint16_t*)((uint8_t*)(uintptr_t)store3_ptr + 0x132);
    if (s3_count == 0) return;

    uint8_t* s3_base = (uint8_t*)(uintptr_t)(store3_ptr + 0x0A90);

    for (int ei = 0; ei <= (int)s3_count; ei++)
    {
        uint8_t* ent = s3_base + ei * 0x100;
        uint32_t efl = *(uint32_t*)(ent + 0x08);
        int a2i = (efl >> 20) & 0xFF;

        if (a2i > 0 || (efl & 0x2000))
        {
            if (a2i > 0)
                *(uint32_t*)(ent + 0x08) = efl | 0x2000;

            *(uint32_t*)(ent + 0xB0) = 0x41;
            ent[0xFC] = 0x41;

            /* Bit 29 (0x20000000) = incoming pending marker from server.
             * entry[0xF8] != 0 -> populate_friend_data cat 2 (type 3). */
            if (efl & 0x20000000)
                *(uint32_t*)(ent + 0xF8) = 1;

            uint16_t* fhi = (uint16_t*)(ent + 0x0C);
            *fhi = (*fhi & 0xF800) | 0x0002;
            uint16_t zid = *(uint16_t*)(ent + 0xE0);
            if (zid != 0)
                *(uint16_t*)(ent + 0xD8) = zid & 0x3FFF;
        }
    }

    /* XI icon injection into render buffers. */
    uint32_t flistmai = *(uint32_t*)(s_ffxiBase + OFF_FLISTMAI_PTR);
    if (flistmai == 0) return;

    uint8_t* fm = (uint8_t*)(uintptr_t)flistmai;
    int32_t  slots       = *(int32_t*)(fm + 0x50);
    uint32_t render_base = *(uint32_t*)(fm + 0x5C);
    uint32_t icon_pp     = *(uint32_t*)(fm + 0x8C);

    if (render_base == 0 || icon_pp == 0) return;
    if (IsBadReadPtr((void*)(uintptr_t)icon_pp, 4)) return;

    uint32_t icon_array = *(uint32_t*)(uintptr_t)icon_pp;
    if (icon_array == 0 || IsBadReadPtr((void*)(uintptr_t)icon_array, 4)) return;

    uint32_t xi_icon = *(uint32_t*)(uintptr_t)icon_array;
    int limit = (slots < 64) ? slots : 64;

    for (int ri = 0; ri < limit; ri++)
    {
        uint8_t* rb = (uint8_t*)(uintptr_t)(render_base + ri * 0x54);
        uint32_t disp_ptr = *(uint32_t*)(rb + 0x48);
        if (disp_ptr != 0 && !IsBadReadPtr((void*)(uintptr_t)disp_ptr, 1))
        {
            uint8_t category = *(uint8_t*)(uintptr_t)disp_ptr;
            if (category == 5)
            {
                rb[2] = 0x0E;
                *(uint32_t*)(rb + 0x10) = 0x80808080;
                *(uint32_t*)(rb + 0x30) = xi_icon;
            }
        }
    }

    /* Deferred populate: arrays just became available. */
    if (s_populate_pending)
    {
        uint32_t gk_render  = *(uint32_t*)(fm + 0x5C);
        uint32_t gk_display = *(uint32_t*)(fm + 0x60);

        if (gk_render != 0 && gk_display != 0)
        {
            s_populate_pending = false;

            FnEnrich enrich_fn = (FnEnrich)(s_polBase + OFF_ENRICH_FN);

            DWORD ep = 0;
            VirtualProtect(s3_base, (s3_count + 1) * 0x100, PAGE_READWRITE, &ep);

            for (int ei = 0; ei <= (int)s3_count; ei++)
            {
                uint8_t* ent = s3_base + ei * 0x100;
                uint32_t efl2 = *(uint32_t*)(ent + 0x08);
                int a2i = (efl2 >> 20) & 0xFF;
                if (a2i == 0) continue;
                *(uint32_t*)(ent + 0x08) = efl2 | 0x2000;
                enrich_and_clean(enrich_fn, a2i, ent);
            }

            FnPopulate populate = (FnPopulate)(s_ffxiBase + OFF_POPULATE_FN);
            uint8_t param = *(uint8_t*)(fm + 0x58);

            __try
            {
                populate((void*)(uintptr_t)flistmai, param);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                s_populate_pending = true;
            }

            s3_count = *(uint16_t*)((uint8_t*)(uintptr_t)store3_ptr + 0x132);
            for (int ei = 0; ei <= (int)s3_count; ei++)
            {
                uint8_t* ent = s3_base + ei * 0x100;
                uint32_t efl2 = *(uint32_t*)(ent + 0x08);
                int a2i = (efl2 >> 20) & 0xFF;
                if (a2i == 0) continue;
                *(uint32_t*)(ent + 0x08) = efl2 | 0x2000;
                enrich_and_clean(enrich_fn, a2i, ent);
            }

            VirtualProtect(s3_base, (s3_count + 1) * 0x100, ep, &ep);

            write_handle_array();

            xiloader::console::output_to_channel("friend",
                "FriendSys: deferred populate completed");
        }
    }
}

/* Mark the sub-entry populate_friend_data's in-game render predicate reads.
 *
 * FUN_03ED77A0 only lets an online friend's character name, zone and XI icon
 * render when
 *     *(u16*)(entry + 0x1A + ((entry[0x08] >> 17) & 7) * 0x10) == 1
 * Those 8x16B sub-entries come from the friend_status record, but polcore
 * copies them only when FUN_1001EEB0 is called with is_new, and its caller
 * computes is_new as (entry[0x10] | entry[0x14]) == 0. A status push writes
 * those two dwords -- they are its timestamps -- so after the first push
 * is_new is false forever and the sub-entries can never arrive. The friend
 * then renders online but with no name, zone or icon.
 *
 * enrich memcpys entry+0x08.. wholesale from Array2, where these are zero, so
 * this has to be re-applied after every enrich pass, not just once. */
static void mark_ingame_subentry(uint8_t* ent)
{
    const uint32_t efl    = *(uint32_t*)(ent + 0x08);
    const uint32_t online = (efl >> 13) & 7;
    if (online < 1 || online > 3)
        return;
    uint16_t* slot = (uint16_t*)(ent + 0x1A + ((efl >> 17) & 7) * 0x10);
    if (*slot != 1)
        *slot = 1;
}

/* True once populate_friend_data has allocated flistmai's render/display
 * arrays, i.e. the friend list has been built at least once. do_sync_status
 * refuses to touch Store 3 before this -- see the comment there for why
 * running it earlier wedges world entry. */
static bool friend_list_ui_ready()
{
    if (s_ffxiBase == nullptr)
        return false;
    uint32_t flistmai_ptr = *(uint32_t*)(s_ffxiBase + OFF_FLISTMAI_PTR);
    if (flistmai_ptr == 0)
        return false;
    uint8_t* fm = (uint8_t*)(uintptr_t)flistmai_ptr;
    return *(uint32_t*)(fm + 0x5C) != 0 && *(uint32_t*)(fm + 0x60) != 0;
}

static void do_sync_status()
{
    if (s_ffxiBase == nullptr)
        return;

    /* Do not touch Store 3 until the friend-list UI exists.
     *
     * This function was dead code on this client until the Store 3 pointer was
     * corrected (it read NULL and returned immediately). Once it started
     * running it wedged world entry: it enriches Store 3 entries and drives
     * polcore's enrich from the worker thread, and doing that while the client
     * is still building those structures during zone-in leaves the client
     * black-screened on "Downloading data" after character select. Verified by
     * A/B: friend system on + this disabled reaches the world, enabled does not.
     *
     * flistmai's render/display arrays are allocated by populate_friend_data,
     * so their presence means the list has been built at least once and the
     * structures are stable. Gating here costs nothing: the refresh is only
     * observable when the list is actually on screen. */
    uint32_t flistmai_ptr = *(uint32_t*)(s_ffxiBase + OFF_FLISTMAI_PTR);
    if (flistmai_ptr == 0)
        return;
    {
        uint8_t* fm = (uint8_t*)(uintptr_t)flistmai_ptr;
        if (*(uint32_t*)(fm + 0x5C) == 0 || *(uint32_t*)(fm + 0x60) == 0)
            return;
    }

    uint32_t store3_ptr = *(uint32_t*)(s_ffxiBase + OFF_STORE3_PTR);
    if (store3_ptr == 0) return;

    /* Container layout, from the FFXi entry accessor (FFXi+0xE6B70):
     *   count       u16  at container+0x830
     *   index table u16[] at container+0x832
     *   entry i          = container + 0xA90 + idx[i] * 0x100
     * The old +0x132 count offset belonged to an earlier build; on current
     * clients it reads an unrelated field. */
    uint8_t* s3_cont   = (uint8_t*)(uintptr_t)store3_ptr;
    uint16_t s3_count  = *(uint16_t*)(s3_cont + 0x830);
    const uint16_t* s3_idx = (const uint16_t*)(s3_cont + 0x832);
    if (s3_count == 0)
        return;

    uint8_t* s3_base   = (uint8_t*)(uintptr_t)(store3_ptr + 0x0A90);
    uint8_t* src_base  = s_polBase + OFF_ARRAY1;
    uint8_t* enr_tbl   = s_polBase + OFF_STATUS_TABLE;
    FnEnrich enrich_fn = (FnEnrich)(s_polBase + OFF_ENRICH_FN);

    /* Step 1: build fd_to_a2i mapping + save S3 entry->a2i for enrichment. */
    int fd_to_a2i[64];
    memset(fd_to_a2i, -1, sizeof(fd_to_a2i));

    int s3_a2i[64];
    memset(s3_a2i, -1, sizeof(s3_a2i));

    for (int ei = 0; ei < (int)s3_count && ei < 64; ei++)
    {
        uint8_t* ent = s3_base + s3_idx[ei] * 0x100;
        uint32_t efl = *(uint32_t*)(ent + 0x08);

        /* a2i (Array2 index) lives in bits 20-27, written by polcore's enrich
         * (mask 0xf00fffff). Do NOT gate on bit 13 here: bit 13 is part of the
         * online field (bits 13-15) that enrich COPIES IN from Array2, so
         * requiring it before enriching is circular -- it kept every entry
         * permanently offline. An a2i of 0 means "not yet enriched". */
        int a2i = (efl >> 20) & 0xFF;
        if (a2i == 0) continue;
        s3_a2i[ei] = a2i;

        uint16_t s3_fid = *(uint16_t*)(ent + 0x00);
        for (int fi = 1; fi < 64; fi++)
        {
            uint8_t* src = src_base + fi * 0x68;
            if (!(src[0] & 1)) continue;
            uint16_t fd_fid = *(uint16_t*)(src + 0x02);
            if (fd_fid == s3_fid || fi == a2i)
            {
                fd_to_a2i[fi] = a2i;
                break;
            }
        }
    }

    /* Step 2: write status table. */
    DWORD stProt = 0;
    VirtualProtect(enr_tbl, 200 * 0x84, PAGE_READWRITE, &stProt);

    for (int i = 1; i < 64; i++)
    {
        uint8_t* src = src_base + i * 0x68;
        if (!(src[0] & 1)) continue;
        uint32_t flags = *(uint32_t*)(src + 0x08);
        if (!(flags & 0x2000)) continue;

        int tbl_idx = (fd_to_a2i[i] >= 0) ? fd_to_a2i[i] : i;
        uint8_t* tbl = enr_tbl + tbl_idx * 0x84;
        memset(tbl, 0, 0x84);
        *(uint32_t*)(tbl + 0x00) = 0x00000041;
        memcpy(tbl + 0x04, src + 0x18, 15);

        uint16_t* structWords = (uint16_t*)(tbl + 0x1C);
        for (int j = 0; j < 25; j++)
            structWords[j] = (j == 22) ? 0x0100 : 0x0101;
        structWords[25] = 0x0000;

        uint16_t zid = *(uint16_t*)(src + 0x0E);
        if (zid > 0)
            *(uint16_t*)(tbl + 0x30) = zid | 0x4000;

        tbl[0x4C] = 0x41;
    }

    VirtualProtect(enr_tbl, 200 * 0x84, stProt, &stProt);

    /* Step 3: enrich Store 3 entries (using saved s3_a2i to avoid race). */
    DWORD s3Prot = 0;
    VirtualProtect(s3_base, (s3_count + 1) * 0x100, PAGE_READWRITE, &s3Prot);

    for (int ei = 0; ei < (int)s3_count && ei < 64; ei++)
    {
        if (s3_a2i[ei] < 0) continue;
        uint8_t* ent = s3_base + s3_idx[ei] * 0x100;
        /* Do not force bit 13 on: enrich memcpys entry+0x08 wholesale from
         * Array2, so the real online field (bits 13-15) arrives with the copy.
         * Forcing it here only produced a false "online" when enrich failed. */
        enrich_and_clean(enrich_fn, s3_a2i[ei], ent);

        mark_ingame_subentry(ent);
    }

    /* Step 4: populate (if display arrays allocated). */
    uint32_t flistmai = *(uint32_t*)(s_ffxiBase + OFF_FLISTMAI_PTR);
    if (flistmai != 0)
    {
        uint8_t* fm = (uint8_t*)(uintptr_t)flistmai;
        uint32_t fm_render  = *(uint32_t*)(fm + 0x5C);
        uint32_t fm_display = *(uint32_t*)(fm + 0x60);

        if (fm_render != 0 && fm_display != 0)
        {
            FnPopulate populate = (FnPopulate)(s_ffxiBase + OFF_POPULATE_FN);
            uint8_t param = *(uint8_t*)(fm + 0x58);

            __try
            {
                populate((void*)(uintptr_t)flistmai, param);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                s_populate_pending = true;
            }
        }
        else
        {
            s_populate_pending = true;
        }
    }
    else
    {
        s_populate_pending = true;
    }

    /* Step 5: re-enrich (populate may have overwritten Store 3). */
    s3_count = *(uint16_t*)(s3_cont + 0x830);
    for (int ei = 0; ei < (int)s3_count && ei < 64; ei++)
    {
        if (s3_a2i[ei] < 0) continue;
        uint8_t* ent = s3_base + s3_idx[ei] * 0x100;
        enrich_and_clean(enrich_fn, s3_a2i[ei], ent);
        mark_ingame_subentry(ent);
    }

    VirtualProtect(s3_base, (s3_count + 1) * 0x100, s3Prot, &s3Prot);

    /* Step 6: write handle array. */
    write_handle_array();

    xiloader::console::output_to_channel("friend",
        "FriendSys: sync complete");
}

/* Message file writing -- filesystem-based delivery. Retail persists messages
 * at PlayOnlineViewer\pub\homeNN\msg\r\b\; main.cpp's CreateFileA hook
 * redirects \msg\ paths to a local directory. The game's full_init task
 * reads body files written here. */

/* Custom base64 alphabet from polcore .rdata 0x10065DE0. */
static const char MSG_B64_ALPHA[] =
    "TSG8IncW3HFKokOg79qzeCmZs2yBYEQVAUxR5rbwi4P@jMDLtpvad0f_J1hlN6uX";

/* Encode 72 bytes -> 96-char filename using custom base64. */
static std::string encode_msg_filename(const uint8_t* data72)
{
    std::string out;
    out.reserve(96);
    for (int i = 0; i < 72; i += 3)
    {
        uint32_t val = ((uint32_t)data72[i] << 16)
                     | ((uint32_t)data72[i+1] << 8)
                     | (uint32_t)data72[i+2];
        out += MSG_B64_ALPHA[(val >> 18) & 0x3F];
        out += MSG_B64_ALPHA[(val >> 12) & 0x3F];
        out += MSG_B64_ALPHA[(val >>  6) & 0x3F];
        out += MSG_B64_ALPHA[(val      ) & 0x3F];
    }
    return out;
}

static void read_polcore_filename_iv(uint32_t& iv_lo, uint32_t& iv_hi)
{
    iv_lo = 0;
    iv_hi = 0;
    if (s_polBase != nullptr)
    {
        iv_lo = *(uint32_t*)(s_polBase + OFF_POL_IV_LO);
        iv_hi = *(uint32_t*)(s_polBase + OFF_POL_IV_HI);
    }
}

/* SEH-protected dword read. File scope because __try cannot live in
 * functions that use C++ object unwinding (C2712). */
static uint32_t safe_read_dword_at(uint32_t addr)
{
    __try {
        return *(uint32_t*)(uintptr_t)addr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xDEADBEEF;
    }
}

/* Identify which loaded module an address falls in. Writes
 * "<modname>+0x<rva>" or "unknown" into the caller-supplied buffer. */
static void classify_addr(uint32_t addr, char* out, size_t out_sz)
{
    struct Mod { HMODULE h; const char* name; };
    Mod mods[] = {
        { GetModuleHandleA("polcore.dll"),    "polcore" },
        { GetModuleHandleA("polcoreeu.dll"),  "polcoreeu" },
        { GetModuleHandleA("FFXiMain.dll"),   "FFXi" },
        { GetModuleHandleA("FFXiMaineu.dll"), "FFXieu" },
        { GetModuleHandleA(NULL),             "self" },
        { GetModuleHandleA("Ashita.dll"),     "Ashita" },
        { GetModuleHandleA("Ashita-x86.dll"), "Ashita-x86" },
    };
    for (auto& m : mods)
    {
        if (m.h == nullptr) continue;
        uintptr_t base = (uintptr_t)m.h;
        if (addr >= base && addr < base + 0x800000)
        {
            _snprintf_s(out, out_sz, _TRUNCATE, "%s+0x%X",
                m.name, (uint32_t)(addr - base));
            return;
        }
    }
    _snprintf_s(out, out_sz, _TRUNCATE, "unknown");
}

/* Build the 72-byte filename metadata block.
 * polcore would write this file in response to NotificationResponse natively.
 * Layout decoded from retail home01\msg\r\b\ filenames:
 *   +0x00 sender accid (4B) + msg_id (4B) -- XOR-encrypted on disk
 *   +0x08 recipient accid (8B) -- XOR-encrypted on disk
 *   +0x10 sender nickname (16B) -- plaintext
 *   +0x20 subject (16B) -- plaintext
 *   +0x30 sub-menu picker byte (0=mes1rcv, 1=mes2frnd) -- read as
 *         source_struct[0] first byte
 *   +0x34 unix timestamp (4B) -- polcore renders date from this
 *   +0x38 body file size (4B) -- body-text parser (polcore+0x1AA80) walk
 *         limit. ZERO causes click-to-read gate FUN_0491FD53 to return 0 and
 *         the click handler to exit with mode=16 (no menu).
 *   +0x3E..+0x3F flags ushort: bits 7-11 = icon-type index (input to
 *         FUN_048105D0); bit 15 (0x8000) = "valid", always set in retail.
 *         FFXi+0x102B20 reads as `(*ushort & 0xF80) >> 7` and passes as
 *         inbox_row_callback's icon_type. */
static void build_msg_filename_data(uint8_t* out72, const NotifMessage& nm,
    uint32_t body_size)
{
    memset(out72, 0, 72);
    *(uint32_t*)(out72 + 0x00) = nm.from_accid;
    *(uint32_t*)(out72 + 0x04) = nm.msg_id;       /* uniqueness key */
    *(uint32_t*)(out72 + 0x08) = globals::g_AccountId;
    strncpy((char*)(out72 + 0x10), nm.sender, 15);
    strncpy((char*)(out72 + 0x20), nm.subject, 15);
    *(uint32_t*)(out72 + 0x30) = nm.msg_type;
    *(uint32_t*)(out72 + 0x34) = nm.timestamp ? nm.timestamp : (uint32_t)time(NULL);
    *(uint32_t*)(out72 + 0x38) = body_size;       /* polcore body parser walk limit */

    /* +0x3E ushort: bits 7-11 = icon-type, bit 15 = always-on valid flag. */
    uint16_t icon_field = (uint16_t)((nm.msg_type & 0x1F) << 7) | 0x8000;
    *(uint16_t*)(out72 + 0x3E) = icon_field;

    /* XOR-encrypt blocks 0/1 so polcore's filename decoder recovers the
     * intended plaintext accids. Without this, polcore reads garbage and
     * click-to-read hangs at "Downloading data". */
    uint32_t iv_lo, iv_hi;
    read_polcore_filename_iv(iv_lo, iv_hi);

    uint32_t* b0_lo = (uint32_t*)(out72 + 0x00);
    uint32_t* b0_hi = (uint32_t*)(out72 + 0x04);
    *b0_lo ^= POL_FNAME_XOR_LO ^ iv_lo;
    *b0_hi ^= POL_FNAME_XOR_HI ^ iv_hi;

    uint32_t* b1_lo = (uint32_t*)(out72 + 0x08);
    uint32_t* b1_hi = (uint32_t*)(out72 + 0x0C);
    *b1_lo ^= POL_FNAME_XOR_LO ^ iv_lo;
    *b1_hi ^= POL_FNAME_XOR_HI ^ iv_hi;
}

/* Local msg dir (one level above xiloader.exe), created by main.cpp's
 * CreateFileA hook. */
static std::string get_local_msg_dir()
{
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string dir(exePath);
    /* exe -> bootloader dir -> Ashita root. */
    size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos)
        dir = dir.substr(0, slash);
    slash = dir.find_last_of("\\/");
    if (slash != std::string::npos)
        dir = dir.substr(0, slash);

    /* Must match main.cpp EnsureMsgDir exactly. The file-API hooks pass an
     * already-qualified path through unchanged, so a path built without the
     * account segment gets the segment appended a second time. */
    char acct[32] = {};
    if (globals::g_AccountId != 0)
        wsprintfA(acct, "%u", globals::g_AccountId);
    else
        strcpy_s(acct, "_no_accid");
    return dir + "\\msg\\" + acct;
}

/* Write a message body file under msg\r\b\. Captures the encoded filename
 * into nm.filename so cleanup can DeleteFileA the exact name without
 * recomputing (which would embed a fresh time(NULL) at +0x34). */
static bool write_msg_file(NotifMessage& nm)
{
    /* Build body first so size can be embedded in the filename at +0x38
     * (polcore body-parser walk limit). */
    /* Wire format is subject <0x07> body <0x00> -- the same layout polcore
     * writes for sent messages. This previously emitted the SUBJECT as the
     * text and the local account's own name as the body, which made every
     * received message read as your own charname and, with an empty
     * subject, produced the blank "ghost" rows.
     */
    std::string body(nm.subject);
    body += (char)0x07;
    body += nm.body;
    body += (char)0;
    uint32_t body_size = (uint32_t)body.size();

    /* The server created_at, never time(NULL): this value is encoded into
     * the filename at +0x34, so a wall-clock stamp renames the same
     * message every login and defeats both existence checks below. */
    if (nm.timestamp == 0)
        nm.timestamp = (uint32_t)time(NULL);

    uint8_t fndata[72];
    build_msg_filename_data(fndata, nm, body_size);
    std::string filename = encode_msg_filename(fndata);
    strncpy(nm.filename, filename.c_str(), sizeof(nm.filename) - 1);
    nm.filename[sizeof(nm.filename) - 1] = '\0';

    std::string root = get_local_msg_dir();
    std::string dir  = root + "\\r\\b";
    std::string path = dir + "\\" + filename;

    /* Read messages live in r\a. Nothing tells the server a message was
     * read, so rewriting one into r\b resurrects it unread every login. */
    if (GetFileAttributesA((root + "\\r\\a\\" + filename).c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;

    if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return true;

    CreateDirectoryA(dir.c_str(), NULL);

    /* Body layout: text + 0x07 + recipient_charname + 0x00. */
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    DWORD written = 0;
    WriteFile(hFile, body.c_str(), body_size, &written, NULL);
    CloseHandle(hFile);

    xiloader::console::output_to_channel("friend",
        "FriendSys: wrote msg file '%s' (%d bytes)", filename.c_str(), (int)written);
    return true;
}

/* full_init reads the notification count at [FFXi+0x4DD798]+0x0A to know how
 * many files to scan; per-frame would normally set it. */
static constexpr uint32_t OFF_NOTIF_COUNT_PTR = 0x4DD798;

/* Re-fire FUN_048102F0 on the cached msg_obj to refresh the inbox display
 * from msg/r/b/. Worker-thread safe via call_inbox_enum_seh. */
static void trigger_inbox_refresh(const char* reason)
{
    if (s_ffxiBase == nullptr) return;
    uint32_t msg_obj_ptr = *(uint32_t*)(s_ffxiBase + OFF_MSG_OBJ_NATIVE);
    if (msg_obj_ptr == 0) return;

    uint8_t* msg_obj = (uint8_t*)(uintptr_t)msg_obj_ptr;

    /* Only refresh when the inbox has actually been opened. full_init
     * allocates the render array at msg_obj+0x68 when the user opens
     * Messages; until then it is NULL. Re-firing the enumerator on a
     * never-opened inbox re-enters the "waiting for server data" render
     * (inbox_wait_render, FFXi+0x200EF0) whose load never completes in
     * our setup, leaving the "Downloading data..." banner stuck. When the
     * inbox is closed the message is already written to disk and the native
     * load picks it up on open, so skipping the refresh loses nothing. */
    if (*(uint32_t*)(msg_obj + 0x68) == 0)
        return;

    uint32_t arg2 = *(uint32_t*)(msg_obj + 0x58);
    uint32_t arg3 = *(uint32_t*)(msg_obj + 0x5C);
    uint32_t arg4 = *(uint32_t*)(msg_obj + 0x60);

    int ok = call_inbox_enum_seh(s_ffxiBase, msg_obj, arg2, arg3, arg4);
    xiloader::console::output(ok ? xiloader::color::success : xiloader::color::error,
        "FriendSys: inbox re-enum (%s) -> %s", reason, ok ? "ok" : "CRASHED");
}

/* React to native polcore dismissals: Read/Exit moves the msg file
 * msg/r/b/ -> msg/r/a/. For each cached entry whose filename is now in /a/,
 * drop it from the cache and refresh the UI. Key stays in s_injected_keys
 * so the next notification poll doesn't re-inject the same message into /b/. */
static void sweep_dismissed_messages()
{
    if (s_cached_messages.empty()) return;

    std::set<std::string> a_files;
    std::string pattern = get_local_msg_dir() + "\\r\\a\\*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            a_files.insert(fd.cFileName);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    if (a_files.empty()) return;

    int dismissed = 0;
    auto it = s_cached_messages.begin();
    while (it != s_cached_messages.end())
    {
        if (it->filename[0] != '\0' && a_files.count(it->filename))
        {
            xiloader::console::output_to_channel("friend",
                "FriendSys: msg dismissed natively (b->a) -- '%s' subj='%s'",
                it->filename, it->subject);
            it = s_cached_messages.erase(it);
            dismissed++;
        }
        else
        {
            ++it;
        }
    }

    /* No trigger_inbox_refresh: re-firing FUN_048102F0 here either does a
     * network re-fetch or re-walks polcore's notification queue, causing the
     * dismissed row to reappear with stale body data. Retail relies on
     * polcore's per-frame loop to refresh once the file is gone from /b/. */
    (void)dismissed;
}

static void write_notification_files()
{
    int written = 0;
    {
        std::lock_guard<std::mutex> lk(s_notif_mtx);
        while (!s_notif_queue.empty())
        {
            NotifMessage nm = s_notif_queue.front();
            s_notif_queue.pop();
            if (!write_msg_file(nm))
                continue;
            written++;
            if ((int)s_cached_messages.size() < MAX_CACHED_MESSAGES)
                s_cached_messages.push_back(nm);
        }
        /* Drive the S:/R: notification-overlay badge from the cached-message
         * count. Without this, update_overlay_count() sees zero and skips
         * inject_notification forever -- so incoming friend requests never
         * pulse in the top-of-screen overlay until the user manually opens
         * the flist inbox (which populates the overlay via a different
         * FFXi-side path). */
        s_pending_notif_count = (int)s_cached_messages.size();
    }

    if (written > 0)
        trigger_inbox_refresh("new msg(s)");

    /* Set the notification manager count so full_init's task scans files. */
    if (written > 0 && s_ffxiBase != nullptr)
    {
        uint32_t mgr_ptr = *(uint32_t*)(s_ffxiBase + OFF_NOTIF_COUNT_PTR);
        if (mgr_ptr != 0)
        {
            uint8_t* mgr = (uint8_t*)(uintptr_t)mgr_ptr;
            uint16_t current = *(uint16_t*)(mgr + 0x0A);
            if (current == 0)
            {
                std::string dir = get_local_msg_dir() + "\\r\\b";
                int file_count = 0;
                WIN32_FIND_DATAA fd;
                std::string pattern = dir + "\\*";
                HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
                if (hFind != INVALID_HANDLE_VALUE)
                {
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                            file_count++;
                    } while (FindNextFileA(hFind, &fd));
                    FindClose(hFind);
                }

                if (file_count > 0)
                {
                    *(uint16_t*)(mgr + 0x0A) = (uint16_t)file_count;
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: set notif count = %d (mgr=0x%08X)",
                        file_count, mgr_ptr);
                }
            }
        }
    }
}

static constexpr uint32_t OFF_MSG_VTABLE = 0x33AC28;  /* set by constructor at +0x2006E0 */

static bool s_msg_insert_failed = false;

/* full_init binds UI, type string table, and message store on the native
 * msg_obj at [FFXi+0x62FF94]. The constructor at +0x2006E0 creates the object
 * but doesn't run full_init; called once from STATE_STEADY. */
static bool s_native_msg_init = false;

static int count_msg_files()
{
    std::string dir = get_local_msg_dir() + "\\r\\b\\*";
    int count = 0;
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(dir.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                count++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    return count;
}

static bool ensure_native_msg_obj()
{
    if (s_ffxiBase == nullptr)
        return false;

    if (s_native_msg_init)
        return true;

    uint32_t native_ptr = *(uint32_t*)(s_ffxiBase + OFF_MSG_OBJ_NATIVE);
    if (native_ptr == 0)
        return false;

    /* Vtable check: confirm correct type. Logged once per session. */
    uint32_t vt = *(uint32_t*)(uintptr_t)native_ptr;
    uint32_t expected_vt = (uint32_t)(uintptr_t)(s_ffxiBase + OFF_MSG_VTABLE);
    if (vt != expected_vt)
    {
        static bool s_logged = false;
        if (!s_logged)
        {
            xiloader::console::output(xiloader::color::warning,
                "FriendSys: native msg_obj vtable mismatch (got 0x%08X, want 0x%08X) -- logging once",
                vt, expected_vt);
            s_logged = true;
        }
        return false;
    }

    /* full_init binds vtable methods, type-string table, mode, and the
     * type_str_table pointer onto msg_obj. The function's tail invokes
     * `show_menu("msglist", 1, 0)` followed by a conditional second
     * `show_menu("titlehan", 1, 0)`; both pop the inbox panel visible.
     *
     * The vis-arg of show_menu was NOT the visibility control in this
     * build, so patching `PUSH 1 -> PUSH 0` did not suppress the panel
     * open. Instead, NOP both 19-byte show_menu call sequences in place.
     * The init work (msg_obj field writes, type_str_table install) runs
     * before the show_menu calls; only the visual open is removed.
     *
     * Layout (relative to full_init start):
     *   +0x76 .. +0x88   show_menu site 1 (19B)  <- NOP
     *   +0x89 .. +0x91   conditional check on second show_menu
     *   +0x92 .. +0xA4   show_menu site 2 (19B)  <- NOP
     *   +0xA5            success return (MOV AL,1; RET 0x0C)
     *
     * OFF_FULL_INIT_VIS1 points at the `01` of `6A 01` (PUSH 1) at +0x79,
     * which is 3 bytes into the show_menu call. So call start = VIS1-3. */
    typedef int (__thiscall* FnFullInit)(void*, int, int, int);
    FnFullInit fullInit = (FnFullInit)(s_ffxiBase + OFF_FULL_INIT);

    uint8_t* call1 = s_ffxiBase + OFF_FULL_INIT_VIS1 - 3;
    uint8_t* call2 = s_ffxiBase + OFF_FULL_INIT_VIS2 - 3;
    constexpr size_t SHOW_MENU_CALL_LEN = 19;
    uint8_t saved1[SHOW_MENU_CALL_LEN];
    uint8_t saved2[SHOW_MENU_CALL_LEN];
    DWORD prot1 = 0, prot2 = 0;
    VirtualProtect(call1, SHOW_MENU_CALL_LEN, PAGE_EXECUTE_READWRITE, &prot1);
    memcpy(saved1, call1, SHOW_MENU_CALL_LEN);
    memset(call1, 0x90, SHOW_MENU_CALL_LEN);
    VirtualProtect(call2, SHOW_MENU_CALL_LEN, PAGE_EXECUTE_READWRITE, &prot2);
    memcpy(saved2, call2, SHOW_MENU_CALL_LEN);
    memset(call2, 0x90, SHOW_MENU_CALL_LEN);
    xiloader::console::output_to_channel("friend",
        "FriendSys: full_init show_menu NOP'd at +0x%X and +0x%X (19B each)",
        OFF_FULL_INIT_VIS1 - 3, OFF_FULL_INIT_VIS2 - 3);

    int file_count = count_msg_files();
    xiloader::console::output_to_channel("friend",
        "FriendSys: ensure_native_msg_obj: %d files in msg\\r\\b\\", file_count);

    __try
    {
        fullInit((void*)(uintptr_t)native_ptr, file_count, 0, 0);
        s_native_msg_init = true;

        uint8_t* obj = (uint8_t*)(uintptr_t)native_ptr;

        /* full_init leaves a phantom +0x54=1 sentinel; polcore's file-loader
         * appends N file entries onto +0x54, so the sentinel produces N+1
         * visible rows (off-by-one in inbox). */
        *(uint32_t*)(obj + 0x54) = 0;
        *(uint32_t*)(obj + 0x1C) = 0;
        *(uint16_t*)(obj + 0x20) = 0;

        xiloader::console::output_to_channel("friend",
            "FriendSys: native msg_obj initialized at 0x%08X (render=0x%08X, data=0x%08X, arg1=%d, +0x18=%u, +0x54=%u, +0x58=%d)",
            native_ptr,
            *(uint32_t*)(obj + 0x68),
            *(uint32_t*)(obj + 0x6C),
            file_count,
            (uint32_t)*(uint16_t*)(obj + 0x18),
            *(uint32_t*)(obj + 0x54),
            *(uint32_t*)(obj + 0x58));
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: full_init crashed on native msg_obj 0x%08X", native_ptr);
    }

    memcpy(call1, saved1, SHOW_MENU_CALL_LEN);
    VirtualProtect(call1, SHOW_MENU_CALL_LEN, prot1, &prot1);
    memcpy(call2, saved2, SHOW_MENU_CALL_LEN);
    VirtualProtect(call2, SHOW_MENU_CALL_LEN, prot2, &prot2);
    xiloader::console::output_to_channel("friend",
        "FriendSys: full_init show_menu bytes restored");


    return s_native_msg_init;
}

static bool init_callerC_slot();

typedef int  (__cdecl* FnCallerCInit)();
typedef int  (__cdecl* FnGenericDriver)(int slot);

static bool has_befriend_queued()
{
    std::lock_guard<std::mutex> lk(s_befriend_mtx);
    return !s_befriend_queue.empty();
}

static bool init_callerC_slot()
{
    if (s_polBase == nullptr)
        return false;

    FnCallerCInit ccInit = (FnCallerCInit)(s_polBase + OFF_CALLERC_INIT);
    s_callerC_slot = ccInit();

    if (s_callerC_slot < 0)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: CallerC no free slot (%d)", s_callerC_slot);
        return false;
    }

    /* Disable BF crypto on slot. */
    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_callerC_slot * OFF_DESC_STRIDE;
    desc[0x0B] = 0;

    s_callerC_pumps = 0;
    s_callerC_active = true;
    return true;
}

static void try_start_callerC()
{
    if (s_callerC_active || s_polBase == nullptr)
        return;

    BefriendRequest req;
    {
        std::lock_guard<std::mutex> lk(s_befriend_mtx);
        if (s_befriend_queue.empty())
            return;
        req = s_befriend_queue.front();
        s_befriend_queue.pop();
    }

    /* Save target data for on_send injection. */
    memset(s_befriend_target_charname, 0, sizeof(s_befriend_target_charname));
    memset(s_befriend_target_nickname, 0, sizeof(s_befriend_target_nickname));
    strncpy(s_befriend_target_charname, req.charname.c_str(), 15);
    strncpy(s_befriend_target_nickname, req.nickname.c_str(), 15);

    xiloader::console::output_to_channel("friend",
        "FriendSys: CallerC befriend '%s' nick='%s'",
        s_befriend_target_charname, s_befriend_target_nickname);

    if (!init_callerC_slot())
        return;

    s_callerC_is_notification = false;
    xiloader::console::output_to_channel("friend",
        "FriendSys: CallerC slot %d (befriend)", s_callerC_slot);
}

/* Direct ACPT (accept) request to the profile server, bypassing polcore's
 * CallerC pump. Server creates the friendship and marks the related
 * friend-request message as read. Returns true on status=0. */
static bool send_acpt_request(const char* target_charname, const char* nickname)
{
    if (globals::g_AccountId == 0 || s_FriendPort == 0 || target_charname == nullptr)
        return false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        xiloader::console::output(xiloader::color::error,
            "ACPT: socket() failed: %d", WSAGetLastError());
        return false;
    }
    DWORD timeout_ms = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(static_cast<u_short>(s_FriendPort));
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "ACPT: connect failed WSA=%d", WSAGetLastError());
        closesocket(sock);
        return false;
    }

    /* ACPT packet (40B padded). Server dispatches by 'ACPT' magic, parses
     * [4..7]=accid, [8..22]=target, [23..37]=nick. */
    uint8_t packet[40] = {};
    memcpy(packet, "ACPT", 4);
    *(uint32_t*)(packet + 4) = globals::g_AccountId;
    strncpy((char*)(packet + 8), target_charname, 15);
    if (nickname && nickname[0])
        strncpy((char*)(packet + 23), nickname, 15);

    int sent = send(sock, (const char*)packet, 40, 0);
    if (sent != 40)
    {
        xiloader::console::output(xiloader::color::warning,
            "ACPT: send returned %d (WSA=%d)", sent, WSAGetLastError());
        closesocket(sock);
        return false;
    }

    uint8_t resp[5] = {};
    int got = recv(sock, (char*)resp, sizeof(resp), 0);
    closesocket(sock);
    if (got < 5 || memcmp(resp, "ACPT", 4) != 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "ACPT: bad response (got=%d bytes, magic=0x%08X)", got, *(uint32_t*)resp);
        return false;
    }
    uint8_t status = resp[4];
    if (status == 0)
    {
        xiloader::console::output_to_channel("friend",
            "ACPT: server accepted friendship target='%s' nick='%s'",
            target_charname, nickname ? nickname : "");
        return true;
    }
    xiloader::console::output(xiloader::color::warning,
        "ACPT: server returned status=%u (target='%s')", status, target_charname);
    return false;
}


static void pump_callerC()
{
    if (!s_callerC_active || s_callerC_slot < 0 || s_polBase == nullptr)
        return;

    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_callerC_slot * OFF_DESC_STRIDE;

    if (desc[0] == 0)
    {

        xiloader::console::output_to_channel("friend",
            "FriendSys: CallerC %s completed (%d pumps)",
            s_callerC_is_notification ? "notification" : "befriend",
            s_callerC_pumps);
        s_callerC_slot = -1;
        s_callerC_active = false;
        s_callerC_is_notification = false;
        return;
    }

    FnGenericDriver driver = (FnGenericDriver)(s_polBase + OFF_GENERIC_DRIVER);
    driver(s_callerC_slot);
    s_callerC_pumps++;

    /* Hard timeout. */
    if (s_callerC_pumps > PUMP_TIMEOUT)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: CallerC %s timeout after %d pumps (mode=%d state=%d)",
            s_callerC_is_notification ? "notification" : "befriend",
            s_callerC_pumps, desc[0x08], desc[0x09]);
        force_free_slot(s_callerC_slot);
        s_callerC_slot = -1;
        s_callerC_active = false;
        s_callerC_is_notification = false;
    }
}



/* NotificationPickup -- native polcore init/driver pair for auth (03,03).
 * Init at polcore+0x25B50, driver at polcore+0x25D10. Driver auto-frees the
 * slot on completion. */

typedef int  (__cdecl* FnNotifPickupInit)(uint32_t, uint8_t, uint32_t, uint32_t, uint8_t);
typedef int  (__cdecl* FnNotifPickupDriver)(int, void*);

static int  s_notif_pickup_slot   = -1;
static bool s_notif_pickup_active = false;
static int  s_notif_pickup_pumps  = 0;

/* msgrec_recv probe state -- definitions live here so notif_pickup can set
 * s_msgrec_probe_pending on completion. Driver functions are defined further
 * below (after pump_notification_pickup). */
static int      s_msgrec_slot          = -1;
static bool     s_msgrec_active        = false;
static int      s_msgrec_pumps         = 0;
static bool     s_msgrec_probe_pending = false;
static uint8_t  s_msgrec_buf[16 * 0x50] = {};
static uint32_t s_msgrec_expected      = 0;

/* WhoIs (per-friend status query) state. Slot 0 is shared with notif_pickup,
 * msgrec_recv, and CallerC, so all four start paths gate on each other.
 * Driver functions are defined further below. */
static int      s_whois_slot           = -1;
static bool     s_whois_active         = false;
static int      s_whois_pumps          = 0;
static uint32_t s_whois_target_accid   = 0;

/* friend_status_recv_pump (Auth (2,3), bulk Array2 updater) state. Same slot
 * pool as WhoIs/notif_pickup/msgrec_recv/CallerC -- start paths must gate. */
static int      s_friend_status_slot   = -1;
static bool     s_friend_status_active = false;
static int      s_friend_status_pumps  = 0;

static bool s_notif_pickup_done_once = false;

static void try_start_notification_pickup()
{
    if (s_notif_pickup_active || s_polBase == nullptr)
        return;

    /* Native delivery is persistent -- run once per session. */
    if (s_notif_pickup_done_once)
        return;

    FnNotifPickupInit npInit = (FnNotifPickupInit)(s_polBase + OFF_NOTIF_PICKUP_INIT);

    /* Driver memcpy's arg1 (383B) into the 416B packet, so arg1 must be a
     * valid pointer. Server ignores packet content (responds by account state). */
    static uint8_t s_notif_pickup_buf[384] = {};
    __try
    {
        s_notif_pickup_slot = npInit(
            (uint32_t)(uintptr_t)s_notif_pickup_buf,  /* arg1: data ptr */
            0,                                         /* arg2: packet byte[0] */
            0,                                         /* arg3: -> packet[0x08] */
            0,                                         /* arg4: -> packet[0x0C] */
            0                                          /* arg5: packet byte[1] */
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: NotifPickup init crashed");
        s_notif_pickup_done_once = true;
        return;
    }

    if (s_notif_pickup_slot < 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: NotifPickup no free slot (%d)", s_notif_pickup_slot);
        return;
    }

    /* Disable BF crypto (same as CallerB/C). */
    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_notif_pickup_slot * OFF_DESC_STRIDE;
    desc[0x0B] = 0;

    s_notif_pickup_pumps = 0;
    s_notif_pickup_active = true;
}

static void pump_notification_pickup()
{
    if (!s_notif_pickup_active || s_notif_pickup_slot < 0 || s_polBase == nullptr)
        return;

    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_notif_pickup_slot * OFF_DESC_STRIDE;
    uint8_t mode_before = desc[0x0A];

    FnNotifPickupDriver npDriver = (FnNotifPickupDriver)(s_polBase + OFF_NOTIF_PICKUP_DRIVER);
    uint32_t result_val = 0;
    int status = 0;

    __try
    {
        status = npDriver(s_notif_pickup_slot, &result_val);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: NotifPickup driver crashed (pump %d, mode=%d->%d, desc[0]=%d)",
            s_notif_pickup_pumps, mode_before, desc[0x0A], desc[0]);
        s_notif_pickup_slot = -1;
        s_notif_pickup_active = false;
        s_notif_pickup_done_once = true;
        return;
    }

    s_notif_pickup_pumps++;

    /* Log mode transitions. */
    (void)mode_before;

    if (status == 1)
    {
        /* Driver returned 1 = done, slot auto-freed. */
        s_notif_pickup_slot = -1;
        s_notif_pickup_active = false;
        s_notif_pickup_done_once = true;

        /* Fetch every record the pickup announced, not just one.
         * result_val is the count polcore read from the NotifPickup header;
         * hardcoding 1 configured polcore's SM for a single record, so a
         * multi-record response never completed and NOTHING was parsed --
         * only the first pending message was ever delivered. */
        uint32_t announced = result_val;
        if (announced > 16) announced = 16;
        s_msgrec_expected = announced;
        /* Zero means nothing pending: do NOT fetch anyway. Fetching one record
         * regardless produced a zeroed entry that became an empty message and
         * got written to disk as a blank inbox row -- the "ghost" message. */
        s_msgrec_probe_pending = (announced > 0);
        return;
    }

    if (status < 0 && s_notif_pickup_pumps > 5)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: NotifPickup aborted on negative status %d (pump %d)",
            status, s_notif_pickup_pumps);
        force_free_slot(s_notif_pickup_slot);
        s_notif_pickup_slot = -1;
        s_notif_pickup_active = false;
        s_notif_pickup_done_once = true;
        return;
    }

    /* Hard timeout. */
    if (s_notif_pickup_pumps > PUMP_TIMEOUT)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: NotifPickup timeout after %d pumps", s_notif_pickup_pumps);
        force_free_slot(s_notif_pickup_slot);
        s_notif_pickup_slot = -1;
        s_notif_pickup_active = false;
        s_notif_pickup_done_once = true;
    }
}

/* ── msgrec_recv_pump driver ──────────────────────────────────────────────────
 * The second (3,3) 416B SM. Init at +0x27660 takes (entry_arr, count, stride),
 * driver at +0x276E0 pumps the SM. After successful completion, the entry
 * array is filled with `count` records (0x50B each when stride_flag==0,
 * 0x48B each when stride_flag!=0). One-shot probe gated by s_msgrec_probe_pending. */

typedef int (__cdecl* FnMsgRecRecvInit)(uint32_t /*entry_arr*/, uint32_t /*count*/, uint32_t /*stride_flag*/);
typedef int (__cdecl* FnMsgRecRecvDriver)(int /*slot*/);

/* (state vars are defined earlier, alongside notif_pickup state) */

static void try_start_msgrec_recv(uint32_t expected_count)
{
    if (s_msgrec_active || s_polBase == nullptr)
        return;

    if (expected_count == 0 || expected_count > 16)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: MsgRecRecv invalid count %u", expected_count);
        return;
    }

    memset(s_msgrec_buf, 0, sizeof(s_msgrec_buf));
    s_msgrec_expected = expected_count;

    FnMsgRecRecvInit mrInit = (FnMsgRecRecvInit)(s_polBase + OFF_MSGREC_RECV_INIT);

    __try
    {
        s_msgrec_slot = mrInit(
            (uint32_t)(uintptr_t)s_msgrec_buf,  /* entry array */
            expected_count,                      /* count -> desc[0x94] + desc[0xA0] (discriminator) */
            0                                    /* stride flag -> 0x50/entry; 1 -> 0x48/entry */
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: MsgRecRecv init crashed");
        return;
    }

    if (s_msgrec_slot < 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: MsgRecRecv no free slot (%d)", s_msgrec_slot);
        return;
    }

    /* Disable BF crypto on this slot (same as our other pumps). */
    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_msgrec_slot * OFF_DESC_STRIDE;
    desc[0x0B] = 0;

    s_msgrec_pumps = 0;
    s_msgrec_active = true;
}

/* Translate decoded msgrec entries (per docs/profile-server/msgrec-entry-layout.md)
 * into NotifMessage objects on s_notif_queue.
 * Returns the number of new entries bridged. write_notification_files() drains
 * the queue and feeds the existing native msg-object injection. */
/* Body-continuation records (see docs/profile-server/message-send-path.md).
 * entry[0x19..0x3D] carries text; 0x3E/0x3F stay the 0x0880 flag word. */
static constexpr uint32_t MSGREC_CHUNK = 0x25;
static constexpr uint8_t  MSGREC_TYPE_BODY_CHUNK = 0xFE;
static std::map<uint32_t, std::string> s_body_chunks;

static int bridge_msgrec_to_notif_queue(const uint8_t* buf, uint32_t count)
{
    int bridged = 0;
    std::lock_guard<std::mutex> lk(s_notif_mtx);

    /* Pre-pass: continuation records FOLLOW their parent, so chunks must be
     * collected before any message is built -- otherwise every body is
     * attached one delivery late, or missed entirely. */
    for (uint32_t i = 0; i < count; i++)
    {
        const uint8_t* e = buf + i * 0x50;
        if (e[0x18] != MSGREC_TYPE_BODY_CHUNK)
            continue;
        uint32_t parent = *(uint32_t*)(e + 0x10);
        uint32_t index  = *(uint32_t*)(e + 0x14);
        char piece[MSGREC_CHUNK + 1] = {};
        memcpy(piece, e + 0x19, MSGREC_CHUNK);
        size_t at = (size_t)index * MSGREC_CHUNK;
        std::string& acc = s_body_chunks[parent];
        if (acc.size() < at)
            acc.resize(at, 32);
        acc.replace(at, strlen(piece), piece, strlen(piece));
    }

    for (uint32_t i = 0; i < count; i++)
    {
        const uint8_t* e = buf + i * 0x50;
        NotifMessage nm = {};
        nm.from_accid = *(uint32_t*)(e + 0x10);
        nm.msg_id     = *(uint32_t*)(e + 0x14);
        nm.msg_type   = e[0x18];
        nm.timestamp  = *(uint32_t*)(e + 0x1C);
        /* Body-continuation record: carries message text, not an inbox row.
         * The msgrec entry has no body field and polcore ignores the
         * per-record pad, so the server splits the text across extra entries
         * (entry[0x10..0x47] is opaque to polcore). Stitch them onto the
         * parent by msg_id and never queue them. */
        if (nm.msg_type == MSGREC_TYPE_BODY_CHUNK)
            continue;   /* already gathered in the pre-pass */

        memcpy(nm.sender,  e + 0x20, 15);
        memcpy(nm.subject, e + 0x30, 13);

        xiloader::console::output_to_channel("friend",
            "FriendSys: MsgRecRecv[%u] from=%u id=%u type=%u ts=%u "
            "sender='%s' subj='%s' flag=%04X",
            i, nm.from_accid, nm.msg_id, nm.msg_type, nm.timestamp,
            nm.sender, nm.subject, *(uint16_t*)(e + 0x3E));

        /* A record with no sender and no subject carries nothing renderable;
         * queueing it writes a blank inbox row. */
        if (nm.sender[0] == 0 && nm.subject[0] == 0)
            continue;

        auto bit = s_body_chunks.find(nm.msg_id);
        if (bit != s_body_chunks.end())
        {
            strncpy(nm.body, bit->second.c_str(), sizeof(nm.body) - 1);
            nm.body[sizeof(nm.body) - 1] = (char)0;
            s_body_chunks.erase(bit);
        }

        std::string key = make_message_key(nm);
        if (s_injected_keys.count(key)) continue;
        s_injected_keys.insert(key);
        s_notif_queue.push(nm);
        bridged++;
    }
    return bridged;
}

static void pump_msgrec_recv()
{
    if (!s_msgrec_active || s_msgrec_slot < 0 || s_polBase == nullptr)
        return;

    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_msgrec_slot * OFF_DESC_STRIDE;
    /* msgrec_recv_pump's state byte is desc[0x08] (NOT desc[0x0A] which
     * notif_pump uses). polcore_init_descriptor doesn't reset desc[0x0A]
     * so it carries over from the previous SM. */
    uint8_t mode_before = desc[0x08];

    FnMsgRecRecvDriver mrDriver = (FnMsgRecRecvDriver)(s_polBase + OFF_MSGREC_RECV_DRIVER);
    int status = 0;

    __try
    {
        status = mrDriver(s_msgrec_slot);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: MsgRecRecv driver crashed (pump %d, mode=%d->%d, desc[0]=%d)",
            s_msgrec_pumps, mode_before, desc[0x08], desc[0]);
        s_msgrec_slot = -1;
        s_msgrec_active = false;
        return;
    }

    s_msgrec_pumps++;
    (void)mode_before;

    if (status == 1)
    {
        /* Decode + bridge the entries via helper (extracted because __try in
         * this function precludes C++ stack-unwound objects like
         * lock_guard from being defined in the same scope). */
        uint32_t actual_count = (s_msgrec_expected < 16) ? s_msgrec_expected : 16;
        int bridged = bridge_msgrec_to_notif_queue(s_msgrec_buf, actual_count);
        if (bridged > 0)
        {
            xiloader::console::output_to_channel("friend",
                "FriendSys: MsgRecRecv bridged %d notification(s) to s_notif_queue", bridged);
            write_notification_files();
        }
        s_msgrec_slot = -1;
        s_msgrec_active = false;
        return;
    }

    if (status < 0 && s_msgrec_pumps > 5)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: MsgRecRecv aborted on negative status %d (pump %d)",
            status, s_msgrec_pumps);
        force_free_slot(s_msgrec_slot);
        s_msgrec_slot = -1;
        s_msgrec_active = false;
        return;
    }

    if (s_msgrec_pumps > PUMP_TIMEOUT)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: MsgRecRecv timeout after %d pumps", s_msgrec_pumps);
        force_free_slot(s_msgrec_slot);
        s_msgrec_slot = -1;
        s_msgrec_active = false;
    }
}

/* ── WhoIs / friend-status query ──────────────────────────────────────────────
 * Native (4,6,0x18) per-friend status SM exposed via polcore's function table
 * (slots +0x304/+0x308). Init at +0x1D480 allocates a slot and zeroes the 0x18B
 * request buffer at *(slot+0x328); driver at +0x1D7D0 pumps the SM and writes
 * the result into globals at polcore+0x405820 (status table) and the +0x754xx /
 * +0xACxxx accessor cluster. See docs/profile-server/whois-status-query.md. */

typedef int (__cdecl* FnWhoIsInit)(void);
typedef int (__cdecl* FnWhoIsDriver)(int /*slot*/);

static void try_start_whois(uint32_t target_accid)
{
    if (s_whois_active || s_polBase == nullptr)
        return;

    FnWhoIsInit wInit = (FnWhoIsInit)(s_polBase + OFF_WHOIS_INIT);

    int slot = -1;
    __try
    {
        slot = wInit();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: WhoIs init crashed");
        return;
    }

    if (slot < 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: WhoIs no free slot (%d)", slot);
        return;
    }

    /* Disable BF crypto for this slot. */
    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + slot * OFF_DESC_STRIDE;
    desc[0x0B] = 0;

    /* The init zeroed the 0x18B query buffer at *(slot+0x328). Write the
     * target accid at offset 0 as a first-pass hypothesis; if the wire shape
     * shows a different field placement (e.g. charname at offset 4..0x13),
     * update here once we observe what the SM actually sends. */
    uint8_t* req_buf = (uint8_t*)*(uint32_t*)(desc + 0x328);
    if (req_buf != nullptr)
    {
        memset(req_buf, 0, 0x18);
        *(uint32_t*)(req_buf + 0) = target_accid;
    }

    s_whois_slot         = slot;
    s_whois_active       = true;
    s_whois_pumps        = 0;
    s_whois_target_accid = target_accid;
}

static void pump_whois()
{
    if (!s_whois_active || s_whois_slot < 0 || s_polBase == nullptr)
        return;

    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_whois_slot * OFF_DESC_STRIDE;
    uint8_t mode_before = desc[0x08];

    FnWhoIsDriver wDriver = (FnWhoIsDriver)(s_polBase + OFF_WHOIS_DRIVER);
    int status = 0;

    __try
    {
        status = wDriver(s_whois_slot);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: WhoIs driver crashed (pump %d, mode=%d->%d, desc[0]=%d)",
            s_whois_pumps, mode_before, desc[0x08], desc[0]);
        s_whois_slot = -1;
        s_whois_active = false;
        return;
    }

    s_whois_pumps++;

    static uint8_t s_last_inner_state = 0xFF;
    static bool s_logged_first_negative = false;
    bool log_neg = (status < 0)
                && (status == -0x140F || !s_logged_first_negative);
    if (status < 0) s_logged_first_negative = true;
    if (log_neg)
    {
        uint32_t recv_count = *(uint32_t*)(desc + 0x48);
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: WhoIs pump %d NEG status: mode=%d->%d inner=%d->%d status=%d bf=%d recv=%u",
            s_whois_pumps, mode_before, desc[0x08],
            s_last_inner_state, desc[0x09], status, desc[0x0B], recv_count);
        s_last_inner_state = desc[0x09];

        /* Dump on the FIRST CRC-error status only (-0x140F = -5135). Later
         * pumps return -0x1410 (-5136 = slot_validity_check stale-slot)
         * because the slot has been reused by a parallel CallerA keepalive,
         * which clobbers the recv buffer with a fresh AuthConfirm. We need
         * the buffer state at the moment of the actual CRC failure. */
        static bool s_whois_crc_dumped = false;
        if (status == -0x140F && !s_whois_crc_dumped)
        {
            s_whois_crc_dumped = true;
            xiloader::console::output(xiloader::color::error,
                "FriendSys: WhoIs CRC FAIL (status=%d) -- dumping recv buffer", status);
            uint32_t recv_buf_addr = *(uint32_t*)(desc + 0x328);
            if (recv_buf_addr != 0)
            {
                __try
                {
                    uint8_t* rb = (uint8_t*)recv_buf_addr;
                    char hex[64 * 3 + 1] = {};
                    for (int b = 0; b < 64; b++)
                        sprintf_s(hex + b * 3, 4, "%02x ", rb[b]);
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: WhoIs recv_buf[0..64]: %s", hex);
                    for (int b = 0; b < 64; b++)
                        sprintf_s(hex + b * 3, 4, "%02x ", rb[64 + b]);
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: WhoIs recv_buf[64..128]: %s", hex);
                }
                __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
    }

    if (status == 1)
    {
        /* Snapshot the WhoIs result globals so we can verify the SM produced
         * fresh data. Polcore writes 11+ globals on success; the most useful
         * for live-status updates are the online flag at +0xAC540 and the
         * account index at +0x7541C. */
        uint32_t r_online_flag = *(uint32_t*)(s_polBase + 0xAC540);
        uint32_t r_acct_index  = *(uint32_t*)(s_polBase + 0x7541C);
        uint32_t r_subindex    = *(uint32_t*)(s_polBase + 0x75420);
        uint32_t r_count_m1    = *(uint32_t*)(s_polBase + 0x75424);
        xiloader::console::output_to_channel("friend",
            "FriendSys: WhoIs done %d pumps; target_accid=%u "
            "online_flag=0x%08X acct_index=%d subindex=%u count-1=%u",
            s_whois_pumps, s_whois_target_accid,
            r_online_flag, (int32_t)r_acct_index, r_subindex, r_count_m1);
        s_whois_slot = -1;
        s_whois_active = false;
        return;
    }

    /* Negative status means polcore hit an unrecoverable wire error (e.g.
     * connection refused mid-flight when the profile server restarted).
     * The SM does not heal on its own, so free the slot and bail; the next
     * pump cycle will start a fresh WhoIs. */
    if (status < 0 && s_whois_pumps > 5)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: WhoIs aborted on negative status %d (pump %d, target_accid=%u)",
            status, s_whois_pumps, s_whois_target_accid);
        force_free_slot(s_whois_slot);
        s_whois_slot = -1;
        s_whois_active = false;
        return;
    }

    if (s_whois_pumps > PUMP_TIMEOUT)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: WhoIs timeout after %d pumps (target_accid=%u)",
            s_whois_pumps, s_whois_target_accid);
        force_free_slot(s_whois_slot);
        s_whois_slot = -1;
        s_whois_active = false;
    }
}

/* friend_status_recv_pump driver -- bulk live-status updater. Init returns a
 * fresh slot index; driver pumps cases 0-8 and returns 1 when complete. */
typedef int (__cdecl* FnFriendStatusInit)(void);
typedef int (__cdecl* FnFriendStatusDriver)(int slot);

static void try_start_friend_status()
{
    if (s_friend_status_active || s_polBase == nullptr)
        return;

    FnFriendStatusInit fInit = (FnFriendStatusInit)(s_polBase + OFF_FRIEND_STATUS_INIT);

    int slot = -1;
    __try
    {
        slot = fInit();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: friend_status init crashed");
        return;
    }

    if (slot < 0)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: friend_status no free slot (%d)", slot);
        return;
    }

    /* Disable BF crypto for this slot -- same as WhoIs/notif_pickup/msgrec. */
    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + slot * OFF_DESC_STRIDE;
    desc[0x0B] = 0;

    s_friend_status_slot   = slot;
    s_friend_status_active = true;
    s_friend_status_pumps  = 0;

    xiloader::console::output_to_channel("friend",
        "FriendSys: friend_status started (slot %d)", slot);
}

static void pump_friend_status()
{
    if (!s_friend_status_active || s_friend_status_slot < 0 || s_polBase == nullptr)
        return;

    uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_friend_status_slot * OFF_DESC_STRIDE;
    uint8_t mode_before = desc[0x08];
    uint8_t inner_before = desc[0x09];

    FnFriendStatusDriver fDriver = (FnFriendStatusDriver)(s_polBase + OFF_FRIEND_STATUS_DRIVER);
    int status = 0;

    __try
    {
        status = fDriver(s_friend_status_slot);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: friend_status driver crashed (pump %d, mode=%d->%d)",
            s_friend_status_pumps, mode_before, desc[0x08]);
        s_friend_status_slot = -1;
        s_friend_status_active = false;
        return;
    }

    s_friend_status_pumps++;

    /* Log first 5 pumps + state transitions + any negative status + periodic
     * snapshots. Same pattern as WhoIs -- first SM run will reveal the cases
     * that fire, so we capture every transition without flooding. */
    static uint8_t s_fs_last_inner = 0xFF;
    static bool    s_fs_logged_neg = false;
    if (status < 0 && !s_fs_logged_neg)
    {
        s_fs_logged_neg = true;
        uint32_t recv_count = *(uint32_t*)(desc + 0x48);
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: friend_status pump %d NEG status: mode=%d->%d inner=%d->%d "
            "status=%d bf=%d recv=%u",
            s_friend_status_pumps, mode_before, desc[0x08],
            inner_before, desc[0x09], status, desc[0x0B], recv_count);
        s_fs_last_inner = desc[0x09];
    }
    (void)mode_before; (void)inner_before;

    if (status == 1)
    {
        /* Snapshot the completion flag (DAT_0463CA80 -- resolved at runtime
         * into OFF_FRIEND_STATUS_DONE) and Array2 entries that the
         * friend_status_recv records would have touched. Stride is 0xB0
         * (verified via case-6 disasm of +0x237F0). Dump entry+0x8 (bit 28 =
         * online check, bit 29 = pending marker) and entry+0x98 (bit 0 =
         * occupied). */
        uint32_t completion = *(uint32_t*)(s_polBase + OFF_FRIEND_STATUS_DONE);
        uint8_t* arr2 = s_polBase + OFF_ARRAY2;
        uint32_t s1_8  = *(uint32_t*)(arr2 + 1 * 0xB0 + 0x08);
        uint32_t s1_c  = *(uint32_t*)(arr2 + 1 * 0xB0 + 0x0C);
        uint32_t s1_98 = *(uint32_t*)(arr2 + 1 * 0xB0 + 0x98);
        xiloader::console::output_to_channel("friend",
            "FriendSys: friend_status done %d pumps; completion=0x%08X "
            "Array2[1]+0x8=0x%08X +0xC=0x%08X +0x98=0x%08X",
            s_friend_status_pumps, completion, s1_8, s1_c, s1_98);
        s_friend_status_slot = -1;
        s_friend_status_active = false;
        /* friend_status just refreshed Array2 (including the online field at
         * entry+0x08 bits 13-15). Store 3 -- what /flist renders from -- only
         * picks that up when polcore's enrich copies Array2 -> Store 3, so
         * re-run the sync here. Without this the display keeps whatever state
         * enrich captured at CallerB time and never goes online. */
        s_resync_pending = true;
        return;
    }

    if (status < 0 && s_friend_status_pumps > 5)
    {
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: friend_status aborted on negative status %d (pump %d)",
            status, s_friend_status_pumps);
        force_free_slot(s_friend_status_slot);
        s_friend_status_slot = -1;
        s_friend_status_active = false;
        return;
    }

    if (s_friend_status_pumps > PUMP_TIMEOUT)
    {
        xiloader::console::output(xiloader::color::error,
            "FriendSys: friend_status timeout after %d pumps",
            s_friend_status_pumps);
        force_free_slot(s_friend_status_slot);
        s_friend_status_slot = -1;
        s_friend_status_active = false;
    }
}
static int s_overlay_last_notified_count = 0;

void friend_system::init()
{
    s_state = STATE_WAITING;
    s_tick_counter = 0;
    s_pump_slot = -1;
    s_pump_count = 0;
    s_populate_pending = false;
    s_wait_ticks = 0;
    s_patches_applied = false;
    s_consecutive_failures = 0;
    s_backoff_ticks = 0;
    s_inner_state_snapshot = -1;
    s_notif_overlay_applied = false;
    s_injected_keys.clear();
    s_pending_notif_count = 0;
    s_overlay_last_notified_count = 0;
    s_native_msg_init = false;
    s_notif_pickup_slot = -1;
    s_notif_pickup_active = false;
    s_notif_pickup_pumps = 0;
    s_notif_pickup_done_once = false;
    s_msg_insert_failed = false;
    s_pol_push_enabled = globals::g_EnablePolPush;
    if (s_pol_push_enabled)
        xiloader::console::output(xiloader::color::warning,
            "FriendSys: POL push channel ENABLED (--pol-push). Experimental: this "
            "has killed the client before.");
    xiloader::console::output_to_channel("friend", "FriendSys: initialized");
}

/* Drive polcore's POL connection state machine far enough to open the push
 * channel that carries friend status notifications.
 *
 * Nothing calls pol_msg_router during gameplay (the native per-frame caller
 * only runs during PlayOnline bootstrap), and its config block is empty on
 * xiloader, so it sits in the case-0 error state (-0x2C04) forever. We seed
 * the connect target and step it ourselves, exactly as the worker already
 * pumps CallerB/CallerC/WhoIs.
 *
 * State 0x16 is the connect state: it hands the handler table (which contains
 * status_update_dispatch) to the connection layer. Seeding the resolved-IP
 * string lets us start there and skip the DNS states, because FUN_10013A80
 * treats a leading digit as a literal IP. */
/* Inverse of polcore's buffer obfuscation (FUN_10047EC0), used for the host
 * buffer and the session-token blob:
 *   plain[len-1-i] = ror8(raw[i], i & 7), bitwise NOT when i is odd
 * so encoding is the reverse: rotate left, inverting on odd indices, writing
 * the plaintext backwards. Verified against the live params blob, which
 * encodes 8 zero bytes as 00 ff 00 ff 00 ff 00 ff. */
static void pol_obfuscate(uint8_t* dst, const uint8_t* plain, int len)
{
    for (int i = 0; i < len; i++)
    {
        uint8_t p = plain[len - 1 - i];
        if (i & 1)
            p = (uint8_t)~p;
        const int k = i & 7;
        dst[i] = (uint8_t)((p << k) | (p >> ((8 - k) & 7)));
    }
}

typedef void* (__cdecl* FnPolMalloc)(size_t);

/* Supply the key material polcore's own generator would have produced.
 *
 * polcore+0x47E40 is a shared `xor eax,eax; ret` placeholder that fills 13+
 * slots of the published function table -- the push channel's key generator is
 * one of the features compiled out of this build. Push SM case 5 calls it as
 * FUN_10047E40(fd, 1, &conn[0x39E4]) and then advances ONLY if conn[0x39F0] is
 * non-NULL, so with the stub it parks at state 5 forever. Confirmed live
 * 2026-08-23: channel 1 sat at state 5 with conn[0x39F0] == 0.
 *
 * Do NOT detour polcore+0x47E40 to fix this -- it is shared by unrelated
 * callers and hooking it would change all of them. Populate the fields
 * directly instead and let the native SM walk itself.
 *
 * The two "mask" fields are XOR-obfuscated pointers, not masks: the op-0x28
 * serializer reads its source bytes from (mask ^ buf). Leaving a mask 0 makes
 * it read the buffer itself, which yields a deterministic digest the profile
 * server can reproduce -- for buffer A the emitted byte is just the index i,
 * and for buffer B the first byte computes to 0 so its loop breaks at once.
 *
 * Returns false if the buffer could not be allocated from polcore's heap. */
static bool pol_push_provide_keys(int chan)
{
    if (s_polBase == nullptr)
        return false;

    uint8_t* conn = s_polBase + OFF_POL_CONN_ARRAY + (uint32_t)chan * POL_CONN_STRIDE;

    if (*(uint32_t*)(conn + CONN_KEY_BUF) != 0)
        return true;

    auto pol_malloc = (FnPolMalloc)(s_polBase + OFF_POL_MALLOC);

    auto alloc = [](FnPolMalloc fn, size_t n) -> void* {
        __try {
            return fn(n);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
    };
    void* bufA = alloc(pol_malloc, 16);
    if (bufA == nullptr)
    {
        xiloader::console::output_to_channel("friend", "PolPush: polcore malloc failed");
        return false;
    }
    memset(bufA, 0, 16);

    /* Only buffer A. FUN_10013A80 already allocates buffer B (CONN_KEY_BUF_B)
     * and derives its mask from the session blob; overwriting them leaks that
     * allocation and corrupts polcore's own key derivation. */
    *(uint32_t*)(conn + CONN_KEY_LEN)    = 16;
    *(uint32_t*)(conn + CONN_KEY_BUF)    = (uint32_t)(uintptr_t)bufA;
    *(uint32_t*)(conn + CONN_KEY_MASK_A) = 0;
    *(uint16_t*)(conn + CONN_KEY_READY)  = 1;

    xiloader::console::output_to_channel("friend",
        "PolPush: chan %d keys supplied (A=%p len=16, state=0x%02X flags=0x%02X)",
        chan, bufA, *(conn + CONN_STATE), *(conn + CONN_FLAGS));
    return true;
}

/* OFF by default.
 *
 * Driving pol_msg_router from the worker races with polcore's own friend state
 * machines: they share the connection-slot array at DAT_103E58A0, and the
 * bring-up left WhoIs failing with -0x203/-5136 and the client dying before it
 * reached the world. It also seeds a host buffer that polcore's resolver reads
 * unterminated ("Resolving host: 127.0.0.1<garbage>").
 *
 * The channel itself does reach us -- it connects to 51240 natively and the
 * server accepts it -- but polcore then sends nothing, because its connection
 * driver parks at sub-state 5 waiting on a buffer (DAT_103E9290[slot]) that is
 * never allocated in this build. Forcing the state machine further is not the
 * answer; polcore's own preconditions need to be satisfied so it walks the
 * sequence itself. Until then this stays off so the friend system keeps
 * working. */
/* Definition lives near the POL offsets above. */

static void pump_pol_push()
{
    if (s_polBase == nullptr || !s_pol_push_enabled)
        return;

    static int  s_last_state = INT32_MIN;
    static int  s_steps      = 0;

    int32_t* state = (int32_t*)(s_polBase + OFF_POL_SM_STATE);

    if (!s_seeded)
    {
        /* Seed the obfuscated pp host, then hand polcore its own config call
         * rather than force-writing the state.
         *
         * The earlier version jumped straight to 0x13 with hand-seeded
         * buffers. pol_set_conn_config does the whole job natively: it sets
         * the router mode AND resets the latched -0x2C04 state to 0x12, from
         * which polcore walks 0x13 (its own crypto bootstrap) -> 0x14/0x15
         * (resolve) -> 0x16 (connect) -> 0x17 (push SM) by itself.
         *
         * cfg+0x14 must point at 16 readable bytes. cfg+0x8/+0xC/+0x10 are
         * read only when the connection class (DAT_10099C80) is 0 or 2 -- it
         * is 1 here -- but they are pointed at a zeroed buffer regardless so a
         * class change cannot dereference null. */
        /* Static: polcore keeps cfg+0x14 only for the duration of the call,
         * but the pad must outlive it if the class ever changes. */
        static uint8_t s_cfg_seed[16] = {};
        static uint8_t s_cfg_pad[64]  = {};
        static uint32_t s_cfg[8]      = {};
        for (int i = 0; i < 8; i++)
            s_cfg[i] = (uint32_t)(uintptr_t)s_cfg_pad;
        s_cfg[5] = (uint32_t)(uintptr_t)s_cfg_seed;

        typedef int (__cdecl* FnPolSetConnConfig)(int, void*);
        auto set_cfg = [](uint8_t* base, void* cfg) -> int {
            __try {
                auto fn = (FnPolSetConnConfig)(base + OFF_POL_SET_CONN_CONFIG);
                return fn(1, cfg);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return INT32_MIN;
            }
        };

        /* MINIMAL UNLATCH -- do not call pol_set_conn_config.
         *
         * That function resets a dozen shared globals (DAT_1009924C,
         * DAT_10099254/58, DAT_1009AA0C/14/5C, DAT_1009A5D0, DAT_100993F0[0x18],
         * _DAT_100996BC, _DAT_10099410) and re-derives the session crypto blob.
         * With it, friend_status never completes again for the rest of the
         * session -- and tearing the push channel back down does NOT recover,
         * so the damage is persistent. Restoring just the key blob was not
         * enough.
         *
         * Only two things actually gate the router:
         *   DAT_10099414 != 0   -> state 0x11 goes to 0x12 instead of 0x1E
         *   DAT_10099408        -> latched at -0x2C04 from a first-tick race
         * Set exactly those and leave every other global alone. */
        /* Creating the push connection clears polcore's session-ready flag,
         * which every friend operation depends on. Save it now. */
        pol_session_ready_snapshot(s_polBase);

        const int32_t before = *state;
        DWORD gp = 0;
        if (VirtualProtect(s_polBase + OFF_POL_ROUTER_MODE, 4, PAGE_READWRITE, &gp))
        {
            *(uint32_t*)(s_polBase + OFF_POL_ROUTER_MODE) = 1;
            VirtualProtect(s_polBase + OFF_POL_ROUTER_MODE, 4, gp, &gp);
        }
        *state = 0x12;
        const int rc = 0;
        s_seeded = true;
        xiloader::console::output_to_channel("friend",
            "PolPush: pol_set_conn_config(1) rc=%d, state 0x%08X -> 0x%08X",
            rc, (unsigned)before, (unsigned)*state);

        /* Seed the pp host AFTER the config call, never before: that call
         * encodes the session seed into OFF_POL_KEY_BLOB with a length of
         * strlen(seed)+1, and the seed is 16 bit-sliced bytes with no
         * guaranteed NUL, so it can run past the 0x11-byte slot and clobber
         * this buffer, which begins immediately after it.
         *
         * The length MUST include the terminator. The decoder (FUN_10047EC0,
         * reached via FUN_10047370) writes exactly src[0x41] bytes and does
         * not append one, so a length of strlen() leaves the resolver reading
         * an unterminated string off the stack. */
        uint8_t host_plain[] = "127.0.0.1";
        const int host_len = (int)sizeof(host_plain);

        uint8_t* hbuf = s_polBase + OFF_POL_HOST_BUF;
        DWORD prot = 0;
        if (VirtualProtect(hbuf, 0x42, PAGE_READWRITE, &prot))
        {
            memset(hbuf, 0, 0x42);
            pol_obfuscate(hbuf, host_plain, host_len);
            hbuf[0x41] = (uint8_t)host_len;
            VirtualProtect(hbuf, 0x42, prot, &prot);
        }
    }

    int32_t st = *state;

    /* State 0x17 re-drives the push SM every tick and only advances when that
     * SM reports completion. The SM parks at its own sub-state 5 until the key
     * buffer exists, so supply it here before pumping -- otherwise 0x17 spins
     * forever. Verified live 2026-08-23: without this, channel 1 sat at
     * sub-state 5 with a NULL buffer indefinitely. */
    /* Point the push SM at THIS client's proxy port.
     *
     * polcore otherwise dials a hardcoded 0xC828 (51240). Only one client can
     * own that, so a second client would connect to the FIRST client's proxy
     * and be pushed the wrong account's friends. Case 2/3 of the push SM uses
     * conn+0x2A8 as a port override when non-zero, byteswapping it into the
     * sockaddr -- so it wants host order. Written before the SM connects
     * (sub-state < 4); after that the socket already exists. */
    if ((st == 0x16 || st == 0x17) && s_proxyActive)
    {
        const int pchan = (int)*(uint32_t*)(s_polBase + OFF_POL_CONN_HANDLE);
        if (pchan >= 0 && pchan < 8)
        {
            uint8_t* pconn = s_polBase + OFF_POL_CONN_ARRAY
                           + (uint32_t)pchan * POL_CONN_STRIDE;
            if (*(pconn + CONN_STATE) < 4)
            {
                /* Byteswapped: case 2/3 does word[conn+0x28A] = swap(this),
                 * while the DEFAULT path writes the constant 0xC828 straight
                 * in. So to land on port P the override must hold swap(P) --
                 * writing P directly aims at the wrong port and the channel
                 * fails to connect. */
                const uint16_t want = (uint16_t)((s_proxyPushPort >> 8) |
                                                 (s_proxyPushPort << 8));
                uint16_t* portField = (uint16_t*)(pconn + CONN_PORT_OVERRIDE);
                if (*portField != want)
                    *portField = want;
            }
        }
    }

    if (st == 0x17)
    {
        const int chan = (int)*(uint32_t*)(s_polBase + OFF_POL_CONN_HANDLE);
        if (chan >= 0 && chan < 8)
        {
            uint8_t* conn = s_polBase + OFF_POL_CONN_ARRAY
                          + (uint32_t)chan * POL_CONN_STRIDE;
            if (*(conn + CONN_STATE) == 5 && *(uint32_t*)(conn + CONN_KEY_BUF) == 0)
            {
                if (!pol_push_provide_keys(chan))
                {
                    s_pol_push_enabled = false;
                    return;
                }
            }
        }
    }

    /* Terminal/error states: stop pumping so a failure does not spin. 0x1E is
     * the connected/idle state -- the channel is up and polcore's own receive
     * path takes over from there. */
    /* 0x1E is the router's connected/idle state -- the channel is UP, not
     * finished. Keep draining receive so pushed status notifications are
     * parsed; only stop stepping the router itself. */
    if (st == 0x1E)
    {
        if (st != s_last_state)
        {
            xiloader::console::output(xiloader::color::success,
                "PolPush: channel established (router 0x1E after %d steps)", s_steps);
            s_last_state = st;
        }
        pol_session_ready_restore(s_polBase);
        const int rchan = (int)*(uint32_t*)(s_polBase + OFF_POL_CONN_HANDLE);
        if (rchan >= 0 && rchan < 8)
        {
            auto drain = [](uint8_t* b, int c) {
                __try {
                    auto recv = (FnPolRecvConn)(b + OFF_POL_RECV_CONN);
                    for (int i = 0; i < 8; i++)
                        recv(c);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            };
            drain(s_polBase, rchan);

            /* Refresh is driven by polcore's native status-change callback
             * (Mine_PolStatusNotify), which status_update_dispatch fires once
             * per decoded record. Polling conn+0x39E0 here was the stand-in
             * for that before the stubbed slot was reclaimed. */
        }
        return;
    }

    if (st < 0 || st == 0x21)
    {
        if (st != s_last_state)
        {
            xiloader::console::output(st < 0 ? xiloader::color::warning
                                             : xiloader::color::success,
                "PolPush: state 0x%X after %d steps%s", st, s_steps,
                st < 0 ? " (error)" : " (channel established)");
            s_last_state = st;
        }

        /* Never give up, and never surface the failure.
         *
         * The channel dies for ordinary reasons -- the profile server was
         * restarted, the box went to sleep, a transient socket error. Any of
         * those used to end with FFXi polling the pp error slot and showing
         * POL-0008. Clear the error, park the router, and try again later; the
         * channel comes back on its own once the server is listening.
         *
         * Backoff is deliberate: retrying hard during zone-in is what has
         * killed the client before. */
        if (st < 0)
        {
            const DWORD now = GetTickCount();
            const DWORD delay = (s_push_retries < POL_PUSH_FAST_RETRIES)
                              ? POL_PUSH_RETRY_DELAY_MS
                              : POL_PUSH_SLOW_RETRY_MS;
            if (s_push_retry_at == 0)
            {
                s_push_retry_at = now + delay;
                return;
            }
            if (now < s_push_retry_at)
                return;

            s_push_retries++;
            s_push_retry_at = 0;
            s_seeded = false;
            s_last_state = INT32_MIN;
            if (s_push_retries <= POL_PUSH_FAST_RETRIES + 1)
                xiloader::console::output_to_channel("friend",
                    "PolPush: channel lost, reconnecting (attempt %d)", s_push_retries);
            return;
        }

        s_pol_push_enabled = false;
        return;
    }

    __try
    {
        FnPolMsgRouter router = (FnPolMsgRouter)(s_polBase + OFF_POL_MSG_ROUTER);
        router();
        s_steps++;

        /* Receive is NOT driven by the router or the push SM; without pumping
         * it the server's IRC replies are never parsed and the channel stalls
         * at sub-state 8 forever. It handles one message per call, so drain a
         * few per tick.
         *
         * Call FUN_10015C30(slot) directly rather than the outer pump at
         * polcore+0x45480. That outer pump RELEASES polcore's global lock
         * (FUN_10047FE0) and re-takes it around the receive, which from the
         * worker thread breaks mutual exclusion with the friend state machines
         * and wedges friend_status. FUN_10015C30 takes its own per-connection
         * lock only. */
        const int rchan = (int)*(uint32_t*)(s_polBase + OFF_POL_CONN_HANDLE);
        if (rchan >= 0 && rchan < 8)
        {
            FnPolRecvConn recv = (FnPolRecvConn)(s_polBase + OFF_POL_RECV_CONN);
            for (int i = 0; i < 8; i++)
                recv(rchan);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        xiloader::console::output(xiloader::color::error,
            "PolPush: pol_msg_router raised 0x%08X at state 0x%X -- disabling",
            GetExceptionCode(), st);
        s_pol_push_enabled = false;
        return;
    }

    /* Connection creation (router state 0x16) zeroes the session-ready flag.
     * Put it back every tick -- cheap, and it must not stay clear even briefly
     * or in-flight friend operations abort with -5136. */
    if (pol_session_ready_restore(s_polBase))
        xiloader::console::output_to_channel("friend",
            "PolPush: restored polcore session-ready flag cleared by connection setup");

    int32_t now = *state;
    if (now != s_last_state)
    {
        uint32_t handle = *(uint32_t*)(s_polBase + OFF_POL_CONN_HANDLE);
        xiloader::console::output_to_channel("friend",
            "PolPush: state 0x%X -> 0x%X (conn_handle=0x%08X)",
            st, now, handle);
        s_last_state = now;
    }
}

static void update_overlay_count()
{
    /* Show the server-reported pending count as the unread badge. */
    int effective = s_pending_notif_count;
    if (effective == 0)
        return;

    if (effective == s_overlay_last_notified_count)
        return;

    /* S must be non-zero for the pulsing animation. Do NOT re-inject
     * repeatedly -- addNotif would flood the node list. */
    uint8_t buf[0x48] = {};
    buf[0] = 0x01;
    if (inject_notification(buf, static_cast<uint16_t>(effective), static_cast<uint16_t>(effective)))
    {
        s_overlay_last_notified_count = effective;
        xiloader::console::output_to_channel("friend",
            "NotifOverlay: S:1 R:%d", effective);
    }
}

/* Captured by the __except filter so we can log the faulting EIP without
 * calling GetExceptionInformation() from inside the handler body (which
 * would return NULL). Module-static so the filter expression and handler
 * body share storage. */
static void* s_exc_addr = nullptr;

/* Set when offset resolution comes back incomplete. Once true the worker is
 * permanently inert: every OFF_* the pumps/hooks would use is unverified, so
 * touching s_polBase/s_ffxiBase with a stale or sentinel offset risks a wild
 * write. Better to run with the friend system off and a loud log than to
 * corrupt the game off a mis-resolved address. */
static bool s_friend_disabled = false;

void friend_system::on_tick()
{
    if (!globals::g_IsRunning || s_friend_disabled)
        return;

    __try
    {
        switch (s_state)
        {
        case STATE_WAITING:
        {
            HMODULE hFFXi = GetModuleHandleA("FFXiMain.dll");
            if (hFFXi == NULL)
            {
                if (s_wait_ticks % 300 == 0)
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: waiting for FFXiMain.dll...");
                s_wait_ticks++;
                break;
            }

            HMODULE hPol = GetModuleHandleA(polcore_module());
            if (hPol == NULL)
            {
                if (s_wait_ticks % 300 == 0)
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: waiting for polcore.dll...");
                s_wait_ticks++;
                break;
            }

            /* Module-init settle delay. */
            s_wait_ticks++;
            if (s_wait_ticks < SETTLE_TICKS) break;

            s_polBase  = (uint8_t*)(DWORD)hPol;
            s_ffxiBase = (uint8_t*)(DWORD)hFFXi;
            bool pol_ok  = resolve_polcore_offsets(s_polBase);
            bool ffxi_ok = resolve_ffximain_offsets(s_ffxiBase);
            if (!pol_ok || !ffxi_ok)
            {
                /* A signature failed to resolve (a client patch shifted or
                 * re-encoded something -- see the FAIL entries in the two
                 * dashboards above). Do NOT proceed: installing hooks and
                 * running the pumps against unresolved offsets would use
                 * stale/sentinel addresses. Disable the friend system and
                 * stop, loudly. */
                xiloader::console::output(xiloader::color::error,
                    "FriendSys: DISABLED -- offset resolution incomplete "
                    "(polcore=%s ffximain=%s). Update the broken FindPattern "
                    "signatures in resolve_*_offsets for this client build.",
                    pol_ok ? "ok" : "FAIL", ffxi_ok ? "ok" : "FAIL");
                s_friend_disabled = true;
                break;
            }

            /* Install friend-conn init/teardown hooks before any user
             * interaction -- game-start fires the auto-init/teardown sequence
             * before the Messages tab is ever opened. The downstream hook
             * block installs too late to catch them. */
            {
                static bool s_early_friend_hooks = false;
                if (!s_early_friend_hooks)
                {
                    Real_FriendConnInit     = (FnFriendConnInit)(s_ffxiBase + OFF_FRIEND_CONN_INIT);
                    Real_FriendConnTeardown = (FnFriendConnTeardown)(s_ffxiBase + OFF_FRIEND_CONN_TEARDOWN);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID&)Real_FriendConnInit, (PVOID)Mine_FriendConnInit);
                    DetourAttach(&(PVOID&)Real_FriendConnTeardown, (PVOID)Mine_FriendConnTeardown);
                    if (DetourTransactionCommit() == NO_ERROR)
                    {
                        s_early_friend_hooks = true;
                        xiloader::console::output_to_channel("friend",
                            "FriendSys: early friend-conn init/teardown hooks installed");
                    }
                }
            }

            /* Install /befriend diagnostic hooks unconditionally at STATE_READY
             * so they fire regardless of whether the user has opened the
             * Messages tab. */
            {
                static bool s_befriend_diag_hooks = false;
                if (!s_befriend_diag_hooks)
                {
                    Real_BefriendHandler  = (FnBefriendHandler)(s_ffxiBase + OFF_FFXI_BEFRIEND_HANDLER);
                    Real_BefriendOuter    = (FnBefriendOuter)(s_ffxiBase + OFF_FFXI_BEFRIEND_OUTER);
                    Real_BefriendInner    = (FnBefriendInner)(s_ffxiBase + OFF_FFXI_BEFRIEND_INNER);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID&)Real_BefriendHandler,   (PVOID)Mine_BefriendHandler);
                    DetourAttach(&(PVOID&)Real_BefriendOuter,      (PVOID)Mine_BefriendOuter);
                    DetourAttach(&(PVOID&)Real_BefriendInner,      (PVOID)Mine_BefriendInner);
                    Real_BefriendSubmit  = (FnBefriendSubmit)(s_ffxiBase + OFF_FFXI_BEFRIEND_SUBMIT);
                    Real_BefriendOpSend  = (FnBefriendOpSend)(s_ffxiBase + OFF_FFXI_BEFRIEND_OP_SEND);
                    Real_CharRecordInit  = (FnCharRecordInit)(s_ffxiBase + OFF_FFXI_CHAR_RECORD_INIT);
                    DetourAttach(&(PVOID&)Real_BefriendSubmit,     (PVOID)Mine_BefriendSubmit);
                    DetourAttach(&(PVOID&)Real_BefriendOpSend,     (PVOID)Mine_BefriendOpSend);
                    DetourAttach(&(PVOID&)Real_CharRecordInit,     (PVOID)Mine_CharRecordInit);
                    /* Mine_PolSendBodySm NOT attached: build 2026-07-02 changed
                     * polcore_send_body_sm to an ESI-in convention (desc in ESI,
                     * no stack prologue). A __cdecl Detour hook would forward
                     * through the trampoline with the wrong register/stack state
                     * and corrupt body-send (befriend / NotifPickup). The hook
                     * is a no-op diagnostic, so it stays disabled until rewritten
                     * as a naked ESI-preserving thunk. Offset still resolved. */
                    LONG commit = DetourTransactionCommit();
                    if (commit == NO_ERROR)
                    {
                        s_befriend_diag_hooks = true;
                        xiloader::console::output_to_channel("friend",
                            "FriendSys: /befriend diagnostic hooks installed early "
                            "(handler/submit/op_send/dat_msg)");
                    }
                    else
                    {
                        xiloader::console::output(xiloader::color::error,
                            "FriendSys: early /befriend hook commit failed: %ld", commit);
                    }
                }
            }

            uint32_t store3 = *(uint32_t*)(s_ffxiBase + OFF_STORE3_PTR);

            /* FFXiMain patches + notification overlay deferred to
             * STATE_ARRAY_SYNC, when Store3 != 0 confirms full game init. */

            xiloader::console::output_to_channel("friend",
                "FriendSys: ready (Store3=0x%08X, FFXi=0x%08X, pol=0x%08X), starting CallerB",
                store3, (uint32_t)(uintptr_t)s_ffxiBase, (uint32_t)(uintptr_t)s_polBase);

            /* Click-to-read gate: FUN_0491FD53 (mode=0 vs mode=16 in
             * msg_process_handler) thunks through `*(DAT_04A65A24 + 0x43C)`.
             * DAT_04A65A24 (FFXi+0x455A24) holds polcore's COM object ptr.
             * Resolve and classify the gate function for RE. */
            {
                constexpr uint32_t OFF_DAT_04A65A24 = 0x455A24;
                uint32_t pol_obj = *(uint32_t*)(s_ffxiBase + OFF_DAT_04A65A24);
                xiloader::console::output_to_channel("friend",
                    "ClickGate: DAT_04A65A24 (FFXi+0x%X) = polcore_obj=0x%08X",
                    OFF_DAT_04A65A24, pol_obj);
                if (pol_obj != 0)
                {
                    uint32_t fn_ptr = safe_read_dword_at(pol_obj + 0x43C);
                    uint32_t vtable = safe_read_dword_at(pol_obj);

                    /* C-style buffers -- enclosing on_tick uses __try
                     * (no C++ unwinding allowed). */
                    char fn_loc[64] = "unknown";
                    char vt_loc[64] = "unknown";
                    classify_addr(fn_ptr, fn_loc, sizeof(fn_loc));
                    classify_addr(vtable, vt_loc, sizeof(vt_loc));

                    xiloader::console::output_to_channel("friend",
                        "ClickGate: pol_obj+0 (vtable) = 0x%08X (%s)", vtable, vt_loc);
                    xiloader::console::output_to_channel("friend",
                        "ClickGate: pol_obj+0x43C = 0x%08X (%s) <-- the gate function",
                        fn_ptr, fn_loc);

                    /* Dump neighboring fields -- +0x43C may be part of a
                     * callback struct. */
                    char hex[256] = {};
                    int n = 0;
                    for (int off = 0x430; off <= 0x450 && n < 240; off += 4)
                    {
                        uint32_t v = safe_read_dword_at(pol_obj + off);
                        n += wsprintfA(hex + n, "+%X=%08X ", off, v);
                    }
                    xiloader::console::output_to_channel("friend",
                        "ClickGate: pol_obj fields: %s", hex);
                }
            }

            s_state = STATE_READY;
            break;
        }

        case STATE_READY:
        {
            /* FFXiMain offset health check. Build skew can shift these globals;
             * verify each pointer at startup. flistmai also gets a vtable check
             * to catch silent address shifts. */
            static bool s_ffxi_offsets_logged = false;
            if (!s_ffxi_offsets_logged)
            {
                s_ffxi_offsets_logged = true;
                struct { const char* name; uint32_t off; } ptrs[] = {
                    {"chat_obj",      0x62FF90},
                    {"msg_obj",       OFF_MSG_OBJ_NATIVE},
                    {"event_handler", 0x62FF9C},
                    {"flistmai",      OFF_FLISTMAI_PTR},
                    {"store3",        OFF_STORE3_PTR},
                    {"notif_mgr",     OFF_NOTIF_MGR_PTR},
                };
                for (auto& p : ptrs)
                {
                    uint32_t v = *(uint32_t*)(s_ffxiBase + p.off);
                    if (v == 0)
                        xiloader::console::output(xiloader::color::warning,
                            "FriendSys: FFXi+0x%06X (%s) = NULL", p.off, p.name);
                    else
                        xiloader::console::output_to_channel("friend",
                            "FriendSys: FFXi+0x%06X (%s) = 0x%08X", p.off, p.name, v);
                }
            }

            /* Restore sockaddr after failure -- polcore may clear it during
             * error cleanup. */
            if (s_consecutive_failures > 0)
            {
                uint8_t* sa = s_polBase + OFF_SOCKADDR;
                *(uint16_t*)(sa + 0) = 1;             /* AF_INET */
                *(uint16_t*)(sa + 2) = s_FriendPort;  /* network order */
                *(uint32_t*)(sa + 4) = 0x7F000001;    /* 127.0.0.1 BE */
            }

            FnCallerBInit cbInit = (FnCallerBInit)(s_polBase + OFF_CALLERB_INIT);
            s_pump_slot = cbInit();

            if (s_pump_slot < 0)
            {
                xiloader::console::output(xiloader::color::error,
                    "FriendSys: no free slot (%d), retry after backoff", s_pump_slot);
                s_consecutive_failures++;
                s_backoff_ticks = compute_backoff_ticks(s_consecutive_failures);
                s_tick_counter = 0;
                s_state = STATE_STEADY;
                break;
            }

            uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_pump_slot * OFF_DESC_STRIDE;
            desc[0x0B] = 0;

            s_pump_count = 0;
            s_inner_state_snapshot = -1;
            s_state = STATE_PUMPING;
            xiloader::console::output_to_channel("friend",
                "FriendSys: CallerB slot %d, pumping", s_pump_slot);
            break;
        }

        case STATE_PUMPING:
        {
            uint8_t* desc = s_polBase + OFF_DESC_ARRAY + s_pump_slot * OFF_DESC_STRIDE;

            if (desc[0] == 0)  /* slot freed by driver */
            {
                int synced = do_array_sync();
                write_handle_array();

                /* flistmai is allocated by FFXi engine init but stays
                 * uninitialized (slot count = -1, color/font handles NULL)
                 * until the user opens the friend menu visually. /befriend
                 * bails on a precondition before that happens. We replicate
                 * the SETUP-only portion of native flistmai_menu_open so
                 * /befriend has a fully drawable flistmai to act on. */
                flistmai_init_for_befriend();

                xiloader::console::output_to_channel("friend",
                    "FriendSys: CallerB done (%d pumps, %d synced)", s_pump_count, synced);
                s_pump_count = 0;
                s_consecutive_failures = 0;
                s_state = STATE_ARRAY_SYNC;
                break;
            }

            /* Snapshot inner state for stall detection. */
            if (s_pump_count == 0)
                s_inner_state_snapshot = desc[0x09];

            /* Early failure: inner state stuck at connect phase. */
            if (s_pump_count >= EARLY_FAIL_TICKS &&
                desc[0x09] == s_inner_state_snapshot && desc[0x09] <= 2)
            {
                xiloader::console::output(xiloader::color::error,
                    "FriendSys: CallerB early fail - inner state stuck at %d after %d pumps",
                    desc[0x09], s_pump_count);
                force_free_slot(s_pump_slot);
                s_pump_slot = -1;
                s_consecutive_failures++;
                s_backoff_ticks = compute_backoff_ticks(s_consecutive_failures);
                s_tick_counter = 0;
                s_state = STATE_STEADY;
                break;
            }

            FnCallerBPump cbPump = (FnCallerBPump)(s_polBase + OFF_CALLERB_PUMP);
            cbPump(s_pump_slot);
            s_pump_count++;

            /* Hard timeout. */
            if (s_pump_count > PUMP_TIMEOUT)
            {
                xiloader::console::output(xiloader::color::error,
                    "FriendSys: CallerB timeout after %d pumps (inner=%d)",
                    s_pump_count, desc[0x09]);
                force_free_slot(s_pump_slot);
                s_pump_slot = -1;
                s_consecutive_failures++;
                s_backoff_ticks = compute_backoff_ticks(s_consecutive_failures);
                s_tick_counter = 0;
                s_state = STATE_STEADY;
            }
            break;
        }

        case STATE_ARRAY_SYNC:
        {
            uint32_t store3_ptr = *(uint32_t*)(s_ffxiBase + OFF_STORE3_PTR);
            if (store3_ptr != 0)
            {
                uint16_t s3c = *(uint16_t*)((uint8_t*)(uintptr_t)store3_ptr + 0x132);
                if (s3c > 0)
                {
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: Store 3 has %d entries, proceeding to sync", s3c);
                    s_state = STATE_SYNC;
                    break;
                }
            }
            s_pump_count++;
            if (s_pump_count > SETTLE_TICKS)  /* ~5s wait for Store3 */
            {
                xiloader::console::output_to_channel("friend",
                    "FriendSys: Store3 not available, proceeding to steady");
                s_tick_counter = 0;
                s_consecutive_failures = 0;
                s_backoff_ticks = 0;
                s_state = STATE_STEADY;
            }
            break;
        }

        case STATE_SYNC:
        {
            do_sync_status();
            s_tick_counter = 0;
            s_consecutive_failures = 0;
            s_backoff_ticks = 0;
            s_state = STATE_STEADY;
            xiloader::console::output_to_channel("friend",
                "FriendSys: entering steady state (keepalive every %ds)",
                KEEPALIVE_TICKS / 60);
            break;
        }

        case STATE_STEADY:
        {
            /* Re-sync Store 3 from Array2 after a friend_status refresh so
             * online/offline transitions reach /flist. Cheap: no-ops when the
             * container or entry list is empty. */
            /* Hold the flag until the sync can actually run. A push that
             * lands while the list is closed used to clear it against a
             * do_sync_status() that early-returned at the UI gate, so the
             * update was dropped and only reappeared when the next 30s
             * keepalive happened to fire with the list open.
             *
             * The closed->open transition itself sets the flag, so data
             * pushed while the list was shut is applied as soon as it opens.
             * Not a timer: this is driven by UI readiness, which is by
             * definition outside the world-entry window. */
            const bool ui_ready = friend_list_ui_ready();
            if (ui_ready && !s_ui_was_ready)
                s_resync_pending = true;
            s_ui_was_ready = ui_ready;

            if (s_resync_pending && ui_ready)
            {
                s_resync_pending = false;
                do_sync_status();
            }

            /* NOTE: a 1s periodic do_sync_status() while the friend list is
             * open was tried here and REVERTED -- the client died at world
             * entry (push SM reached 0x17, then the process exited). This is
             * the same function that wedged world entry before it was gated on
             * the UI existing; calling it on a fast timer puts it back in the
             * dangerous window. Refresh stays driven by friend_status only. */

            /* If FFXi registers natively at some point after our write, the
             * slot changes out from under us -- that is the signal that the
             * native path exists and the shim is redundant. */
            if (s_notif_cb_expected != 0 && s_polBase != nullptr)
            {
                uint32_t* slot = (uint32_t*)(s_polBase + OFF_CALLBACK_PTR);
                if (*slot != s_notif_cb_expected)
                {
                    if (!s_notif_cb_drift_logged)
                    {
                        s_notif_cb_drift_logged = true;
                        xiloader::console::output_to_channel("friend",
                            "NotifCB: slot reclaimed from 0x%08X (stub) -> 0x%08X",
                            *slot, s_notif_cb_expected);
                    }
                    *slot = s_notif_cb_expected;
                }
            }

            /* Bring up the POL push channel (live friend status updates). */
            pump_pol_push();

            /* Apply deferred FFXiMain patches now that we're in steady state. */
            if (!s_patches_applied)
            {
                nop_bytes(s_ffxiBase + OFF_TYPE5_CHECK, 2);
                nop_bytes(s_ffxiBase + OFF_POP_CHECK1,  2);
                nop_bytes(s_ffxiBase + OFF_POP_CHECK2,  2);
                s_patches_applied = true;
                xiloader::console::output_to_channel("friend",
                    "FriendSys: FFXiMain patches applied (deferred)");
            }
            apply_notification_overlay_patches();

            /* Do NOT pre-open the inbox on login. full_init puts the inbox
             * window into its "waiting for server data" render state
             * (inbox_wait_render, FFXi+0x200EF0), which draws the persistent
             * "Downloading data..." banner until the inbox-list load
             * completes and swaps the render callback. That completion does
             * not fire in our worker-driven setup, so pre-opening the inbox
             * here left the banner stuck for the whole session. Retail does
             * not pre-open the inbox either; the message-notification overlay
             * (driven separately by msgrec -> inject_notification) still
             * surfaces new messages on login without it. */

            /* Retry flistmai_init_for_befriend until the engine's menu
             * resource tables (RES[1]/RES[2]/RES[5]) are populated by
             * FUN_047E0CF0. Without populate_friend_data on the flistmai
             * object, FFXi keeps the "Downloading data..." placeholder up
             * for the entire friend-system UI (Members tab, Messages tab,
             * S:/R: overlay) until the user opens flist manually. Poll
             * every ~30 ticks (~0.5s) so the retry is cheap but responsive. */
            {
                static int s_flist_retry_ticks = 0;
                if (++s_flist_retry_ticks >= 30)
                {
                    s_flist_retry_ticks = 0;
                    flistmai_init_for_befriend();
                }
            }

            /* One-shot probe of FFXi's command-line buffer (DAT_04A659A8 at
             * FFXi+0x4559A8). Empty here means polcore isn't propagating
             * SetParamInit args, so friend init can't read _pcnt and
             * FUN_046FFFD0 bails. */
            static bool s_cmdline_probed = false;
            if (!s_cmdline_probed && s_ffxiBase != nullptr)
            {
                s_cmdline_probed = true;
                __try {
                    uint32_t cmd_ptr = *(uint32_t*)(s_ffxiBase + 0x4559A8);
                    xiloader::console::output_to_channel("friend",
                        "FFXiCmdProbe: DAT_04A659A8 (FFXi+0x4559A8) = 0x%08X",
                        cmd_ptr);
                    if (cmd_ptr != 0)
                    {
                        char buf[256] = {};
                        strncpy(buf, (const char*)(uintptr_t)cmd_ptr, 255);
                        buf[255] = '\0';
                        xiloader::console::output_to_channel("friend",
                            "FFXiCmdProbe: cmdline = '%s'", buf);
                    }
                    else
                    {
                        xiloader::console::output(xiloader::color::warning,
                            "FFXiCmdProbe: cmd_ptr is NULL -> FFXi sees no args");
                    }

                    /* DAT_049E2C88 (FFXi+0x3D2C88) -- parsed args buffer
                     * FUN_04611E30 fills. Non-null = arg parsing ran. */
                    uint32_t parsed_ptr = *(uint32_t*)(s_ffxiBase + 0x3D2C88);
                    xiloader::console::output_to_channel("friend",
                        "FFXiCmdProbe: DAT_049E2C88 (parsed args) = 0x%08X",
                        parsed_ptr);
                    if (parsed_ptr != 0)
                    {
                        char buf[256] = {};
                        strncpy(buf, (const char*)(uintptr_t)parsed_ptr, 255);
                        buf[255] = '\0';
                        xiloader::console::output_to_channel("friend",
                            "FFXiCmdProbe: parsed = '%s'", buf);
                    }

                    /* Friend init chain "did it run?" globals. */
                    uint32_t a9edf4 = *(uint32_t*)(s_ffxiBase + 0x48EDF4);   /* DAT_04A9EDF4 -- FUN_046E9240 done flag */
                    uint32_t aefaec = *(uint32_t*)(s_ffxiBase + 0x4DFAEC);   /* DAT_04AEFAEC -- FUN_047121E0 buffer */
                    uint32_t aefae8 = *(uint32_t*)(s_ffxiBase + 0x4DFAE8);   /* DAT_04AEFAE8 -- FUN_047121E0 buffer */
                    uint32_t aee768 = *(uint32_t*)(s_ffxiBase + 0x4DE768);   /* DAT_04AEE768 -- FUN_046FFFD0 buffer */
                    uint32_t a9ee08 = *(uint32_t*)(s_ffxiBase + 0x48EE08);   /* DAT_04A9EE08 -- FUN_046E9810 */
                    uint32_t aee900 = *(uint32_t*)(s_ffxiBase + 0x4DE900);   /* DAT_04AEE900 -- FUN_04707550 / friend conn */
                    xiloader::console::output_to_channel("friend",
                        "FFXiInitProbe: A9EDF4=%08X (FUN_046E9240 done) "
                        "AEFAEC=%08X AEFAE8=%08X (FUN_047121E0 buffers)",
                        a9edf4, aefaec, aefae8);
                    xiloader::console::output_to_channel("friend",
                        "FFXiInitProbe: A9EE08=%08X (FUN_046E9810) "
                        "AEE768=%08X (FUN_046FFFD0 buffer) "
                        "AEE900=%08X (FUN_04707550 / friend conn)",
                        a9ee08, aee768, aee900);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    xiloader::console::output(xiloader::color::error,
                        "FFXiCmdProbe: AV (0x%08X)", GetExceptionCode());
                }
            }

            /* HandleMessageClick clears rebuild_flag on each Enter, so a
             * stale "Leave Unread" set bit unsticks on the next click without
             * a per-tick clear (which interfered with the rebuild consumer). */

            /* chat_obj at [FFXi+0x62FF90] needs embedded marker/buttonto UI
             * element definitions for the body display panel. Retail's
             * constructor populates this template; LSB leaves it zero. */
            {
                static bool s_chat_layout_init = false;
                if (!s_chat_layout_init && s_ffxiBase != nullptr)
                {
                    uint32_t chat_ptr = *(uint32_t*)(s_ffxiBase + 0x62FF90);
                    if (chat_ptr != 0)
                    {
                        uint8_t* co = (uint8_t*)(uintptr_t)chat_ptr;
                        if (*(co + 0x0D) == 0x00)
                        {
                            /* Retail chat_obj template, +0x0C..+0x1FF (500B):
                             * 6 marker + 2 buttonto + end marker. */
                            static const uint8_t CHAT_TEMPLATE[] = {
                                /* +0x0C */ 0x01,0x0A,0xFF,0xFF,
                                /* +0x10 */ 0x00,0x0A,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,
                                /* +0x20 */ 0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x01,0x00,0x01,0x01,
                                /* +0x30 */ 0x6D,0x65,0x6E,0x75,0x20,0x20,0x20,0x20,0x6D,0x61,0x72,0x6B,0x65,0x72,0x20,0x20, /* "menu    marker  " */
                                /* +0x40 */ 0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x0F,0x00,0x20,0x00,0x0F,0x00,
                                /* +0x50 */ 0x20,0x00,0x0F,0x00,0x00,0x00,0x30,0x00,0x00,0x60,0x60,0x7F,0x70,0x60,0x60,0x7F,
                                /* +0x60 */ 0x70,0x60,0x60,0x7F,0x70,0x60,0x60,0x7F,0x70,0x01,0x00,0x02,0x01,0x6D,0x65,0x6E,
                                /* +0x70 */ 0x75,0x20,0x20,0x20,0x20,0x62,0x75,0x74,0x74,0x6F,0x6E,0x74,0x6F,0x06,0x07,0x00, /* "menu    buttonto" */
                                /* +0x80 */ 0x05,0x00,0x0D,0x00,0x05,0x00,0x07,0x00,0x0B,0x00,0x0D,0x00,0x0B,0x00,0x10,0x00,
                                /* +0x90 */ 0x10,0x00,0x10,0x00,0x10,0x00,0x00,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,
                                /* +0xA0 */ 0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x01,0x00,0x01,0x01,0x6D,0x65,0x6E,0x75,0x20, /* "menu " */
                                /* +0xB0 */ 0x20,0x20,0x20,0x6D,0x61,0x72,0x6B,0x65,0x72,0x20,0x20,0x0D,0x00,0xFF,0xFF,0x13, /* "   marker  " */
                                /* +0xC0 */ 0x00,0xFF,0xFF,0x0D,0x00,0x05,0x00,0x13,0x00,0x05,0x00,0x10,0x00,0x10,0x00,0x10,
                                /* +0xD0 */ 0x00,0x10,0x00,0x00,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,
                                /* +0xE0 */ 0x7F,0x7F,0x7F,0x7F,0x01,0x00,0x01,0x01,0x6D,0x65,0x6E,0x75,0x20,0x20,0x20,0x20, /* "menu    " */
                                /* +0xF0 */ 0x6D,0x61,0x72,0x6B,0x65,0x72,0x20,0x20,0x0D,0x00,0x05,0x00,0x13,0x00,0x05,0x00, /* "marker  " */
                                /* +0x100 */ 0x0D,0x00,0x0B,0x00,0x13,0x00,0x0B,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x10,0x00,
                                /* +0x110 */ 0x00,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,
                                /* +0x120 */ 0x7F,0x01,0x00,0x01,0x01,0x6D,0x65,0x6E,0x75,0x20,0x20,0x20,0x20,0x6D,0x61,0x72, /* "menu    mar" */
                                /* +0x130 */ 0x6B,0x65,0x72,0x20,0x20,0x0D,0x00,0x0B,0x00,0x13,0x00,0x0B,0x00,0x0D,0x00,0x11, /* "ker  " */
                                /* +0x140 */ 0x00,0x13,0x00,0x11,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x00,0x7F,0x7F,
                                /* +0x150 */ 0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x01,0x00,
                                /* +0x160 */ 0x01,0x01,0x6D,0x65,0x6E,0x75,0x20,0x20,0x20,0x20,0x6D,0x61,0x72,0x6B,0x65,0x72, /* "menu    marker" */
                                /* +0x170 */ 0x20,0x20,0x13,0x00,0x05,0x00,0x19,0x00,0x05,0x00,0x13,0x00,0x0B,0x00,0x19,0x00, /* "  " */
                                /* +0x180 */ 0x0B,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x10,0x00,0x00,0x7F,0x7F,0x7F,0x7F,0x7F,
                                /* +0x190 */ 0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x01,0x00,0x01,0x01,0x6D, /* "m" */
                                /* +0x1A0 */ 0x65,0x6E,0x75,0x20,0x20,0x20,0x20,0x6D,0x61,0x72,0x6B,0x65,0x72,0x20,0x20,0x00, /* "enu    marker  " */
                                /* +0x1B0 */ 0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x0F,0x00,0x20,0x00,0x0F,0x00,0x20,
                                /* +0x1C0 */ 0x00,0x0F,0x00,0x00,0x00,0x30,0x00,0x00,0x60,0x60,0x7F,0x70,0x60,0x60,0x7F,0x70,
                                /* +0x1D0 */ 0x60,0x60,0x7F,0x70,0x60,0x60,0x7F,0x70,0x01,0x00,0x02,0x01,0x6D,0x65,0x6E,0x75,
                                /* +0x1E0 */ 0x20,0x20,0x20,0x20,0x62,0x75,0x74,0x74,0x6F,0x6E,0x74,0x6F,0x00,0x00,0x00,0x00, /* "    buttonto" */
                                /* +0x1F0 */ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x65,0x6E,0x64,0x00,                      /* "end" */
                            };
                            memcpy(co + 0x0C, CHAT_TEMPLATE, sizeof(CHAT_TEMPLATE));
                            xiloader::console::output_to_channel("friend",
                                "FriendSys: chat_obj layout initialized (%d bytes)", (int)sizeof(CHAT_TEMPLATE));
                        }
                        s_chat_layout_init = true;
                    }
                }
            }

            gate_keeper();

            /* React to native polcore-driven dismissals (file b/->a/).
             * Throttle to ~0.5s -- the FindFirstFileA inside is hooked by
             * main.cpp's MsgHook and would flood xiloader.log at 60Hz. */
            {
                static int s_dismiss_sweep_ticks = 0;
                if (++s_dismiss_sweep_ticks >= 30)
                {
                    s_dismiss_sweep_ticks = 0;
                    sweep_dismissed_messages();
                }
            }

            {
                static int s_notif_pickup_ticks = 0;
                constexpr int NOTIF_PICKUP_TICKS = 60 * 30; /* ~30s @ 60Hz */
                if (++s_notif_pickup_ticks >= NOTIF_PICKUP_TICKS)
                {
                    s_notif_pickup_ticks = 0;
                    if (!s_callerC_active && !s_notif_pickup_active && !s_msgrec_active && !s_whois_active)
                    {
                        /* All slot-0 pumps stomp each other if started concurrently.
                         * Skip this tick if any pump is in flight -- next 30s
                         * interval retries. */
                        s_notif_pickup_done_once = false;
                        try_start_notification_pickup();
                    }
                }
            }

            /* Drive the notification-pickup SM if active. */
            if (s_notif_pickup_active)
            {
                pump_notification_pickup();
            }

            /* Drive the msgrec_recv_pump SM if active (post-pump record fetch). */
            if (s_msgrec_active)
            {
                pump_msgrec_recv();
            }
            else if (s_msgrec_probe_pending && !s_callerC_active && !s_notif_pickup_active && !s_whois_active)
            {
                /* One-shot probe -- triggered after each NotifPickup completes. */
                s_msgrec_probe_pending = false;
                if (s_msgrec_expected > 0)
                    try_start_msgrec_recv(s_msgrec_expected);
            }

            /* Drive WhoIs (per-friend status query) if active, else fire one
             * smoke-test pump on a slow cadence. Slot 0 is shared with
             * notif_pickup, msgrec_recv, and CallerC; all four start paths
             * gate on each other.
             *
             * First-pass implementation: hardcoded test accid (1007 = CharB)
             * so we can observe the wire shape and validate the SM end-to-end.
             * Once the wire+result globals are confirmed, replace with
             * round-robin iteration over polcore's friend table at +0xB40D8
             * (stride 0x2C, occupancy bitmap at DAT_0463CA58). */
            if (s_whois_active)
            {
                pump_whois();
            }
            else
            {
                static int s_whois_ticks   = 0;
                static int s_whois_friend_idx = 0;
                /* Cycle one friend every ~10s so a typical 7-friend list
                 * refreshes every ~70s, comparable to retail's WhoIs cadence. */
                constexpr int WHOIS_TICKS  = 60 * 10;
                if (++s_whois_ticks >= WHOIS_TICKS)
                {
                    /* Only reset the counter and advance the index when we
                     * actually start a pump. If another slot-0 pump is in
                     * flight, hold at the threshold so we retry next tick. */
                    if (!s_callerC_active && !s_notif_pickup_active &&
                        !s_msgrec_active && !s_friend_status_active)
                    {
                        /* Walk Array2 (polcore+0xB40D8, stride 0x2C -- copy size
                         * 0xB0 reads ahead into neighboring entries) starting
                         * from s_whois_friend_idx until we find an occupied
                         * slot. NOTE: offset 0 is a 64-bit HASH from
                         * FUN_04599D40(record[4], record[5]), NOT raw accid.
                         * Accid extraction needs further RE -- for now this
                         * iteration finds *some* non-zero value to query, but
                         * it's not the friend's accid. Acceptable while
                         * friend_status_recv_pump is the primary path; WhoIs
                         * here is informational only. */
                        constexpr int MAX_FRIENDS = 200;
                        uint8_t* arr2 = s_polBase + OFF_ARRAY2;
                        uint32_t target = 0;
                        for (int n = 0; n < MAX_FRIENDS; n++)
                        {
                            int i = (s_whois_friend_idx + n) % MAX_FRIENDS;
                            uint32_t accid = *(uint32_t*)(arr2 + i * 0x2C);
                            if (accid != 0)
                            {
                                target = accid;
                                s_whois_friend_idx = (i + 1) % MAX_FRIENDS;
                                break;
                            }
                        }
                        if (target != 0)
                        {
                            s_whois_ticks = 0;
                            try_start_whois(target);
                        }
                        else
                        {
                            /* Empty friend list -- back off so we don't busy-loop
                             * over an empty array every tick. */
                            s_whois_ticks = 0;
                        }
                    }
                }
            }

            /* Drive friend_status_recv_pump (Auth (2,3) bulk Array2 updater).
             * This is the SM that actually moves /flist online status post
             * game-start. WhoIs only writes scattered globals; only this SM
             * writes Array2 directly (via FUN_0459EEB0).
             *
             * Cadence: every ~30s. Slot 0 is shared with all the other auth
             * pumps -- gate on every other slot-0 user. */
            if (s_friend_status_active)
            {
                pump_friend_status();
            }
            else
            {
                static int s_fs_ticks = 0;
                constexpr int FS_TICKS = 60 * 30;
                if (++s_fs_ticks >= FS_TICKS)
                {
                    if (!s_callerC_active && !s_notif_pickup_active &&
                        !s_msgrec_active && !s_whois_active)
                    {
                        s_fs_ticks = 0;
                        try_start_friend_status();
                    }
                }
            }

            update_overlay_count();

            /* Drive CallerC if active (befriend). */
            if (s_callerC_active)
            {
                pump_callerC();
            }
            else if (has_befriend_queued())
            {
                try_start_callerC();
            }

            /* CallerB re-pump only on failure recovery, never periodic.
             * Native polcore invokes op_type 0x08 (FUN_045A2210) once at
             * game-start via polcore->CreateFriendList(); accept inserts run
             * inline via BefriendResponse (FUN_045A4170 case 11), and live
             * status flows through CallerC notification pickup. Periodic
             * re-entry produced duplicate friend rows because the dynamic
             * slot allocator picked a different slot than the inline insert. */
            if (s_backoff_ticks > 0)
            {
                s_tick_counter++;
                if (s_tick_counter >= s_backoff_ticks)
                {
                    xiloader::console::output_to_channel("friend",
                        "FriendSys: backoff expired (%ds), retrying (failures=%d)",
                        s_backoff_ticks / 60, s_consecutive_failures);
                    s_tick_counter = 0;
                    s_backoff_ticks = 0;
                    s_state = STATE_READY;
                }
            }
            break;
        }
        }
    }
    __except(s_exc_addr = ((GetExceptionInformation() != nullptr &&
                            GetExceptionInformation()->ExceptionRecord != nullptr)
                           ? GetExceptionInformation()->ExceptionRecord->ExceptionAddress
                           : nullptr),
             EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD code = GetExceptionCode();
        static int s_exception_count = 0;
        s_exception_count++;
        xiloader::console::output(xiloader::color::error,
            "FriendSys: exception in state %d (code=0x%08X addr=%p count=%d)",
            s_state, code, s_exc_addr, s_exception_count);
        /* After 3 exceptions in STATE_WAITING, bail to a quiescent STEADY
         * state to stop the crash-loop and let the user actually use the
         * game. The resolver mis-resolved something; nothing we can do at
         * runtime to recover, but at least don't burn the log. */
        if (s_state == STATE_WAITING && s_exception_count >= 3)
        {
            xiloader::console::output(xiloader::color::error,
                "FriendSys: too many exceptions in STATE_WAITING -- "
                "forcing STATE_STEADY (friend system disabled)");
            s_state = STATE_STEADY;
            s_backoff_ticks = 0x7FFFFFFF;
        }
    }
}

void friend_system::shutdown()
{
    if (s_pump_slot >= 0 && s_pump_slot < 4 && s_polBase != nullptr)
    {
        force_free_slot(s_pump_slot);
        s_pump_slot = -1;
    }
    if (s_callerC_slot >= 0 && s_callerC_slot < 4 && s_polBase != nullptr)
    {
        force_free_slot(s_callerC_slot);
        s_callerC_slot = -1;
    }
    s_callerC_active = false;

    s_state = STATE_WAITING;
    xiloader::console::output_to_channel("friend", "FriendSys: shutdown");
}

void friend_system::request_befriend(const std::string& charname, const std::string& nickname)
{
    if (!s_FriendActive)
    {
        xiloader::console::output(xiloader::color::error, "FriendSys: not active, cannot befriend");
        return;
    }

    /* Queue a CallerC op -- polcore drives the TCP connection; on_send()
     * injects target charname/nickname into the 304B BefriendRequest. */
    {
        std::lock_guard<std::mutex> lk(s_befriend_mtx);
        s_befriend_queue.push({charname, nickname.empty() ? charname : nickname});
    }

    xiloader::console::output_to_channel("friend",
        "FriendSys: queued befriend request for '%s'", charname.c_str());
}

void friend_system::request_accept(uint32_t from_accid, const std::string& nickname)
{
    if (!s_FriendActive) return;
    xiloader::console::output(xiloader::color::warning,
        "FriendSys: TODO request_accept(accid=%u, nick='%s') -- needs BefriendResponse packet builder",
        from_accid, nickname.c_str());
}

void friend_system::request_decline(uint32_t from_accid)
{
    if (!s_FriendActive) return;
    xiloader::console::output(xiloader::color::warning,
        "FriendSys: TODO request_decline(accid=%u) -- needs decline packet builder", from_accid);
}

void friend_system::request_remove(uint32_t target_accid)
{
    if (!s_FriendActive) return;
    xiloader::console::output(xiloader::color::warning,
        "FriendSys: TODO request_remove(accid=%u) -- needs remove packet builder", target_accid);
}

void friend_system::send_message(uint32_t to_accid, const std::string& subject, const std::string& body)
{
    if (!s_FriendActive) return;
    xiloader::console::output(xiloader::color::warning,
        "FriendSys: TODO send_message(accid=%u, subj='%s', body=%zuB) -- needs message send packet builder",
        to_accid, subject.c_str(), body.size());
}

void friend_system::force_refresh()
{
    if (!s_FriendActive) return;

    /* Reset keepalive timer to trigger CallerB on the next tick. */
    if (s_state == STATE_STEADY)
    {
        s_tick_counter = KEEPALIVE_TICKS;
        xiloader::console::output_to_channel("friend",
            "FriendSys: forcing CallerB refresh");
    }
}
