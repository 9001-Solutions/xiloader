"""
FFXI Profile Server Test Implementation (Python)

TEMPORARY DEVELOPMENT TOOL: This Python server is used for protocol RE and
testing. It will be replaced by the C++ implementation in LandSandBoat
(src/login/) once the protocol is fully understood.

Handles the profile protocol (port 51220) with XOR mask encoding.

Protocol per TCP connection (HEALTHY mode):
  1. C->S: Init (40B plaintext) -- account ID + token
  2. S->C: ACK (24B plaintext) -- byte[1]=0x00 for success
  3. C->S: Auth (40B) -- mode + mask data
  4. S->C: AuthResponse (40B) -- contains sizes + server IP
  5. C->S: Data (variable) -- operation-specific request
  6. S->C: AuthConfirm (24B) + Status (variable)
  7. Server FIN

Three connection families (determined by Auth[1:3]):
  CallerA (04,05): Keepalive -- AuthResponse required, 40B Data, 32B Status
  CallerB (01,03): Friend list download -- no AuthResponse, sends records
  ShortAuth (01,0b): Session setup -- no AuthResponse, 24B Data, 128B Status

Mask extraction: mask[0:12] = Auth[0:12] XOR Init[0:12]
"""

import select
import socket
import struct
import zlib
import sys
import os
import time
import json
import threading
from datetime import datetime
from dotenv import load_dotenv

import pymysql

# Load .env from same directory as this script
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

# ============================================================================
# Database
# ============================================================================

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', '127.0.0.1'),
    'port': int(os.environ.get('DB_PORT', '3306')),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', 'root'),
    'database': os.environ.get('DB_NAME', 'xidblsb'),
    'charset': 'utf8mb4',
}

# FFXI Blowfish -- uses modified TT round function and custom subkey constants.
# Ported from LandSandBoat src/common/blowfish.cpp.
# NOTE: Currently unused -- xiloader sets desc[0x0B]=0 for all descriptor slots,
# disabling BF-OFB encryption. Kept for when crypto is eventually enabled.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ffxi_blowfish import FFXIBlowfish
from pol_b64 import build_status_notice, build_status_notice_rich

# ============================================================================
# BF-OFB Stream Cipher
# ============================================================================

class BFOFBStream:
    """Blowfish Output Feedback stream cipher with CR/LF passthrough.

    polcore's profile protocol encryption layer (separate from XOR mask encoding).
    Uses FFXI-variant Blowfish in OFB mode:
      - OFB state (8 bytes) initialized to the raw key bytes
      - Every 8 bytes consumed: encipher OFB state to produce next keystream block
      - XOR each data byte with keystream byte
      - CR (0x0D) and LF (0x0A) bytes pass through unchanged

    Two modes of operation (from RE analysis):
      - Encrypt (C->S): OFB state resets to IV per packet
      - Decrypt (S->C at client): running state across packets per connection

    Since we control both sides with a known key, we reset per-packet for simplicity
    and adjust if empirical testing reveals otherwise.
    """

    def __init__(self, key: bytes):
        """Initialize with 8-byte key."""
        assert len(key) == 8, f"BF-OFB key must be 8 bytes, got {len(key)}"
        self.bf = FFXIBlowfish(key)
        self.key = key  # saved for IV reset
        self.ofb_state = bytearray(key)  # OFB IV = raw key bytes
        self.position = 0  # position within current keystream block
        self.keystream = bytearray(8)  # current keystream block

    def reset(self):
        """Reset OFB state to initial IV (key bytes) and position to 0."""
        self.ofb_state = bytearray(self.key)
        self.position = 0

    def _advance_keystream(self):
        """Encipher OFB state to produce next 8-byte keystream block."""
        encrypted = self.bf.encrypt(bytes(self.ofb_state))
        self.ofb_state = bytearray(encrypted)
        self.keystream = bytearray(encrypted)

    def process(self, data: bytes, reset_iv: bool = True) -> bytes:
        """Encrypt or decrypt data (OFB mode -- same operation both ways).

        Args:
            data: Input bytes to process.
            reset_iv: If True, reset OFB state to initial IV before processing.
                      Use True for per-packet mode, False for running state.
        Returns:
            Processed bytes.
        """
        if reset_iv:
            self.reset()

        result = bytearray(len(data))
        for i, byte in enumerate(data):
            # Advance keystream block every 8 bytes
            if self.position % 8 == 0:
                self._advance_keystream()
                self.position = 0

            ks_byte = self.keystream[self.position]
            out_byte = byte ^ ks_byte

            # CR/LF passthrough: if source OR result is 0x0A or 0x0D, output unchanged
            if byte in (0x0A, 0x0D) or out_byte in (0x0A, 0x0D):
                result[i] = byte
            else:
                result[i] = out_byte

            self.position += 1

        return bytes(result)


# Dev-only fallback key for the BFOFBStream class. Production polcore derives
# its BF session key per-connection (see docs/profile-server/pol-bf-key-derivation.md);
# this constant is only used when the client never goes through the auth
# handshake AND BF crypto is somehow enabled -- in practice xiloader sets
# desc[0x0B]=0 on every slot, so this path is currently dead.
BF_OFB_KEY = bytes([0x4C, 0x53, 0x42, 0x46, 0x52, 0x49, 0x45, 0x4E])


# ============================================================================
# Constants
# ============================================================================

# 51322/51340, NOT the 51222/51240 polcore dials. xiloader's profile proxy owns
# the dialled ports and forwards here (+100). Binding 51222 here just loses the
# race with the proxy and leaves the profile channel with no listener at all --
# which does not raise an error, because the proxy holds the client socket open
# and retries silently by design.
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 51322

# Auth classes we implement. Anything outside this set is treated as an
# unknown channel and characterised rather than answered with a guess.
KNOWN_AUTH_CLASSES = {
    (0x01, 0x03),  # CallerB friend list
    (0x01, 0x0b),  # ShortAuth session setup
    (0x02, 0x03),  # friend_status_recv
    (0x02, 0x06),  # befriend request declaration
    (0x03, 0x00),  # befriend_response_pump
    (0x03, 0x01),  # body upload
    (0x03, 0x03),  # NotifPickup / MsgRecRecv
    (0x04, 0x05),  # CallerA keepalive
    (0x04, 0x06),  # WhoIs
    (0x04, 0x07),  # CallerB token exchange
}
# The POL push channel (51240) handshakes slowly: polcore sends op 2, then
# waits for a reply before it will send op 0x28. Dropping the socket at 60s
# idle truncates the capture mid-handshake.
UNKNOWN_CHANNEL_HOLD_SECONDS = 600
# The push channel must not be closed on idle: polcore reads the close as a
# connection error and tears its router down to state 0x20.
POL_PUSH_HOLD_SECONDS = 3600
POL_PUSH_EOL = bytes([0x0D])
POL_IRC_HOST = "pol.com"
# The push channel carries no account id of its own -- its USER realname is an
# opaque session token. The profile server is single-player-per-run in practice,
# so the channel adopts the account most recently authenticated on 51222.
# How long to wait for IRC registration after PASS before assuming this is a
# proxy reconnect (where registration will never come again).
POL_PUSH_REG_GRACE_SECONDS = 3.0
POL_STATUS_POLL_SECONDS = 5
# NOTICE target for status pushes.
#
# It must be a well-formed polcore nick -- 'U' followed by 8 base-36 digits
# (FUN_1001A390 writes the 0x55 'U' itself at buf[-1]). polcore decodes the
# target and the NOTICE handler skips the message outright when it decodes to
# zero, which is why a plain nick like "x" is silently ignored. It does NOT
# have to be the player's own nick -- any value that decodes non-zero is
# accepted, verified live.
POL_STATUS_TARGET_NICK = "UGITW5DT0"
POL_PUSH_INJECT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "push_inject.txt")
POL_PUSH_EOL_STR = chr(0x0D) + chr(0x0A)
POL_PUSH_LF = chr(0x0A)

# The PlayOnline profile ("pp") service is one server exposing several ports,
# one per connection class:
#   51220  request/response (CallerA/B/C, WhoIs, msgrec, ...)
#   51240  push family, default branch -- live friend status notifications
#   51241 / 51242  push family, alternate flag branches (unused here)
#
# We listen on 51240 natively rather than patching polcore to dial elsewhere.
# 51222 is used for the request/response channel only because a real
# xi_connect may already own the standard 51220; no such conflict exists on
# 51240, so there is nothing to gain by rewriting the port the client already
# reaches for -- and every avoided byte patch is one less thing to re-verify
# after a client update.
# xiloader's profile proxy owns the ports polcore dials (51222 / 51240) and
# forwards here, 100 up. That way the socket the GAME holds never drops when
# this server restarts -- see xiloader src/profile_proxy.cpp.
EXTRA_LISTEN_PORTS = (51340,)

# Server IP -- used in AuthConfirm bytes[8:12] computation.
# This should be the IP the CLIENT thinks it's connecting to.
# With xiloader proxy: pp000.pol.com resolves to g_ServerAddress.
SERVER_IP = os.environ.get('PROFILE_SERVER_IP', '127.0.0.1')
# IP as LE uint32: 202.67.54.174 -> 0xCA4336AE -> LE bytes AE 36 43 CA
_ip_parts = [int(x) for x in SERVER_IP.split('.')]
SERVER_IP_LE = struct.pack('<I', (_ip_parts[0] << 24) | (_ip_parts[1] << 16) | (_ip_parts[2] << 8) | _ip_parts[3])

# Init[8:12] constant across all accounts
INIT_SUFFIX_4B = bytes.fromhex('A2371A4B')

ACK_COUNTER_START = int(time.time())  # Use real Unix timestamp like retail

# Session token (12 bytes). Set to zeros to force polcore into session-setup
# mode on next connection (zero token in Init -> type 01,0B -> 128B Status).
# Non-zero token -> polcore enters keepalive mode (04,05 -> 32B Status).
SESSION_TOKEN = bytes(12)  # zeros -- forces session setup on each boot

# Packet sizes
INIT_SIZE = 40
ACK_SIZE = 24
AUTH_SIZE = 40
SHORT_AUTH_SIZE = 24
AUTH_CONFIRM_SIZE = 24
STATUS_SIZE = 48
BEFRIEND_REQ_SIZE = 304
BEFRIEND_EXTRA_176 = 176
BEFRIEND_EXTRA_168 = 168
BEFRIEND_RESP_SIZE = 184
CONFIRMATION_SIZE = 408
NOTIFICATION_SIZE = 416
FINALIZE_8B = 8

# polcore custom 6-bit alphabet -- inverse of decode table at polcore+0x65D64.
# Used by msgrec_recv_pump records (0x48 raw bytes encoded as 0x60 wire bytes).
POLCORE_B64_ALPHABET = b'TSG8IncW3HFKokOg79qzeCmZs2yBYEQVAUxR5rbwi4P@jMDLtpvad0f_J1hlN6uX'


def b64_encode_polcore(raw: bytes) -> bytes:
    """Encode raw bytes via polcore's custom 6-bit alphabet (4-out-3-in).
    Inverse of b64_decode_polcore @ polcore+0x078A0. Length must be a multiple
    of 3; output is 4/3 of input."""
    if len(raw) % 3 != 0:
        raise ValueError(f"b64_encode_polcore needs len%%3==0, got {len(raw)}")
    out = bytearray()
    for i in range(0, len(raw), 3):
        v = (raw[i] << 16) | (raw[i + 1] << 8) | raw[i + 2]
        out.append(POLCORE_B64_ALPHABET[(v >> 18) & 0x3F])
        out.append(POLCORE_B64_ALPHABET[(v >> 12) & 0x3F])
        out.append(POLCORE_B64_ALPHABET[(v >> 6) & 0x3F])
        out.append(POLCORE_B64_ALPHABET[v & 0x3F])
    return bytes(out)


def build_msgrec_record_wire(raw_48: bytes, session_token_8b: bytes) -> bytes:
    """Build a single msgrec wire chunk (0x60 b64-encoded bytes).

    Encrypts entry[0..7] (and conditionally entry[8..0xF] when flag word at
    [0x3E..0x3F] & 0xF80 != 0x880) using session_mask^XOR_MAGIC, then
    custom-base64 encodes. polcore's msgrec_recv_pump state 8 reverses both."""
    if len(raw_48) != 0x48:
        raise ValueError(f"need 0x48 raw bytes, got {len(raw_48)}")

    from pol_filename_iv import derive_iv, XOR_MAGIC_LO, XOR_MAGIC_HI
    iv_lo, iv_hi = derive_iv(session_token_8b)

    out = bytearray(raw_48)

    plain_lo = struct.unpack_from('<I', out, 0)[0]
    plain_hi = struct.unpack_from('<I', out, 4)[0]
    struct.pack_into('<I', out, 0, (plain_lo ^ XOR_MAGIC_LO ^ iv_lo) & 0xFFFFFFFF)
    struct.pack_into('<I', out, 4, (plain_hi ^ XOR_MAGIC_HI ^ iv_hi) & 0xFFFFFFFF)

    flag_word = struct.unpack_from('<H', out, 0x3E)[0]
    if (flag_word & 0xF80) != 0x880:
        plain_lo = struct.unpack_from('<I', out, 8)[0]
        plain_hi = struct.unpack_from('<I', out, 12)[0]
        struct.pack_into('<I', out, 8, (plain_lo ^ XOR_MAGIC_LO ^ iv_lo) & 0xFFFFFFFF)
        struct.pack_into('<I', out, 12, (plain_hi ^ XOR_MAGIC_HI ^ iv_hi) & 0xFFFFFFFF)

    return b64_encode_polcore(bytes(out))


def build_msgrec_response_body(records_48b: list, session_token_8b: bytes,
                               bodies=None) -> bytes:
    """Returns the 0x108-per-record body (after the 8B size header).

    Layout: 8B initial pad + per-record [0x60 b64][0xA8 pad] (last record's
    pad is 0xA0). Caller appends 4B sum-of-dwords trailer.

    `bodies` supplies the message text per record, written into the pad that
    follows it. polcore writes the received message file at NOTIFICATION time
    and does not re-fetch it when the user opens it, so a body not delivered
    here renders as polcore placeholder text (the subject plus the
    RECIPIENT's own charname) and cannot be corrected afterwards.
    """
    body = bytearray(bytes(8))  # initial padding before first record
    n = len(records_48b)
    for i, rec in enumerate(records_48b):
        wire = build_msgrec_record_wire(rec, session_token_8b)
        if len(wire) != 0x60:
            raise RuntimeError(f"encoded record is {len(wire)}B, expected 0x60")
        body += wire
        # NOTE: the per-record pad is NOT the message-body channel. Writing the
        # text here was tried and the client still rendered polcore's
        # placeholder, so the pad stays zeroed.
        body += bytes(0xA8 if i < n - 1 else 0xA0)
    return bytes(body)


def msgrec_trailer(size_header_8b: bytes, body: bytes) -> bytes:
    """Compute the 4B sum-of-dwords trailer over (size_header + body).
    Matches FUN_045E3DF0 (CRC accumulator); polcore's recv_body_sm with
    type=1 validates this in state 9 of msgrec_recv_pump."""
    crc_data = size_header_8b + body
    if len(crc_data) % 4 != 0:
        raise RuntimeError(f"crc data len {len(crc_data)} not 4B-aligned")
    crc = 0
    for j in range(0, len(crc_data), 4):
        crc = (crc + struct.unpack_from('<I', crc_data, j)[0]) & 0xFFFFFFFF
    return struct.pack('<I', crc)

# Body-continuation records: entry[0x19..0x3D] carries the text, so 37 bytes
# per record. 0x3E/0x3F must stay the 0x0880 flag word.
MSGREC_CHUNK = 0x25
MSGREC_TYPE_BODY_CHUNK = 0xFE


def msgrec_record_count(pending, unread):
    """Total msgrec entries for an account: one per item plus its body chunks.

    NotifPickup announces this, and xiloader configures polcore's SM with it.
    Announcing only the item count makes the SM expect too few records and the
    transfer never completes.
    """
    total = len(pending)
    for u in unread:
        text = (u.get('body') or '')
        total += 1 + (len(text.encode('ascii', 'replace')) + MSGREC_CHUNK - 1) // MSGREC_CHUNK
    return total


# Protocol markers
TYPE_MARKER = 0x81  # Type byte in ACK and AuthConfirm headers

# Server IP in big-endian (for Status header [8:12])
SERVER_IP_BE = bytes([int(x) for x in SERVER_IP.split('.')])

# Global ACK counter
g_ack_counter = ACK_COUNTER_START

# Log directory
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_logs")
os.makedirs(LOG_DIR, exist_ok=True)


def db_query(sql, args=None):
    """Execute a query and return all rows as dicts."""
    conn = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.fetchall()
    finally:
        conn.close()


def get_friends_for_account(accid):
    """Return friend list for an account with online status.

    Returns list of dicts: {accid, nickname, login, charname, online}.
    charname is blank unless the friend is in the world.

    **`nickname` is what /flist displays, and `login` must NEVER be sent to
    another player.**

    This is not a full PlayOnline emulator, so the true account name is
    deliberately never surfaced. When a friend is added, the friend's CHARACTER
    name is offered as the prefill for the nickname; the player accepts or
    edits it, and that nickname stands in for the account name from then on. It
    matches the real login only by coincidence.

    `login` is returned only for server-side use (never placed in a record).
    """
    # Get all friends for this account, with the target's ACCOUNT name.
    friends = db_query(
        "SELECT af.accid_target, af.nickname, a.login "
        "FROM account_friends af "
        "LEFT JOIN accounts a ON a.id = af.accid_target "
        "WHERE af.accid_owner = %s",
        (accid,)
    )
    if not friends:
        return []

    # Check which friends are online (have active session)
    target_ids = [f['accid_target'] for f in friends]
    placeholders = ','.join(['%s'] * len(target_ids))
    sessions = db_query(
        # LEFT JOIN on purpose: a session row whose charid resolves to no
        # character means the account is sitting at CHARACTER SELECT -- online
        # at the POL level, but not in the world. An inner join drops that row
        # and the friend renders as offline instead of online-with-no-character.
        f"SELECT s.accid, c.charname, c.pos_zone, c.nation, c.settings, "
        f"cs.mjob, cs.mlvl, cs.sjob, cs.slvl "
        f"FROM accounts_sessions s "
        f"LEFT JOIN chars c ON c.charid = s.charid "
        f"LEFT JOIN char_stats cs ON cs.charid = s.charid "
        f"WHERE s.accid IN ({placeholders})",
        target_ids
    )
    online_map = {s['accid']: s for s in sessions}

    result = []
    for f in friends:
        tid = f['accid_target']
        # Get the primary character name for this account
        away = False
        if tid in online_map:
            sess = online_map[tid]
            # chars.settings is the SAVE_CONF bitfield the client sets via /anon
            # and /away (packet 0x0DC); bit1 = AwayFlg, bit2 = AnonymityFlg.
            settings = int(sess.get('settings') or 0)
            away = bool(settings & 0x02)
            if settings & 0x04:
                # Anonymous: the account is online but has asked to be hidden.
                # Report it exactly as offline -- name and zone must go too, or
                # the row renders a character for someone who reads as offline.
                charname = ''
                online = False
                away = False
            else:
                # None at character select -- no character is bound to the session
                # yet. Blank name and zone 0 is exactly how that state renders.
                charname = sess['charname'] or ''
                online = True
        else:
            # Offline friends expose NO character name -- only the account nickname.
            charname = ''
            online = False

        entry = {
            'accid': tid,
            'nickname': f['nickname'],
            # POL account name -- what /flist displays. Distinct from
            # 'nickname', which is the owner's private alias for this friend.
            'login': f.get('login') or f['nickname'],
            'charname': charname,
            'online': online,
            'away': away,
            'zone_id': 0,
            'nation': 0,
            'mjob': 0,
            'mlvl': 0,
            'sjob': 0,
            'slvl': 0,
        }
        if online and tid in online_map:
            sess = online_map[tid]
            entry['zone_id'] = sess.get('pos_zone') or 0
            entry['nation'] = sess.get('nation', 0) or 0
            entry['mjob'] = sess.get('mjob', 0) or 0
            entry['mlvl'] = sess.get('mlvl', 0) or 0
            entry['sjob'] = sess.get('sjob', 0) or 0
            entry['slvl'] = sess.get('slvl', 0) or 0
        result.append(entry)

    return result


def get_accid_for_charname(charname):
    """Look up account ID from character name."""
    rows = db_query(
        "SELECT accid FROM chars WHERE charname = %s LIMIT 1",
        (charname,)
    )
    return rows[0]['accid'] if rows else None


def get_charname_for_account(accid):
    """Look up most-recent character name for an account."""
    rows = db_query(
        "SELECT charname FROM chars WHERE accid = %s LIMIT 1",
        (accid,)
    )
    return rows[0]['charname'] if rows else None


def create_friend_request(from_accid, to_accid, nickname, charname_from):
    """Create a pending friend request + befriend message."""
    db_execute(
        "INSERT IGNORE INTO account_friend_requests "
        "(accid_from, accid_to, nickname, charname_from) "
        "VALUES (%s, %s, %s, %s)",
        (from_accid, to_accid, nickname, charname_from)
    )
    log(f"  DB: friend request created {from_accid} -> {to_accid} nick='{nickname}' from='{charname_from}'")
    # NOTE: do NOT also insert an account_friend_messages row. The pending
    # request in account_friend_requests is the single source of truth -- the
    # notification path synthesizes the inbox entry from there. Dual-writing
    # surfaced two FWT entries per request in the inbox.


def recipient_from_msg_filename(payload, session_token_8b, sender_accid=None):
    """Recover the recipient account id from an uploaded message reference.

    The upload payload is "O/m/" followed by the 96-char encoded filename of
    the message the client just wrote to its own sent folder. That filename
    decodes to the usual 72-byte record, and block1 (bytes 8..15) carries the
    RECIPIENT account id XOR'd with KEY ^ IV.

    IV is tried from the session token and as zero (observed files decode with
    IV 0). A candidate is accepted only if it names a real account, so a wrong
    guess yields None instead of a misfiled message.
    """
    from pol_b64 import decode as b64_decode
    from pol_filename_iv import derive_iv, XOR_MAGIC_LO
    text = payload.split(bytes(1))[0]
    if len(text) < 100 or not text.startswith(b"O/m/"):
        return None
    try:
        raw = b64_decode(text[4:100].decode("ascii"))
    except Exception:
        return None
    if len(raw) < 16:
        return None
    block1_lo = struct.unpack_from("<I", raw, 8)[0]
    ivs = [0]
    try:
        ivs.insert(0, derive_iv(session_token_8b)[0])
    except Exception:
        pass
    # Validate against the SENDER'S FRIEND LIST, not merely "is an account".
    # Several IVs can each yield a real account id -- one observed candidate was
    # a valid but completely unrelated account -- so existence alone is not
    # evidence. FFXi resolves the target from the friend list before polcore
    # ever sees it, so a recipient that is not a friend of the sender is wrong.
    for iv_lo in ivs:
        accid = (block1_lo ^ XOR_MAGIC_LO ^ iv_lo) & 0xFFFFFFFF
        if not accid:
            continue
        if sender_accid is not None:
            if db_query("SELECT 1 FROM account_friends "
                        "WHERE accid_owner = %s AND accid_target = %s",
                        (sender_accid, accid)):
                return accid
        elif db_query("SELECT 1 FROM accounts WHERE id = %s", (accid,)):
            return accid
    return None


def ashita_root():
    """Ashita install dir that holds the msg tree.

    Resolution order: ASHITA_ROOT, then the bootloader location recorded in
    ASHITA_BOOTLOADER, then the cwd. Must NOT raise -- this runs inside a
    connection handler, and an exception there kills the client's connection
    mid-transfer rather than failing the one lookup.
    """
    root = os.environ.get('ASHITA_ROOT')
    if root:
        return root
    boot = os.environ.get('ASHITA_BOOTLOADER')
    if boot:
        return os.path.dirname(os.path.dirname(boot))
    return os.getcwd()


def session_salt_for_account(accid):
    """Current login's session_key, hex. Empty when the account is offline."""
    rows = db_query("SELECT session_key FROM accounts_sessions WHERE accid = %s LIMIT 1",
                    (accid,))
    if not rows:
        return ''
    key = rows[0].get('session_key') or b''
    return key.hex() if isinstance(key, (bytes, bytearray)) else str(key)


def parse_compose_payload(buf):
    """Split polcore's outgoing message payload into (subject, body).

    Format built by polcore+0x1A8E0: subject <0x07> body <0x00> [blob].
    FFXi's builder caps subject at 50 and body at 300 (FFXi+0x0F2F80), well
    under polcore's own 128/4095 limits -- anything longer than the client can
    produce is not from a legitimate compose.

    Returns None when the buffer is not a compose payload (e.g. a body-fetch
    request, which carries a 96-char encoded filename and no separator).
    """
    sep = buf.find(bytes([7]))
    if sep < 0 or sep > 128:
        return None
    subject = buf[:sep]
    rest = buf[sep + 1:]
    end = rest.find(bytes([0]))
    body = rest if end < 0 else rest[:end]
    try:
        subject_s = subject.decode('ascii')
        body_s = body.decode('ascii')
    except UnicodeDecodeError:
        return None
    # Both halves must be printable. Without this, arbitrary binary that
    # happens to contain a 0x07 byte is mistaken for a composed message --
    # every byte below 0x80 decodes as ASCII, so decoding alone proves nothing.
    printable = lambda t: all(0x20 <= ord(c) <= 0x7E for c in t)
    if not printable(subject_s) or not printable(body_s):
        return None
    if not subject_s and not body_s:
        return None
    return subject_s[:50], body_s[:300]


def request_notification_id(accid_from, accid_to, created_at, session_salt=''):
    """Non-zero notification id for a pending friend request.

    account_friend_requests has no id column, so a naive row.get('id', 0) gave
    0 -- and polcore drops a zero-token record, so the request never reached
    the inbox at all.

    Stable WITHIN a login, different ACROSS logins. Both halves matter:

      stable  -- the same pending request is re-sent on every poll, and the id
                 is the accept correlator (BefriendExtra+0x14). A changing id
                 would look like a new notification every few seconds and would
                 break accept matching.
      per-login -- the inbox enumerates only msg/<accid>/r/b/. Once a message is
                 marked read it moves to r/a/ and is gone from the inbox for
                 good, while polcore's in-memory dedupe blocks redelivery under
                 the same token. Without a new id per login, a request that was
                 read but not accepted would be invisible forever while still
                 pending in the DB. Salting with the login's session_key makes
                 it reappear on the next login.
    """
    stamp = int(created_at.timestamp()) if hasattr(created_at, 'timestamp') else int(created_at or 0)
    key = f"{accid_from}:{accid_to}:{stamp}:{session_salt}".encode('ascii')
    return (zlib.crc32(key) & 0x7FFFFFFF) or 1


def get_pending_requests_for_account(accid):
    """Return incoming pending friend requests for an account."""
    return db_query(
        "SELECT accid_from, nickname, charname_from, created_at "
        "FROM account_friend_requests WHERE accid_to = %s "
        "ORDER BY created_at DESC",
        (accid,)
    )


def get_outgoing_requests_for_account(accid):
    """Return outgoing pending friend requests from an account."""
    return db_query(
        "SELECT accid_to, nickname, charname_from, created_at "
        "FROM account_friend_requests WHERE accid_from = %s "
        "ORDER BY created_at DESC",
        (accid,)
    )


def _charname_for_accid(accid):
    """Resolve an account's primary charname (lowest charid) for system messages."""
    rows = db_query(
        "SELECT charname FROM chars WHERE accid = %s ORDER BY charid LIMIT 1",
        (accid,)
    )
    return rows[0]['charname'] if rows else f'Acct{accid}'


# System-message templates pulled verbatim from polcore.dll (RVA 0x74A30 / 0x74B30).
# `%s` is filled with the actor's charname (acceptor or decliner).
#
# Canonical msg_type -> inbox icon (from FFXiMain icon-type table at +0x383088,
# mirrored in friend.cpp:get_icon_label):
#   0  = NRM (normal message)
#   1  = FWT (incoming friend request -- "asking to be friends")
#   3  = KNK
#   9  = FOK (friend-OK -- accept response)
#   10 = FNO (friend-NO -- decline response)
#   anything else -> OTR (default fallthrough)
ACCEPT_MESSAGE_TEMPLATE  = "%s accepted friend registration.\nWill be added to Friend List."
DECLINE_MESSAGE_TEMPLATE = "%s declined friend registration."


def accept_friend_request(from_accid, to_accid, nickname_for_sender=''):
    """Accept a friend request: create bidirectional friendship, delete request,
    notify the original requester with the official polcore accept message."""
    # Get the original request to find the nickname the sender chose
    req = db_query(
        "SELECT nickname, charname_from FROM account_friend_requests "
        "WHERE accid_from = %s AND accid_to = %s",
        (from_accid, to_accid)
    )
    if not req:
        return {'error': 'No pending request found'}

    sender_nickname = req[0]['nickname']  # nickname sender chose for target
    charname_from = req[0]['charname_from']

    # If acceptor didn't provide a nickname, use the sender's charname
    if not nickname_for_sender:
        nickname_for_sender = charname_from

    # Create bidirectional friendship
    db_execute(
        "INSERT IGNORE INTO account_friends (accid_owner, accid_target, nickname) "
        "VALUES (%s, %s, %s)",
        (from_accid, to_accid, sender_nickname)
    )
    db_execute(
        "INSERT IGNORE INTO account_friends (accid_owner, accid_target, nickname) "
        "VALUES (%s, %s, %s)",
        (to_accid, from_accid, nickname_for_sender)
    )

    # Delete the request
    db_execute(
        "DELETE FROM account_friend_requests WHERE accid_from = %s AND accid_to = %s",
        (from_accid, to_accid)
    )

    # Notify the original requester with polcore's official accept message.
    acceptor_charname = _charname_for_accid(to_accid)
    body = ACCEPT_MESSAGE_TEMPLATE % acceptor_charname
    send_friend_message(
        from_accid=to_accid,        # message comes FROM the acceptor
        to_accid=from_accid,        # TO the original requester
        subject='Friend Accepted',  # short summary for inbox row
        body=body,
        msg_type=9,                 # FOK icon (accept)
    )

    log(f"  DB: friend request accepted {from_accid} <-> {to_accid}")
    return {'success': True}


def decline_friend_request(from_accid, to_accid):
    """Decline a friend request: delete it, notify the original requester
    with the official polcore decline message."""
    db_execute(
        "DELETE FROM account_friend_requests WHERE accid_from = %s AND accid_to = %s",
        (from_accid, to_accid)
    )

    decliner_charname = _charname_for_accid(to_accid)
    body = DECLINE_MESSAGE_TEMPLATE % decliner_charname
    send_friend_message(
        from_accid=to_accid,
        to_accid=from_accid,
        subject='Friend Declined',
        body=body,
        msg_type=10,                # FNO icon (decline)
    )

    log(f"  DB: friend request declined {from_accid} -> {to_accid}")


def remove_friend(owner_accid, target_accid):
    """Remove a friend (unilateral -- only removes owner's side)."""
    db_execute(
        "DELETE FROM account_friends WHERE accid_owner = %s AND accid_target = %s",
        (owner_accid, target_accid)
    )
    log(f"  DB: friend removed {owner_accid} -> {target_accid}")


def send_friend_message(from_accid, to_accid, subject, body, msg_type=0):
    """Send a friend message (offline mailbox). msg_type: 0=regular, 1=befriend."""
    db_execute(
        "INSERT INTO account_friend_messages "
        "(from_accid, to_accid, msg_type, subject, body) VALUES (%s, %s, %s, %s, %s)",
        (from_accid, to_accid, msg_type, subject, body)
    )
    log(f"  DB: message sent {from_accid} -> {to_accid} type={msg_type} subj='{subject}'")


def get_unread_messages(accid):
    """Return unread messages for an account (includes msg_type and sender charname).

    Resolve sender charname from chars table directly -- the sender may be offline
    (no row in accounts_sessions), so session-based joins drop names. An account
    can have multiple characters; pick the lowest charid for stability.
    """
    return db_query(
        "SELECT m.id, m.from_accid, m.msg_type, m.subject, m.body, m.created_at, "
        "  COALESCE("
        "    (SELECT charname FROM chars WHERE accid = m.from_accid ORDER BY charid LIMIT 1),"
        "    CONCAT('Acct', m.from_accid)"
        "  ) AS from_charname "
        "FROM account_friend_messages m "
        "WHERE m.to_accid = %s AND m.is_read = 0 "
        "ORDER BY m.created_at DESC",
        (accid,)
    )


def db_execute(sql, args=None):
    """Execute a write query (INSERT/UPDATE/DELETE)."""
    conn = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
        conn.commit()
    finally:
        conn.close()


# ============================================================================
# Helpers
# ============================================================================

def hex_dump(data, prefix="  "):
    """Hex dump with ASCII sidebar."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{offset:04x}: {hex_part:<48s} {ascii_part}")
    return "\n".join(lines)


def xor_bytes(a, b):
    """XOR two byte sequences (truncates to shorter)."""
    return bytes(x ^ y for x, y in zip(a, b))


def log(msg, conn_id=""):
    """Print timestamped log message."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = f"[{ts}]"
    if conn_id:
        prefix += f" [{conn_id}]"
    print(f"{prefix} {msg}", flush=True)


# AuthConfirm bytes[8:12] = Init[8:12] XOR server_IP_LE
AUTH_CONFIRM_XORED_IP = xor_bytes(INIT_SUFFIX_4B, SERVER_IP_LE)


# ============================================================================
# Connection Handler
# ============================================================================

class FriendConnection:
    """Handles a single profile server TCP connection."""

    def __init__(self, conn, addr, ack_counter):
        """Initialize connection handler.

        Args:
            conn: TCP socket for this connection.
            addr: (ip, port) tuple of client address.
            ack_counter: Monotonic counter for ACK packet timestamp field.
        """
        self.conn = conn
        self.addr = addr
        self.ack_counter = ack_counter
        self.conn_id = f"{addr[0]}:{addr[1]}"

        # Credential header from xiloader proxy (20B: 4B account_id + 16B session_hash)
        self.cred_account_id = 0
        self.cred_session_hash = b'\x00' * 16

        # Session data
        self.init_packet = None
        self.preauth_packet = None
        self.auth_packet = None
        self.account_id = None
        self.token = None
        self.mask = None  # 12-byte XOR mask
        self.auth_mode = 0x01  # 0x01=healthy, 0x02=degraded

        # BF-OFB crypto state
        self.bf_crypto_active = False
        self.bf_stream_recv = None  # for decrypting C->S
        self.bf_stream_send = None  # for encrypting S->C

        # Packet log for this connection
        self.packet_log = []

    def run(self):
        """Main connection handler loop.

        Two modes:
        DEGRADED (Auth[0]=0x02): Init -> ACK -> Auth -> DegradedAuthResp(144B) -> Data -> AuthConfirm+Status -> FIN
        HEALTHY  (Auth[0]=0x01): Init -> ACK -> Auth -> AuthConfirm(24B) -> [client sends more OR server sends data] -> FIN
        """
        try:
            self.conn.settimeout(30.0)

            # Phase 0: Detect connection type (proxied via xiloader vs direct from polcore).
            # Proxied: 20B credential header + 40B Init = 60B total first send
            # Direct:  40B Init only (no credential header)
            # Detection: read first 40B, check bytes[4:6] for Init marker 0x0001.
            # If marker present at [4:6], it's a direct connection (Init starts at byte 0).
            # If not, first 20B are credential header and we need 20 more for Init.
            first = self._recv_raw(40)
            if not first:
                return

            # ACPT direct accept request: 'ACPT' + acceptor_accid (4B) +
            # target_charname (15B null-padded) + nickname (15B null-padded) = 38B.
            # Created so xiloader can route the menu Accept around polcore (which
            # in LSB never actually sends a BefriendResponse for the operation).
            if len(first) >= 38 and first[0:4] == b'ACPT':
                acceptor_accid = struct.unpack_from('<I', first, 4)[0]
                target_charname = first[8:23].rstrip(b'\x00').decode('ascii', errors='replace')
                nickname = first[23:38].rstrip(b'\x00').decode('ascii', errors='replace')
                log(f"  ACPT request: accid={acceptor_accid} target='{target_charname}' nick='{nickname}'", self.conn_id)
                self.handle_acpt_request(acceptor_accid, target_charname, nickname)
                return

            if struct.unpack_from('<H', first, 4)[0] == 0x0001:
                # Direct connection -- first 40B ARE the Init packet
                log(f"  Direct connection (no credential header)", self.conn_id)
                self.packet_log.append({
                    "direction": "C2S", "label": "Init", "size": 40,
                    "data": first.hex(), "time": time.time(),
                })
                log(f"C->S Init ({len(first)}B):", self.conn_id)
                print(hex_dump(first), flush=True)
                self.handle_init(first)
            else:
                # Proxied connection -- first 20B are credential header
                self.cred_account_id = struct.unpack_from('<I', first, 0)[0]
                self.cred_session_hash = first[4:20]
                log(f"  Credential header: acct_id={self.cred_account_id} session={self.cred_session_hash.hex()}", self.conn_id)
                # Remaining 20B are start of Init, need 20 more
                rest = self._recv_raw(20)
                if not rest:
                    return
                init_data = first[20:] + rest
                self.packet_log.append({
                    "direction": "C2S", "label": "Init", "size": 40,
                    "data": init_data.hex(), "time": time.time(),
                })
                log(f"C->S Init ({len(init_data)}B):", self.conn_id)
                print(hex_dump(init_data), flush=True)
                self.handle_init(init_data)

            # Phase 2: ACK (24B)
            self.send_ack()

            # Phase 3: Auth
            data = self.recv_exact("Auth", AUTH_SIZE)
            if not data:
                return
            self.handle_auth(data)

            # Phase 4: Dispatch based on connection type.
            #
            # Three connection families (determined by Auth[1:3]):
            #
            # CallerB (01,03): Friend list download. Uses +0x1F4D0 second SM
            #   (peeks at available bytes, does NOT block). NO AuthResponse.
            #   Server sends: AuthConfirm(24B) + ControlHeader(8B) + N*104B records + Mode7Confirm(4B)
            #
            # ShortAuth (01,0b): Session setup. Also uses +0x1F4D0 second SM.
            #   NO AuthResponse needed. Client sends ShortAuth Data (24B) immediately.
            #   Server sends: AuthConfirm(24B) + Status(128B)
            #
            # CallerA (04,05): Keepalive. Uses standard +0x1E4D0 second SM
            #   (blocks until AuthResponse received). Server sends:
            #   AuthResponse(40B) -> recv Data(40B) -> AuthConfirm + Status + KeepaliveData(64B)
            auth_seq = self.auth_packet[1] if self.auth_packet else 0
            auth_op = self.auth_packet[2] if self.auth_packet else 0

            if auth_seq == 0x01 and auth_op == 0x03:
                # CallerB: friend list download
                log(f"  Detected CallerB (Auth[1:3]={auth_seq:02x},{auth_op:02x})", self.conn_id)
                seq, op, param = self.get_auth_confirm_params()
                self.send_auth_confirm(seq=seq, op=op, param=param)
                self.send_friend_records()
            elif auth_seq == 0x01 and auth_op == 0x0b:
                # ShortAuth: session setup -- NO AuthResponse, client sends Data immediately
                log(f"  Detected ShortAuth (Auth[1:3]={auth_seq:02x},{auth_op:02x})", self.conn_id)
                self.handle_short_auth()
            elif auth_seq == 0x03 and auth_op == 0x00:
                # befriend_response_pump (Auth (3,0,0x1A0)). polcore +0x26190.
                # Auto-fires at game-start to pull pending friend-request
                # responses (accept/decline/cancel notifications). Wire shape:
                #   C->S Init+ACK, Auth(3,0,0x1A0), Data[0] 416B body
                #   S->C AuthConfirm(24B, param=4 minimum so ae4-4>=0),
                #        body bytes (size = AuthConfirm.param-4),
                #        4B sum-of-dwords CRC trailer.
                # NO 40B AuthResponse (same gotcha as (2,3)/(2,6)/(3,1)/(3,3)).
                # For now: minimal response, count=0 (no pending notifications),
                # advance polcore's SM cleanly without aborting.
                log(f"  Detected befriend_response_pump (Auth[1:3]={auth_seq:02x},{auth_op:02x}) -- no AuthResponse", self.conn_id)
                self.handle_befriend_response_pump()
            elif auth_seq == 0x02 and auth_op == 0x03:
                # friend_status_recv_pump (Auth (2,3), body_size=0). polcore's
                # +0x237F0 SM sends Auth header only (no Data[0]) and recv's:
                #   24B AuthConfirm + 8B size header [N][0] + N*0xA8 records +
                #   4B sum-of-dwords trailer
                # Records are written DIRECTLY to Array2 via FUN_0459EEB0 -- this
                # is the live friend-status updater /flist actually reads from.
                # Same no-AuthResponse gotcha as (2,6)/(3,1)/(3,3)/(4,6).
                log(f"  Detected friend_status_recv (Auth[1:3]={auth_seq:02x},{auth_op:02x}) -- no AuthResponse", self.conn_id)
                self.handle_friend_status_recv()
            elif auth_seq == 0x02 and auth_op == 0x06:
                # BefriendRequest declaration. polcore's FUN_0459f4d0 sends this
                # 40B Auth purely to declare the upcoming payload size -- it polls
                # SEND completion only, so it does NOT recv a 40B AuthResponse.
                # Sending one here would shift polcore's read alignment for the
                # subsequent BefriendRequest pumper (FUN_045a4170 cases 8-12),
                # which strictly reads 24B AuthConfirm + 8B header + N*168B
                # records + 8B trailer. A misaligned N=0 -> 0-byte recv ->
                # FUN_04590d10 returns -8 -> op[4]=5.
                log(f"  Detected BefriendRequest declaration (Auth[1:3]={auth_seq:02x},{auth_op:02x}) -- no AuthResponse", self.conn_id)
                self.handle_operation()
            elif auth_seq == 0x03 and auth_op == 0x01:
                # Body-upload (Auth (3,1)). polcore's FUN_045a6870 SM sends a
                # 408B request + N-byte body + 4B CRC, then recvs 24B response
                # via FUN_0459f690 (case 12). Same as BefriendRequest: only the
                # SEND-completion poll uses FUN_04591170 here, no AuthResponse
                # is consumed. Sending an extra 40B AuthResponse misaligns
                # case 12's read and the SM aborts (-6 = WSAECONNABORTED via
                # FUN_045905E0 or similar) -> op[6]=5.
                log(f"  Detected body-upload (Auth[1:3]={auth_seq:02x},{auth_op:02x}) -- no AuthResponse", self.conn_id)
                self.handle_operation()
            elif auth_seq == 0x03 and auth_op == 0x03:
                # NotificationPickup / msgrec_recv_pump (Auth (3,3), 416B body).
                # polcore's notif_pump @ +0x25B90 and msgrec_recv_pump @ +0x276E0
                # both go straight from polcore_send_ixff_header_sm (sends Auth)
                # to polcore_send_body_sm (sends 416B Data[0]) without recv'ing
                # an AuthResponse in between. Sending one here leaves 40B in
                # polcore's recv queue; drain_sm then reads 24B of that as the
                # "AuthConfirm" and the 8B size header recv pulls the orphan
                # tail bytes (zeros) -- polcore sees count=0 and skips records.
                log(f"  Detected NotifPickup/MsgRecRecv (Auth[1:3]={auth_seq:02x},{auth_op:02x}) -- no AuthResponse", self.conn_id)
                self.handle_operation()
            elif auth_seq == 0x04 and auth_op == 0x06:
                # WhoIs / friend-status query (polcore+0x1D490 SM).
                # NO 40B AuthResponse -- polcore_send_ixff_header_sm is send-only,
                # it does not consume an AuthResponse. Sending one leaves 40B
                # in the recv queue; drain_sm then reads AR[0..23] as the
                # "AuthConfirm" and case 5's 128B recv pulls AR[24..39] +
                # real AuthConfirm + first 88B of WhoIsStatus, shifting the
                # CRC trailer's expected position by 40 bytes. Same gotcha
                # we hit for (3,3), (2,6), (3,1).
                log(f"  Detected WhoIs (Auth[1:3]={auth_seq:02x},{auth_op:02x}) -- no AuthResponse", self.conn_id)
                self.handle_whois()
            elif (auth_seq, auth_op) not in KNOWN_AUTH_CLASSES:
                # Unrecognised class. The POL push channel (which carries live
                # friend status notifications) is expected to show up here the
                # first time pol_msg_router is driven far enough to open it.
                # Do NOT assume CallerA and hang up -- a push channel must stay
                # open. Capture everything instead.
                self.handle_unknown_channel(auth_seq, auth_op)
                return
            else:
                # CallerA / standard flow -- AuthResponse required
                log(f"  Detected CallerA (Auth[1:3]={auth_seq:02x},{auth_op:02x})", self.conn_id)
                self.send_auth_response_40b()
                self.handle_operation()
            self.close_connection()

        except socket.timeout:
            log("Connection timed out", self.conn_id)
        except ConnectionResetError:
            log("Connection reset by client", self.conn_id)
        except Exception as e:
            log(f"Error: {e}", self.conn_id)
        finally:
            self.conn.close()
            self.save_log()
            log("Connection closed", self.conn_id)

    def handle_unknown_channel(self, auth_seq, auth_op):
        """Log and hold open a connection whose auth class we do not implement.

        Used to characterise the POL push channel. Rather than replying with a
        guess, dump the Init/Auth packets and then read until the peer closes
        or we time out, logging every chunk. Holding the socket open matters:
        polcore's push connection is long-lived, and closing it would make the
        state machine tear down before it reveals anything.
        """
        log(f"  *** UNKNOWN auth class (Auth[1:3]={auth_seq:02x},{auth_op:02x}) "
            f"-- holding open to characterise ***", self.conn_id)
        if self.account_id:
            log(f"      Init : {bytes(self.account_id).hex()}", self.conn_id)
        if self.auth_packet:
            log(f"      Auth : {bytes(self.auth_packet).hex()}", self.conn_id)

        self.conn.settimeout(5.0)
        idle = 0
        total = 0
        while idle < UNKNOWN_CHANNEL_HOLD_SECONDS:
            try:
                chunk = self.conn.recv(4096)
            except socket.timeout:
                idle += 5
                continue
            except OSError as e:
                log(f"      socket error: {e}", self.conn_id)
                break
            if not chunk:
                log("      peer closed", self.conn_id)
                break
            idle = 0
            total += len(chunk)
            log(f"      RECV {len(chunk)}B: {chunk[:64].hex()}"
                f"{'...' if len(chunk) > 64 else ''}", self.conn_id)
        log(f"  *** UNKNOWN channel done ({total}B received) ***", self.conn_id)

    def _recv_raw(self, size):
        """Receive exactly `size` bytes without logging."""
        buf = b''
        try:
            while len(buf) < size:
                chunk = self.conn.recv(size - len(buf))
                if not chunk:
                    return None
                buf += chunk
        except socket.timeout:
            return None
        return buf

    def recv_exact(self, label, size):
        """Receive exactly `size` bytes from the socket."""
        buf = b''
        try:
            while len(buf) < size:
                chunk = self.conn.recv(size - len(buf))
                if not chunk:
                    if not buf:
                        log(f"No data received (expected {label})", self.conn_id)
                    else:
                        log(f"Connection closed mid-recv ({len(buf)}/{size}B for {label})", self.conn_id)
                    return None
                buf += chunk
        except socket.timeout:
            log(f"Timeout waiting for {label} ({len(buf)}/{size}B received)", self.conn_id)
            return None

        self.packet_log.append({
            "direction": "C2S",
            "label": label,
            "size": len(buf),
            "data": buf.hex(),
            "time": time.time(),
        })

        log(f"C->S {label} ({len(buf)}B):", self.conn_id)
        print(hex_dump(buf), flush=True)
        return buf

    def recv_any(self, label):
        """Receive any available data (unknown size)."""
        try:
            data = self.conn.recv(4096)
            if not data:
                log(f"No data received (expected {label})", self.conn_id)
                return None

            self.packet_log.append({
                "direction": "C2S",
                "label": label,
                "size": len(data),
                "data": data.hex(),
                "time": time.time(),
            })

            log(f"C->S {label} ({len(data)}B):", self.conn_id)
            print(hex_dump(data), flush=True)
            return data

        except socket.timeout:
            log(f"Timeout waiting for {label}", self.conn_id)
            return None

    def bf_decrypt(self, data):
        """Decrypt C->S data with BF-OFB if crypto is active.
        Resets OFB state per packet (matches client encrypt behavior)."""
        if not self.bf_crypto_active or self.bf_stream_recv is None:
            return data
        decrypted = self.bf_stream_recv.process(data, reset_iv=True)
        log(f"  BF-OFB decrypt: {data[:16].hex()}... -> {decrypted[:16].hex()}...", self.conn_id)
        return decrypted

    def bf_encrypt(self, data):
        """Encrypt S->C data with BF-OFB if crypto is active.
        Resets OFB state per packet (conservative; may need running state)."""
        if not self.bf_crypto_active or self.bf_stream_send is None:
            return data
        encrypted = self.bf_stream_send.process(data, reset_iv=True)
        log(f"  BF-OFB encrypt: {data[:16].hex()}... -> {encrypted[:16].hex()}...", self.conn_id)
        return encrypted

    def send_data(self, label, data):
        """Send data to client (with optional BF-OFB encryption)."""
        # Apply BF-OFB encryption for post-ACK packets
        wire_data = data
        if self.bf_crypto_active and label not in ("ACK",):
            wire_data = self.bf_encrypt(data)

        self.packet_log.append({
            "direction": "S2C",
            "label": label,
            "size": len(wire_data),
            "data": wire_data.hex(),
            "time": time.time(),
        })

        log(f"S->C {label} ({len(wire_data)}B):", self.conn_id)
        print(hex_dump(wire_data))

        self.conn.sendall(wire_data)

    # ========================================================================
    # Protocol Handlers
    # ========================================================================

    def handle_init(self, data):
        """Process Init packet (40B plaintext)."""
        self.init_packet = data

        # Parse fields
        padding = struct.unpack_from('<I', data, 0)[0]
        marker = struct.unpack_from('<H', data, 4)[0]
        self.account_id = data[6:12]
        self.token = data[12:24]
        self.has_init_token = any(b != 0 for b in self.token)

        acct_hex = self.account_id[:2].hex()
        token_label = self.token.hex() if self.has_init_token else "NONE (INITIAL-AUTH)"
        log(f"  Init: marker=0x{marker:04X} acctid={self.account_id.hex()} token={token_label}", self.conn_id)

        if marker != 0x0001:
            log(f"  WARNING: unexpected marker (expected 0x0001)", self.conn_id)

        # Detect BF-OFB crypto: Init[1]==0 means crypto is active (desc+0x0B=1)
        # Init[1]==1 means crypto disabled (desc+0x0B=0)
        crypto_flag_byte = data[1]
        if crypto_flag_byte == 0:
            self.bf_crypto_active = True
            self.bf_stream_recv = BFOFBStream(BF_OFB_KEY)
            self.bf_stream_send = BFOFBStream(BF_OFB_KEY)
            log(f"  BF-OFB crypto ACTIVE (Init[1]=0x{crypto_flag_byte:02X})", self.conn_id)
        else:
            log(f"  BF-OFB crypto DISABLED (Init[1]=0x{crypto_flag_byte:02X})", self.conn_id)

    def send_ack(self):
        """Send ACK packet (24B plaintext).

        State 9 checks byte[1] == 0x00 for success.
        Bytes[20:24] stored at descriptor[+0xB8] and [+0x32C].
        """
        ack = bytearray(ACK_SIZE)  # 24 bytes
        ack[0] = TYPE_MARKER
        struct.pack_into('<I', ack, 20, self.ack_counter)

        log(f"  ACK counter=0x{self.ack_counter:08X}", self.conn_id)
        self.send_data("ACK", bytes(ack))

    def get_auth_confirm_params(self):
        """Derive AuthConfirm seq/op/param from the Auth packet type bytes.

        CRITICAL: The plaintext seq/op must equal mask[1:3] so that after XOR
        encoding, wire[1]=0x00.  The client checks wire byte[1]==0x00 at
        +0x1F710; non-zero enters a wait/timer path that blocks mode 3.

        Auth[1:3] is used ONLY for the PARAM_TABLE lookup (conn-type specific).
        """
        if not self.auth_packet:
            return (0x04, 0x05, 0x0009)  # fallback to login type

        # Auth[1:3] for table lookup (identifies connection type)
        auth_seq = self.auth_packet[1]
        auth_op = self.auth_packet[2]

        # mask[1:3] for the actual plaintext values (ensures wire[1]==0x00)
        seq = self.mask[1] if self.mask else auth_seq
        op = self.mask[2] if self.mask else auth_op

        PARAM_TABLE = {
            (0x01, 0x0b): 0x0029,  # 24B ShortAuth (befriend/flist)
            (0x04, 0x05): 0x0009,  # 40B login/status (post-game keepalive)
            (0x04, 0x06): 0x0099,  # POL-stage ShortAuth status check
            (0x04, 0x07): 0x0049,  # POL-stage initial auth
            (0x07, 0x0c): 0x0011,  # POL-stage quick validation
            (0x02, 0x03): 0x5369,  # POL-stage friend list download
            (0x00, 0x09): 0x0099,  # POL-stage additional data
            (0x01, 0x03): 0x0079,  # POL-stage additional data
            (0x03, 0x03): 0x01ad,  # Notification pickup
            (0x03, 0x01): 0x0009,  # Body-fetch (click-to-read, FUN_045A6870 pump)
        }
        param = PARAM_TABLE.get((auth_seq, auth_op), 0x0009)

        log(f"  AuthConfirm params: seq=0x{seq:02x} op=0x{op:02x} param=0x{param:04x} (Auth[1:3]={auth_seq:02x} {auth_op:02x}, mask[1:3]={seq:02x} {op:02x})", self.conn_id)
        return (seq, op, param)

    def handle_auth(self, data):
        """Process Auth packet (40B encoded). Extract XOR mask.

        BF-OFB: if crypto is active, data arrives BF-encrypted. Decrypt first.
        """
        data = self.bf_decrypt(data)
        self.auth_packet = data
        wire_mask = xor_bytes(data[:12], self.init_packet[:12])

        # Decode Auth[0] to determine protocol mode
        decoded_byte0 = data[0] ^ self.init_packet[0]
        self.auth_mode = decoded_byte0

        mode_label = {0x01: 'healthy', 0x02: 'degraded'}.get(decoded_byte0, 'unknown')
        log(f"  Auth mode: 0x{decoded_byte0:02X} ({mode_label})", self.conn_id)
        log(f"  Wire mask: {wire_mask.hex()}", self.conn_id)

        # Compute polcore's mask (undo xiloader Init[6:12] injection)
        polcore_mask = bytearray(wire_mask)
        # Init[6:12] was injected by xiloader (was zeros in polcore's original)
        # polcore's mask[6:12] = Auth[6:12] XOR 0 = Auth[6:12]
        polcore_mask[6:12] = self.auth_packet[6:12]

        self.mask = bytes(polcore_mask)
        log(f"  Polcore mask: {self.mask.hex()}", self.conn_id)

        log(f"  Auth[12:24] (token): {data[12:24].hex()}", self.conn_id)
        log(f"  Auth[24:40]: {data[24:40].hex()}", self.conn_id)

        # Verify: Auth[12:24] should be a token (may differ from Init token)
        if data[12:24] == self.token:
            log(f"  Token matches Init token", self.conn_id)
        else:
            log(f"  Token differs from Init (expected for session token rotation)", self.conn_id)

    def close_connection(self):
        """Send FIN to client (server-initiated close, like retail)."""
        try:
            self.conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def get_status_size_for_type(self):
        """Determine Status response size based on Auth type bytes.

        Retail Status sizes (from full_login_flow capture analysis):
          (0x04, 0x07) CallerB 64B data: 8B Status
          (0x01, 0x0B) ShortAuth session setup: 128B Status
          (0x04, 0x05) CallerA keepalive 40B data: 32B Status
          (0x04, 0x07) CallerB 416B operation: 12B Status
          QUERY (no data): 16B-21KB (depends on server state)
        """
        if not self.auth_packet:
            return 0x20  # default 32B

        seq = self.auth_packet[1]
        op = self.auth_packet[2]

        STATUS_SIZE_TABLE = {
            (0x01, 0x0B): 0x80,   # 128B -- session setup (populates friend manager)
            (0x04, 0x05): 0x20,   # 32B -- CallerA keepalive (retail size)
            (0x04, 0x07): 0x10,   # 16B -- CallerB token exchange
            (0x04, 0x06): 0x80,   # 128B -- POL-stage status
            (0x07, 0x0C): 0x10,   # 16B -- POL-stage quick validation
            (0x02, 0x03): 0x20,   # 32B -- friend list download (placeholder)
            (0x03, 0x03): 0x10,   # 16B -- notification pickup
        }
        size = STATUS_SIZE_TABLE.get((seq, op), 0x20)
        log(f"  Status size for type ({seq:02x},{op:02x}): 0x{size:02X} ({size}B)", self.conn_id)
        return size

    def send_auth_response_40b(self):
        """Send 40B AuthResponse after Auth.

        Both CallerA (+0x1E4D0 state 3) and CallerB (+0x1F4D0 state 3) accumulate
        recv until 40 bytes, then advance. Content doesn't matter -- state 3 only
        counts bytes, doesn't parse the response.
        """
        resp = bytearray(40)
        status_size = self.get_status_size_for_type()
        struct.pack_into('<I', resp, 0, 0x28)         # Auth size = 40
        struct.pack_into('<I', resp, 4, status_size)   # Status size
        resp[8:12] = SERVER_IP_LE                      # Server IP
        log(f"  AuthResponse (40B): {bytes(resp[:16]).hex()}...", self.conn_id)
        self.send_data("AuthResponse", bytes(resp))


    def decode_header(self, data):
        """Decode packet header [0:12] using XOR mask."""
        if self.mask and len(data) >= 12:
            return xor_bytes(data[:12], self.mask)
        return data[:12]

    def encode_header(self, plaintext):
        """Encode packet header [0:12] using XOR mask."""
        if self.mask and len(plaintext) >= 12:
            return xor_bytes(plaintext[:12], self.mask)
        return plaintext[:12]

    def handle_operation(self):
        """Handle the operation-specific phase after Auth + AuthResponse.

        Dispatches based on received packet size:
          40B:  CallerA keepalive data -> AuthConfirm + 32B Status
          24B:  ShortAuth -> AuthConfirm + type-specific Status
          64B:  CallerB data -> AuthConfirm + friend records
          304B: BefriendRequest -> AuthConfirm + BefriendResponse
          408B: Confirmation -> AuthConfirm
          416B: NotificationPickup -> AuthConfirm + Status
        """
        # Loop to handle multiple packets per connection
        pkt_num = 0
        while True:
            data = self.recv_any(f"Data[{pkt_num}]")
            if not data:
                if pkt_num == 0:
                    # No data after Auth -- this is a QUERY or BULK-DATA type
                    # Server should send AuthConfirm + response data without client data
                    log(f"  No client data after Auth -- QUERY/BULK-DATA type", self.conn_id)
                    seq, op, param = self.get_auth_confirm_params()
                    self.send_auth_confirm(seq=seq, op=op, param=param)
                    # Send type-specific Status
                    self.send_status(client_data=None)
                    self.close_connection()
                return

            # BF-OFB decrypt if crypto active
            data = self.bf_decrypt(data)
            size = len(data)
            decoded_hdr = self.decode_header(data)
            log(f"  Decoded header[{pkt_num}]: {decoded_hdr.hex()}", self.conn_id)
            pkt_num += 1

            if size == SHORT_AUTH_SIZE:
                # 24B ShortAuth (SESSION-SETUP type)
                self.handle_short_auth(data)
                return
            elif size == 64:
                # 64B data -- dispatch based on auth type
                decoded = self.decode_header(data)
                charname = data[1:9]
                charname_str = charname.rstrip(b'\x00').decode('ascii', errors='replace')
                log(f"  64B data: charname='{charname_str}' decoded={decoded.hex()}", self.conn_id)

                # Check auth type to distinguish CallerB vs CallerC
                auth_seq = self.auth_packet[1] if self.auth_packet else 0
                auth_op = self.auth_packet[2] if self.auth_packet else 0
                is_callerC = (auth_seq == 0x04 and auth_op == 0x07)

                if is_callerC:
                    # CallerC (04,07) + 64B = notification pickup
                    log(f"  CallerC notification pickup (Auth 04,07)", self.conn_id)
                    self.handle_callerC_notification(data)
                else:
                    # CallerB (01,03) + 64B = friend list download
                    log(f"  CallerB friend list (Auth {auth_seq:02x},{auth_op:02x})", self.conn_id)
                    seq, op, param = self.get_auth_confirm_params()
                    self.send_auth_confirm(seq=seq, op=op, param=param)
                    self.send_friend_records(charname)

                self.close_connection()
                return
            elif size == AUTH_SIZE:
                # 40B -- status/keepalive data
                log(f"  40B data packet (status/keepalive)", self.conn_id)
                log(f"  Raw[0:12]:  {data[0:12].hex()}", self.conn_id)
                log(f"  Raw[12:24]: {data[12:24].hex()}", self.conn_id)
                log(f"  Raw[24:40]: {data[24:40].hex()}", self.conn_id)

                # Send AuthConfirm + Status(32B) -- matches retail CallerA pattern.
                # Retail: AuthConfirm(24B) + Status(32B), nothing else.
                # No KeepaliveData or KeepaliveAck (those were our invention).
                seq, op, param = self.get_auth_confirm_params()
                self.send_auth_confirm(seq=seq, op=op, param=param)
                self.send_status(client_data=data)

                self.close_connection()
                return
            elif size == BEFRIEND_REQ_SIZE:
                self.handle_befriend_request(data)
                return
            elif size == CONFIRMATION_SIZE:
                # 408-byte packets are AMBIGUOUS -- disambiguate by auth type:
                #   Auth (3,1) = body-fetch (click-to-read msg body)
                #   Auth (?,?) = Confirmation (befriend/accept/decline finalize)
                auth_seq = self.auth_packet[1] if self.auth_packet else 0
                auth_op = self.auth_packet[2] if self.auth_packet else 0
                if auth_seq == 0x03 and auth_op == 0x01:
                    self.handle_body_fetch(data)
                else:
                    self.handle_confirmation(data)
                return
            elif size == NOTIFICATION_SIZE:
                self.handle_notification(data)
                return
            else:
                log(f"  Data packet {size}B (unexpected size)", self.conn_id)
                self.handle_unknown(data)
                # Keep reading

    def handle_short_auth(self, data=None):
        """Handle ShortAuth packet (24B).

        Called from run() for Auth[1:3]=(01,0b) session setup (data=None,
        receives from socket), or from handle_operation() when 24B data
        arrives in the CallerA flow (data provided).

        Wire opcode (01,0b) is reused by polcore for two distinct flows.
        Disambiguated by body[20..23]:
          0x02 -- ShortAuth session setup -> 128B SessionStatus
          0x00 -- Befriend handshake (polcore_befriend_finalize_sm) -> 48B response

        Other types: sends type-specific Status (auto-sized from Auth type).
        """
        if data is None:
            data = self.recv_exact("ShortAuth", SHORT_AUTH_SIZE)
            if not data:
                return
            data = self.bf_decrypt(data)

        decoded = self.decode_header(data)
        log(f"  ShortAuth({len(data)}B) decoded header: {decoded.hex()}", self.conn_id)
        if len(data) > 12:
            log(f"  ShortAuth[12:24]: {data[12:min(24, len(data))].hex()}", self.conn_id)

        seq, op, param = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=param)

        auth_seq = self.auth_packet[1] if self.auth_packet else 0
        auth_op = self.auth_packet[2] if self.auth_packet else 0
        if auth_seq == 0x01 and auth_op == 0x0b:
            # Disambiguate ShortAuth session-setup vs befriend handshake by
            # body[8..11]: ShortAuth always sends the session-version constant
            # `0x00000001`; befriend writes the target's `packed = (zone<<16)
            # | (world<<24) | acct_lo` value, which is normally != 1 once a
            # target has been resolved (e.g., 0x000003E8 for accid 1000).
            packed = struct.unpack_from('<I', data, 8)[0] if len(data) >= 12 else 0
            if packed != 0x00000001 and packed != 0:
                self.send_befriend_handshake_response(data)
            else:
                self.send_session_status()
        else:
            self.send_status(client_data=data)

    def handle_befriend_request(self, data):
        """Handle BefriendRequest (304B).

        Two flows arrive here:
          1. Initiator sending /befriend (176B BefriendExtra, no Finalize)
          2. Target accepting request (168B BefriendExtra + 8B Finalize)

        Our simplified protocol: xiloader injects target charname at data[24:39]
        and nickname at data[40:55]. Server resolves and creates request/friendship.
        """
        decoded = self.decode_header(data)
        log(f"  BefriendReq decoded header: {decoded.hex()}", self.conn_id)

        # Try to extract target info from request data
        # Our convention: data[24:39] = target charname, data[40:55] = nickname
        target_charname = data[24:39].rstrip(b'\x00').decode('ascii', errors='replace')
        nickname = data[40:55].rstrip(b'\x00').decode('ascii', errors='replace')
        log(f"  BefriendReq target='{target_charname}' nick='{nickname}'", self.conn_id)

        # Wait for BefriendExtra
        extra = self.recv_any("BefriendExtra")
        if not extra:
            return
        extra = self.bf_decrypt(extra)

        extra_decoded = self.decode_header(extra)
        log(f"  BefriendExtra ({len(extra)}B) decoded header: {extra_decoded.hex()}", self.conn_id)

        # Packet SHAPE does not identify the flow. An initiator /befriend was
        # captured sending a 168B Extra AND an 8B Finalize -- the same shape the
        # accept flow uses -- so keying on length classified a brand-new request
        # as an acceptance and no request row was ever written. Length is used
        # only for FRAMING (whether to consume a Finalize); the accept-vs-create
        # decision is made from server state further down.
        has_finalize = (len(extra) == BEFRIEND_EXTRA_168)

        # Candidate 32-bit fields in the Extra, logged so the account-id offset
        # can be pinned from a capture once the search server sends a real one.
        cand = {off: struct.unpack_from('<I', extra, off)[0]
                for off in (0x00, 0x04, 0x08, 0x0C, 0x10, 0x14)
                if off + 4 <= len(extra)}
        log("  BefriendExtra dwords: " +
            " ".join(f"+0x{o:02X}={v}" for o, v in cand.items()), self.conn_id)

        if has_finalize:
            # Consume the trailing Finalize so the stream stays framed.
            finalize = self.recv_any("BefriendFinalize")
            if finalize:
                finalize = self.bf_decrypt(finalize)
                if len(finalize) == FINALIZE_8B:
                    log(f"  BefriendFinalize (8B): {finalize.hex()}", self.conn_id)

        # ---- identify both parties, whatever the packet shape ----
        # Us: direct polcore connections carry no xiloader credential header,
        # so fall back to the acctid polcore sent in its Init packet (LE u16).
        me_accid = self.cred_account_id
        if not me_accid and self.account_id:
            me_accid = struct.unpack_from('<H', self.account_id, 0)[0]

        zero = bytes(1)
        # Extra+0x18 is the name THIS user typed: the nickname on an initiate,
        # the acceptor's nickname for the sender on an accept. It is not a
        # charname -- resolving it as one silently yields nothing. The 0x28
        # field is filler on the initiate side.
        # NUL-TERMINATED, not NUL-padded: bytes after the terminator are
        # leftover filler, so rstrip() alone leaves the name plus garbage.
        extra_typed_name = extra[0x18:0x27].split(zero)[0].decode('ascii', errors='replace')

        # Target account. The declaration's charname is populated only on the
        # accept side; on an initiate it is filler, so fall back to the account
        # id the Extra carries. See the 'BefriendExtra dwords' log line for
        # which offset actually holds it.
        other_accid = get_accid_for_charname(target_charname) if target_charname else None
        # Extra+0x14 identifies an ACCEPT: it echoes the notification id of the
        # request being accepted (0 on an initiate). Match it against the
        # pending requests addressed to us -- that names the requester exactly,
        # with no guessing.
        echo_notif_id = struct.unpack_from('<I', extra, 0x14)[0] if 0x18 <= len(extra) else 0
        accepting_request = None
        if echo_notif_id and me_accid:
            salt = session_salt_for_account(me_accid)
            for req in (get_pending_requests_for_account(me_accid) or []):
                if request_notification_id(req['accid_from'], me_accid,
                                           req.get('created_at'), salt) == echo_notif_id:
                    accepting_request = req
                    other_accid = req['accid_from']
                    log(f"  accept of request {echo_notif_id} from "
                        f"{other_accid} ({req.get('charname_from')})", self.conn_id)
                    break
            if accepting_request is None:
                log(f"  Extra+0x14={echo_notif_id} matched no pending request",
                    self.conn_id)

        # Initiate: Extra+0x10 is two u16s -- charid low, account id high --
        # holding befriend_submit's rec[6] and rec[5]. Read as a u32 it is
        # nonsense (e.g. 0x03EF0006). Do NOT fall back to resolving the charid:
        # on an accept that field holds something else entirely, and looking it
        # up silently resolved a real but WRONG account.
        if not other_accid and 0x14 <= len(extra):
            packed_accid = struct.unpack_from('<H', extra, 0x12)[0]
            if packed_accid and db_query('SELECT 1 FROM accounts WHERE id = %s', (packed_accid,)):
                other_accid = packed_accid
                packed_charid = struct.unpack_from('<H', extra, 0x10)[0]
                log(f'  target account {packed_accid} (charid {packed_charid}) '
                    f'from Extra+0x12', self.conn_id)

        # ---- accept or create, decided from server state, not packet shape ----
        pending_reverse = accepting_request is not None
        if not pending_reverse and me_accid and other_accid:
            pending_reverse = bool(db_query(
                'SELECT 1 FROM account_friend_requests '
                'WHERE accid_from = %s AND accid_to = %s LIMIT 1',
                (other_accid, me_accid)))

        from_accid = me_accid
        to_accid = other_accid
        # The declaration's [40:55] nickname is filler on an initiate, so prefer
        # the name the user actually typed.
        nickname = extra_typed_name or nickname
        if pending_reverse:
            if not nickname:
                nickname = target_charname
            result = accept_friend_request(to_accid, from_accid, nickname)
            log(f"  Accept (via befriend reply) {to_accid} -> {from_accid} "
                f"nick='{nickname}' result={result}", self.conn_id)
        elif from_accid and to_accid:
            # Initiator befriend flow -- create friend request
            # Get sender's charname
            sender_chars = db_query(
                "SELECT c.charname FROM accounts_sessions s "
                "JOIN chars c ON c.charid = s.charid "
                "WHERE s.accid = %s LIMIT 1",
                (from_accid,)
            )
            charname_from = sender_chars[0]['charname'] if sender_chars else 'Unknown'
            if not nickname:
                nickname = target_charname
            create_friend_request(from_accid, to_accid, nickname, charname_from)
            log(f"  Friend request created: {from_accid} -> {to_accid}", self.conn_id)
        else:
            log(f"  Cannot create request: from={from_accid} to={to_accid} target='{target_charname}'", self.conn_id)

        # Identity echoed back in the 168B record. Resolve it from the account
        # we actually identified -- the declaration's charname is filler on an
        # initiate, so echoing it sends the client a garbage name.
        echo_accid = None
        echo_charname = None
        if other_accid:
            _rows = db_query("SELECT charname FROM chars WHERE accid = %s LIMIT 1",
                             (other_accid,))
            if _rows:
                echo_charname = _rows[0]['charname']
        insert_friend = False
        friend_index = None
        # Echo the new friend only when a friendship was actually created --
        # i.e. this was an accept. from_accid is US and to_accid is the friend,
        # so the record echoed back is to_accid, not from_accid.
        if pending_reverse:
            echo_accid = to_accid
            sender_chars = db_query(
                "SELECT charname FROM chars WHERE accid = %s LIMIT 1",
                (to_accid,)
            ) if to_accid else []
            echo_charname = sender_chars[0]['charname'] if sender_chars else None
            # Tell polcore to insert the new friend into its internal table
            # (DAT_046340D8) inline, matching retail behavior -- the
            # BefriendResponse 184B carries the new friend record. Without
            # this, the friend list won't update until the next CallerB
            # bulk fetch (which retail also doesn't trigger here, but our
            # initial bootstrap does only once at login).
            insert_friend = True
            # Pick the next free slot. CallerB writes index 0 = self, so
            # 1..N are friend slots. Use the new friend count as the index
            # (= prior count + 1 in 1-based, since accept just inserted the
            # bidirectional friendship row).
            if from_accid:
                cnt_rows = db_query(
                    "SELECT COUNT(*) AS c FROM account_friends WHERE accid_owner = %s",
                    (from_accid,)
                )
                friend_index = (cnt_rows[0]['c'] if cnt_rows else 1)
        elif other_accid:
            echo_accid = other_accid

        # Send AuthConfirm + BefriendResponse, then wait for polcore to close.
        #
        # polcore's BefriendRequest pumper (FUN_045a4170) reads in chunks -- the
        # AuthConfirm via FUN_0459f690, then header/records/trailer via
        # FUN_0459fab0/FUN_0459f800. Each chunk goes through polcore's
        # FUN_04590d10 which returns -8 when recv() returns 0 (graceful close).
        # Closing the socket immediately after the last sendall() races polcore's
        # next recv(): if our FIN arrives before polcore drains the kernel
        # buffer for any pending chunk, that chunk's recv() returns 0 and
        # the SM bails with -8 (which propagates as op[4]=5). Wait for polcore
        # to half-close from its side instead.
        self.send_auth_confirm(seq=2, op=0x06, param=0x0159,
                               force_status_zero=True)
        log(f"  BefriendResponse: insert={insert_friend} idx={friend_index} "
            f"accid={echo_accid} char='{echo_charname}'", self.conn_id)
        self.send_befriend_response(insert_friend=insert_friend,
                                    friend_index=friend_index,
                                    target_accid=echo_accid,
                                    target_charname=echo_charname,
                                    nickname=nickname)
        try:
            self.conn.settimeout(2.0)
            while True:
                tail = self.conn.recv(64)
                if not tail:
                    break
                log(f"  Tail recv after BefriendResponse ({len(tail)}B): {tail.hex()}", self.conn_id)
        except socket.timeout:
            log(f"  Tail wait timed out; polcore did not close -- closing now", self.conn_id)
        except Exception as e:
            log(f"  Tail wait error: {e}", self.conn_id)
        self.close_connection()

    def handle_confirmation(self, data):
        """Handle Confirmation (408B).

        ConfirmFinalize size indicates the action:
          22B = accept confirmation
          26-30B = befriend confirmation (initiator)
          34B = decline
        """
        decoded = self.decode_header(data)
        log(f"  Confirmation decoded header: {decoded.hex()}", self.conn_id)
        log(f"  Confirmation[12:24]: {data[12:24].hex()}", self.conn_id)

        token_match = data[12:24] == self.token
        log(f"  Token at [12:24]: {token_match}", self.conn_id)

        # Wait for ConfirmFinalize (22-34B)
        finalize = self.recv_any("ConfirmFinalize")
        if finalize:
            finalize = self.bf_decrypt(finalize)
            finalize_size = len(finalize)
            log(f"  ConfirmFinalize ({finalize_size}B): {finalize[:24].hex()}", self.conn_id)

            if finalize_size == 34:
                # Decline -- extract from_accid from confirmation data
                # Our convention: data[16:20] = from_accid (the requester)
                from_accid = struct.unpack_from('<I', data, 16)[0]
                to_accid = self.cred_account_id
                if from_accid and to_accid:
                    decline_friend_request(from_accid, to_accid)
                    log(f"  Decline processed: {from_accid} -> {to_accid}", self.conn_id)
            elif finalize_size == 22:
                log(f"  Accept confirmation (already processed in BefriendRequest)", self.conn_id)
            else:
                log(f"  Befriend confirmation (initiator, size={finalize_size})", self.conn_id)

        # Send AuthConfirm
        self.send_auth_confirm(seq=3, op=0x01, param=0x01A9)
        self.close_connection()

    def handle_callerC_notification(self, data):
        """Handle CallerC notification pickup (64B data, Auth type 04,07).

        CallerC uses the generic driver (modes 0-5). After Auth+AuthResponse,
        it sends 64B data. Server responds with AuthConfirm + Status.
        Status contains notification data (pending friend requests, messages).

        Retail CallerC expects: AuthConfirm(24B) + Status(16B) + FIN.

        Notifications are delivered natively via NotifPickup + msgrec_recv;
        this handler no longer emits the invented NotificationData block.
"""
        accid = self.cred_account_id
        if not accid and self.account_id:
            accid = struct.unpack_from('<H', self.account_id, 0)[0]
        pending = get_pending_requests_for_account(accid) if accid else []
        unread = get_unread_messages(accid) if accid else []

        # Build notification data with message details
        notif_messages = []

        # Pending friend requests -> FWT (type 1, 'asking to be friends').
        for req in pending:
            notif_messages.append({
                'msg_id': request_notification_id(req['accid_from'], accid,
                                                  req.get('created_at'),
                                                  session_salt_for_account(accid)),
                'from_accid': req['accid_from'],
                'msg_type': 1,  # FWT -- "asking to be friends" (incoming request)
                'sender': req.get('charname_from', 'Unknown'),
                'subject': "Friend Request",
                'body': f"Friend request from {req.get('charname_from', 'Unknown')}",
            })

        # Unread messages -- pass through every type. The msg_type drives the
        # icon polcore renders (NRM/FWT/FOK/FNO/etc.).
        for msg in unread:
            notif_messages.append({
                'msg_id': int(msg.get('id', 0)),
                'from_accid': msg['from_accid'],
                'msg_type': int(msg.get('msg_type', 0)),
                'sender': msg.get('from_charname', f"Acct{msg['from_accid']}"),
                'subject': msg.get('subject', 'No subject')[:15],
                'body': msg.get('body', '')[:127],
            })

        if notif_messages:
            log(f"  CallerC: {len(notif_messages)} notification(s) for accid={accid}", self.conn_id)
            for i, nm in enumerate(notif_messages):
                log(f"    [{i}] type={nm['msg_type']} from={nm['sender']} subj='{nm['subject']}'", self.conn_id)
        else:
            log(f"  CallerC: no notifications for accid={accid}", self.conn_id)

        # Send standard AuthConfirm + Status
        seq, op, param = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=param)
        self.send_status(size=16, client_data=data)


    def handle_acpt_request(self, acceptor_accid, target_charname, nickname):
        """Direct accept used by xiloader to bypass the broken polcore CallerC
        path. Resolves target_charname to its accid, verifies a pending request
        exists from that accid TO us, calls accept_friend_request to create the
        bidirectional friendship and clean up state, and marks the matching
        friend-request message as read so the inbox dismisses it.

        Response: 4 bytes 'ACPT' + 1 byte status (0=ok, non-zero=error code).
        """
        status = 0xFF
        try:
            target_accid = get_accid_for_charname(target_charname)
            if not target_accid:
                log(f"  ACPT: target charname '{target_charname}' has no accid", self.conn_id)
                status = 1
            elif not acceptor_accid:
                log(f"  ACPT: acceptor accid is 0", self.conn_id)
                status = 2
            else:
                rows = db_query(
                    "SELECT 1 FROM account_friend_requests "
                    "WHERE accid_from = %s AND accid_to = %s LIMIT 1",
                    (target_accid, acceptor_accid)
                )
                if not rows:
                    log(f"  ACPT: no pending request from {target_accid} to {acceptor_accid}", self.conn_id)
                    status = 3
                else:
                    nick = nickname or target_charname
                    # accept_friend_request(from_accid, to_accid, ...) where
                    # from_accid = original requester (target_accid here, i.e.,
                    # the row's accid_from) and to_accid = acceptor. Reversed
                    # args meant the FOK ("X accepted your request") got sent
                    # to the acceptor (CharA) instead of the requester
                    # (CharB). Swap them.
                    accept_friend_request(target_accid, acceptor_accid, nick)
                    # Mark the friend-request msg in the inbox as read so it
                    # disappears on the next notification poll. account_friend_messages
                    # records of msg_type=1 from the target are the request notice.
                    db_execute(
                        "UPDATE account_friend_messages SET is_read = 1 "
                        "WHERE to_accid = %s AND from_accid = %s",
                        (acceptor_accid, target_accid)
                    )
                    log(f"  ACPT: friendship {acceptor_accid} <-> {target_accid} created, "
                        f"nickname='{nick}', request msgs marked read", self.conn_id)
                    status = 0
        except Exception as e:
            log(f"  ACPT exception: {e}", self.conn_id)
            status = 0xEE
        try:
            self.conn.sendall(b'ACPT' + bytes([status]))
        except Exception as e:
            log(f"  ACPT response send error: {e}", self.conn_id)
        self.close_connection()

    def handle_body_fetch(self, data):
        """Handle body-fetch (Auth (3,1), 408B = 0x198).

        Polcore's body-upload SM (FUN_045A6870, op_type 0x0E) is shared across
        three operations, distinguished by op_code at wire offset +0x190:
          - 0x00: body-fetch / message-send announcement. The only op_code
            ever observed on the wire (159557 archived connection logs).

        For body-fetch we expect:
          1. AuthConfirm (24B)
          2. 4-byte size header (uint32 LE = total body size)
          3. Body bytes (size from header), optionally BF-OFB encrypted
          4. After full body delivery, polcore enqueues a type-3 notification
             via FUN_0459C570 -> FFXi callback fires -> mes2frnd opens

        Request layout (408 bytes after BF-decrypt; we currently disable BF
        so the buffer is plaintext for our LSB session):
          [0x00..0x01]  msg_type bytes (from filename +0x30..+0x31)
          [0x08..0x0F]  64-bit hash from FUN_04599D40(slot+0xC0..+0xC4)
          [0x10..0x18F] 0x17F bytes from slot+0xD8 -- body content:
                        96-char encoded filename of the message
          [0x190..0x193] op_code
          [0x194..0x197] size_param

        Marking a message read is purely local (polcore deletes the file from
        msg/<accid>/r/b); it never reaches the server. See
        docs/profile-server/native-mark-read.md and inbox-msg-system.md.
        """
        log(f"  Body-upload-SM packet received (408B / Auth(3,1))", self.conn_id)
        log(f"    msg_type bytes: {data[0:2].hex()}", self.conn_id)
        log(f"    hash[0x08:0x10]: {data[0x08:0x10].hex()}", self.conn_id)
        log(f"    payload[0x10:0x40]: {data[0x10:0x40].hex()}", self.conn_id)

        op_code = struct.unpack_from('<I', data, 0x190)[0] if len(data) >= 0x194 else 0
        size_param = struct.unpack_from('<I', data, 0x194)[0] if len(data) >= 0x198 else 0
        log(f"    op_code=0x{op_code:X} size_param=0x{size_param:X}", self.conn_id)

        # Send AuthConfirm first -- same as other handlers. force_status_zero
        # makes encoded byte+1 = 0 so polcore's FUN_0459f690 (case 12 of the
        # body-upload SM FUN_045a6870) passes its success check
        # (byte+1 != 0 -> -0x1450-byte error).
        seq, op, param = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=param,
                               force_status_zero=True)

        # A user-composed message is announced here and UPLOADED afterwards:
        # the frame carries only "O/m/<96-char filename>" plus size_param (the
        # body length), and the client pushes the body bytes once we reply.
        # The body is therefore picked up from the drained tail below, not from
        # this frame -- an earlier attempt to parse it inline never fired.
        self._pending_upload = None
        if size_param:
            sender_accid = self.cred_account_id
            if not sender_accid and self.account_id:
                sender_accid = struct.unpack_from('<H', self.account_id, 0)[0]
            recipient = recipient_from_msg_filename(
                data[0x10:0x10 + 0x17F],
                bytes(self.auth_packet[16:24]) if self.auth_packet else bytes(8),
                sender_accid)
            if recipient:
                self._pending_upload = (recipient, size_param)
                log(f"  MsgUpload: announced {size_param}B for recipient {recipient}",
                    self.conn_id)

        # Default: body-fetch. Extract encoded filename from offset 0x10 and
        # look up the matching local msg body.
        try:
            body_bytes = self._lookup_body_for_request(data[0x10:0x10 + 0x17F])
        except Exception as exc:
            # Never let a lookup failure escape: this runs mid-transfer and an
            # exception here drops the connection instead of the one request.
            log(f"  Body-fetch lookup failed: {exc}", self.conn_id)
            body_bytes = None

        if body_bytes is None:
            log(f"  Body-fetch: could not identify message -- sending zero size",
                self.conn_id)
            self.conn.sendall(struct.pack('<I', 0))
        else:
            # Encrypt body if BF crypto is active for this connection.
            if self.bf_crypto_active and self.bf_stream_send is not None:
                body_to_send = self.bf_stream_send.process(body_bytes, reset_iv=True)
            else:
                body_to_send = body_bytes

            # Send 4-byte size header + body bytes.
            size_header = struct.pack('<I', len(body_to_send))
            try:
                self.conn.sendall(size_header)
                self.conn.sendall(body_to_send)
                log(f"  Body-fetch: sent {len(body_to_send)}B body (header + content)",
                    self.conn_id)
            except Exception as e:
                log(f"  Body-fetch send error: {e}", self.conn_id)

        self._drain_tail_then_close()

    def _drain_tail_then_close(self):
        """Drain anything polcore is still sending (body + CRC for body-upload
        variants -- accept-success "Friend registration" message,
        etc.). If we close while polcore's case 8/10 of FUN_045a6870 is mid-send,
        send() returns WSAECONNABORTED -> FUN_045905E0 maps to -6 -> op[6]=5 ->
        "Failed to send reply. (5)".
        """
        collected = bytearray()
        try:
            self.conn.settimeout(2.0)
            while True:
                tail = self.conn.recv(512)
                if not tail:
                    break
                collected += tail
                log(f"  Tail recv after body response ({len(tail)}B): {tail[:32].hex()}...",
                    self.conn_id)
        except socket.timeout:
            log(f"  Tail wait timed out; closing", self.conn_id)
        except Exception as e:
            log(f"  Tail wait error: {e}", self.conn_id)
        self._pending_tail = bytes(collected)
        self._persist_uploaded_message()
        self.close_connection()

    def _persist_uploaded_message(self):
        """Store a message whose body arrived in the tail after our response."""
        pending = getattr(self, '_pending_upload', None)
        tail = getattr(self, '_pending_tail', b'')
        if not pending or not tail:
            return
        recipient, size = pending
        composed = parse_compose_payload(tail[:size])
        if composed is None:
            log(f"  MsgUpload: {len(tail)}B tail did not parse as a message",
                self.conn_id)
            return
        subject, body = composed
        sender = self.cred_account_id
        if not sender and self.account_id:
            sender = struct.unpack_from('<H', self.account_id, 0)[0]
        log(f"  MsgUpload: from={sender} to={recipient} "
            f"subject={subject!r} body={body!r}", self.conn_id)
        if sender and recipient:
            send_friend_message(from_accid=sender, to_accid=recipient,
                                subject=subject, body=body, msg_type=0)
        self._pending_upload = None

    def _lookup_body_for_request(self, payload):
        """Identify the message body referenced by a body-fetch request payload
        and return the body bytes. Returns None if no match found.

        We match by scanning the on-disk msg dir (same one polcore reads) and
        finding a file whose name appears in the request payload. The on-disk
        body file IS the body content we want to send back.
        """
        # Serve from the DATABASE first. The on-disk file polcore wrote is only
        # a PLACEHOLDER: subject <0x07> <recipient's own charname>. Returning it
        # would echo that placeholder back as the message body -- which is
        # exactly the "body shows my own name" symptom. The real text is ours.
        body = self._body_from_db(payload)
        if body is not None:
            return body

        msg_dir = self._get_local_msg_dir()
        if not msg_dir or not os.path.isdir(msg_dir):
            log(f"  msg dir not found: {msg_dir}", self.conn_id)
            return None

        try:
            files = os.listdir(msg_dir)
        except Exception as e:
            log(f"  could not list msg dir: {e}", self.conn_id)
            return None

        # Look for any 96-char filename from the dir present anywhere in the payload.
        # Polcore embeds the filename string in the request; if we find it, that's
        # the message being fetched.
        payload_str = payload.decode('latin-1', errors='replace')
        for fname in files:
            if len(fname) == 96 and fname in payload_str:
                path = os.path.join(msg_dir, fname)
                try:
                    with open(path, 'rb') as f:
                        body = f.read()
                    log(f"  matched filename: {fname[:30]}... ({len(body)}B)",
                        self.conn_id)
                    return body
                except Exception as e:
                    log(f"  could not read body file: {e}", self.conn_id)
                    return None

        log(f"  no matching 96-char filename found in payload", self.conn_id)
        return None

    def _body_from_db(self, payload):
        """Rebuild a message body from our own records.

        The requested filename decodes to the usual 72-byte record, which
        carries the SENDER name at +0x10 and a 13-char subject prefix at +0x20.
        Together with the connection's account (the recipient) that identifies
        the row, so no filesystem access is needed -- and the server stays
        correct when it is not co-located with the client.
        """
        try:
            from pol_b64 import decode as b64_decode
            text = payload.split(bytes(1))[0].decode('ascii', errors='replace')
            start = text.find('O/m/')
            fname = text[start + 4:start + 100] if start >= 0 else text[:96]
            if len(fname) < 96:
                return None
            raw = b64_decode(fname[:96])
            sender_name = raw[0x10:0x20].split(bytes(1))[0].decode('ascii', 'replace')
            subj_prefix = raw[0x20:0x30].split(bytes(1))[0].decode('ascii', 'replace')
        except Exception as exc:
            log(f"  body-from-db: could not decode request ({exc})", self.conn_id)
            return None

        me = self.cred_account_id
        if not me and self.account_id:
            me = struct.unpack_from('<H', self.account_id, 0)[0]
        if not me or not sender_name:
            return None

        rows = db_query(
            "SELECT m.subject, m.body FROM account_friend_messages m "
            "JOIN chars c ON c.accid = m.from_accid "
            "WHERE m.to_accid = %s AND c.charname = %s AND m.subject LIKE %s "
            "ORDER BY m.id DESC LIMIT 1",
            (me, sender_name, subj_prefix + '%'))
        if not rows:
            log(f"  body-from-db: no message to {me} from {sender_name!r} "
                f"subj {subj_prefix!r}", self.conn_id)
            return None

        subject = (rows[0]['subject'] or '').encode('ascii', 'replace')
        body = (rows[0]['body'] or '').encode('ascii', 'replace')
        out = subject + bytes([7]) + body + bytes(1)
        log(f"  body-from-db: served {len(out)}B for {sender_name!r} "
            f"subj {subj_prefix!r}", self.conn_id)
        return out

    def _get_local_msg_dir(self):
        """The Ashita-side msg dir (one level above the bootloader exe).
        Mirrors xiloader's main.cpp EnsureMsgDir."""
        return os.path.join(ashita_root(), 'msg', 'r', 'b')

    def handle_notification(self, data):
        """Handle 416B (3,3) IXFF body -- used by TWO distinct polcore SMs:
          - notif_pump @ polcore+0x25B90: "do I have notifications?" poll.
            Body[0x190..0x191] == 0. Response: AuthConfirm + 8B [count][0].
          - msgrec_recv_pump @ polcore+0x276E0: "give me the records".
            Body[0x190..0x191] != 0 (set to expected count by caller).
            Response: AuthConfirm + 8B [count][0] + count*0x108B b64-encoded
            records + 4B sum-of-dwords trailer (validated via type=1 recv).

        See memory/project_msgrec_recv_pump.md for the full SM trace.
        """
        decoded = self.decode_header(data)
        log(f"  Notification decoded header: {decoded.hex()}", self.conn_id)

        # Discriminator: body byte at offset 0x190..0x191 is the expected-count
        # field. notif_pump writes 0; msgrec_recv_pump writes desc[0xA0]
        # (= claimed count), which is non-zero whenever fetch is requested.
        disc = struct.unpack_from('<H', data, 0x190)[0] if len(data) >= 0x192 else 0
        is_record_fetch = (disc != 0)
        log(f"  Notification disc[0x190]={disc:04x} ({'msgrec_fetch' if is_record_fetch else 'count_poll'})",
            self.conn_id)

        accid = self.cred_account_id
        if not accid and self.account_id:
            accid = struct.unpack_from('<H', self.account_id, 0)[0]
        pending = get_pending_requests_for_account(accid) if accid else []
        unread = get_unread_messages(accid) if accid else []

        seq, op, param = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=param)

        if is_record_fetch:
            # msgrec_recv_pump variant. Pack real DB notifications into our
            # entry layout (see docs/profile-server/msgrec-entry-layout.md):
            #   +0x10 from_accid u32, +0x14 msg_id u32, +0x18 msg_type u8,
            #   +0x1C created_at u32, +0x20 sender_name 16B, +0x30 subject 14B,
            #   +0x3E flag_word=0x0880 (mandatory).
            token_8b = b'\x00' * 8
            if self.auth_packet and len(self.auth_packet) >= 24:
                token_8b = bytes(self.auth_packet[16:24])

            # Combine pending friend requests + unread inbox messages, cap at 16.
            records_meta = []
            for p in pending[:8]:
                records_meta.append({
                    # Keys are accid_from / charname_from -- the names the
                    # query actually selects. from_accid / from_charname read
                    # as absent, which is why records went out as from=0 with
                    # an empty sender.
                    'from_accid': p.get('accid_from', 0),
                    'msg_id': request_notification_id(p.get('accid_from', 0),
                                                      accid,
                                                      p.get('created_at'),
                                                      session_salt_for_account(accid)),
                    'msg_type': 1,  # FWT -- incoming request. 9 is FOK (accepted).
                    'created_at': int(p.get('created_at', datetime.utcnow()).timestamp())
                                   if hasattr(p.get('created_at', None), 'timestamp')
                                   else int(time.time()),
                    'sender': (p.get('charname_from') or '')[:15],
                    'subject': 'Friend Request',
                    'body': f"Friend request from {p.get('charname_from') or 'Unknown'}",
                })
            for u in unread[:8]:
                records_meta.append({
                    'from_accid': u.get('from_accid', 0),
                    'msg_id': u.get('id', 0),
                    'msg_type': u.get('msg_type', 0),
                    'created_at': int(u.get('created_at', datetime.utcnow()).timestamp())
                                   if hasattr(u.get('created_at', None), 'timestamp')
                                   else int(time.time()),
                    'sender': u.get('from_charname', '')[:15],
                    'subject': u.get('subject', '')[:13],
                    'body': (u.get('body') or '')[:150],
                })

            count = len(records_meta)
            if count == 0:
                # Nothing to deliver -- short-circuit with count=0.
                self.send_data("NotifSizeHeader", struct.pack('<II', 0, 0))
                self.send_data("MsgRecTrailer", struct.pack('<I', 0))
                log(f"  MsgRecRecv: count=0 (no pending/unread for accid={accid})",
                    self.conn_id)
            else:
                try:
                    raw_records = []
                    for m in records_meta:
                        raw = bytearray(0x48)
                        # token = msg_id padded into u64 -- must be unique per record
                        struct.pack_into('<Q', raw, 0x00, m['msg_id'] & 0xFFFFFFFFFFFFFFFF)
                        struct.pack_into('<I', raw, 0x10, m['from_accid'])
                        struct.pack_into('<I', raw, 0x14, m['msg_id'])
                        raw[0x18] = m['msg_type'] & 0xFF
                        struct.pack_into('<I', raw, 0x1C, m['created_at'] & 0xFFFFFFFF)
                        sn = m['sender'].encode('ascii', errors='replace')[:15]
                        raw[0x20:0x20 + len(sn)] = sn
                        sb = m['subject'].encode('ascii', errors='replace')[:13]
                        raw[0x30:0x30 + len(sb)] = sb
                        struct.pack_into('<H', raw, 0x3E, 0x0880)
                        raw_records.append(bytes(raw))

                        # Body continuation records. The msgrec entry has no
                        # body field and polcore ignores the per-record pad, so
                        # the text is carried in extra entries -- entry bytes
                        # 0x10..0x47 are opaque to polcore (our convention),
                        # and xiloader reassembles them and drops them from the
                        # inbox queue.
                        text = (m.get('body') or '').encode('ascii', 'replace')
                        for ci in range(0, (len(text) + MSGREC_CHUNK - 1) // MSGREC_CHUNK):
                            piece = text[ci * MSGREC_CHUNK:(ci + 1) * MSGREC_CHUNK]
                            c = bytearray(0x48)
                            struct.pack_into('<Q', c, 0x00,
                                             (m['msg_id'] ^ ((ci + 1) << 24)) & 0xFFFFFFFFFFFFFFFF)
                            struct.pack_into('<I', c, 0x10, m['msg_id'])
                            struct.pack_into('<I', c, 0x14, ci)
                            c[0x18] = MSGREC_TYPE_BODY_CHUNK
                            c[0x19:0x19 + len(piece)] = piece
                            struct.pack_into('<H', c, 0x3E, 0x0880)
                            raw_records.append(bytes(c))

                    count = len(raw_records)
                    body = build_msgrec_response_body(raw_records, token_8b)
                    size_header = struct.pack('<II', count, 0)
                    trailer = msgrec_trailer(size_header, body)
                    self.send_data("NotifSizeHeader", size_header)
                    self.send_data("MsgRecBody", body)
                    self.send_data("MsgRecTrailer", trailer)
                    summary = '; '.join(
                        f"[{i}] from={m['from_accid']} type={m['msg_type']} "
                        f"sender={m['sender']!r} subj={m['subject']!r}"
                        for i, m in enumerate(records_meta)
                    )
                    log(f"  MsgRecRecv: AuthConfirm + 8B [count={count}][0] + "
                        f"{len(body)}B body + 4B trailer; {summary}",
                        self.conn_id)
                except Exception as e:
                    log(f"  MsgRecRecv build failed ({e}); falling back to count=0",
                        self.conn_id)
                    self.send_data("NotifSizeHeader", struct.pack('<II', 0, 0))
                    self.send_data("MsgRecTrailer", struct.pack('<I', 0))
        else:
            # notif_pump variant. Send count via 8B header. polcore returns
            # this in *param_2 to its caller, who is expected to invoke
            # msgrec_recv_pump if count > 0 (high-level orchestration that
            # we don't see in the dump -- likely happens via a vtable consumer
            # on FFXi side).
            count = msgrec_record_count(pending, unread)
            size_header = struct.pack('<II', count, 0)
            self.send_data("NotifSizeHeader", size_header)
            log(f"  NotifPickup: AuthConfirm + 8B [count={count}][0]; "
                f"pending={len(pending)} unread={len(unread)}", self.conn_id)

        # Hold connection briefly to capture any follow-up the client may
        # chain on this socket. polcore historically closes within ~300ms
        # of consuming the size header.
        try:
            self.conn.settimeout(5.0)
            tail = self.conn.recv(4096)
            if tail:
                log(f"  Notif post-header tail recv {len(tail)}B: "
                    f"{tail[:64].hex()}", self.conn_id)
                self.packet_log.append({
                    "direction": "C2S",
                    "label": "NotifTail",
                    "size": len(tail),
                    "data": tail.hex(),
                    "time": time.time(),
                })
        except Exception:
            pass
        self.close_connection()

    def handle_befriend_response_pump(self):
        """Handle befriend_response_pump (Auth (3,0,0x1A0)).

        polcore's SM @ +0x26190 (function +0x26190..+0x26580ish, decompiled
        as `befriend_response_pump`). Cases 0..0xD:
          0..4: connect/auth/setup/send 416B body
          5: drain 24B AuthConfirm; expects ae4 >= 4 (else -0x1400 error)
             then b9c capped at ae4-4 (= response body size to expect)
          6..7: recv body bytes via raw socket up to b9c total
          8: BF-decrypt body if BF enabled
          9..10: recv 4B CRC trailer
          11: validate trailer (mismatch -> -0x140F)
          12..13: parse msg record + enqueue notification (type 6)

        Phase 1 stub: count=0 path. Send AuthConfirm with param=4 so ae4=4
        after drain -> ae4-4=0=b9c -> case 6 recvs 0 bytes -> case 9 reads 4B
        zero trailer -> SM advances to case 12 with no record -> case 13
        skips enqueue (DAT_04984ba4 stays 0). Clean exit.

        We MUST NOT consume the 416B body -- it's encrypted and doesn't
        carry server-actionable data for the count=0 path. Read+discard.
        """
        # Read+discard the 416B encrypted request body -- polcore sends it
        # regardless of whether there are pending records to fetch.
        body = self.recv_exact("Data[0]", 416)

        # AuthConfirm with param=4 (the minimum that lets case 5 advance
        # without -0x1400). polcore reads param into desc+ae4; case 5
        # subtracts 4 -> ae4=0 -> b9c=0 -> case 6 needs no body bytes.
        seq, op, _ = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=4)

        # 4B sum-of-dwords trailer over preceding-zero-length body = 0.
        trailer = struct.pack('<I', 0)
        self.send_data("BefriendRespTrailer", trailer)
        log("  BefriendResponsePump: count=0 (Phase 1 wiring stub)", self.conn_id)

    def handle_friend_status_recv(self):
        """Handle friend_status_recv_pump (Auth (2,3), body_size=0).

        polcore's SM @ +0x237F0:
          Cases 0-3: connect / auth / drain 24B AuthConfirm
          Case 4:    recv 8B size header (first dword = N record count)
          Case 5:    recv N * 0xA8 record bytes (capped at 0x7E0 per chunk)
          Case 6:    for each record, validate via FUN_0459F090 (just checks
                     record[8] low byte < 200), set bitmap, write to Array2
                     via FUN_0459EEB0
          Case 7:    recv 4B sum-of-dwords trailer (CRC validated)
          Case 8:    finalize -- FFXi handoff via FUN_045A34F0, set
                     DAT_0463CA80=1 completion flag

        Writes DIRECTLY to Array2 (polcore+0xB40D8, stride 0x2C) -- the
        source of truth /flist renders from. Distinct from CallerB (which
        writes to Array1) and WhoIs (scattered globals only).

        0xA8-byte record wire layout (RE'd from FUN_0459EEB0 + FUN_0459F090):
          [0..3]    flags1   bits 5-6 (0x60) -> entry+0x98 bit 0 (occupied);
                             bit 4 (0x10) -> linkshell flag (writes to alt
                             array at +0xAFC18 instead of Array2)
          [4..7]    flags2   bit 30 (0x40000000) -> entry+0x8 bit 28 = OFFLINE
                             (CLEAR for online; INVERTED semantics)
          [8]       slot     u8, 0..199 -- Array2 index. Validator
                             FUN_0459F090 rejects >=200 (or >=100 for linkshell)
          [9]       sub      u8, 9 bits -> entry+0x8 bits 2..10
          [0x10-17] accid_pair  8B hashed via FUN_04599D40 -> entry[0..7]
                                (the friend identifier hash FFXi reads)
          [0x18-26] charname    15B -> entry+0xA0
          [0x2A-A7] sub-entries 8 x 16B packed (only used if is_new flag)

        Phase 2: send 1 test record to verify Array2 write + /flist display.
        Real DB-driven implementation comes after the wire shape is confirmed
        on a live test.
        """
        # No body to recv -- Auth (2,3) sends body_size=0. Polcore's send_body_sm
        # is skipped entirely on this auth class.

        seq, op, param = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=param)

        # Build one record per friend, slot index matching CallerB's
        # handle_index assignment (i+1, since slot 0 = self). bit 30 of
        # record[1] (-> entry+0x8 bit 28) reflects live session state from
        # accounts_sessions.
        records = []
        try:
            # Resolve our player accid from the connection.
            accid = self.cred_account_id
            if not accid and self.account_id:
                accid = struct.unpack_from('<H', self.account_id, 0)[0]


            friends = get_friends_for_account(accid) if accid else []

            for i, f in enumerate(friends[:63]):
                slot = i + 1  # Matches CallerB record[0] = i+1 placement
                online = bool(f.get('online'))

                rec = bytearray(0xA8)
                # flags1: bits 5+6 (0x60) -> entry+0x98 bit 0 = occupied
                struct.pack_into('<I', rec, 0x00, 0x60)
                # flags2: bit 30 (0x40000000) -> Array2 entry+0x08 bit 28.
                #
                # Bit 28 is NOT an online/offline flag. populate_friend_data's
                # FUN_03ED75D0 tests it and routes the entry to category 3 --
                # the PENDING bucket -- before the online test is ever reached.
                # Online/offline lives in bits 13-15 and arrives by a different
                # path entirely.
                #
                # A confirmed friend must always have this CLEAR, online or not.
                # Setting it for offline friends rendered CharB as 'pending';
                # setting it for online friends (the original) was wrong the
                # other way. Pending requests get bit 28 from their own records.
                flags2 = 0x00000000
                struct.pack_into('<I', rec, 0x04, flags2)
                # slot index in low byte of record[2]
                rec[0x08] = slot
                rec[0x09] = 0
                # accid pair -> hashed (FUN_04599D40) into entry[0..7]
                struct.pack_into('<II', rec, 0x10, f['accid'], 0)
                # charname at +0x18..+0x26 (15 bytes)
                # A friend row carries two names, in these slots:
                #   entry+0xA0        the NICKNAME -- the account-name stand-in
                #                     the list shows (friend-list-ui.md calls
                #                     this "display name (account nickname)")
                #   status tbl +0x04  the REAL charname -- what /tell targets
                # Never accounts.login in either.
                cname = (f.get('nickname') or f['charname']).encode('ascii', errors='replace')[:15]
                rec[0x18:0x18 + len(cname)] = cname

                # Sub-entries: 8 x 16B at record+0x2A -> Store 3 entry+0x1A.
                #
                # populate_friend_data only renders an online friend's XI icon
                # and server/zone name when FUN_03ED77A0 passes, and that reads
                #     *(u16*)(entry + 0x1A + ((entry[0x08] >> 17) & 7) * 0x10)
                # and requires it to be exactly 1. Leaving these zero is why an
                # online friend showed with no name, zone or icon -- the row was
                # categorised online but the in-game extras were skipped.
                #
                # The selector comes from the flag bits a status push sets, so
                # fill every sub-entry that fits rather than guessing the index.
                # Stop at 7: the 8th would run to entry+0x9A and clobber the
                # occupied flag at entry+0x98.
                for sub in range(7):
                    struct.pack_into('<H', rec, 0x2A + sub * 0x10, 1)
                records.append(bytes(rec))

            summary = '; '.join(
                f"slot={i+1} accid={f['accid']} {f['charname']!r} online={f.get('online')}"
                for i, f in enumerate(friends[:63])
            ) or '(no friends)'
            log(f"  friend_status: accid={accid} {summary}", self.conn_id)
        except Exception as e:
            log(f"  friend_status_recv build failed: {e}", self.conn_id)
            records = []

        count = len(records)
        size_header = struct.pack('<II', count, 0)
        body = b''.join(records)

        # Trailer = sum of dwords over size_header + body, mod 2^32.
        all_data = size_header + body
        crc = 0
        for j in range(0, len(all_data), 4):
            crc = (crc + struct.unpack_from('<I', all_data, j)[0]) & 0xFFFFFFFF
        trailer = struct.pack('<I', crc)

        self.send_data("FriendStatusSizeHeader", size_header)
        if body:
            self.send_data("FriendStatusBody", body)
        self.send_data("FriendStatusTrailer", trailer)
        log(f"  FriendStatusRecv: count={count} (Phase 2 test record)", self.conn_id)

    def handle_whois(self):
        """Handle WhoIs / friend-status query (Auth (4,6), 24B body).

        polcore's WhoIs SM (+0x1D490) -- 7 cases:
          0..4: connect/auth/send 24B body/drain 24B AuthConfirm
          5:    recv 128B response (param_3=1 -> CRC-validated)
          6:    parse response into 11+ result globals

        The 24B request body carries the target accid at offset 0..3 (raw u32
        LE -- body content is sent raw, only the 12B auth header is mask-XOR'd).
        polcore's case 6 parses these response fields out of the 124B payload:

          result[0x06]  uint8   non-zero = found, zero = not-found
          result[0x76]  uint8   low-bit = online flag (-> +0xAC528)

        Plus 9+ other dwords/words/bytes documented in
        docs/profile-server/whois-status-query.md.
        """
        body = self.recv_exact("Data[0]", 24)
        if not body:
            return
        body = self.bf_decrypt(body)

        # Body[0..3] holds the target accid raw (no mask XOR applies to body).
        # The remaining 16 bytes carry padding and a 4B CRC trailer added by
        # polcore_send_body_sm with type=1.
        target_accid = struct.unpack_from('<I', body, 0)[0]
        log(f"  WhoIs req: target_accid={target_accid}", self.conn_id)

        seq, op, param = self.get_auth_confirm_params()
        self.send_auth_confirm(seq=seq, op=op, param=param)

        # Look up the target's session row. Presence in accounts_sessions
        # (with last_zoneout_time = '0000-00-00 00:00:00') means online.
        row = None
        try:
            rows = db_query(
                "SELECT s.accid, s.charid, "
                "  COALESCE("
                "    (SELECT charname FROM chars WHERE accid = s.accid ORDER BY charid LIMIT 1),"
                "    CONCAT('Acct', s.accid)"
                "  ) AS charname "
                "FROM accounts_sessions s "
                "WHERE s.accid = %s "
                "  AND s.last_zoneout_time = '0000-00-00 00:00:00' "
                "LIMIT 1",
                (target_accid,)
            )
            row = rows[0] if rows else None
        except Exception as e:
            log(f"  WhoIs DB lookup failed: {e}", self.conn_id)

        # 128B status response. polcore's recv-side CRC accumulator at
        # desc+0x10 was zeroed by polcore_connect_sm case 0 and is NOT touched
        # by polcore_drain_sm (the AuthConfirm recv), so it's still 0 when
        # case 5 of the WhoIs SM runs recv_body_sm with param_3=1. Trailer is
        # therefore just sum-of-dwords over the 124B payload.
        payload = bytearray(124)
        # found bit must be set for any known account regardless of online
        # state -- polcore uses it to gate the local handle-table reverse
        # lookup that writes the slot index into +0x7541C. If clear, the SM
        # takes the not-found branch and writes -1, hiding the friend from
        # the UI entirely.
        payload[0x06] = 0x01
        if row is not None:
            payload[0x76] = 0x01   # online flag (low bit -> +0xAC528)
            log(f"  WhoIs response: accid={target_accid} ONLINE charname={row['charname']!r}",
                self.conn_id)
        else:
            log(f"  WhoIs response: accid={target_accid} OFFLINE (no live session)",
                self.conn_id)

        crc = 0
        for j in range(0, len(payload), 4):
            crc = (crc + struct.unpack_from('<I', payload, j)[0]) & 0xFFFFFFFF
        trailer = struct.pack('<I', crc)

        status_128 = bytes(payload) + trailer
        self.send_data("WhoIsStatus", status_128)
        log(f"  WhoIs wire: AuthConfirm + 124B payload + 4B CRC=0x{crc:08X}",
            self.conn_id)

        # Hold connection briefly so polcore has time to drain. polcore's
        # recv_body_sm pumps async; closing immediately can race the OS-level
        # recv. Mirrors the post-header hold used by handle_notification.
        try:
            self.conn.settimeout(2.0)
            tail = self.conn.recv(64)
            if tail:
                log(f"  WhoIs post-response tail recv {len(tail)}B: {tail.hex()}",
                    self.conn_id)
        except Exception:
            pass
        self.close_connection()

    def handle_unknown(self, data):
        """Handle unknown packet type."""
        decoded = self.decode_header(data)
        log(f"  Unknown ({len(data)}B) decoded: {decoded.hex()}", self.conn_id)

    # ========================================================================
    # Response Builders
    # ========================================================================

    def send_auth_confirm(self, seq, op, param, token_override=None,
                          force_status_zero=False):
        """Send AuthConfirm (24B mask-encoded).

        Decoded format:
          [0]    = TYPE_MARKER (0x81)
          [1]    = seq  (mask[1]: 0x01=ShortAuth, 0x04=login)
          [2]    = op   (mask[2]: 0x0b=ShortAuth, 0x05=login)
          [3]    = 0x00
          [4:6]  = param (LE uint16: 0x0029=ShortAuth, 0x0009=login)
          [6:8]  = acctid[0:2]
          [8:12] = Init[8:12] XOR server_IP_LE
          [12:24]= token (NOT mask-encoded, plaintext)

        force_status_zero: When True, set plain[1] = mask[1] so encoded[1]==0.
        polcore's FUN_0459f690 (BefriendRequest pumper case 8) reads byte+1
        of the raw recv buffer and treats non-zero as error code -0x1450-byte.
        With BF crypto disabled and no XOR-decode, encoded[1] must be 0.
        Used for the BefriendRequest accept flow.
        """
        plain = bytearray(AUTH_CONFIRM_SIZE)

        # Header [0:12] -- will be XOR'd with mask
        plain[0] = TYPE_MARKER
        plain[1] = seq
        plain[2] = op
        plain[3] = 0x00
        if force_status_zero and self.mask:
            # Cancel the XOR for byte[1] so polcore's recv-byte+1 status
            # check sees 0 (success).
            plain[1] = self.mask[1]
        struct.pack_into('<H', plain, 4, param)
        # [6:8] = account ID first 2 bytes
        acct_id = self.cred_account_id
        if not acct_id and self.account_id:
            acct_id = struct.unpack_from('<H', self.account_id, 0)[0]
        acct_lo = acct_id & 0xFFFF
        plain[6] = acct_lo & 0xFF
        plain[7] = (acct_lo >> 8) & 0xFF
        # [8:12] = Init[8:12] XOR server_IP_LE
        init_suffix = self.init_packet[8:12] if self.init_packet else b'\x00\x00\x00\x00'
        plain[8:12] = xor_bytes(init_suffix, SERVER_IP_LE)

        # [12:24] = session token (plaintext, NOT mask-encoded)
        token = token_override if token_override is not None else SESSION_TOKEN
        plain[12:24] = token

        # Encode header [0:12] with mask
        encoded = bytearray(plain)
        encoded[:12] = self.encode_header(bytes(plain[:12]))

        log(f"  AuthConfirm decoded[0:12]: {bytes(plain[:12]).hex()}", self.conn_id)
        log(f"  AuthConfirm encoded[0:12]: {bytes(encoded[:12]).hex()}", self.conn_id)
        log(f"  AuthConfirm token: {token.hex()}", self.conn_id)

        # Stash the wire bytes so CRC-validated handlers (e.g. WhoIs) can
        # include them in their sum-of-dwords trailer -- polcore's running CRC
        # accumulates across each recv on this slot.
        self._last_authconfirm_wire = bytes(encoded)

        self.send_data("AuthConfirm", bytes(encoded))

    def send_status(self, size=None, client_data=None):
        """Send Status response.

        Size is determined by connection type if not explicitly provided.

        Retail Status sizes:
          8B:   INITIAL-AUTH probe response
          12B:  CallerB operation ACK
          16B:  Minimal ACK / notification
          32B:  CallerA keepalive
          128B: Session setup (contains account/handle data)
          21KB: Friend list dump (bulk data)
        """
        if size is None:
            size = self.get_status_size_for_type()

        plain = bytearray(size)

        # Header [0:12] -- will be XOR-encoded with mask
        # Status[0:2] = mask type bytes (mirrored from connection)
        # Status[1] != 0 triggers additional processing in polcore (IP read, etc.)
        # Status[8:12] = profile server IP in big-endian (127.0.0.1 = 7F000001)
        plain[0:min(12, size)] = b'\x00' * min(12, size)
        if self.mask and size >= 12:
            # Status[1] != 0 triggers additional processing in polcore:
            #   - Reads Status[8:12] as profile server IP (big-endian)
            #   - Writes sockaddr global if not already set
            #   - May trigger additional connection setup
            # Our mask[1] is 0x00 (zero globals), so we must set plain[1]
            # to a non-zero value explicitly.
            plain[0] = self.mask[0]  # type A (mirror mask)
            plain[1] = 0x01         # type B -- MUST be non-zero to trigger IP/connection processing
            plain[2] = self.mask[2]
            plain[3] = self.mask[3]
            # Profile server IP at [8:12] big-endian
            plain[8:12] = SERVER_IP_BE
            log(f"  Status header plain: {bytes(plain[:12]).hex()} (type={plain[0]:02X},{plain[1]:02X} IP={SERVER_IP})", self.conn_id)

        if size >= 16:
            # [12:16]: timestamp
            plain[12:16] = struct.pack('<I', int(time.time()) & 0xFFFFFFFF)

        if size == 128:
            # 128B Session Setup Status -- contains account/handle data.
            # This is the response that should populate the friend manager.
            # Plaintext structure is unknown; we fill with identifiable test data.
            #
            # Hypothesis: this contains the player's friend handle, account ID,
            # and possibly friend count / server config.
            # Using recognizable byte patterns for protocol analysis.
            #
            # [12:16] = timestamp (already set above)
            # [16:32] = account_id (6B) + padding
            if self.account_id:
                plain[16:22] = self.account_id
            # [32:48] = "HANDLE" test string (16 bytes, padded)
            plain[32:48] = b'LSB_TestHandle\x00\x00'
            # [48:64] = friend count (0) + flags
            struct.pack_into('<I', plain, 48, 0)  # friend count = 0
            struct.pack_into('<I', plain, 52, 1)  # flags = 1 (active)
            # [64:80] = server info / config
            plain[64:72] = b'LSBSRV\x00\x00'
            # [80:96] = pattern bytes for identification in memory dumps
            for i in range(80, 96):
                plain[i] = (i - 80 + 0xA0) & 0xFF  # A0 A1 A2 ... AF
            # [96:112] = more pattern for identification
            for i in range(96, 112):
                plain[i] = (i - 96 + 0xB0) & 0xFF  # B0 B1 B2 ... BF
            # [112:128] = timestamp + counter
            struct.pack_into('<I', plain, 112, int(time.time()) & 0xFFFFFFFF)
            struct.pack_into('<I', plain, 116, self.ack_counter)
            # [120:128] = zeros (padding)

            log(f"  Session Setup Status (128B) with test data", self.conn_id)
            log(f"  account_id: {self.account_id.hex() if self.account_id else 'none'}", self.conn_id)
        elif size <= 32:
            # CallerA keepalive Status (32B).
            # Retail pattern: AuthConfirm(24B) + Status(32B), nothing else.
            # Status should contain version/counter data that the SM compares
            # against client's Data[12:40] to decide whether to fire ShortAuth.
            if size >= 12:
                # [4:8] = size marker (size+1, following observed pattern)
                struct.pack_into('<I', plain, 4, size + 1)
            if size >= 32:
                # [12:16] = timestamp
                plain[12:16] = struct.pack('<I', int(time.time()) & 0xFFFFFFFF)
                # [16:28] = version counters -- echo client's header [0:12]
                # with modifications to signal "data has changed"
                if client_data and len(client_data) >= 12:
                    plain[16:28] = client_data[0:12]
                # [28:32] = timestamp+1
                plain[28:32] = struct.pack('<I', (int(time.time()) + 1) & 0xFFFFFFFF)

        log(f"  Status({size}B) plain[0:12]: {bytes(plain[:min(12,size)]).hex()}", self.conn_id)

        # Encode header [0:12]
        encoded = bytearray(plain)
        if self.mask and size >= 12:
            encoded[:12] = self.encode_header(bytes(plain[:12]))

        self.send_data("Status", bytes(encoded))

    def send_session_status(self):
        """Send Session Setup Status (128B) for ShortAuth (01,0b).

        This is the response that establishes the friend session during
        bootstrap. The polcore state machine checks this to decide whether
        to proceed to CallerB (friend list download).

        Client ShortAuth Data (24B) consistently sends:
          decoded header: 02 01 0b 00 19 00 [acctid] 03 00 00 00
          plaintext[12:24]: 01 00 00 00 | 00 00 00 00 | 04 00 00 00
          -> header[4]=0x19=25(=24+1), header[8:12]=3
          -> plaintext: version=1, 0, counter=4

        Pattern: header[4] = packet_size + 1.

        Status format (128B, header [0:12] mask-encoded):
          Header [0:4]  = type/identity bytes
          Header [4:8]  = 0x81 = 129 = 128+1 (status size marker)
          Header [8:12] = profile server IP (big-endian, for sockaddr)
          Body [12:128] = session data (plaintext)
        """
        size = 128
        plain = bytearray(size)

        # Header [0:12] -- mask-encoded
        if self.mask:
            plain[0] = self.mask[0]
            plain[1] = 0x04         # non-zero -> triggers IP/connection processing
            plain[2] = self.mask[2]
            plain[3] = self.mask[3]
            # [4:8] = status size marker (size+1, following client Data pattern)
            struct.pack_into('<I', plain, 4, size + 1)
            # Profile server IP at [8:12] big-endian
            plain[8:12] = SERVER_IP_BE

        # Session data -- query DB for actual friend count
        accid = self.cred_account_id
        if not accid and self.account_id:
            accid = struct.unpack_from('<H', self.account_id, 0)[0]
        friend_count = 0
        if accid:
            friends = get_friends_for_account(accid)
            friend_count = len(friends)

        # Body [12:128] -- session data (plaintext)
        # Mirror the client's ShortAuth Data structure with server-side values.
        # Client sends: [12:16]=1(version), [16:20]=0, [20:24]=4(counter)
        # Server responds with incremented versions to signal "data changed":

        # [12:16] = timestamp
        plain[12:16] = struct.pack('<I', int(time.time()) & 0xFFFFFFFF)

        # [16:20] = friend list version (incremented from client's 1)
        struct.pack_into('<I', plain, 16, 2 if friend_count > 0 else 1)

        # [20:24] = notification/status version
        struct.pack_into('<I', plain, 20, 0)

        # [24:28] = data version (incremented from client's 4)
        struct.pack_into('<I', plain, 24, 5 if friend_count > 0 else 4)

        # [28:32] = friend count (actual from DB)
        struct.pack_into('<I', plain, 28, friend_count)

        # [32:36] = session flags (non-zero = active session)
        struct.pack_into('<I', plain, 32, 1)

        # [36:40] = another counter
        struct.pack_into('<I', plain, 36, 1 if friend_count > 0 else 0)

        # [40:46] = account_id (6B)
        if self.account_id:
            plain[40:46] = self.account_id

        # [48:52] = server capabilities / feature flags
        struct.pack_into('<I', plain, 48, 0x03)  # version 3 (matches client header[8:12])

        log(f"  SessionStatus(128B): accid={accid} friends={friend_count}", self.conn_id)
        log(f"  SessionStatus plain[0:40]: {bytes(plain[:40]).hex()}", self.conn_id)

        # Encode header [0:12]
        encoded = bytearray(plain)
        if self.mask:
            encoded[:12] = self.encode_header(bytes(plain[:12]))

        self.send_data("SessionStatus", bytes(encoded))

    def send_befriend_handshake_response(self, request_data):
        """Send polcore befriend handshake response (48B body).

        Triggered when (01,0b) ShortAuth body[8..11] != 1, indicating
        polcore_befriend_finalize_sm submit (not session-setup, which uses
        the version constant 0x01000000).

        NOTE: distinct from `send_befriend_response` (line 2309) which builds
        a 184B native BefriendResponse for the *retail-shaped* CallerC accept
        flow. This method is the **handshake** response polcore_befriend_
        finalize_sm state 6 expects (48B body per polcore RE in
        docs/profile-server/befriend-ixff-wire-format.md §6).

        Request body layout (24B, decrypted) per polcore RE
        (docs/profile-server/befriend-ixff-wire-format.md §5a):
          [0x00..0x03] uint32  acct_hi  -- target account_id high half
          [0x04..0x07] uint32  reserved
          [0x08..0x0B] uint32  packed   -- (zone<<16)|(world<<24)|acct_lo
          [0x0C..0x0D] uint16  seq
          [0x0E]       uint8   sub_id
          [0x0F]       uint8   pad
          [0x10..0x17] 8B zero-at-submit / retry counters

        Response body layout (48B = 0x30) per agent RE:
          [0x00..0x07] uint64  account_id (FFXi expects FUN_04599D40 hash;
                               we send a raw acct as 8 LE bytes -- polcore
                               passes this back through the hash function
                               which is reversible-ish for our acct values)
          [0x08..0x0F] 8B unused
          [0x10..0x1E] 15B nickname (null-padded)
          [0x1F]       1B NUL pad
          [0x20]       uint8 accept (1 = accept; 0 = reject -> polcore returns
                                    -0x1C12 -> FFXi rc=0xB)
          [0x21]       uint8 status code
          [0x22..0x2F] 14B reserved/zero

        polcore_befriend_finalize_sm state 6 reads this and returns to FFXi
        via befriend_op_send -> befriend_response_callback.
        """
        size = 48
        plain = bytearray(size)

        # Extract target identity from request body.
        acct_hi = struct.unpack_from('<I', request_data, 0)[0]
        packed  = struct.unpack_from('<I', request_data, 8)[0]
        acct_lo = packed & 0xFFFF
        target_accid = (acct_hi << 16) | acct_lo

        # Look up target charname/nickname from chars table.
        target_charname = ''
        if target_accid:
            row = db_query(
                "SELECT charname FROM chars WHERE accid = %s LIMIT 1",
                (target_accid,)
            )
            if row:
                target_charname = (row[0]['charname'] or '')[:15]

        # Body [0x00..0x07] = account_id (8B). Pack as little-endian uint64.
        struct.pack_into('<Q', plain, 0x00, target_accid)

        # Body [0x10..0x1E] = nickname (15B, null-padded).
        if target_charname:
            name_bytes = target_charname.encode('ascii', errors='replace')[:15]
            plain[0x10:0x10 + len(name_bytes)] = name_bytes

        # Body [0x20] = accept flag. Non-zero = accept (server confirms target
        # exists and accepts the befriend handshake).
        plain[0x20] = 0x01 if target_accid else 0x00

        # Body [0x21] = status code (informational, currently unused by FFXi).
        plain[0x21] = 0x00

        # polcore_recv_body_sm (polcore+0x1F800) with type=1 verifies a 4-byte
        # checksum at body[size-4 .. size-1] = sum of dwords body[0 .. size-5].
        # Mismatch returns -0x140f, which propagates as FFXi result_code 5.
        # Initial accumulator is desc[+0x10] which is 0 on a fresh connection.
        checksum = 0
        for i in range(0, 44, 4):
            checksum = (checksum + struct.unpack_from('<I', plain, i)[0]) & 0xFFFFFFFF
        struct.pack_into('<I', plain, 44, checksum)

        # Persist the friend request so the target's notification poll surfaces it as
        # an inbox notification on next refresh. The handshake itself only
        # confirms the target exists -- actual request creation happens here.
        from_accid = self.cred_account_id
        if not from_accid and self.account_id:
            from_accid = struct.unpack_from('<H', self.account_id, 0)[0]
        from_charname = get_charname_for_account(from_accid) if from_accid else ''
        if from_accid and target_accid and from_accid != target_accid and target_charname:
            create_friend_request(
                from_accid=from_accid,
                to_accid=target_accid,
                # The TARGET's character name, not the sender's.
                #
                # This field is the nickname the sender is choosing FOR the
                # target, and the design prefills it from the target's
                # character name (the player can then edit it). Passing the
                # sender's own name here produced friendships where each side
                # was labelled with the requester's name -- CharB's list
                # showed CharA as "CharB".
                nickname=(target_charname or '')[:15],
                charname_from=(from_charname or '')[:15],
            )

        log(
            f"  BefriendResponseHandshake(48B): target_accid={target_accid} "
            f"charname='{target_charname}' accept={plain[0x20]} "
            f"checksum=0x{checksum:08X} from={from_accid}/'{from_charname}'",
            self.conn_id,
        )

        # Send raw bytes -- polcore_befriend_finalize_sm state 6 reads the body
        # directly (account_id at body[0..7], nickname at body[0x10..0x1E],
        # accept at body[0x20]). NO mask XOR on the header -- that would
        # corrupt the account_id field. ShortAuth-session-status uses encoded
        # header, befriend-handshake response does not.
        self.send_data("BefriendHandshakeResp", bytes(plain))

    def send_friend_records(self, charname=None):
        """Send friend data records for CallerB response.

        Queries account_friends + accounts_sessions to build real friend records.

        Wire format (after AuthConfirm):
          8B control header: byte[0] = record_count
          N x 104B friend data records

        CallerB driver modes:
          Mode 4: receives 8B header, extracts record count
          Mode 5: receives count*104 bytes of record data
          Mode 6: processes records into friend_data array (+0x403080)

        Record format (104 bytes, 0x68):
          [0]     handle_index (0-63, friend_data array index)
          [1:4]   unknown / padding
          [4]     flag byte (non-zero triggers handle_array write)
          [5]     sub_index (handle_array entry selector, < 64)
          [6]     sub_offset (offset in handle_entry flags area)
          [7]     unknown
          [8:10]  u16 value -> friend_data+0x02
          [10:12] unknown
          [12:16] u32 -> friend_data+0x04
          [16:20] u32 -> friend_data+0x08
          [20:24] u32 -> friend_data+0x0C
          [20:22] u16 zone_id -> friend_data+0x0C (online only)
          [22]    nation -> friend_data+0x0E (online only)
          [23]    mjob -> friend_data+0x0F (online only)
          [24:39] 15 bytes text -> friend_data+0x18 (display name)
          [40:55] 15 bytes nickname -> friend_data+0x28
          [55:104] padding (not copied by mode 6 past byte 55)
        """
        # Resolve account ID from credential header, Init packet, or charname
        accid = self.cred_account_id
        if not accid and self.account_id:
            accid = struct.unpack_from('<H', self.account_id, 0)[0]
        if not accid and charname:
            cn = charname.rstrip(b'\x00').decode('ascii', errors='replace')
            accid = get_accid_for_charname(cn)
        if not accid:
            log(f"  No account ID for friend lookup, sending 0 records", self.conn_id)
            header = bytearray(8)
            header[0] = 0
            self.send_data("ControlHeader", bytes(header))
            return

        # Query database for friends + online status
        friends = get_friends_for_account(accid)
        num_friends = min(len(friends), 63)  # max 63 friends (index 1-63)

        # Look up player's own character name for handle index 0
        player_chars = db_query(
            "SELECT c.charname FROM accounts_sessions s "
            "JOIN chars c ON c.charid = s.charid "
            "WHERE s.accid = %s LIMIT 1",
            (accid,)
        )
        player_charname = player_chars[0]['charname'] if player_chars else 'Unknown'

        # Outgoing pending requests (shown in sender's Pending section with bit 28)
        # These only appear for the SENDER, not the recipient.
        pending_outgoing = get_outgoing_requests_for_account(accid)
        num_pending_out = min(len(pending_outgoing), 10)

        num_records = num_friends + num_pending_out
        log(f"  Account {accid}: {len(friends)} friend(s), {len(pending_outgoing)} pending-out, sending {num_records} record(s)", self.conn_id)

        all_records = bytearray()

        # Friend records (index 1+)
        for i, f in enumerate(friends[:63]):
            record = bytearray(104)
            record[0] = i + 1       # handle_index (1-based; index 0 = player's own handle)
            record[4] = 1           # flag = 1 (triggers handle_array update)
            record[5] = i + 1       # sub_index (1-based, matches handle_index)
            record[6] = 0           # sub_offset

            # [8:10] = u16, >= 4 enables extended processing
            struct.pack_into('<H', record, 8, 0x0004)

            # [12:16] = friend account ID as identifier
            struct.pack_into('<I', record, 12, f['accid'])

            # [16:20] = flags -> friend_data+0x08 -> Array2a+0x08
            # Retail online: 0x80000010 (bits 31+4), bit 13 added by native status processing
            # We add bit 13 ourselves + bit 16 as our online marker
            if f['online']:
                struct.pack_into('<I', record, 16, 0x80072010)  # bits 31+19+18+17+16+13+4
            else:
                struct.pack_into('<I', record, 16, 0x80000000)  # bit 31 only (offline)

            # [24:39] = 15 bytes character name (display name in friend list)
            charname = f['charname'].encode('ascii', errors='replace')[:15]
            charname = charname.ljust(15, b'\x00')
            record[24:39] = charname

            # [40:55] = 15 bytes nickname/handle (shown as "Handle" in friend list)
            # NOTE: wire[39] (friend_data+0x27) is zeroed by mode 6 (name null terminator).
            # Nickname starts at wire[40] -> friend_data+0x28.
            nickname = f['nickname'].encode('ascii', errors='replace')[:15]
            nickname = nickname.ljust(15, b'\x00')
            record[40:55] = nickname

            # [20:24] u32 -> friend_data+0x0C (flags_hi)
            #   Low u16 [20:22]: bits 1-10 = game type (1=FFXI), extracted as (flags_hi>>1)&0x3FF
            #   High u16 [22:24]: zone_id -- read by syncstatus from friend_data+0x0E
            if f['online']:
                struct.pack_into('<H', record, 20, 0x0002)  # game_type=1 (FFXI) at bit 1
                struct.pack_into('<H', record, 22, f.get('zone_id', 0))  # zone_id

            log(f"  Record[{i}]: idx={i+1} accid={f['accid']} char='{f['charname']}' nick='{f['nickname']}' online={f['online']} zone={f.get('zone_id',0)}", self.conn_id)
            all_records += record

        # Outgoing pending requests (bit 28 = pending)
        for k, req in enumerate(pending_outgoing[:num_pending_out]):
            idx = num_friends + k + 1
            if idx > 63:
                break
            record = bytearray(104)
            record[0] = idx
            record[4] = 1
            record[5] = idx
            record[6] = 0

            struct.pack_into('<H', record, 8, 0x0004)
            struct.pack_into('<I', record, 12, req['accid_to'])

            # Bit 28 (0x10000000) = pending, bit 31 always set
            struct.pack_into('<I', record, 16, 0x90000000)

            # Resolve target charname from accid
            target_chars = db_query(
                "SELECT charname FROM chars WHERE accid = %s LIMIT 1",
                (req['accid_to'],)
            )
            target_name = target_chars[0]['charname'] if target_chars else f"Acct{req['accid_to']}"
            cn = target_name.encode('ascii', errors='replace')[:15]
            cn = cn.ljust(15, b'\x00')
            record[24:39] = cn

            # Nickname
            nick = req.get('nickname', target_name)
            if isinstance(nick, str):
                nick = nick.encode('ascii', errors='replace')[:15]
            nick = nick.ljust(15, b'\x00')
            record[40:55] = nick

            log(f"  OutgoingRecord[{k}]: idx={idx} to={req['accid_to']} char='{target_name}'", self.conn_id)
            all_records += record

        # Incoming pending requests are NOT sent as friend records.
        # They appear as "Let's be friends!" messages in the Messages table
        # via the CallerC notification mechanism.

        # Send 8B control header
        header = bytearray(8)
        header[0] = num_records
        log(f"  FriendRecords: {num_records} record(s), header={bytes(header).hex()}", self.conn_id)
        self.send_data("ControlHeader", bytes(header))

        # Send all record data
        if num_records > 0:
            self.send_data("FriendRecords", bytes(all_records))

        # Mode 7 confirmation: 4 zero bytes
        # polcore +0x1FAD0 reads 4 bytes, compares against desc+0x10 (0).
        # Match -> success -> triggers post-processing that copies +0x403080 -> +0xB40D8
        self.send_data("Mode7Confirm", bytes(4))

    def send_befriend_response(self, target_accid=None, target_charname=None,
                                nickname=None, insert_friend=False,
                                friend_index=None):
        """Send BefriendResponse: native 184B (8B header + 168B record + 8B trailer).

        Wire shape matches retail (`docs/profile-server/ffxi_friend_list_protocol.md`).
        Bytes are plaintext (no XOR encoding) because polcore's BefriendRequest
        pumper at pol+0x24170 streams the response through a running-sum
        checksum at desc+0x10 -- XOR encoding would inflate the sum and the
        trailer comparison at case 12 / case 13 would fail with -0x140f
        (which propagates as op[4]=5, "Failed to send reply. (5)").

        polcore reads (FUN_045a4170):
          case 9:  8B header   via FUN_0459fab0 mode 0  (sum updates desc+0x10)
          case 11: N*168 records via FUN_0459f800 mode 0 (sum updates desc+0x10)
          case 12: 8B trailer  via FUN_0459f800 mode 1
                   verifies (running_sum + sum(trailer[0:4])) == trailer[4:8]

        Record processing (case 11 inner loop, FUN_045a4170 case 0xb):
          record[+10] gates whether polcore mutates its internal friend table
          (DAT_046340D8 = polcore+0xB40D8 -- same table CallerB Mode 7
          post-processing copies into) from this record.
            =1: skip (used for BefriendRequest initiate-side, where the request
                is queued server-side and no local friendship exists yet)
            =0: process. record[0..3]&0xf selects the operation:
                  1 = ONLINE add: writes charname (record[24..38]) + a hash
                      derived from FUN_04599D40(record[16],record[20]) into the
                      friend slot indexed by record[8] (range 0..199 if
                      record[0]&0x10==0, else 0..99 from a second table)
                  2 = OFFLINE: clears the online bit on the existing slot
            For the accept path we want polcore to insert the new friend
            inline so the friend list refreshes without a full CallerB re-pump
            (matches retail -- the BefriendResponse 184B carries the friend
            record).
        """
        BEFRIEND_HDR_SIZE = 8
        BEFRIEND_REC_SIZE = 168
        BEFRIEND_TRL_SIZE = 8

        # CONTROLLED EXPERIMENT (task #61): send N=1 record with the
        # SKIP-PROCESSING flag set (record[+10] = 1). This satisfies polcore's
        # FUN_045a4170 case 11 read alignment (need real bytes; N=0 hits the
        # 0-byte recv -> -8 graceful-close path) while telling polcore NOT to
        # mutate its friend table from this record. The accept SM still
        # advances to case 13 success (state=13 result=1), all FFXi accept
        # ops 0-7 complete, and we observe whether a CharB entry still
        # appears in the friend list:
        #   - If it appears with the user-typed nickname: polcore inserts the
        #     friend natively from local state during the accept SM (the
        #     nickname it embedded in BefriendExtra at offset 40 is also
        #     stored in polcore-side memory and committed on success).
        #   - If no entry appears: polcore relies on a server-provided record
        #     for the insert; we'd need to switch back to N=1 with insert
        #     flag and find why retail's encoded record produces the nickname
        #     entry rather than charname.
        #
        # Either way, the experiment narrows down where the duplicate came
        # from in our previous N=1+insert runs.
        header = bytearray(BEFRIEND_HDR_SIZE)
        header[0] = 1

        record = bytearray(BEFRIEND_REC_SIZE)
        record[10] = 1  # skip -- polcore won't mutate friend table from this

        running = bytes(header) + bytes(record) + b'\x00\x00\x00\x00'
        checksum = 0
        for i in range(0, len(running), 4):
            checksum = (checksum + struct.unpack_from('<I', running, i)[0]) & 0xFFFFFFFF

        trailer = bytearray(BEFRIEND_TRL_SIZE)
        struct.pack_into('<I', trailer, 4, checksum)

        body = bytes(header) + bytes(record) + bytes(trailer)
        self.send_data("BefriendResponse", body)
        _ = (insert_friend, friend_index, target_accid, target_charname, nickname)

    # ========================================================================
    # Logging
    # ========================================================================

    def save_log(self):
        """Save packet log to file."""
        if not self.packet_log:
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        acct = self.account_id[:2].hex() if self.account_id else "unknown"
        fname = f"{ts}_{acct}_{self.addr[1]}.json"
        fpath = os.path.join(LOG_DIR, fname)

        log_data = {
            "conn_id": self.conn_id,
            "cred_account_id": self.cred_account_id,
            "cred_session_hash": self.cred_session_hash.hex(),
            "account_id": self.account_id.hex() if self.account_id else None,
            "token": self.token.hex() if self.token else None,
            "mask": self.mask.hex() if self.mask else None,
            "ack_counter": self.ack_counter,
            "packets": self.packet_log,
        }

        with open(fpath, 'w') as f:
            json.dump(log_data, f, indent=2)
        log(f"Log saved: {fpath}", self.conn_id)


# ============================================================================
# Server
# ============================================================================

def run_server():
    """Main server loop."""
    global g_ack_counter

    listeners = []
    for port in (LISTEN_PORT,) + tuple(EXTRA_LISTEN_PORTS):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(('0.0.0.0', port))
        except OSError as e:
            log(f"Could not bind port {port}: {e}")
            srv.close()
            continue
        srv.listen(5)
        listeners.append(srv)
    if not listeners:
        raise SystemExit("no listening ports available")
    server = listeners[0]

    log(f"Profile server listening on port(s) "
        f"{', '.join(str(l.getsockname()[1]) for l in listeners)}")
    log(f"Server IP for AuthConfirm: {SERVER_IP} ({SERVER_IP_LE.hex()})")
    log(f"AuthConfirm XOR'd IP bytes[8:12]: {AUTH_CONFIRM_XORED_IP.hex()}")
    log(f"ACK counter starting at 0x{g_ack_counter:08X} (Unix timestamp)")


    try:
        while True:
            ready, _, _ = select.select(listeners, [], [], 1.0)
            if not ready:
                continue
            conn, addr = ready[0].accept()
            local_port = ready[0].getsockname()[1]
            ack = g_ack_counter
            g_ack_counter += 1

            log(f"New connection from {addr[0]}:{addr[1]} -> :{local_port} "
                f"(ACK=0x{ack:08X})")

            # The POL push channel speaks a CR-terminated ASCII protocol, not
            # the binary Init/Auth/Data one. Routing it through
            # FriendConnection makes the server sit waiting for a 40-byte Auth
            # that never comes, and the 30s timeout close drives polcore's
            # router into its error state.
            if local_port in POL_PUSH_PORTS:
                t = threading.Thread(
                    target=lambda c, a: PolPushConnection(c, a).run(),
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
                continue

            # Handle in a thread for concurrent connections
            t = threading.Thread(
                target=lambda c, a, ak: FriendConnection(c, a, ak).run(),
                args=(conn, addr, ack),
                daemon=True,
            )
            t.start()

    except KeyboardInterrupt:
        log("Server shutting down")
    finally:
        for l in listeners:
            l.close()



POL_PUSH_PORTS = frozenset(EXTRA_LISTEN_PORTS)


class PolPushConnection:
    """POL push channel (pp service, port 51240).

    Line protocol: each message is ASCII terminated by CR (0x0D). Captured
    2026-08-23, the first packet polcore has ever sent on this channel:

        "1uOIiP8GbLDx3KizGeuKkggJxf@Tdk7HT55ZokR<CR>"

    polcore builds every op on this channel with a vsnprintf-style formatter
    (FUN_10012420) against format strings in .rdata, so the payloads are
    formatted text rather than packed structs.

    This handler does not yet answer: the op-2 reply format is still unknown,
    and guessing risks driving the SM somewhere worse. It captures and holds.
    Do NOT let it close the socket on idle -- polcore treats the close as a
    connection error and tears the router down to state 0x20.
    """

    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.tag = f"{addr[0]}:{addr[1]}"
        self.lines = []
        self.nick = None
        self._status = {}
        self._stamp = 0
        self._last_poll = 0.0
        # Set from the proxy's PASS line; see dispatch().
        self._account_id = None
        self._registered = False
        self._pass_time  = 0.0

    def run(self):
        peer = self.tag
        log(f"[{peer}] POL PUSH channel opened (ASCII line protocol), "
            f"account=pending")
        buf = bytearray()
        try:
            self.conn.settimeout(1.0)
            start = time.time()
            while time.time() - start < POL_PUSH_HOLD_SECONDS:
                self.drain_inject()
                self.poll_status()
                try:
                    chunk = self.conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError as exc:
                    log(f"[{peer}] POL PUSH recv error: {exc}")
                    break
                if not chunk:
                    log(f"[{peer}] POL PUSH closed by client")
                    break
                buf += chunk
                log(f"[{peer}] POL PUSH C->S {len(chunk)}B:")
                hex_dump(chunk, prefix="  ")
                while POL_PUSH_EOL in buf:
                    line, _, rest = buf.partition(POL_PUSH_EOL)
                    buf = bytearray(rest)
                    text = line.decode("latin-1").lstrip(POL_PUSH_LF)
                    if not text:
                        continue
                    self.lines.append(text)
                    log(f"[{peer}]   LINE[{len(self.lines) - 1}] ({len(line)}B): {text!r}")
                    self.dispatch(text)


        finally:
            log(f"[{peer}] POL PUSH channel done, {len(self.lines)} line(s) captured")
            try:
                self.conn.close()
            except OSError:
                pass

    def drain_inject(self):
        """Send any lines dropped into POL_PUSH_INJECT, then truncate it.

        Lets IRC messages be probed against a live registered channel without
        relaunching the client, which otherwise costs a full login cycle.
        """
        try:
            if not os.path.exists(POL_PUSH_INJECT):
                return
            with open(POL_PUSH_INJECT, "r", encoding="latin-1") as fh:
                lines = [l.rstrip(POL_PUSH_EOL_STR) for l in fh if l.strip()]
            open(POL_PUSH_INJECT, "w").close()
        except OSError:
            return
        for line in lines:
            self.send(line)

    def send(self, text):
        # polcore terminates its own lines with a bare CR, so match it rather
        # than sending CRLF.
        data = (text + POL_PUSH_EOL_STR).encode("latin-1")
        log(f"[{self.tag}] POL PUSH S->C: {text!r}")
        try:
            self.conn.sendall(data)
        except OSError as exc:
            log(f"[{self.tag}] POL PUSH send failed: {exc}")

    def poll_status(self):
        """Emit a status NOTICE whenever anything in a friend's record changes.

        polcore only learns about online/offline transitions through this
        channel; friend_status does not carry the online field.
        """
        # Only the account binding is required.
        #
        # Do NOT also wait for USER. The proxy keeps the client socket alive
        # across a server restart, so polcore never sees a disconnect and never
        # re-registers -- a restarted server gets PASS (the proxy re-sends it)
        # but no USER, and waiting for one meant the poller never ran again.
        # The NOTICE target is POL_STATUS_TARGET_NICK regardless, so the
        # client's own nick was never needed here.
        #
        # No fallback binding on purpose: without a PASS we do not know whose
        # friends these are, and pushing the wrong list is worse than pushing
        # nothing. An unbound channel simply stays idle.
        if self._account_id is None:
            return

        # A NOTICE sent before registration completes is DISCARDED by polcore --
        # its dispatcher only applies records once the handshake reaches the
        # complete sub-state. PASS arrives first, so pushing on the binding
        # alone races the NICK/USER that follows microseconds later.
        #
        # On a proxy reconnect there is no second registration to wait for (the
        # client socket never dropped, so polcore never re-registers), hence the
        # grace period rather than a hard requirement.
        now = time.time()
        if not self._registered and (now - self._pass_time) < POL_PUSH_REG_GRACE_SECONDS:
            return
        if now - self._last_poll < POL_STATUS_POLL_SECONDS:
            return
        self._last_poll = now

        try:
            friends = get_friends_for_account(self._account_id)
        except Exception as exc:
            log(f"[{self.tag}] POL PUSH friend lookup failed: {exc}")
            return

        # No IV needed. The client stores identity = accid ^ IV
        # (FUN_10019D40 is just XOR with the filename IV), and the record's
        # first 8 bytes decrypt as raw ^ KEY ^ IV. Encoding raw = accid ^ KEY
        # therefore yields accid ^ IV -- exactly what is stored -- for ANY IV,
        # so the server never has to know it.

        # A status push is addressed by friend INDEX, so it is dropped if the
        # client's friend array has no such slot yet. When a friendship is
        # created mid-session the push races the client's friend_status
        # refresh and loses -- and the cache then reads 'already ONLINE', so
        # nothing is re-announced and the friend shows offline indefinitely.
        # Reset the cache whenever the friend set changes.
        current_ids = tuple(sorted(
            (f.get('accid') or f.get('accid_target') or 0) for f in friends))
        if current_ids != getattr(self, '_friend_ids', None):
            if getattr(self, '_friend_ids', None) is not None:
                log(f'[{self.tag}] POL PUSH friend set changed -- re-announcing')
            self._friend_ids = current_ids
            self._status = {}

        for i, f in enumerate(friends[:63]):
            index = i + 1               # slot 0 is self; matches CallerB
            accid = f.get('accid') or f.get('accid_target')
            if accid is None:
                continue
            online   = bool(f.get('online'))
            zone     = f.get('zone_id') or 0
            charname = f.get('charname') or ''
            nickname = f.get('nickname') or charname

            # Track EVERY field the pushed record carries, not just the online
            # bit. None of zone, character, or nickname changes that bit, so
            # keying on it alone emitted no NOTICE at all for those -- the list
            # kept showing whatever was true when the friend last came online.
            # charname follows the session's charid, so switching characters on
            # one account changes it while the account stays online.
            away     = bool(f.get('away'))
            state = (online, zone if online else 0, charname, nickname, away)
            if self._status.get(index) == state:
                continue
            self._status[index] = state
            # Always announce, including the first observation.
            #
            # Silently seeding here was wrong: the client's own state comes
            # from the CallerB snapshot taken at ITS login, so a friend who
            # came online after that is already stale by the time this channel
            # opens. Seeding captured "online" and suppressed the very update
            # that would have corrected it, leaving the friend shown offline
            # indefinitely. Pushing the current state on open is idempotent --
            # the record carries everything -- so re-announcing is harmless.
            # Must be strictly newer than the pair polcore already stored for
            # this friend, or the update is silently ignored. Use wall-clock
            # seconds so it also beats stamps left by a previous run, and keep
            # it monotonic within the session.
            self._stamp = max(self._stamp + 1, int(time.time()))
            # Rich (branch B) record: carries the character name, zone and
            # the sub-entry the in-game render predicate needs, not just the
            # online bit. The plain build_status_notice sets only the bit
            # fields, which renders the friend online but with no name, zone
            # or XI icon -- everything else came from the CallerB snapshot
            # taken at OUR login, which never refreshes.
            if online:
                payload = build_status_notice_rich(
                    index, online, accid, f.get('nickname') or f.get('charname') or '',
                    f.get('zone_id') or 0,
                    ts=self._stamp,
                    dispname=f.get('charname') or '',
                    away=away)
            else:
                # Branch A for offline. The rich (branch B) record does NOT
                # clear the online bits -- Array2 entry+0x08 stays at the
                # online value -- because branch B routes through FUN_100250F0
                # (name/zone/sub-entry) rather than FUN_1001ECB0, which is what
                # actually writes bits 13-15. An offline row needs no name or
                # zone anyway.
                payload = build_status_notice(
                    index, online, accid,
                    ts_hi=self._stamp, ts_lo=self._stamp)
            self.send(f":{POL_IRC_HOST} NOTICE {POL_STATUS_TARGET_NICK} :{payload}")
            state = 'OFFLINE' if not online else ('AWAY' if away else 'ONLINE')
            log(f"[{self.tag}] POL PUSH status: friend index {index} "
                f"(accid {accid}) -> {state}")

    def dispatch(self, text):
        parts = text.split(" ")
        cmd = parts[0].upper() if parts else ""

        if cmd == "PASS":
            # xiloader's proxy states which account this channel belongs to:
            #     PASS acct:<accid>
            # The channel itself carries no identity -- polcore's USER realname
            # is 32 bytes of opaque per-connection session material -- and the
            # proxy is the only party that knows, since it runs inside the
            # client process. Deterministic; no guessing from timing.
            arg = parts[1] if len(parts) > 1 else ""
            if arg.startswith("acct:"):
                try:
                    self._account_id = int(arg[5:])
                    self._pass_time = time.time()
                    log(f"[{self.tag}] POL PUSH bound to account {self._account_id} (PASS)")
                except ValueError:
                    log(f"[{self.tag}] POL PUSH bad PASS identity: {arg!r}")
            return

        if cmd == "NICK" and len(parts) > 1:
            self.nick = parts[1]
            return

        if cmd == "USER":
            # polcore sends USER before NICK and carries its session token in
            # the realname field. Standard IRC registration completes with the
            # 001-004 numerics, so answer those and let it proceed.
            if self.nick is None:
                self.nick = parts[1] if len(parts) > 1 else "x"
            self.send(f":{POL_IRC_HOST} 001 {self.nick} :Welcome to the POL network {self.nick}")
            self.send(f":{POL_IRC_HOST} 002 {self.nick} :Your host is {POL_IRC_HOST}, running version POL1.0")
            self.send(f":{POL_IRC_HOST} 003 {self.nick} :This server was created today")
            self.send(f":{POL_IRC_HOST} 004 {self.nick} {POL_IRC_HOST} POL1.0 aiwroOs aiwabeiIklmnostv")
            # pol_irc_recv_dispatch (polcore+0x15E80) drives the handshake off
            # IRC numerics:
            #   300 while sub-state 8 -> derives the session key from the 3rd
            #       token (46 chars) and sets conn+0x209 |= 0x44, which unlocks
            #       op 0x28 AND switches sends to the encrypted path.
            #   422 -> sub-state 0xC = complete; the push SM returns 1 and the
            #       router leaves 0x17.
            #   433 -> error 0xB.  Any other numeric >399 -> error 0xE.
            # 422 alone completes the handshake in PLAINTEXT, because only 300
            # sets the encryption bit. Do that first; adding 300 means
            # implementing polcore's key derivation server-side.
            self.send(f":{POL_IRC_HOST} 422 {self.nick} :MOTD File is missing")
            self._registered = True
            return

        if cmd == "PING":
            arg = parts[1] if len(parts) > 1 else POL_IRC_HOST
            self.send(f":{POL_IRC_HOST} PONG {POL_IRC_HOST} {arg}")
            return

        if cmd == "QUIT":
            log(f"[{self.tag}] POL PUSH client sent QUIT")
            return

        log(f"[{self.tag}] POL PUSH unhandled command: {cmd!r}")


if __name__ == "__main__":
    run_server()
