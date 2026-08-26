addon.name    = 'fdiag'
addon.author  = '9001-Solutions'
addon.version = '1.0'
addon.desc    = 'Friend system diagnostic — dumps polcore + FFXiMain handoff state'
addon.link    = 'https://ashitaxi.com/'

require('common')
local ffi = require('ffi')
local fonts = require('fonts')

ffi.cdef[[
    uint32_t GetModuleHandleA(const char* name);
    int IsBadReadPtr(const void* lp, uint32_t ucb);
    int IsBadWritePtr(void* lp, uint32_t ucb);
    void* VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
    int VirtualProtect(void* addr, uint32_t size, uint32_t newProt, uint32_t* oldProt);

    // Winsock structs
    typedef struct { uint32_t fd_count; uint32_t fd_array[64]; } fd_set_t;
    typedef struct { long tv_sec; long tv_usec; } timeval_t;
    // Winsock functions (loaded from ws2_32.dll)
    int __stdcall select(int nfds, fd_set_t* readfds, fd_set_t* writefds, fd_set_t* exceptfds, timeval_t* timeout);
    int __stdcall getpeername(uint32_t s, uint8_t* name, int* namelen);
    int __stdcall getsockname(uint32_t s, uint8_t* name, int* namelen);
    int __stdcall WSAGetLastError();
    uint32_t __stdcall socket(int af, int type, int protocol);
    int __stdcall connect(uint32_t s, const uint8_t* name, int namelen);
    int __stdcall closesocket(uint32_t s);
    int __stdcall bind(uint32_t s, const uint8_t* name, int namelen);

    // Thread creation
    typedef uint32_t (__stdcall *THREAD_START_ROUTINE)(void*);
    void* __stdcall CreateThread(void* lpSecurityAttributes, uint32_t dwStackSize,
        THREAD_START_ROUTINE lpStartAddress, void* lpParameter,
        uint32_t dwCreationFlags, uint32_t* lpThreadId);
]]

local ws2 = ffi.load('ws2_32')

-- Print capture for HTTP mode
local _orig_print = print
local _capture_mode = false
local _capture_lines = {}

print = function(...)
    local parts = {}
    for i = 1, select('#', ...) do
        parts[i] = tostring(select(i, ...))
    end
    local line = table.concat(parts, '\t')
    if _capture_mode then
        table.insert(_capture_lines, line)
    else
        _orig_print(line)
    end
end

-- Forward declarations
local dispatch_fdiag
local handle_http

-- HTTP server state
local socket_ok, lsocket = pcall(require, 'socket')
local http_server = nil
local http_clients = {}
-- Base port. Multiple clients can run at once (CharA + CharB), and each
-- needs its own listener, so fall forward until one binds: 18780, 18781, ...
-- The chosen port is printed at startup.
local HTTP_PORT_BASE  = 18780
local HTTP_PORT_TRIES = 4
local HTTP_PORT = HTTP_PORT_BASE

-- Helper: hex dump a memory region
local function hexdump(ptr, len, label)
    local lines = {}
    table.insert(lines, ('=== %s (%d bytes at 0x%08X) ==='):format(label, len, tonumber(ffi.cast('uint32_t', ptr))))
    local p = ffi.cast('uint8_t*', ptr)
    for off = 0, len - 1, 16 do
        local hex = {}
        local ascii = {}
        for i = 0, 15 do
            if off + i < len then
                table.insert(hex, ('%02X'):format(p[off + i]))
                local b = p[off + i]
                table.insert(ascii, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
            else
                table.insert(hex, '  ')
                table.insert(ascii, ' ')
            end
        end
        table.insert(lines, ('  %04X: %s  %s'):format(off, table.concat(hex, ' '), table.concat(ascii)))
    end
    return lines
end

-- Helper: print lines to chat
local function output(lines)
    for _, line in ipairs(lines) do
        print(line)
    end
end

-- Helper: find pattern in module (simple byte scan)
local function find_pattern(base, size, pattern, mask)
    local p = ffi.cast('uint8_t*', base)
    local plen = #pattern
    for i = 0, size - plen do
        local match = true
        for j = 0, plen - 1 do
            if mask:sub(j+1, j+1) == 'x' then
                if p[i + j] ~= pattern:byte(j+1) then
                    match = false
                    break
                end
            end
        end
        if match then
            return tonumber(ffi.cast('uint32_t', p + i))
        end
    end
    return nil
end

-- Get section info from PE header
local function get_sections(base_n)
    local dos = ffi.cast('uint8_t*', base_n)
    local pe_off = ffi.cast('uint32_t*', dos + 0x3C)[0]
    local pe = dos + pe_off
    local num_sec = ffi.cast('uint16_t*', pe + 6)[0]
    local opt_size = ffi.cast('uint16_t*', pe + 20)[0]
    local sec_hdr = pe + 24 + opt_size

    local sections = {}
    for i = 0, num_sec - 1 do
        local sec = sec_hdr + i * 40
        local name = ffi.string(sec, 8):gsub('%z', '')
        local vsize = ffi.cast('uint32_t*', sec + 8)[0]
        local rva = ffi.cast('uint32_t*', sec + 12)[0]
        table.insert(sections, {name = name, rva = rva, vsize = vsize})
    end
    return sections
end

-- Find polConnection using the known pattern from xiloader
local function find_pol_connection(polcore_base)
    local sections = get_sections(polcore_base)
    -- Pattern: 81 C6 38 03 00 00 83 C4 04 81 FE
    -- The polconn address is at (match - 10), reading a DWORD
    local pat = '\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE'
    local mask = 'xxxxxxxxxxx'

    for _, sec in ipairs(sections) do
        if sec.name == '.text' or sec.name == 'CODE' then
            local addr = find_pattern(polcore_base + sec.rva, sec.vsize, pat, mask)
            if addr then
                -- polconn ptr = *(DWORD*)(addr - 10)
                local polconn_ptr = ffi.cast('uint32_t*', addr - 10)[0]
                return polconn_ptr, addr
            end
        end
    end
    return nil
end

-- Find g_auth_mode address by scanning polcore .text
-- Pattern: CMP DWORD [addr], 0x02; JNE +0x39; MOV BYTE [EDI], 0x02
-- Bytes:   83 3D [4B addr] 02 75 39 C6 07 02
local function find_auth_mode_addr(polcore_base)
    local sections = get_sections(polcore_base)
    -- Pattern: CMP DWORD [addr], 0x02; JNE/JMP +0x39; MOV BYTE [EDI], 0x02
    -- After xiloader patches JNE(0x75)->JMP(0xEB), must match both opcodes
    for _, jcc in ipairs({'\x75', '\xEB'}) do
        local pat = '\x83\x3D\x00\x00\x00\x00\x02' .. jcc .. '\x39\xC6\x07\x02'
        local mask = 'xx????xxxxxx'
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local addr = find_pattern(polcore_base + sec.rva, sec.vsize, pat, mask)
                if addr then
                    local mode_addr = ffi.cast('uint32_t*', addr + 2)[0]
                    return mode_addr, addr
                end
            end
        end
    end
    return nil
end

-- Find the profile server port addresses (to see what port polcore uses)
local function find_profile_port(polcore_base)
    local sections = get_sections(polcore_base)
    -- Pattern: 66 C7 46 26 14 C8 88 46 09 8D 46 24
    local pat = '\x66\xC7\x46\x26\x14\xC8\x88\x46\x09\x8D\x46\x24'
    local mask = 'xxxxxxxxxxxx'

    for _, sec in ipairs(sections) do
        if sec.name == '.text' or sec.name == 'CODE' then
            local addr = find_pattern(polcore_base + sec.rva, sec.vsize, pat, mask)
            if addr then
                -- Port value at addr+4 (2 bytes)
                local port = ffi.cast('uint16_t*', addr + 4)[0]
                return port, addr
            end
        end
    end
    return nil
end

-- Watch state (must be before command handler closure)
local watch_active = false
local watch_last_val = 0
local watch_last_cmgr = 0
local watch_tick = 0
local watch_last_slots = {0, 0, 0}

-- Handle render state
local handle_render_active = false
local handle_font = nil

-- Gate keeper state: per-frame direct-write of Store 3 gate/marker bytes
local gate_keeper_active = false

-- Pump state: drive a connection slot from d3d_present
local pump_active = false
local pump_driver_addr = 0  -- +0x1E5D0 (connection driver function)
local pump_slot = -1
local pump_count = 0
local pump_max = 600  -- max frames (10 seconds at 60fps)
local pump_last_mode = -1
local pump_last_state = -1

-- Keepalive state: periodic CallerB refresh
local keepalive_active = false
local keepalive_interval = 30   -- seconds between refreshes
local keepalive_frame_count = 0 -- frame counter since last refresh
local keepalive_busy = false    -- true while a CallerB pump is in progress

dispatch_fdiag = function(args)
    local cmd = args[2] or 'all'

    if cmd == 'help' then
        print('[fdiag] Commands:')
        print('  /fdiag all      - dump everything')
        print('  /fdiag desc     - dump connection descriptor array (18 slots)')
        print('  /fdiag enable N - enable descriptor slot N (+0xDE=1)')
        print('  /fdiag clone S D [mode] - copy host from slot S to D, set mode (default 0x08)')
        print('  /fdiag dumpslot N - hex dump full slot N (824 bytes)')
        print('  /fdiag polconn  - dump polConnection object')
        print('  /fdiag modetbl  - dump FFXiMain mode table')
        print('  /fdiag friend   - dump friend manager (base+0x51E880)')
        print('  /fdiag connmgr  - dump connection manager (base+0x3CDC28)')
        print('  /fdiag polcore  - dump polcore sections/globals')
        print('  /fdiag authdata - show g_auth_mode and mask data')
        print('  /fdiag patch    - set g_auth_mode=1 (healthy) + write mask bytes')
        print('  /fdiag unpatch  - restore g_auth_mode=2 (degraded)')
        print('  /fdiag scan     - scan polcore for Auth-related patterns')
        print('  /fdiag watch    - poll friend manager, report changes')
        print('  /fdiag watch stop - stop watching')
        print('  /fdiag scanvt   - scan .data for friend manager vtable')
        print('  /fdiag friendwide - dump wider region around friend manager addr')
        print('  /fdiag scanauth - broad search polcore for auth mode code')
        print('  /fdiag patchauth2 - patch instance #2 of degraded mode setter')
        print('  /fdiag scanrefs - find all refs to g_auth_mode block')
        print('  /fdiag authblock - raw hex dump of g_auth_mode 48B block')
        print('  /fdiag setbyte OFF VAL - write byte at g_auth_mode+OFF')
        print('  /fdiag setglobals [v1 v2] - dump/set auth builder globals')
        print('  /fdiag patchlogin - install cave that calls CallerA+B+C')
        print('  /fdiag readcave [addr] - read cave diagnostic values')
        print('  /fdiag readabs ADDR [len] - hex dump absolute memory address')
        print('  /fdiag writeabs ADDR B1 [B2..] - write bytes at absolute address')
        print('  /fdiag callA/callB/callC - directly invoke caller functions')
        print('  /fdiag patchconnect - patch create_connect to use slot sockaddr')
        print('  /fdiag patchconnect2 - extended: sockaddr fix + WSAEWOULDBLOCK handling')
        print('  /fdiag unpatchconnect - restore original bytes at +0x10482')
        print('  /fdiag bfctx [N]    - structured BF context dump (P-array, S-box, OFB)')
        print('  /fdiag bfinit N [key] - call BF_init_key for slot N (allocs S-box if needed)')
        print('  /fdiag pumpcaller b|c [crypto] - pump CallerB/C (crypto: init BF key)')
        print('  /fdiag keepalive [secs|stop]   - periodic CallerB refresh (default 30s)')
        print('  /fdiag activateflist - activate flistmai menu (enables /flist command)')
        print('  /fdiag flistdiag    - comprehensive /flist prerequisites check')
        return
    end

    -- Get module bases
    local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
    local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))

    if polcore_base == 0 then
        print('[fdiag] polcore.dll not loaded!')
        return
    end
    if ffximain_base == 0 then
        print('[fdiag] FFXiMain.dll not loaded!')
        return
    end

    print(('[fdiag] polcore.dll base: 0x%08X'):format(polcore_base))
    print(('[fdiag] FFXiMain.dll base: 0x%08X'):format(ffximain_base))

    -----------------------------------------------------------------
    -- POLCONN: Dump the polConnection object
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'polconn' then
        local polconn_addr, pat_addr = find_pol_connection(polcore_base)
        if not polconn_addr then
            print('[fdiag] Could not find polConnection pattern!')
        else
            print(('[fdiag] polConnection at 0x%08X (pattern at 0x%08X)'):format(polconn_addr, pat_addr))

            if ffi.C.IsBadReadPtr(ffi.cast('void*', polconn_addr), 0x68) == 0 then
                -- Dump all 0x68 bytes
                output(hexdump(polconn_addr, 0x68, 'polConnection'))

                -- Check enc buffer pointer at +0x48
                local enc_ptr = ffi.cast('uint32_t*', polconn_addr + 0x48)[0]
                if enc_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', enc_ptr), 64) == 0 then
                    output(hexdump(enc_ptr, 64, 'polConn enc buffer (+0x48 ptr, first 64B)'))
                else
                    print(('[fdiag] enc buffer ptr at +0x48 = 0x%08X (NULL or unreadable)'):format(enc_ptr))
                end

                -- Summarize non-zero regions
                local p = ffi.cast('uint8_t*', polconn_addr)
                local nonzero = {}
                for i = 0, 0x67 do
                    if p[i] ~= 0 then
                        table.insert(nonzero, ('[+0x%02X]=0x%02X'):format(i, p[i]))
                    end
                end
                if #nonzero > 0 then
                    print('[fdiag] Non-zero polConn bytes: ' .. table.concat(nonzero, ', '))
                else
                    print('[fdiag] polConnection is ALL ZEROS (except maybe enc ptr)')
                end
            else
                print('[fdiag] polConnection address not readable!')
            end
        end
    end

    -----------------------------------------------------------------
    -- MODETBL: Dump FFXiMain mode table
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'modetbl' then
        local table_off = 0x377930
        local table_addr = ffximain_base + table_off
        print(('[fdiag] Mode table at 0x%08X (base+0x%06X)'):format(table_addr, table_off))

        if ffi.C.IsBadReadPtr(ffi.cast('void*', table_addr), 56) == 0 then
            local p = ffi.cast('uint8_t*', table_addr)
            print('[fdiag] Mode table entries (14 x 4B):')
            for i = 0, 13 do
                local mode = p[i*4]
                local ctype = p[i*4+1]
                local b2 = p[i*4+2]
                local b3 = p[i*4+3]
                local mode_str = ''
                if mode == 0x33 then mode_str = ' (retail)'
                elseif mode == 0x02 then mode_str = ' (degraded)'
                elseif mode == 0x0B then mode_str = ' (special)'
                elseif mode == 0x00 then mode_str = ' (null)'
                end
                print(('  [%2d] mode=0x%02X%s type=0x%02X b2=0x%02X b3=0x%02X'):format(
                    i, mode, mode_str, ctype, b2, b3))
            end
        else
            print('[fdiag] Mode table not readable!')
        end
    end

    -----------------------------------------------------------------
    -- FRIEND: Dump friend connection manager
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'friend' then
        -- Friend connection manager at base + 0x64E880
        -- This was 0x0494E880 with base 0x04430000 -> offset 0x51E880
        -- But the mode table was at 0x047A7930 with base 0x04430000 -> offset 0x377930
        -- Let me try the offset derived from the absolute address
        local mgr_off = 0x51E880
        local mgr_addr = ffximain_base + mgr_off
        print(('[fdiag] Friend manager at 0x%08X (base+0x%06X)'):format(mgr_addr, mgr_off))

        if ffi.C.IsBadReadPtr(ffi.cast('void*', mgr_addr), 4) == 0 then
            -- Read the pointer stored at this global (it's a pointer to the 124-byte object)
            local obj_ptr = ffi.cast('uint32_t*', mgr_addr)[0]
            print(('[fdiag] Friend manager global value: 0x%08X'):format(obj_ptr))

            if obj_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', obj_ptr), 124) == 0 then
                output(hexdump(obj_ptr, 124, 'Friend connection manager object'))

                -- Parse known fields
                local vtable = ffi.cast('uint32_t*', obj_ptr)[0]
                local conn_ptr = ffi.cast('uint32_t*', obj_ptr + 0x08)[0]
                local entry_count = ffi.cast('uint32_t*', obj_ptr + 0x50)[0]
                local entry_arr = ffi.cast('uint32_t*', obj_ptr + 0x54)[0]
                local flags64 = ffi.cast('uint8_t*', obj_ptr + 0x64)[0]
                local flags65 = ffi.cast('uint8_t*', obj_ptr + 0x65)[0]

                print(('[fdiag]   vtable: 0x%08X'):format(vtable))
                print(('[fdiag]   conn_ptr (+0x08): 0x%08X'):format(conn_ptr))
                print(('[fdiag]   entry_count (+0x50): %d'):format(entry_count))
                print(('[fdiag]   entry_arr (+0x54): 0x%08X'):format(entry_arr))
                print(('[fdiag]   flags (+0x64): 0x%02X'):format(flags64))
                print(('[fdiag]   flags (+0x65): 0x%02X'):format(flags65))

                -- Dump sub-objects at known offsets from the global
                -- Sub-objects: 0x0494E890, 0x0494E894, 0x0494E898, 0x0494E89C, 0x0494E8A0
                -- These are at mgr_global + 0x10, +0x14, +0x18, +0x1C, +0x20
                print('[fdiag] Sub-object pointers:')
                for i, off_name in ipairs({
                    {0x10, 'sub0 (utility, 20B)'},
                    {0x14, 'sub1 (type-2, 40B)'},
                    {0x18, 'sub2 (type-2, 40B)'},
                    {0x1C, 'sub3 (type-2, 40B)'},
                    {0x20, 'sub4 (type-1, 44B)'},
                }) do
                    local sub_ptr = ffi.cast('uint32_t*', obj_ptr + off_name[1])[0]
                    print(('  +0x%02X %s: 0x%08X'):format(off_name[1], off_name[2], sub_ptr))
                    if sub_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', sub_ptr), 44) == 0 then
                        local sub_vt = ffi.cast('uint32_t*', sub_ptr)[0]
                        local sub_type = ffi.cast('uint32_t*', sub_ptr + 0x14)[0]
                        print(('    vtable=0x%08X type=%d'):format(sub_vt, sub_type))
                        -- Dump first 44 bytes of sub-object
                        output(hexdump(sub_ptr, 44, ('sub-object at +0x%02X'):format(off_name[1])))
                    end
                end
            else
                -- Maybe it's not a pointer, it's the object inline
                -- Try dumping 128 bytes from the global address itself
                if ffi.C.IsBadReadPtr(ffi.cast('void*', mgr_addr), 128) == 0 then
                    output(hexdump(mgr_addr, 128, 'Friend manager region (inline)'))
                end
            end
        else
            print('[fdiag] Friend manager address not readable!')
            -- Try alternate offsets
            for _, alt_off in ipairs({0x51E880, 0x64E880, 0x4BE880}) do
                local alt = ffximain_base + alt_off
                if ffi.C.IsBadReadPtr(ffi.cast('void*', alt), 4) == 0 then
                    local val = ffi.cast('uint32_t*', alt)[0]
                    print(('[fdiag]   base+0x%06X = 0x%08X (readable)'):format(alt_off, val))
                end
            end
        end
    end

    -----------------------------------------------------------------
    -- CONNMGR: Dump FFXiMain connection manager (slot lookup table)
    -- Global pointer at base+0x3CDC28, 18 entries × 3564B at obj+0x9860
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'connmgr' then
        local cmgr_off = 0x3CDC28
        local cmgr_addr = ffximain_base + cmgr_off
        print(('[fdiag] ConnMgr global at 0x%08X (base+0x%06X)'):format(cmgr_addr, cmgr_off))

        if ffi.C.IsBadReadPtr(ffi.cast('void*', cmgr_addr), 4) == 0 then
            local cmgr_ptr = ffi.cast('uint32_t*', cmgr_addr)[0]
            print(('[fdiag] ConnMgr pointer: 0x%08X'):format(cmgr_ptr))

            if cmgr_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', cmgr_ptr), 0x100) == 0 then
                -- Dump the header region (first 256 bytes of the object)
                output(hexdump(cmgr_ptr, 256, 'ConnMgr object header'))

                -- Check the slot table at +0x9860
                local slot_base = cmgr_ptr + 0x9860
                local slot_stride = 0x0DEC  -- 3564 bytes
                if ffi.C.IsBadReadPtr(ffi.cast('void*', slot_base), slot_stride * 4) == 0 then
                    print('[fdiag] ConnMgr slot table at +0x9860:')
                    print('[fdiag] Slot  First4B   +0x04      +0x08      +0x0C      +0x10')
                    for i = 0, 17 do
                        local entry = ffi.cast('uint32_t*', slot_base + i * slot_stride)
                        if ffi.C.IsBadReadPtr(ffi.cast('void*', entry), 32) == 0 then
                            local w0 = entry[0]
                            local w1 = entry[1]
                            local w2 = entry[2]
                            local w3 = entry[3]
                            local w4 = entry[4]
                            -- Only print non-zero entries
                            if w0 ~= 0 or w1 ~= 0 or w2 ~= 0 or w3 ~= 0 or w4 ~= 0 then
                                print(('[fdiag]  %2d   0x%08X 0x%08X 0x%08X 0x%08X 0x%08X'):format(
                                    i, w0, w1, w2, w3, w4))
                            end
                        end
                    end
                else
                    print('[fdiag] Slot table region not readable.')
                end
            else
                -- Object not allocated or zero pointer
                if cmgr_ptr == 0 then
                    print('[fdiag] ConnMgr pointer is NULL (not initialized)')
                else
                    print('[fdiag] ConnMgr object not readable')
                end
            end
        else
            print('[fdiag] ConnMgr global address not readable!')
        end
    end

    -----------------------------------------------------------------
    -- POLCORE: Scan polcore sections
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'polcore' then
        local sections = get_sections(polcore_base)
        print('[fdiag] polcore.dll sections:')
        for _, sec in ipairs(sections) do
            print(('  %s: RVA=0x%06X VSize=0x%06X'):format(sec.name, sec.rva, sec.vsize))
        end

        -- Show profile server port
        local port, port_addr = find_profile_port(polcore_base)
        if port then
            print(('[fdiag] Profile server port: %d (at 0x%08X)'):format(port, port_addr))
        end
    end

    -----------------------------------------------------------------
    -- SCAN: Search polcore for Auth-packet-related patterns
    -----------------------------------------------------------------
    if cmd == 'scan' then
        print('[fdiag] Scanning polcore .text for Auth-related patterns...')
        local sections = get_sections(polcore_base)
        local text_rva, text_size
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                text_rva = sec.rva
                text_size = sec.vsize
                break
            end
        end

        if not text_rva then
            print('[fdiag] No .text section found!')
            return
        end

        local text_ptr = ffi.cast('uint8_t*', polcore_base + text_rva)
        print(('[fdiag] .text at 0x%08X, size 0x%06X'):format(polcore_base + text_rva, text_size))

        -- Search for MOV BYTE PTR [reg+xx], 0x02 patterns near send or buffer-fill code
        -- C6 40 00 02 = mov byte ptr [eax+0], 2
        -- C6 01 02    = mov byte ptr [ecx], 2
        -- C6 00 02    = mov byte ptr [eax], 2
        -- C6 45 xx 02 = mov byte ptr [ebp+xx], 2
        -- C6 44 24 xx 02 = mov byte ptr [esp+xx], 2
        local hits = {}
        for i = 0, text_size - 4 do
            local b0 = text_ptr[i]
            if b0 == 0xC6 then
                -- mov byte ptr [reg], imm8
                local b1 = text_ptr[i+1]
                -- Check for various addressing modes where imm8 = 0x02
                if b1 == 0x00 and text_ptr[i+2] == 0x02 then
                    table.insert(hits, {addr = polcore_base + text_rva + i, desc = 'C6 00 02 (mov [eax],0x02)'})
                elseif b1 == 0x01 and text_ptr[i+2] == 0x02 then
                    table.insert(hits, {addr = polcore_base + text_rva + i, desc = 'C6 01 02 (mov [ecx],0x02)'})
                elseif b1 == 0x02 and text_ptr[i+2] == 0x02 then
                    table.insert(hits, {addr = polcore_base + text_rva + i, desc = 'C6 02 02 (mov [edx],0x02)'})
                elseif b1 == 0x03 and text_ptr[i+2] == 0x02 then
                    table.insert(hits, {addr = polcore_base + text_rva + i, desc = 'C6 03 02 (mov [ebx],0x02)'})
                elseif b1 == 0x06 and text_ptr[i+2] == 0x02 then
                    table.insert(hits, {addr = polcore_base + text_rva + i, desc = 'C6 06 02 (mov [esi],0x02)'})
                elseif b1 == 0x07 and text_ptr[i+2] == 0x02 then
                    table.insert(hits, {addr = polcore_base + text_rva + i, desc = 'C6 07 02 (mov [edi],0x02)'})
                elseif (b1 >= 0x40 and b1 <= 0x47) and text_ptr[i+3] == 0x02 then
                    -- C6 4x offset 02 = mov byte ptr [reg+offset], 0x02
                    table.insert(hits, {addr = polcore_base + text_rva + i,
                        desc = ('C6 %02X %02X 02 (mov [reg+0x%02X],0x02)'):format(b1, text_ptr[i+2], text_ptr[i+2])})
                end
            end
        end

        print(('[fdiag] Found %d "mov byte, 0x02" hits:'):format(#hits))
        local show = math.min(#hits, 40)
        for i = 1, show do
            local h = hits[i]
            -- Show context bytes
            local ctx = {}
            local base = h.addr - polcore_base - text_rva
            for j = -4, 8 do
                if base + j >= 0 and base + j < text_size then
                    table.insert(ctx, ('%02X'):format(text_ptr[base + j]))
                end
            end
            print(('  0x%08X: %s [%s]'):format(h.addr, h.desc, table.concat(ctx, ' ')))
        end
        if #hits > show then
            print(('  ... and %d more'):format(#hits - show))
        end

        -- Also search for the polConnection address reference in .text
        -- This tells us what functions READ polConnection
        local polconn_addr, _ = find_pol_connection(polcore_base)
        if polconn_addr then
            print(('[fdiag] Searching for references to polConn (0x%08X) in .text...'):format(polconn_addr))
            local polconn_bytes = {
                polconn_addr % 256,
                math.floor(polconn_addr / 256) % 256,
                math.floor(polconn_addr / 65536) % 256,
                math.floor(polconn_addr / 16777216) % 256
            }

            local refs = {}
            for i = 0, text_size - 4 do
                if text_ptr[i] == polconn_bytes[1] and
                   text_ptr[i+1] == polconn_bytes[2] and
                   text_ptr[i+2] == polconn_bytes[3] and
                   text_ptr[i+3] == polconn_bytes[4] then
                    local ref_addr = polcore_base + text_rva + i
                    local prefix = text_ptr[i-1]
                    local ctx = {}
                    for j = -6, 6 do
                        if i + j >= 0 and i + j < text_size then
                            table.insert(ctx, ('%02X'):format(text_ptr[i + j]))
                        end
                    end
                    table.insert(refs, {addr = ref_addr, ctx = table.concat(ctx, ' ')})
                end
            end
            print(('[fdiag] Found %d references to polConnection:'):format(#refs))
            for _, r in ipairs(refs) do
                print(('  0x%08X: %s'):format(r.addr, r.ctx))
            end
        end
    end

    -----------------------------------------------------------------
    -- FUNCTBL: Dump polcore function table (lpCommandTable)
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'functbl' then
        print('[fdiag] Scanning for polcore function table...')
        local sections = get_sections(polcore_base)

        local table_ptr = nil
        for _, sec in ipairs(sections) do
            if sec.name == '.data' or sec.name == '.bss' then
                local ptr = ffi.cast('uint32_t*', polcore_base + sec.rva)
                local max_idx = math.floor(sec.vsize / 4) - 0x400

                for i = 0, max_idx do
                    local val_7d = ptr[i + 0x7D]
                    local val_7c = ptr[i + 0x7C]

                    if val_7d ~= 0 and val_7c == 0 then
                        local all_zero = true
                        for j = 0, 0x7B do
                            if ptr[i + j] ~= 0 then
                                all_zero = false
                                break
                            end
                        end

                        if all_zero and ptr[i + 0x7E] ~= 0 and ptr[i + 0x7F] ~= 0 then
                            table_ptr = ffi.cast('uint32_t*', ptr + i)
                            local tbl_addr = polcore_base + sec.rva + i * 4
                            print(('[fdiag] Function table at 0x%08X (%s+0x%X)'):format(
                                tbl_addr, sec.name, i * 4))
                            break
                        end
                    end
                end
                if table_ptr then break end
            end
        end

        if table_ptr then
            -- Count and list all non-NULL entries
            local non_null = {}
            for i = 0, 0x3FF do
                local val = table_ptr[i]
                if val ~= 0 then
                    table.insert(non_null, {index = i, addr = tonumber(val)})
                end
            end

            print(('[fdiag] Non-NULL function table entries: %d / 1024'):format(#non_null))

            -- Known POLFUNC indices from xiloader
            local known = {
                [0x007D] = 'INSTALL_FOLDER',
                [0x016F] = 'REGISTRY_KEY',
                [0x01A4] = 'FFXI_LANG',
                [0x032F] = 'INET_MUTEX',
                [0x03C5] = 'REGISTRY_LANG',
                [0x00D3] = 'CHARACTER_LIST_PTR',
            }

            for _, entry in ipairs(non_null) do
                local label = known[entry.index] or ''
                if label ~= '' then label = ' (' .. label .. ')' end
                -- Check if address is in polcore .text range
                local loc = ''
                local text_start = polcore_base + 0x1000
                local text_end = text_start + 0x063BC1
                if entry.addr >= text_start and entry.addr < text_end then
                    loc = (' [polcore.text+0x%05X]'):format(entry.addr - text_start)
                end
                print(('  [0x%04X] = 0x%08X%s%s'):format(entry.index, entry.addr, loc, label))
            end
        else
            print('[fdiag] Could not find function table!')
        end
    end

    -----------------------------------------------------------------
    -- AUTHDATA: Show g_auth_mode and mask data from polcore .data
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'authdata' then
        local mode_addr, pat_found = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode pattern in polcore!')
        else
            print(('[fdiag] g_auth_mode at 0x%08X (pattern at 0x%08X)'):format(mode_addr, pat_found))

            if ffi.C.IsBadReadPtr(ffi.cast('void*', mode_addr), 48) == 0 then
                local p = ffi.cast('uint8_t*', mode_addr)
                local mode_val = ffi.cast('uint32_t*', mode_addr)[0]
                local mode_str = 'unknown'
                if mode_val == 0 then mode_str = 'CLEARED'
                elseif mode_val == 1 then mode_str = 'HEALTHY'
                elseif mode_val == 2 then mode_str = 'DEGRADED'
                end
                print(('[fdiag] g_auth_mode = %d (%s)'):format(mode_val, mode_str))

                -- Dump the full 48-byte block
                output(hexdump(mode_addr, 48, 'Auth data block (48B)'))

                -- Show the reversed mask bytes that will become Auth[1:17]
                -- Stored at mode_addr+5 through mode_addr+0x14 (reversed, NOTed)
                local mask_bytes = {}
                for i = 0, 15 do
                    local stored = p[0x14 - i]  -- read backwards from +0x14
                    if stored == 0 then break end
                    local original = bit.bxor(stored, 0xFF)  -- NOT = XOR 0xFF
                    table.insert(mask_bytes, ('%02X'):format(original))
                end
                if #mask_bytes > 0 then
                    print('[fdiag] Mask16 (will be Auth[1:17]): ' .. table.concat(mask_bytes, ' '))
                else
                    print('[fdiag] Mask16: EMPTY (all zeros)')
                end

                -- Show the forward mask bytes at mode_addr+0x15 through mode_addr+0x28
                local fwd_bytes = {}
                for i = 0, 19 do
                    local b = p[0x15 + i]
                    if b ~= 0 then
                        table.insert(fwd_bytes, ('%02X'):format(bit.bxor(b, 0xFF)))
                    end
                end
                if #fwd_bytes > 0 then
                    print('[fdiag] Mask20 (forward): ' .. table.concat(fwd_bytes, ' '))
                else
                    print('[fdiag] Mask20: EMPTY')
                end

                -- Show extra6 at mode_addr+0x29 through mode_addr+0x2E
                local extra = {}
                for i = 0, 5 do
                    local b = p[0x29 + i]
                    if b ~= 0 then
                        table.insert(extra, ('%02X'):format(b))
                    end
                end
                if #extra > 0 then
                    print('[fdiag] Extra6 (mode2 only): ' .. table.concat(extra, ' '))
                else
                    print('[fdiag] Extra6: EMPTY')
                end
            else
                print('[fdiag] g_auth_mode address not readable!')
            end
        end
    end

    -----------------------------------------------------------------
    -- PATCH: Set g_auth_mode = 1 (healthy) with character name as mask
    -- Retail uses the character name as the mask16 material.
    -----------------------------------------------------------------
    if cmd == 'patch' then
        local mode_addr, pat_found = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode pattern in polcore!')
            return
        end

        print(('[fdiag] g_auth_mode at 0x%08X'):format(mode_addr))

        if ffi.C.IsBadReadPtr(ffi.cast('void*', mode_addr), 48) ~= 0 then
            print('[fdiag] g_auth_mode address not readable!')
            return
        end

        -- Get character name from Ashita
        local party = AshitaCore:GetMemoryManager():GetParty()
        local name = party:GetMemberName(0)
        if not name or #name == 0 then
            print('[fdiag] Could not get character name! Using fallback.')
            name = 'Unknown'
        end
        print(('[fdiag] Character name: %s (%d chars)'):format(name, #name))

        -- Read current state
        local old_mode = ffi.cast('uint32_t*', mode_addr)[0]
        print(('[fdiag] Current mode: %d'):format(old_mode))

        -- Set mode = 1 (healthy)
        ffi.cast('uint32_t*', mode_addr)[0] = 1
        print('[fdiag] Set g_auth_mode = 1 (HEALTHY)')

        -- Write mask16 = character name (NOTed, reversed)
        -- Retail stores: ~name[0] at +0x14, ~name[1] at +0x13, etc.
        local p = ffi.cast('uint8_t*', mode_addr)

        -- Clear the mask area first
        for i = 0x04, 0x14 do
            p[i] = 0
        end

        -- Write name bytes NOTed and reversed
        local name_len = math.min(#name, 16)
        for i = 0, name_len - 1 do
            local b = name:byte(i + 1)
            p[0x14 - i] = bit.bxor(b, 0xFF)  -- NOT, stored reversed
        end

        -- Show what we wrote
        local mask_hex = {}
        for i = 0, name_len - 1 do
            table.insert(mask_hex, ('%02X'):format(name:byte(i + 1)))
        end
        print('[fdiag] Wrote mask16 (name): ' .. table.concat(mask_hex, ' '))

        -- Clear mask20 and extra6 (not used for mode 1, matching retail)
        for i = 0x15, 0x2F do
            p[i] = 0
        end

        -- Verify
        local new_mode = ffi.cast('uint32_t*', mode_addr)[0]
        print(('[fdiag] Verified: g_auth_mode = %d'):format(new_mode))

        -- Show expected Auth header
        local auth_hex = {'01'}
        for i = 0, name_len - 1 do
            table.insert(auth_hex, ('%02X'):format(name:byte(i + 1)))
        end
        print('[fdiag] Expected Auth[0:N]: ' .. table.concat(auth_hex, ' '))
        print('[fdiag] Takes effect on NEXT friend connection.')
    end

    -----------------------------------------------------------------
    -- UNPATCH: Restore g_auth_mode = 2 (degraded, default)
    -----------------------------------------------------------------
    if cmd == 'unpatch' then
        local mode_addr, _ = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode!')
            return
        end
        ffi.cast('uint32_t*', mode_addr)[0] = 2
        print('[fdiag] Restored g_auth_mode = 2 (degraded)')
    end

    -----------------------------------------------------------------
    -- FILE: Write full dump to file
    -----------------------------------------------------------------
    if cmd == 'file' then
        local path = 'fdiag_dump.txt'
        local f = io.open(path, 'w')
        if not f then
            print('[fdiag] Could not open ' .. path)
            return
        end

        -- Redirect print to file
        local old_print = print
        print = function(...)
            local parts = {}
            for i = 1, select('#', ...) do
                table.insert(parts, tostring(select(i, ...)))
            end
            local line = table.concat(parts, '\t')
            f:write(line .. '\n')
            old_print(...)  -- Also show in chat
        end

        -- Run all dumps
        -- Trigger each section manually
        print('[fdiag] Writing full dump to ' .. path)
        print(('[fdiag] polcore.dll base: 0x%08X'):format(polcore_base))
        print(('[fdiag] FFXiMain.dll base: 0x%08X'):format(ffximain_base))

        -- Set cmd temporarily to trigger each section
        local save_cmd = cmd
        for _, sub in ipairs({'polconn', 'modetbl', 'friend', 'polcore', 'functbl'}) do
            cmd = sub
            -- Re-execute the relevant section (ugly but functional)
            -- Instead, just call the function inline - but we can't easily since
            -- the if/elseif structure doesn't support re-entry.
            -- For now, just note this needs refactoring for file output.
        end
        cmd = save_cmd

        print = old_print
        f:close()
        print('[fdiag] Note: /fdiag file not fully implemented. Run /fdiag all and copy from chat log.')
        print('[fdiag] Or use /fdiag all > redirect from Ashita console if supported.')
    end

    -----------------------------------------------------------------
    -- DESC: Dump connection descriptor array (18 slots × 824B)
    -----------------------------------------------------------------
    if cmd == 'all' or cmd == 'desc' then
        local desc_off = 0x404AD0  -- RVA from polcore base
        local desc_base = polcore_base + desc_off
        local slot_size = 0x338  -- 824 bytes
        local num_slots = 18
        local total_size = slot_size * num_slots

        print(('[fdiag] Descriptor array at 0x%08X (polcore+0x%06X)'):format(desc_base, desc_off))

        if ffi.C.IsBadReadPtr(ffi.cast('void*', desc_base), total_size) == 0 then
            print('[fdiag] Slot  Mode  State Crypto Type  Enable Port   Socket     Buffers')
            for i = 0, num_slots - 1 do
                local slot = ffi.cast('uint8_t*', desc_base + i * slot_size)
                local mode = slot[0x08]
                local state = slot[0x09]
                local crypto = slot[0x0B]
                local ctype = slot[0x02]
                local enable = slot[0xDE]
                local port = ffi.cast('uint16_t*', slot + 0x26)[0]
                local socket_h = ffi.cast('int32_t*', slot + 0x04)[0]
                local buf3c = ffi.cast('uint32_t*', slot + 0x3C)[0]
                local buf40 = ffi.cast('uint32_t*', slot + 0x40)[0]
                local cnt44 = ffi.cast('uint32_t*', slot + 0x44)[0]
                local cnt48 = ffi.cast('uint32_t*', slot + 0x48)[0]
                local data328 = ffi.cast('uint32_t*', slot + 0x328)[0]

                local flags = {}
                if enable ~= 0 then table.insert(flags, 'ENABLED') end
                if port == 0xC814 then table.insert(flags, 'port=51220') end
                if socket_h ~= 0 and socket_h ~= -1 then table.insert(flags, 'CONNECTED') end

                print(('[fdiag]  %2d   0x%02X  0x%02X  0x%02X   0x%02X  0x%02X   %5d  0x%08X  [%s]'):format(
                    i, mode, state, crypto, ctype, enable, port, socket_h, table.concat(flags, ', ')))

                -- Show non-zero counters
                if cnt44 ~= 0 or cnt48 ~= 0 then
                    print(('[fdiag]        cnt44=0x%08X cnt48=0x%08X buf3c=0x%08X buf40=0x%08X data=0x%08X'):format(
                        cnt44, cnt48, buf3c, buf40, data328))
                end

                -- Show host address if port is set
                if port ~= 0 then
                    -- Host address at +0x24 (20B struct, first 4 bytes may be family+port, next is IP)
                    local host_bytes = {}
                    for j = 0, 19 do
                        table.insert(host_bytes, ('%02X'):format(slot[0x24 + j]))
                    end
                    print(('[fdiag]        host[+0x24]: %s'):format(table.concat(host_bytes, ' ')))
                end
            end
        else
            print('[fdiag] Descriptor array not readable at this offset!')
            -- Try finding via polConnection pattern as fallback
            local polconn_addr = find_pol_connection(polcore_base)
            if polconn_addr then
                print(('[fdiag] polConnection found at 0x%08X — try using this as array base'):format(polconn_addr))
            end
        end
    end

    -----------------------------------------------------------------
    -- ENABLE: Enable a descriptor slot by setting +0xDE=1
    -----------------------------------------------------------------
    if cmd == 'enable' then
        local slot_idx = tonumber(args[3])
        if not slot_idx then
            print('[fdiag] Usage: /fdiag enable <slot_number>')
            print('[fdiag] Run /fdiag desc first to see available slots')
            return
        end

        local desc_off = 0x404AD0
        local desc_base = polcore_base + desc_off
        local slot_size = 0x338
        local num_slots = 18

        if slot_idx < 0 or slot_idx >= num_slots then
            print('[fdiag] Slot must be 0-17')
            return
        end

        local slot = ffi.cast('uint8_t*', desc_base + slot_idx * slot_size)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', slot), slot_size) ~= 0 then
            print('[fdiag] Slot not readable!')
            return
        end

        local old_enable = slot[0xDE]
        slot[0xDE] = 1
        local mode = slot[0x08]
        local ctype = slot[0x02]
        print(('[fdiag] Slot %d: enable 0x%02X -> 0x01 (mode=0x%02X type=0x%02X)'):format(
            slot_idx, old_enable, mode, ctype))
        print('[fdiag] Will take effect on next connection attempt for this slot.')
    end

    -----------------------------------------------------------------
    -- CLONE: Copy connection config from one slot to another with buffer allocation
    -- /fdiag clone <src> <dst> [mode]
    -----------------------------------------------------------------
    if cmd == 'clone' then
        local src_idx = tonumber(args[3])
        local dst_idx = tonumber(args[4])
        local new_mode = tonumber(args[5]) or 0x02

        if not src_idx or not dst_idx then
            print('[fdiag] Usage: /fdiag clone <src_slot> <dst_slot> [mode]')
            print('[fdiag] Example: /fdiag clone 0 1     (copy slot 0 -> 1, mode=0x02)')
            print('[fdiag] Example: /fdiag clone 0 1 6   (copy slot 0 -> 1, mode=0x06)')
            return
        end

        local desc_off = 0x404AD0
        local desc_base = polcore_base + desc_off
        local slot_size = 0x338
        local num_slots = 18

        if src_idx < 0 or src_idx >= num_slots or dst_idx < 0 or dst_idx >= num_slots then
            print('[fdiag] Slots must be 0-17')
            return
        end
        if src_idx == dst_idx then
            print('[fdiag] Source and destination must differ')
            return
        end

        local src = ffi.cast('uint8_t*', desc_base + src_idx * slot_size)
        local dst = ffi.cast('uint8_t*', desc_base + dst_idx * slot_size)

        if ffi.C.IsBadReadPtr(ffi.cast('void*', src), slot_size) ~= 0 or
           ffi.C.IsBadReadPtr(ffi.cast('void*', dst), slot_size) ~= 0 then
            print('[fdiag] Slot(s) not readable!')
            return
        end

        -- Show source state
        local src_buf3c = ffi.cast('uint32_t*', src + 0x3C)[0]
        local src_buf40 = ffi.cast('uint32_t*', src + 0x40)[0]
        local src_data = ffi.cast('uint32_t*', src + 0x328)[0]
        print(('[fdiag] Source slot %d: mode=0x%02X crypto=0x%02X enable=0x%02X port=%d'):format(
            src_idx, src[0x08], src[0x0B], src[0xDE],
            ffi.cast('uint16_t*', src + 0x26)[0]))
        print(('[fdiag]   buf3c=0x%08X buf40=0x%08X data=0x%08X'):format(src_buf3c, src_buf40, src_data))

        -- Allocate buffers for the new slot
        -- Source slot layout: buf3c and buf40 are ~0x820 apart, buf40 and data are ~0xE60 apart
        -- Total allocation needed: ~0x2000 (8KB) to be safe
        local MEM_COMMIT = 0x1000
        local MEM_RESERVE = 0x2000
        local PAGE_READWRITE = 0x04
        local alloc_size = 0x4000  -- 16KB to be safe
        local mem = ffi.C.VirtualAlloc(nil, alloc_size, bit.bor(MEM_COMMIT, MEM_RESERVE), PAGE_READWRITE)
        if mem == nil then
            print('[fdiag] VirtualAlloc failed!')
            return
        end
        local mem_base = tonumber(ffi.cast('uint32_t', mem))
        print(('[fdiag] Allocated %d bytes at 0x%08X'):format(alloc_size, mem_base))

        -- Zero the allocation
        local mp = ffi.cast('uint8_t*', mem)
        for i = 0, alloc_size - 1 do mp[i] = 0 end

        -- Set up buffer pointers with same offsets as source
        local buf3c_off = 0x0000
        local buf40_off = 0x0820  -- buf40 = buf3c + 0x820 (observed from slot 0)
        local data_off  = 0x1680  -- data = buf40 + 0xE60

        -- Copy host address (+0x24, 20 bytes)
        for i = 0, 19 do
            dst[0x24 + i] = src[0x24 + i]
        end

        -- Copy crypto flag
        dst[0x0B] = src[0x0B]

        -- Set mode
        dst[0x08] = new_mode

        -- Reset state to 0
        dst[0x09] = 0x00

        -- Clear type
        dst[0x02] = 0x00

        -- Set buffer pointers
        ffi.cast('uint32_t*', dst + 0x3C)[0] = mem_base + buf3c_off
        ffi.cast('uint32_t*', dst + 0x40)[0] = mem_base + buf40_off
        ffi.cast('uint32_t*', dst + 0x328)[0] = mem_base + data_off

        -- Clear counters
        ffi.cast('uint32_t*', dst + 0x44)[0] = 0
        ffi.cast('uint32_t*', dst + 0x48)[0] = 0

        -- Set socket to invalid (-1 / 0xFFFFFFFF like slot 0 uses when not connected)
        ffi.cast('int32_t*', dst + 0x04)[0] = -1

        -- Enable the slot
        dst[0xDE] = 0x01

        -- Show result
        local dst_port = ffi.cast('uint16_t*', dst + 0x26)[0]
        print(('[fdiag] Slot %d configured:'):format(dst_idx))
        print(('[fdiag]   mode=0x%02X state=0x00 crypto=0x%02X enable=0x01 port=%d'):format(
            new_mode, dst[0x0B], dst_port))
        print(('[fdiag]   buf3c=0x%08X buf40=0x%08X data=0x%08X'):format(
            mem_base + buf3c_off, mem_base + buf40_off, mem_base + data_off))
        print('[fdiag] Watch for new connection on test server.')
    end

    -----------------------------------------------------------------
    -- DUMPSLOT: Hex dump a full descriptor slot
    -----------------------------------------------------------------
    if cmd == 'dumpslot' then
        local slot_idx = tonumber(args[3])
        if not slot_idx then
            print('[fdiag] Usage: /fdiag dumpslot <slot_number>')
            return
        end

        local desc_off = 0x404AD0
        local desc_base = polcore_base + desc_off
        local slot_size = 0x338

        if slot_idx < 0 or slot_idx >= 18 then
            print('[fdiag] Slot must be 0-17')
            return
        end

        local slot_addr = desc_base + slot_idx * slot_size
        if ffi.C.IsBadReadPtr(ffi.cast('void*', slot_addr), slot_size) ~= 0 then
            print('[fdiag] Slot not readable!')
            return
        end

        output(hexdump(slot_addr, slot_size, ('Descriptor slot %d'):format(slot_idx)))
    end

    -----------------------------------------------------------------
    -- WATCH: Poll friend manager address, report when it changes
    -- /fdiag watch [stop]
    -----------------------------------------------------------------
    if cmd == 'watch' then
        if args[3] == 'stop' then
            watch_active = false
            print('[fdiag] Watch stopped.')
            return
        end
        if watch_active then
            print('[fdiag] Watch already running. Use /fdiag watch stop')
            return
        end
        watch_active = true
        watch_last_val = 0
        watch_tick = 0
        -- Also monitor descriptor slots 1-3
        watch_last_slots = {0, 0, 0}
        print('[fdiag] Watching friend manager at base+0x51E880...')
        print('[fdiag] Will report changes. Use /fdiag watch stop to end.')
        return
    end

    -----------------------------------------------------------------
    -- SCANVT: Scan FFXiMain .data for friend manager vtable pointer
    -- vtable was at base+0x227378 in the analyzed binary
    -----------------------------------------------------------------
    if cmd == 'scanvt' then
        local vt_off = 0x227378
        local vt_addr = ffximain_base + vt_off

        -- First verify the vtable address looks valid
        if ffi.C.IsBadReadPtr(ffi.cast('void*', vt_addr), 16) == 0 then
            local vt_first = ffi.cast('uint32_t*', vt_addr)[0]
            print(('[fdiag] Vtable candidate at base+0x%06X = 0x%08X'):format(vt_off, vt_addr))
            print(('[fdiag]   First entry: 0x%08X'):format(vt_first))
            -- Valid vtable should point to .text section
            if vt_first > ffximain_base and vt_first < ffximain_base + 0x800000 then
                print('[fdiag]   Looks like valid vtable (points to .text)')
            else
                print('[fdiag]   May not be valid vtable')
            end
        else
            print(('[fdiag] Vtable at base+0x227378 not readable!'):format())
        end

        -- Scan .data section for pointers to this vtable
        -- .data section is typically at ~0x430000 to ~0x600000 from base
        local scan_start = ffximain_base + 0x430000
        local scan_end = ffximain_base + 0x600000
        local scan_size = scan_end - scan_start

        if ffi.C.IsBadReadPtr(ffi.cast('void*', scan_start), scan_size) ~= 0 then
            print('[fdiag] .data region not readable, trying smaller range')
            scan_start = ffximain_base + 0x490000
            scan_end = ffximain_base + 0x560000
            scan_size = scan_end - scan_start
        end

        if ffi.C.IsBadReadPtr(ffi.cast('void*', scan_start), scan_size) == 0 then
            print(('[fdiag] Scanning 0x%08X - 0x%08X for vtable ptr 0x%08X...'):format(
                scan_start, scan_end, vt_addr))
            local p = ffi.cast('uint32_t*', scan_start)
            local count = scan_size / 4
            local found = 0
            for i = 0, count - 1 do
                if p[i] == vt_addr then
                    local addr = scan_start + i * 4
                    local off = addr - ffximain_base
                    print(('[fdiag]   FOUND at 0x%08X (base+0x%06X)'):format(addr, off))
                    -- Dump 32 bytes around it
                    if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), 32) == 0 then
                        output(hexdump(addr, 64, ('Object at base+0x%06X'):format(off)))
                    end
                    found = found + 1
                    if found >= 5 then break end
                end
            end
            if found == 0 then
                print('[fdiag] No vtable references found in .data scan range.')
            end
        else
            print('[fdiag] .data scan range not readable.')
        end
        return
    end

    -----------------------------------------------------------------
    -- FRIENDWIDE: Dump wider region around friend manager address
    -----------------------------------------------------------------
    if cmd == 'friendwide' then
        local mgr_off = 0x51E880
        local start = ffximain_base + mgr_off - 0x100
        local size = 0x300  -- 768 bytes centered on the address
        if ffi.C.IsBadReadPtr(ffi.cast('void*', start), size) == 0 then
            output(hexdump(start, size, ('Region around base+0x%06X'):format(mgr_off)))
        else
            print('[fdiag] Region not readable.')
        end
        return
    end

    -----------------------------------------------------------------
    -- SCANAUTH: Broad search of polcore .text for auth mode patterns
    -- Searches for: C6 07 02 (MOV BYTE [EDI], 0x02 = degraded write)
    -- Then checks context for CMP [addr], 2 nearby
    -----------------------------------------------------------------
    if cmd == 'scanauth' then
        local sections = get_sections(polcore_base)
        print('[fdiag] Scanning polcore .text for auth mode patterns...')

        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local base = polcore_base + sec.rva
                local p = ffi.cast('uint8_t*', base)
                local count = 0

                -- Search for C6 07 02 (MOV BYTE [EDI], 0x02)
                print(('[fdiag] Scanning %s at 0x%08X (%d KB)'):format(sec.name, base, sec.vsize / 1024))
                for i = 0, sec.vsize - 3 do
                    if p[i] == 0xC6 and p[i+1] == 0x07 and p[i+2] == 0x02 then
                        local abs_addr = base + i
                        local off = abs_addr - polcore_base
                        count = count + 1

                        -- Look backwards for CMP [addr], 2 (83 3D xx xx xx xx 02)
                        local cmp_found = false
                        local cmp_info = ''
                        for back = 4, 64 do
                            local bi = i - back
                            if bi >= 0 and p[bi] == 0x83 and p[bi+1] == 0x3D and p[bi+6] == 0x02 then
                                local cmp_addr = ffi.cast('uint32_t*', base + bi + 2)[0]
                                local jcc = p[bi+7]
                                local jcc_label = ''
                                if jcc == 0x75 then jcc_label = 'JNE'
                                elseif jcc == 0x74 then jcc_label = 'JE'
                                elseif jcc == 0x0F then jcc_label = 'Jcc(2B)'
                                end
                                local jmp_off = p[bi+8]
                                cmp_info = (' <- CMP [0x%08X],2 at -%d; %s +0x%02X'):format(cmp_addr, back, jcc_label, jmp_off)
                                cmp_found = true

                                -- Check if g_auth_mode address is readable
                                if ffi.C.IsBadReadPtr(ffi.cast('void*', cmp_addr), 4) == 0 then
                                    local val = ffi.cast('uint32_t*', cmp_addr)[0]
                                    cmp_info = cmp_info .. (' [val=%d]'):format(val)
                                end
                                break
                            end
                        end

                        -- Show context bytes
                        local ctx_start = math.max(0, i - 8)
                        local ctx = {}
                        for j = ctx_start, math.min(sec.vsize - 1, i + 10) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        print(('[fdiag]   #%d polcore+0x%06X: %s%s'):format(count, off, table.concat(ctx, ' '), cmp_info))

                        if count >= 15 then
                            print('[fdiag]   (truncated)')
                            break
                        end
                    end
                end
                print(('[fdiag] Found %d instances of MOV BYTE [EDI], 0x02'):format(count))
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- PATCHAUTH2: Patch instance #2 of MOV BYTE [EDI], 0x02
    -- Pattern: 74 05 C6 07 01 EB 03 C6 07 02
    -- Patches JE (74 05) -> NOP NOP (90 90) to force healthy path
    -----------------------------------------------------------------
    if cmd == 'patchauth2' then
        local sections = get_sections(polcore_base)
        print('[fdiag] Searching polcore .text for instance #2 pattern...')

        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local pat = '\x74\x05\xC6\x07\x01\xEB\x03\xC6\x07\x02'
                local mask = 'xxxxxxxxxx'
                local addr = find_pattern(polcore_base + sec.rva, sec.vsize, pat, mask)
                if addr then
                    local off = addr - polcore_base
                    print(('[fdiag] Found instance #2 at polcore+0x%06X (0x%08X)'):format(off, addr))

                    -- Show context (16 bytes before, 16 after)
                    local p = ffi.cast('uint8_t*', addr)
                    local ctx = {}
                    for j = -8, 14 do
                        table.insert(ctx, ('%02X'):format(p[j]))
                    end
                    print(('[fdiag]   Context: %s'):format(table.concat(ctx, ' ')))
                    print('[fdiag]   Current: JE +5 → MOV [EDI],0x01 → JMP +3 → MOV [EDI],0x02')

                    -- Check current state
                    if p[0] == 0x90 and p[1] == 0x90 then
                        print('[fdiag]   Already patched (NOP NOP)')
                        return
                    end

                    -- Patch: 74 05 -> 90 90 (NOP NOP, always take healthy path)
                    local oldProt = ffi.new('uint32_t[1]')
                    if ffi.C.VirtualProtect(ffi.cast('void*', addr), 2, 0x40, oldProt) ~= 0 then
                        p[0] = 0x90  -- NOP
                        p[1] = 0x90  -- NOP
                        ffi.C.VirtualProtect(ffi.cast('void*', addr), 2, oldProt[0], oldProt)
                        print('[fdiag]   PATCHED: JE -> NOP NOP (healthy path forced)')
                    else
                        print('[fdiag]   VirtualProtect failed!')
                    end
                else
                    print('[fdiag] Instance #2 pattern not found in .text')
                end
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- AUTHBLOCK: Raw hex dump of g_auth_mode 48-byte block
    -----------------------------------------------------------------
    if cmd == 'authblock' then
        local mode_addr, pat_found = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode pattern in polcore!')
            return
        end
        print(('[fdiag] g_auth_mode at 0x%08X (pattern at 0x%08X)'):format(mode_addr, pat_found))
        if ffi.C.IsBadReadPtr(ffi.cast('void*', mode_addr), 48) ~= 0 then
            print('[fdiag] g_auth_mode address not readable!')
            return
        end
        output(hexdump(mode_addr, 48, 'g_auth_mode raw 48B'))
        -- Annotate known field boundaries
        local p = ffi.cast('uint8_t*', mode_addr)
        print(('[fdiag]   +0x00 mode DWORD: %d'):format(ffi.cast('uint32_t*', mode_addr)[0]))
        print(('[fdiag]   +0x04 sentinel: 0x%02X'):format(p[0x04]))
        local m16 = {}
        for i = 0x05, 0x14 do table.insert(m16, ('%02X'):format(p[i])) end
        print('[fdiag]   +0x05..+0x14 mask16: ' .. table.concat(m16, ' '))
        local m20 = {}
        for i = 0x15, 0x28 do table.insert(m20, ('%02X'):format(p[i])) end
        print('[fdiag]   +0x15..+0x28 mask20: ' .. table.concat(m20, ' '))
        local e6 = {}
        for i = 0x29, 0x2F do table.insert(e6, ('%02X'):format(p[i])) end
        print('[fdiag]   +0x29..+0x2F extra6+: ' .. table.concat(e6, ' '))
        return
    end

    -----------------------------------------------------------------
    -- SETBYTE: Write arbitrary byte to g_auth_mode block
    -- /fdiag setbyte <offset> <value>
    -----------------------------------------------------------------
    if cmd == 'setbyte' then
        local off = tonumber(args[3])
        local val = tonumber(args[4])
        if not off or not val then
            print('[fdiag] Usage: /fdiag setbyte <offset> <value>')
            print('[fdiag]   offset: 0-47 (decimal) or 0x00-0x2F (hex)')
            print('[fdiag]   value:  0-255 (decimal) or 0x00-0xFF (hex)')
            print('[fdiag] Key offsets:')
            print('[fdiag]   0x00  mode DWORD (1=healthy, 2=degraded)')
            print('[fdiag]   0x04  sentinel byte')
            print('[fdiag]   0x05-0x14  mask16 (reversed NOTed username)')
            print('[fdiag]   0x15-0x28  mask20 (session hash)')
            print('[fdiag]   0x29-0x2E  extra6')
            return
        end
        if off < 0 or off > 47 then
            print('[fdiag] Offset must be 0-47 (0x00-0x2F)')
            return
        end
        if val < 0 or val > 255 then
            print('[fdiag] Value must be 0-255 (0x00-0xFF)')
            return
        end

        local mode_addr, _ = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode!')
            return
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', mode_addr), 48) ~= 0 then
            print('[fdiag] g_auth_mode address not readable!')
            return
        end

        local p = ffi.cast('uint8_t*', mode_addr)
        local old_val = p[off]
        p[off] = val
        print(('[fdiag] g_auth_mode+0x%02X: 0x%02X -> 0x%02X'):format(off, old_val, val))
        return
    end

    -----------------------------------------------------------------
    -- READMEM: Read 4 bytes at an absolute address or polcore+offset
    -----------------------------------------------------------------
    if cmd == 'readmem' then
        local addr_str = args[3]
        if not addr_str then
            print('[fdiag] Usage: /fdiag readmem <addr|pol+offset|ffxi+offset>')
            return
        end
        local addr
        if addr_str:match('^pol%+') then
            local off = tonumber(addr_str:match('^pol%+(.+)'))
            if off then addr = polcore_base + off end
        elseif addr_str:match('^ffxi%+') then
            local off = tonumber(addr_str:match('^ffxi%+(.+)'))
            if off then addr = ffximain_base + off end
        else
            addr = tonumber(addr_str)
        end
        if not addr then
            print('[fdiag] Invalid address: ' .. addr_str)
            return
        end
        local p = ffi.cast('uint8_t*', addr)
        if ffi.C.IsBadReadPtr(p, 16) ~= 0 then
            print(('[fdiag] Address 0x%08X not readable'):format(addr))
            return
        end
        local val32 = ffi.cast('uint32_t*', p)[0]
        local bytes = {}
        for i = 0, 15 do table.insert(bytes, ('%02X'):format(p[i])) end
        print(('[fdiag] [0x%08X] = 0x%08X (%d)'):format(addr, val32, val32))
        print(('[fdiag] bytes: %s'):format(table.concat(bytes, ' ')))
        return
    end

    -----------------------------------------------------------------
    -- SEARCHMEM: Search memory for a 4-byte value
    -- Usage: /fdiag searchmem <value_hex> [start_rva] [length]
    -- Defaults: search .text section of FFXiMain
    -----------------------------------------------------------------
    if cmd == 'searchmem' then
        local val_str = args[3]
        if not val_str then
            print('[fdiag] Usage: /fdiag searchmem <hex_value> [start_rva] [length]')
            return
        end
        local search_val = tonumber(val_str)
        if not search_val then
            print('[fdiag] Invalid value: ' .. val_str)
            return
        end
        local start_rva = tonumber(args[4] or '0x1000') or 0x1000
        local length = tonumber(args[5] or '0x326FEE') or 0x326FEE
        local base = ffximain_base + start_rva
        local p = ffi.cast('uint8_t*', base)
        if ffi.C.IsBadReadPtr(p, length) ~= 0 then
            print(('[fdiag] Region ffxi+0x%X len=0x%X not readable'):format(start_rva, length))
            return
        end
        local found = 0
        local results = {}
        local step = 1  -- byte-aligned search
        for off = 0, length - 4, step do
            local v = ffi.cast('uint32_t*', p + off)[0]
            if v == search_val then
                local rva = start_rva + off
                table.insert(results, ('[fdiag]   ffxi+0x%06X (abs 0x%08X)'):format(rva, base + off))
                found = found + 1
                if found >= 30 then break end
            end
        end
        print(('[fdiag] Search for 0x%08X in ffxi+0x%X..+0x%X: %d hits'):format(
            search_val, start_rva, start_rva + length, found))
        for _, r in ipairs(results) do print(r) end
        return
    end

    -----------------------------------------------------------------
    -- WRITEMEM: Write a 32-bit value to memory
    -----------------------------------------------------------------
    if cmd == 'writemem' then
        local addr_str = args[3]
        local val_str = args[4]
        if not addr_str or not val_str then
            print('[fdiag] Usage: /fdiag writemem <addr|pol+offset|ffxi+offset> <value>')
            return
        end
        local addr
        if addr_str:match('^pol%+') then
            local off = tonumber(addr_str:match('^pol%+(.+)'))
            if off then addr = polcore_base + off end
        elseif addr_str:match('^ffxi%+') then
            local off = tonumber(addr_str:match('^ffxi%+(.+)'))
            if off then addr = ffximain_base + off end
        else
            addr = tonumber(addr_str)
        end
        local val = tonumber(val_str)
        if not addr or not val then
            print('[fdiag] Invalid address or value')
            return
        end
        local p = ffi.cast('uint32_t*', addr)
        if ffi.C.IsBadWritePtr(p, 4) ~= 0 then
            print(('[fdiag] Address 0x%08X not writable'):format(addr))
            return
        end
        local old = p[0]
        p[0] = val
        print(('[fdiag] [0x%08X] = 0x%08X (was 0x%08X)'):format(addr, val, old))
        return
    end

    -----------------------------------------------------------------
    -- EXPERIMENTC: Fill extra6 with retail values + clone slot 0 -> 3
    -----------------------------------------------------------------
    if cmd == 'experimentc' then
        local mode_addr, _ = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode!')
            return
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', mode_addr), 48) ~= 0 then
            print('[fdiag] g_auth_mode address not readable!')
            return
        end

        local p = ffi.cast('uint8_t*', mode_addr)
        local retail_extra6 = {0xE5, 0x1A, 0x08, 0x22, 0xF0, 0x18}
        print('[fdiag] Writing retail extra6 at +0x29..+0x2E:')
        for i, v in ipairs(retail_extra6) do
            local off = 0x29 + i - 1
            local old = p[off]
            p[off] = v
            print(('[fdiag]   +0x%02X: 0x%02X -> 0x%02X'):format(off, old, v))
        end

        -- Clone slot 0 -> 3
        local desc_off = 0x404AD0
        local desc_base = polcore_base + desc_off
        local slot_size = 0x338
        local src = ffi.cast('uint8_t*', desc_base + 0 * slot_size)
        local dst = ffi.cast('uint8_t*', desc_base + 3 * slot_size)

        -- Copy host address (+0x24, 20 bytes)
        for i = 0, 19 do dst[0x24 + i] = src[0x24 + i] end
        dst[0x0B] = src[0x0B]  -- crypto
        dst[0x08] = 0x02       -- mode
        dst[0x09] = 0x00       -- state
        dst[0x02] = 0x00       -- type

        -- Allocate buffers
        local MEM_COMMIT = 0x1000
        local MEM_RESERVE = 0x2000
        local mem = ffi.C.VirtualAlloc(nil, 0x4000, bit.bor(MEM_COMMIT, MEM_RESERVE), 0x04)
        if mem == nil then
            print('[fdiag] VirtualAlloc failed!')
            return
        end
        local mb = tonumber(ffi.cast('uint32_t', mem))
        local mp = ffi.cast('uint8_t*', mem)
        for i = 0, 0x3FFF do mp[i] = 0 end

        ffi.cast('uint32_t*', dst + 0x3C)[0] = mb
        ffi.cast('uint32_t*', dst + 0x40)[0] = mb + 0x0820
        ffi.cast('uint32_t*', dst + 0x328)[0] = mb + 0x1680
        ffi.cast('uint32_t*', dst + 0x44)[0] = 0
        ffi.cast('uint32_t*', dst + 0x48)[0] = 0
        ffi.cast('int32_t*', dst + 0x04)[0] = -1
        dst[0xDE] = 0x01  -- enable

        print(('[fdiag] Slot 3 cloned from 0, mode=0x02, enable=1, bufs at 0x%08X'):format(mb))
        print('[fdiag] Experiment C active. Watch for new connections.')
        return
    end

    -----------------------------------------------------------------
    -- SCANREFS: Find all references to g_auth_mode block in polcore
    -----------------------------------------------------------------
    if cmd == 'scanrefs' then
        local mode_addr, _ = find_auth_mode_addr(polcore_base)
        if not mode_addr then
            print('[fdiag] Could not find g_auth_mode!')
            return
        end
        print(('[fdiag] Scanning polcore .text for refs to g_auth_mode block 0x%08X..0x%08X'):format(
            mode_addr, mode_addr + 47))

        local sections = get_sections(polcore_base)
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local text_base = polcore_base + sec.rva
                local p = ffi.cast('uint8_t*', text_base)
                local refs = {}

                -- Search for any 4-byte LE reference to addresses in the 48-byte block
                for i = 0, sec.vsize - 4 do
                    local ref = ffi.cast('uint32_t*', text_base + i)[0]
                    if ref >= mode_addr and ref < mode_addr + 48 then
                        local off = ref - mode_addr
                        local code_off = text_base + i - polcore_base
                        -- Show context bytes
                        local ctx = {}
                        local cs = math.max(0, i - 4)
                        for j = cs, math.min(sec.vsize - 1, i + 8) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(refs, {code_off = code_off, block_off = off, ctx = table.concat(ctx, ' ')})
                    end
                end

                print(('[fdiag] Found %d references:'):format(#refs))
                for _, r in ipairs(refs) do
                    print(('[fdiag]   polcore+0x%06X -> block+0x%02X: %s'):format(r.code_off, r.block_off, r.ctx))
                end
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- DUMPCODE OFFSET [SIZE]: Hex dump polcore code at offset
    -----------------------------------------------------------------
    if cmd == 'dumpcode' then
        local off_str = args[3]
        local size_str = args[4]
        if not off_str then
            print('[fdiag] Usage: /fdiag dumpcode <hex_offset> [size]')
            print('[fdiag]   e.g. /fdiag dumpcode 0x110B0 64')
            return
        end
        local off = tonumber(off_str)
        if not off then
            print('[fdiag] Invalid offset: ' .. off_str)
            return
        end
        local sz = tonumber(size_str) or 96
        if sz > 512 then sz = 512 end

        local addr = polcore_base + off
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), sz) ~= 0 then
            print(('[fdiag] polcore+0x%06X not readable (size=%d)'):format(off, sz))
            return
        end

        local p = ffi.cast('uint8_t*', addr)
        print(('[fdiag] Code at polcore+0x%06X (%d bytes):'):format(off, sz))
        for row = 0, sz - 1, 16 do
            local hex = {}
            local asc = {}
            for col = 0, 15 do
                local idx = row + col
                if idx < sz then
                    local b = p[idx]
                    table.insert(hex, ('%02X'):format(b))
                    table.insert(asc, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
                end
            end
            print(('[fdiag]   +%04X: %s  %s'):format(off + row, table.concat(hex, ' '), table.concat(asc)))
        end
        return
    end

    -----------------------------------------------------------------
    -- DUMPFFXI OFFSET [SIZE]: Hex dump FFXiMain code at offset
    -----------------------------------------------------------------
    if cmd == 'dumpffxi' then
        local off_str = args[3]
        local size_str = args[4]
        if not off_str then
            print('[fdiag] Usage: /fdiag dumpffxi <hex_offset> [size]')
            print('[fdiag]   e.g. /fdiag dumpffxi 0x200710 256')
            return
        end
        local off = tonumber(off_str)
        if not off then
            print('[fdiag] Invalid offset: ' .. off_str)
            return
        end
        local sz = tonumber(size_str) or 256
        if sz > 512 then sz = 512 end

        local addr = ffximain_base + off
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), sz) ~= 0 then
            print(('[fdiag] ffxi+0x%06X not readable (size=%d)'):format(off, sz))
            return
        end

        local p = ffi.cast('uint8_t*', addr)
        print(('[fdiag] FFXi base=0x%08X'):format(ffximain_base))
        print(('[fdiag] Code at ffxi+0x%06X (%d bytes):'):format(off, sz))
        for row = 0, sz - 1, 16 do
            local hex = {}
            local asc = {}
            for col = 0, 15 do
                local idx = row + col
                if idx < sz then
                    local b = p[idx]
                    table.insert(hex, ('%02X'):format(b))
                    table.insert(asc, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
                end
            end
            print(('[fdiag]   +%06X: %s  %s'):format(off + row, table.concat(hex, ' '), table.concat(asc)))
        end
        return
    end

    -----------------------------------------------------------------
    -- SCANCALL: Find E8 CALL instructions targeting ffxi+<offset>
    -- Searches .text section for relative CALL to target
    -----------------------------------------------------------------
    if cmd == 'scancall' then
        local tgt_str = args[3]
        local range_str = args[4]
        if not tgt_str then
            print('[fdiag] Usage: /fdiag scancall <target_rva_hex> [search_range_hex]')
            print('[fdiag]   e.g. /fdiag scancall 0x200710 0x326FEE')
            return
        end
        local tgt_rva = tonumber(tgt_str)
        if not tgt_rva then
            print('[fdiag] Invalid target: ' .. tgt_str)
            return
        end
        local tgt_abs = ffximain_base + tgt_rva
        local search_len = tonumber(range_str) or 0x326FEE
        local text_base = ffximain_base + 0x1000
        if ffi.C.IsBadReadPtr(ffi.cast('void*', text_base), search_len) ~= 0 then
            print('[fdiag] .text not readable')
            return
        end
        local p = ffi.cast('uint8_t*', text_base)
        local found = 0
        local results = {}
        for i = 0, search_len - 5 do
            if p[i] == 0xE8 then
                local rel = ffi.cast('int32_t*', text_base + i + 1)[0]
                local call_target = (text_base + i + 5) + rel
                if call_target == tgt_abs then
                    local call_rva = 0x1000 + i
                    -- dump 8 bytes before the E8 for context
                    local ctx = {}
                    local cs = math.max(0, i - 16)
                    for j = cs, i + 4 do
                        table.insert(ctx, ('%02X'):format(p[j]))
                    end
                    table.insert(results, ('[fdiag]   ffxi+0x%06X: %s'):format(call_rva, table.concat(ctx, ' ')))
                    found = found + 1
                    if found >= 20 then break end
                end
            end
        end
        print(('[fdiag] CALL targets for ffxi+0x%06X: %d hits'):format(tgt_rva, found))
        for _, r in ipairs(results) do print(r) end
        return
    end

    -----------------------------------------------------------------
    -- FINDAUTH: Scan for C6 07 01/02 (MOV BYTE [EDI], 01/02) patterns
    -----------------------------------------------------------------
    if cmd == 'findauth' then
        local sections = get_sections(polcore_base)
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local text_base = polcore_base + sec.rva
                local p = ffi.cast('uint8_t*', text_base)
                local hits = {}
                for i = 0, sec.vsize - 3 do
                    if p[i] == 0xC6 and p[i+1] == 0x07 and (p[i+2] == 0x01 or p[i+2] == 0x02) then
                        local code_off = text_base + i - polcore_base
                        -- Context: 8 bytes before, pattern, 8 bytes after
                        local ctx = {}
                        local cs = math.max(0, i - 8)
                        for j = cs, math.min(sec.vsize - 1, i + 10) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(hits, {off = code_off, val = p[i+2], ctx = table.concat(ctx, ' ')})
                    end
                end
                print(('[fdiag] Found %d MOV BYTE [EDI],01/02 hits in .text:'):format(#hits))
                for _, h in ipairs(hits) do
                    print(('[fdiag]   polcore+0x%06X: [EDI]=0x%02X  %s'):format(h.off, h.val, h.ctx))
                end
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- SCANADDR OFFSET: Find all 4-byte references to polcore+offset in ALL sections
    -----------------------------------------------------------------
    if cmd == 'scanaddr' then
        local tgt_str = args[3]
        if not tgt_str then
            print('[fdiag] Usage: /fdiag scanaddr <hex_offset>')
            return
        end
        local tgt_off = tonumber(tgt_str)
        if not tgt_off then
            print('[fdiag] Invalid offset: ' .. tgt_str)
            return
        end
        local tgt_abs = polcore_base + tgt_off
        local sections = get_sections(polcore_base)
        local hits = {}
        for _, sec in ipairs(sections) do
            local sec_base = polcore_base + sec.rva
            if ffi.C.IsBadReadPtr(ffi.cast('void*', sec_base), sec.vsize) == 0 then
                local p = ffi.cast('uint8_t*', sec_base)
                for i = 0, sec.vsize - 4 do
                    local val = ffi.cast('uint32_t*', sec_base + i)[0]
                    if val == tgt_abs then
                        local ref_off = sec_base + i - polcore_base
                        local ctx = {}
                        local cs = math.max(0, i - 4)
                        for j = cs, math.min(sec.vsize - 1, i + 7) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(hits, {off = ref_off, sec = sec.name, ctx = table.concat(ctx, ' ')})
                    end
                end
            end
        end
        print(('[fdiag] Found %d refs to polcore+0x%06X (0x%08X):'):format(#hits, tgt_off, tgt_abs))
        for _, h in ipairs(hits) do
            print(('[fdiag]   polcore+0x%06X [%s]: %s'):format(h.off, h.sec, h.ctx))
        end
        return
    end

    -----------------------------------------------------------------
    -- FINDCALL TARGET: Find all CALL instructions to a polcore offset
    -- /fdiag findcall 0x1E580
    -----------------------------------------------------------------
    if cmd == 'findcall' then
        local tgt_str = args[3]
        if not tgt_str then
            print('[fdiag] Usage: /fdiag findcall <hex_offset>')
            print('[fdiag] Key targets: 0x1E580 (CallerA) 0x22210 (CallerB) 0x28330 (CallerC)')
            return
        end
        local tgt_off = tonumber(tgt_str)
        if not tgt_off then
            print('[fdiag] Invalid offset: ' .. tgt_str)
            return
        end
        local tgt_abs = polcore_base + tgt_off
        local sections = get_sections(polcore_base)
        local hits = {}
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local text_base = polcore_base + sec.rva
                local p = ffi.cast('uint8_t*', text_base)
                for i = 0, sec.vsize - 5 do
                    if p[i] == 0xE8 then
                        local rel = ffi.cast('int32_t*', text_base + i + 1)[0]
                        local call_site = text_base + i
                        local call_target = call_site + 5 + rel
                        if call_target == tgt_abs then
                            local code_off = call_site - polcore_base
                            local ctx = {}
                            local cs = math.max(0, i - 8)
                            for j = cs, math.min(sec.vsize - 1, i + 12) do
                                table.insert(ctx, ('%02X'):format(p[j]))
                            end
                            table.insert(hits, {off = code_off, ctx = table.concat(ctx, ' ')})
                        end
                    end
                end
                print(('[fdiag] Found %d CALL sites to polcore+0x%06X:'):format(#hits, tgt_off))
                for _, h in ipairs(hits) do
                    print(('[fdiag]   polcore+0x%06X: %s'):format(h.off, h.ctx))
                end
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- SCANVTCALL: Scan FFXiMain for vtable dispatch calls (call [reg+offset])
    -- /fdiag scanvtcall 0x3C       - find all call [reg+0x3C] in FFXiMain
    -- /fdiag scanvtcall 0x74       - find all call [reg+0x74] in FFXiMain
    -----------------------------------------------------------------
    if cmd == 'scanvtcall' then
        local off_str = args[3]
        if not off_str then
            print('[fdiag] Usage: /fdiag scanvtcall <vtable_offset_hex>')
            return
        end
        local vt_off = tonumber(off_str)
        if not vt_off or vt_off < 0 or vt_off > 0xFFFF then
            print('[fdiag] Invalid offset: ' .. off_str)
            return
        end

        local ffxi_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
        if ffxi_base == 0 then
            print('[fdiag] FFXiMain.dll not loaded')
            return
        end

        local sections = get_sections(ffxi_base)
        local hits = {}
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local text_base = ffxi_base + sec.rva
                local p = ffi.cast('uint8_t*', text_base)
                for i = 0, sec.vsize - 6 do
                    -- Check for FF mod/rm patterns: call [reg+disp8] or call [reg+disp32]
                    if p[i] == 0xFF then
                        local modrm = p[i+1]
                        local mod = bit.rshift(modrm, 6)
                        local reg_op = bit.band(bit.rshift(modrm, 3), 7) -- must be 2 for CALL
                        local rm = bit.band(modrm, 7)
                        if reg_op == 2 then
                            local matched = false
                            local disp = 0
                            local insn_len = 0
                            if mod == 1 and rm ~= 4 then
                                -- [reg+disp8], 3 bytes total
                                disp = p[i+2]
                                if disp >= 128 then disp = disp - 256 end
                                insn_len = 3
                                if disp == vt_off then matched = true end
                            elseif mod == 2 and rm ~= 4 then
                                -- [reg+disp32], 6 bytes total
                                disp = ffi.cast('int32_t*', text_base + i + 2)[0]
                                insn_len = 6
                                if disp == vt_off then matched = true end
                            end
                            if matched then
                                local code_addr = text_base + i
                                local reg_names = {'eax','ecx','edx','ebx','esp','ebp','esi','edi'}
                                local ctx = {}
                                local cs = math.max(0, i - 8)
                                for j = cs, math.min(sec.vsize - 1, i + insn_len + 8) do
                                    table.insert(ctx, ('%02X'):format(p[j]))
                                end
                                table.insert(hits, {
                                    addr = code_addr,
                                    off = code_addr - ffxi_base,
                                    reg = reg_names[rm + 1] or '???',
                                    ctx = table.concat(ctx, ' ')
                                })
                            end
                        end
                    end
                end
                print(('[fdiag] Scanned %s (%d bytes), found %d vtable call sites for offset 0x%X:')
                    :format(sec.name, sec.vsize, #hits, vt_off))
                for _, h in ipairs(hits) do
                    print(('[fdiag]   0x%08X (FFXiMain+0x%06X): call [%s+0x%X]  %s')
                        :format(h.addr, h.off, h.reg, vt_off, h.ctx))
                end
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- SCANREF: Scan FFXiMain for DWORD references to an address
    -- /fdiag scanref 0x048EE9E4   - find all references to this address
    -----------------------------------------------------------------
    if cmd == 'scanref' then
        local addr_str = args[3]
        if not addr_str then
            print('[fdiag] Usage: /fdiag scanref <hex_address>')
            return
        end
        local target = tonumber(addr_str)
        if not target then
            print('[fdiag] Invalid address: ' .. addr_str)
            return
        end

        local ffxi_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
        if ffxi_base == 0 then
            print('[fdiag] FFXiMain.dll not loaded')
            return
        end

        local sections = get_sections(ffxi_base)
        local hits = {}
        local target_bytes = ffi.new('uint8_t[4]')
        target_bytes[0] = bit.band(target, 0xFF)
        target_bytes[1] = bit.band(bit.rshift(target, 8), 0xFF)
        target_bytes[2] = bit.band(bit.rshift(target, 16), 0xFF)
        target_bytes[3] = bit.band(bit.rshift(target, 24), 0xFF)

        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' then
                local text_base = ffxi_base + sec.rva
                local p = ffi.cast('uint8_t*', text_base)
                for i = 0, sec.vsize - 4 do
                    if p[i] == target_bytes[0] and p[i+1] == target_bytes[1]
                       and p[i+2] == target_bytes[2] and p[i+3] == target_bytes[3] then
                        local code_addr = text_base + i
                        -- Check preceding opcode
                        local prefix = ''
                        if i > 0 then
                            local prev = p[i-1]
                            if prev == 0xA1 then prefix = 'mov eax,'
                            elseif prev == 0xA3 then prefix = 'mov [...],eax'
                            elseif i >= 2 and p[i-2] == 0x8B then
                                local modrm = p[i-1]
                                local reg_names = {'eax','ecx','edx','ebx','esp','ebp','esi','edi'}
                                local reg_idx = bit.band(bit.rshift(modrm, 3), 7)
                                prefix = 'mov ' .. reg_names[reg_idx+1] .. ','
                            elseif i >= 2 and p[i-2] == 0x89 then
                                local modrm = p[i-1]
                                local reg_names = {'eax','ecx','edx','ebx','esp','ebp','esi','edi'}
                                local reg_idx = bit.band(bit.rshift(modrm, 3), 7)
                                prefix = 'mov [...], ' .. reg_names[reg_idx+1]
                            elseif i >= 2 and p[i-2] == 0xFF then
                                local modrm = p[i-1]
                                local op = bit.band(bit.rshift(modrm, 3), 7)
                                if op == 2 then prefix = 'call'
                                elseif op == 4 then prefix = 'jmp'
                                elseif op == 6 then prefix = 'push' end
                            elseif prev == 0x68 then prefix = 'push'
                            end
                        end
                        local ctx = {}
                        local cs = math.max(0, i - 6)
                        for j = cs, math.min(sec.vsize - 1, i + 10) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(hits, {
                            addr = code_addr,
                            off = code_addr - ffxi_base,
                            prefix = prefix,
                            ctx = table.concat(ctx, ' ')
                        })
                    end
                end
                print(('[fdiag] Found %d references to 0x%08X in FFXiMain .text:'):format(#hits, target))
                for _, h in ipairs(hits) do
                    print(('[fdiag]   0x%08X (+0x%06X) [%s]: %s')
                        :format(h.addr, h.off, h.prefix, h.ctx))
                end
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- SETGLOBALS: Write auth_builder globals manually
    -- /fdiag setglobals        - dump current values
    -- /fdiag setglobals V1 V2  - set [0x404A88]=V1, [0x404A8C]=V2
    -----------------------------------------------------------------
    if cmd == 'setglobals' then
        local g1_addr = polcore_base + 0x404A88
        local g2_addr = polcore_base + 0x404A8C
        local g1 = ffi.cast('uint32_t*', g1_addr)[0]
        local g2 = ffi.cast('uint32_t*', g2_addr)[0]
        print(('[fdiag] Auth globals: [+0x404A88]=0x%08X [+0x404A8C]=0x%08X'):format(g1, g2))

        if args[3] then
            local v1 = tonumber(args[3])
            local v2 = tonumber(args[4] or '0')
            if v1 then
                ffi.cast('uint32_t*', g1_addr)[0] = v1
                ffi.cast('uint32_t*', g2_addr)[0] = v2 or 0
                print(('[fdiag] Set: [+0x404A88]=0x%08X [+0x404A8C]=0x%08X'):format(v1, v2 or 0))
            else
                print('[fdiag] Usage: /fdiag setglobals <hex_val1> [hex_val2]')
            end
        end

        -- Also dump the 16 bytes at +0x404A88 for context
        local p = ffi.cast('uint8_t*', g1_addr)
        local hex = {}
        for i = 0, 15 do table.insert(hex, ('%02X'):format(p[i])) end
        print('[fdiag] Raw +0x404A88..+0x404A97: ' .. table.concat(hex, ' '))

        -- Also dump +0x404A94 (15B config area written by set_globals)
        p = ffi.cast('uint8_t*', polcore_base + 0x404A94)
        hex = {}
        for i = 0, 14 do table.insert(hex, ('%02X'):format(p[i])) end
        print('[fdiag] Raw +0x404A94..+0x404AA2 (config15): ' .. table.concat(hex, ' '))
        return
    end

    -----------------------------------------------------------------
    -- PATCHLOGIN: Install code cave to call CallerA+B+C during login
    -- Patches the CALL CallerA at polcore+0x44FCC to go through a cave
    -- that also calls CallerB and CallerC
    -----------------------------------------------------------------
    if cmd == 'patchlogin' then
        local call_site = polcore_base + 0x44FCC
        local callerA = polcore_base + 0x1E580
        local callerB = polcore_base + 0x22210
        local callerC = polcore_base + 0x28330
        local ret_addr = polcore_base + 0x44FD1

        -- Allocate executable memory for the code cave (128 bytes)
        -- Code goes at cave+0, diagnostics at cave+64
        local MEM_COMMIT = 0x1000
        local MEM_RESERVE = 0x2000
        local PAGE_EXECUTE_READWRITE = 0x40
        local cave = ffi.C.VirtualAlloc(nil, 128, bit.bor(MEM_COMMIT, MEM_RESERVE), PAGE_EXECUTE_READWRITE)
        if cave == nil then
            print('[fdiag] VirtualAlloc for code cave failed!')
            return
        end
        local cave_addr = tonumber(ffi.cast('uint32_t', cave))
        local p = ffi.cast('uint8_t*', cave)

        -- Diagnostic storage at cave+64 (safe from SetAuthMode overwrite)
        local diag_A = cave_addr + 64   -- 4B: CallerA return
        local diag_B = cave_addr + 68   -- 4B: CallerB return
        local diag_C = cave_addr + 72   -- 4B: CallerC return
        local diag_magic = cave_addr + 76 -- 4B: magic marker to confirm cave ran

        -- Write code cave:
        --   CALL CallerA
        --   MOV [diag_A], EAX
        --   PUSH EAX
        --   CALL CallerB
        --   MOV [diag_B], EAX
        --   CALL CallerC
        --   MOV [diag_C], EAX
        --   MOV DWORD [diag_magic], 0xCAFE1234
        --   POP EAX
        --   JMP ret_addr
        local i = 0
        local function emit_call(target)
            p[i] = 0xE8
            local rel = target - (cave_addr + i + 5)
            ffi.cast('int32_t*', cave_addr + i + 1)[0] = rel
            i = i + 5
        end
        local function emit_jmp(target)
            p[i] = 0xE9
            local rel = target - (cave_addr + i + 5)
            ffi.cast('int32_t*', cave_addr + i + 1)[0] = rel
            i = i + 5
        end
        local function emit_byte(b) p[i] = b; i = i + 1 end
        local function emit_mov_mem_eax(addr)
            p[i] = 0xA3
            ffi.cast('uint32_t*', cave_addr + i + 1)[0] = addr
            i = i + 5
        end
        local function emit_mov_mem_imm32(addr, val)
            -- MOV DWORD [addr], imm32 = C7 05 <addr32> <imm32>
            p[i] = 0xC7; p[i+1] = 0x05
            ffi.cast('uint32_t*', cave_addr + i + 2)[0] = addr
            ffi.cast('uint32_t*', cave_addr + i + 6)[0] = val
            i = i + 10
        end

        emit_call(callerA)                       -- CALL CallerA
        emit_mov_mem_eax(diag_A)                 -- MOV [diag_A], EAX
        emit_byte(0x50)                          -- PUSH EAX
        emit_call(callerB)                       -- CALL CallerB
        emit_mov_mem_eax(diag_B)                 -- MOV [diag_B], EAX
        emit_call(callerC)                       -- CALL CallerC
        emit_mov_mem_eax(diag_C)                 -- MOV [diag_C], EAX
        emit_mov_mem_imm32(diag_magic, 0xCAFE1234) -- MOV [magic], 0xCAFE1234
        emit_byte(0x58)                          -- POP EAX
        emit_jmp(ret_addr)                       -- JMP back

        -- Store cave address at polcore+0x404A94 (config15 area, never written on xiloader)
        ffi.cast('uint32_t*', polcore_base + 0x404A94)[0] = cave_addr

        print(('[fdiag] Code cave at 0x%08X (%d bytes):'):format(cave_addr, i))
        print(('[fdiag] Diag storage: A@+64 B@+68 C@+72 magic@+76'):format())
        local hex = {}
        for j = 0, i - 1 do table.insert(hex, ('%02X'):format(p[j])) end
        print('[fdiag]   ' .. table.concat(hex, ' '))

        -- Set sentinel values (will be overwritten by cave when it runs)
        ffi.cast('uint32_t*', diag_A)[0] = 0xDEAD0001
        ffi.cast('uint32_t*', diag_B)[0] = 0xDEAD0002
        ffi.cast('uint32_t*', diag_C)[0] = 0xDEAD0003
        ffi.cast('uint32_t*', diag_magic)[0] = 0x00000000

        -- Patch the CALL at +44FCC to JMP to our cave
        local oldProt = ffi.new('uint32_t[1]')
        if ffi.C.VirtualProtect(ffi.cast('void*', call_site), 5, 0x40, oldProt) ~= 0 then
            local cs = ffi.cast('uint8_t*', call_site)
            cs[0] = 0xE9  -- JMP rel32 (was E8 = CALL)
            local rel = cave_addr - (call_site + 5)
            ffi.cast('int32_t*', call_site + 1)[0] = rel
            ffi.C.VirtualProtect(ffi.cast('void*', call_site), 5, oldProt[0], oldProt)
            print(('[fdiag] Patched polcore+0x044FCC -> JMP cave (0x%08X)'):format(cave_addr))
            print(('[fdiag] Cave addr stored at g_auth_mode+0x25. After login: /fdiag readcave'):format())
        else
            print('[fdiag] VirtualProtect failed!')
        end
        return
    end

    -----------------------------------------------------------------
    -- READCAVE: Read diagnostic values from cave memory after login
    -- Cave address stored at g_auth_mode+0x25 by patchlogin
    -----------------------------------------------------------------
    if cmd == 'readcave' then
        local cave_addr
        -- Accept explicit address: /fdiag readcave 0x05250000
        if args[3] then
            cave_addr = tonumber(args[3])
        end
        -- Fallback: try g_auth_mode+0x25
        if not cave_addr or cave_addr == 0 then
            local mode_addr = find_auth_mode_addr(polcore_base)
            if mode_addr then
                cave_addr = ffi.cast('uint32_t*', mode_addr + 0x25)[0]
            end
        end
        -- Fallback: try config15 area at polcore+0x404A94
        if not cave_addr or cave_addr == 0 then
            cave_addr = ffi.cast('uint32_t*', polcore_base + 0x404A94)[0]
        end
        if not cave_addr or cave_addr == 0 then
            print('[fdiag] No cave address found. Provide explicitly: /fdiag readcave 0xADDRESS')
            return
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', cave_addr + 64), 16) ~= 0 then
            print(('[fdiag] Cave at 0x%08X+64 not readable!'):format(cave_addr))
            return
        end
        local retA = ffi.cast('int32_t*', cave_addr + 64)[0]
        local retB = ffi.cast('int32_t*', cave_addr + 68)[0]
        local retC = ffi.cast('int32_t*', cave_addr + 72)[0]
        local magic = ffi.cast('uint32_t*', cave_addr + 76)[0]
        print(('[fdiag] Cave at 0x%08X:'):format(cave_addr))
        print(('[fdiag]   CallerA returned: %d (0x%08X)%s'):format(retA, retA,
            retA == 0x7EADBEE1 and ' [SENTINEL - never ran]' or retA >= 0 and ' [slot '..retA..']' or ' [FAILED]'))
        print(('[fdiag]   CallerB returned: %d (0x%08X)%s'):format(retB, retB,
            retB == 0x7EADBEE2 and ' [SENTINEL - never ran]' or retB >= 0 and ' [slot '..retB..']' or ' [FAILED]'))
        print(('[fdiag]   CallerC returned: %d (0x%08X)%s'):format(retC, retC,
            retC == 0x7EADBEE3 and ' [SENTINEL - never ran]' or retC >= 0 and ' [slot '..retC..']' or ' [FAILED]'))
        print(('[fdiag]   Magic: 0x%08X %s'):format(magic,
            magic == 0xCAFE1234 and '[CONFIRMED - cave ran to completion]' or '[cave did NOT complete]'))
        -- Hex dump of diag area
        local dp = ffi.cast('uint8_t*', cave_addr + 64)
        local hex = {}
        for j = 0, 19 do table.insert(hex, ('%02X'):format(dp[j])) end
        print('[fdiag]   Raw cave+64: ' .. table.concat(hex, ' '))
        return
    end

    -----------------------------------------------------------------
    -- READABS: Hex dump any absolute memory address
    -- /fdiag readabs 0x05250000        → 64 bytes at that address
    -- /fdiag readabs 0x05250000 128    → 128 bytes
    -----------------------------------------------------------------
    if cmd == 'readabs' then
        if not args[3] then
            print('[fdiag] Usage: /fdiag readabs <address> [length]')
            return
        end
        local addr = tonumber(args[3])
        local len = tonumber(args[4] or '64')
        if not addr or addr == 0 then
            print('[fdiag] Invalid address')
            return
        end
        if len > 512 then len = 512 end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), len) ~= 0 then
            print(('[fdiag] Address 0x%08X (%d bytes) not readable!'):format(addr, len))
            return
        end
        local p = ffi.cast('uint8_t*', addr)
        print(('[fdiag] Hex dump at 0x%08X (%d bytes):'):format(addr, len))
        for off = 0, len - 1, 16 do
            local hex = {}
            local asc = {}
            for j = 0, 15 do
                if off + j < len then
                    local b = p[off + j]
                    table.insert(hex, ('%02X'):format(b))
                    table.insert(asc, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
                end
            end
            print(('  +%04X: %-48s %s'):format(off, table.concat(hex, ' '), table.concat(asc)))
        end
        -- Also show as DWORD array for the first 32 bytes
        if len >= 4 then
            local dwords = {}
            local dp = ffi.cast('uint32_t*', addr)
            local ndw = math.min(math.floor(len / 4), 8)
            for j = 0, ndw - 1 do
                table.insert(dwords, ('+%02d=0x%08X'):format(j * 4, dp[j]))
            end
            print('[fdiag] DWORDs: ' .. table.concat(dwords, '  '))
        end
        return
    end


    -----------------------------------------------------------------
    -- MEMSEARCH: Search for ASCII string in a module's memory range
    -- /fdiag memsearch <module> <string>
    -- e.g. /fdiag memsearch FFXiMain.dll netstat
    -----------------------------------------------------------------
    if cmd == 'memsearch' then
        local modname = args[3] or 'FFXiMain.dll'
        local needle = args[4]
        if not needle then
            print('[fdiag] Usage: /fdiag memsearch <module> <string>')
            return
        end
        local hMod = ffi.C.GetModuleHandleA(modname)
        if hMod == nil or tonumber(ffi.cast('uint32_t', hMod)) == 0 then
            print('[fdiag] Module not found: ' .. modname)
            return
        end
        local base = tonumber(ffi.cast('uint32_t', hMod))
        -- Read PE header to find section ranges
        local dosHdr = ffi.cast('uint8_t*', base)
        local peOff = ffi.cast('uint32_t*', base + 0x3C)[0]
        local peHdr = ffi.cast('uint8_t*', base + peOff)
        local numSections = ffi.cast('uint16_t*', peHdr + 6)[0]
        local optHdrSize = ffi.cast('uint16_t*', peHdr + 20)[0]
        local secHdr = peHdr + 24 + optHdrSize
        print(('[fdiag] Searching %s (base=0x%08X, %d sections) for "%s"'):format(
            modname, base, numSections, needle))
        local needleLen = #needle
        local found = 0
        for s = 0, numSections - 1 do
            local sh = secHdr + s * 40
            local secName = ffi.string(sh, 8):gsub('%z+$', '')
            local va = ffi.cast('uint32_t*', sh + 12)[0]
            local vs = ffi.cast('uint32_t*', sh + 8)[0]
            local secBase = base + va
            if vs > 0 and vs < 0x1000000 and ffi.C.IsBadReadPtr(ffi.cast('void*', secBase), math.min(vs, 4096)) == 0 then
                local p = ffi.cast('uint8_t*', secBase)
                local searchLen = math.min(vs, 0x200000) -- cap at 2MB per section
                for i = 0, searchLen - needleLen do
                    local match = true
                    for j = 0, needleLen - 1 do
                        if p[i + j] ~= needle:byte(j + 1) then
                            match = false
                            break
                        end
                    end
                    if match then
                        found = found + 1
                        print(('[fdiag]   FOUND at 0x%08X (section %s +0x%X)'):format(
                            secBase + i, secName, i))
                        -- dump context
                        local ctx = math.min(64, searchLen - i)
                        local hex = {}
                        for k = 0, ctx - 1 do
                            table.insert(hex, ('%02X'):format(p[i + k]))
                        end
                        print('[fdiag]   ' .. table.concat(hex, ' '))
                        if found >= 10 then break end
                    end
                end
            end
            if found >= 10 then break end
        end
        if found == 0 then
            print('[fdiag] Not found in any section')
        else
            print(('[fdiag] Found %d match(es)'):format(found))
        end
        return
    end

    -----------------------------------------------------------------
    -- SRFIX: Patch SR_BLOCK to check viewport width > 64
    -- Allocates executable memory, writes code cave, patches branch
    -- /fdiag srfix <hook_addr>
    -- hook_addr = address of Hook_DrawPrimitiveUP function
    -- Finds the SR_BLOCK branch (cmp [ebp-8],2; jne; xor eax,eax; jmp)
    -- and redirects it through a cave that checks vp.Width > 64
    -----------------------------------------------------------------
    if cmd == 'srfix' then
        -- Find the SR_BLOCK pattern: 83 7D F8 02 75 04 33 C0 EB
        -- Search in a 1KB range around expected hook location
        local search_base = tonumber(args[3])
        if not search_base then
            -- Try to find it by scanning xiloader's code
            -- The pattern is: 83 7D F8 02 75 04 33 C0 EB
            print('[fdiag] Usage: /fdiag srfix <hook_func_addr>')
            print('[fdiag] Or: /fdiag srfix auto  (scans for pattern)')
            return
        end

        -- If 'auto', scan a broad range for the pattern
        local pattern = {0x83, 0x7D, 0xF8, 0x02, 0x75, 0x04, 0x33, 0xC0, 0xEB}
        local patAddr = nil

        if search_base == 0 then
            -- Scan common xiloader code ranges
            print('[fdiag] Auto-scan not supported, provide hook address')
            return
        end

        -- Scan from search_base for up to 4KB
        local scanLen = 4096
        if ffi.C.IsBadReadPtr(ffi.cast('void*', search_base), scanLen) ~= 0 then
            print(('[fdiag] Cannot read 0x%08X'):format(search_base))
            return
        end
        local p = ffi.cast('uint8_t*', search_base)
        for i = 0, scanLen - #pattern do
            local match = true
            for j = 1, #pattern do
                if p[i + j - 1] ~= pattern[j] then match = false break end
            end
            if match then
                patAddr = search_base + i
                break
            end
        end

        if not patAddr then
            print('[fdiag] SR_BLOCK pattern not found in range')
            return
        end

        print(('[fdiag] Found SR_BLOCK pattern at 0x%08X'):format(patAddr))

        -- Layout at patAddr:
        --   +0: 83 7D F8 02    cmp [ebp-8], 2
        --   +4: 75 04          jne +4 -> +10
        --   +6: 33 C0          xor eax, eax
        --   +8: EB XX          jmp epilogue
        local jmpByte = p[patAddr - search_base + 9]  -- the XX in EB XX
        local epilogue = patAddr + 10 + jmpByte        -- jmp target
        local continueAddr = patAddr + 10               -- after the jne target

        print(('[fdiag] Epilogue at 0x%08X, continue at 0x%08X'):format(epilogue, continueAddr))

        -- Allocate executable memory for code cave
        ffi.cdef[[
            void* VirtualAlloc(void* addr, size_t size, uint32_t type, uint32_t protect);
        ]]
        local MEM_COMMIT_RESERVE = 0x3000
        local PAGE_EXECUTE_READWRITE = 0x40
        local cave = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        if cave == nil then
            print('[fdiag] VirtualAlloc failed')
            return
        end
        local caveAddr = tonumber(ffi.cast('uint32_t', cave))
        print(('[fdiag] Code cave at 0x%08X'):format(caveAddr))

        local cp = ffi.cast('uint8_t*', cave)
        local ci = 0

        -- Write code cave:
        -- cmp dword [ebp-0x1C], 0x40    ; 83 7D E4 40
        cp[ci] = 0x83; ci = ci + 1
        cp[ci] = 0x7D; ci = ci + 1
        cp[ci] = 0xE4; ci = ci + 1  -- ebp-0x1C
        cp[ci] = 0x40; ci = ci + 1  -- 64

        -- jbe .no_block                  ; 76 07
        cp[ci] = 0x76; ci = ci + 1
        cp[ci] = 0x07; ci = ci + 1

        -- xor eax, eax                   ; 33 C0
        cp[ci] = 0x33; ci = ci + 1
        cp[ci] = 0xC0; ci = ci + 1

        -- jmp near epilogue              ; E9 XX XX XX XX
        cp[ci] = 0xE9; ci = ci + 1
        local rel1 = epilogue - (caveAddr + ci + 4)
        local r1 = ffi.cast('int32_t*', cp + ci)
        r1[0] = rel1
        ci = ci + 4

        -- .no_block:
        -- jmp near continue              ; E9 XX XX XX XX
        cp[ci] = 0xE9; ci = ci + 1
        local rel2 = continueAddr - (caveAddr + ci + 4)
        local r2 = ffi.cast('int32_t*', cp + ci)
        r2[0] = rel2
        ci = ci + 4

        print(('[fdiag] Cave written: %d bytes, jmp1_rel=0x%08X jmp2_rel=0x%08X'):format(
            ci, rel1, rel2))

        -- Now patch the original code at patAddr+4 (6 bytes: 75 04 33 C0 EB XX)
        -- Replace with: 0F 84 XX XX XX XX  (je near -> cave, when mode==2)
        local patchAddr = patAddr + 4  -- the jne instruction
        local patchEnd = patchAddr + 6 -- 6 bytes to replace
        local jeRel = caveAddr - (patchAddr + 6)  -- relative to end of je instruction

        -- Use VirtualProtect to make it writable
        ffi.cdef[[
            int VirtualProtect(void* addr, size_t size, uint32_t newProtect, uint32_t* oldProtect);
        ]]
        local oldProt = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', patchAddr), 6, 0x40, oldProt)

        local pp = ffi.cast('uint8_t*', patchAddr)
        pp[0] = 0x0F  -- je near (2-byte opcode)
        pp[1] = 0x84
        local pr = ffi.cast('int32_t*', pp + 2)
        pr[0] = jeRel
        -- The 6 bytes are now: 0F 84 [4-byte offset]

        ffi.C.VirtualProtect(ffi.cast('void*', patchAddr), 6, oldProt[0], oldProt)

        print(('[fdiag] Patched 0x%08X: je near 0x%08X (rel=0x%08X)'):format(
            patchAddr, caveAddr, jeRel))
        print('[fdiag] SR_BLOCK now checks vp.Width > 64')
        return
    end

    -----------------------------------------------------------------
    -- GATETEST: Set gate byte and read back immediately (same frame)
    -- Tests whether clearing happens same-frame or next-frame
    -----------------------------------------------------------------
    if cmd == 'gatetest' then
        local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
        if ffximain_base == 0 then print('[fdiag] FFXiMain not loaded') return end
        local store3_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if store3_ptr == 0 then print('[fdiag] Store 3 NULL') return end
        local s3_base = store3_ptr + 0x0A90
        local s3_count = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_ptr) + 0x132)[0]
        print(('[fdiag] Store 3 count: %d'):format(s3_count))
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3_count + 1) * 0x100, 0x40, prot)
        for ei = 0, s3_count do
            local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
            local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
            if bit.band(efl, 0x2000) ~= 0 then
                local fc_before = ent[0xFC]
                -- Set to 0xFF to see which bits survive per-frame clearing
                ent[0xFC] = 0xFF
                local fc_after = ent[0xFC]
                -- Now call populate_friend_data and check again
                local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
                local fc_after_pop = fc_after
                if flistmai ~= 0 then
                    local fm = ffi.cast('uint8_t*', flistmai)
                    local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
                    populate(ffi.cast('void*', flistmai), fm[0x58])
                    fc_after_pop = ent[0xFC]
                end
                print(('[fdiag] S3[%d] fc: before=0x%02X, set=0xFF, readback=0x%02X, after_populate=0x%02X'):format(
                    ei, fc_before, fc_after, fc_after_pop))
                -- Also dump entry[0xF0..0xFF] to see what else is at the end
                local tail = {}
                for j = 0xF0, 0xFF do
                    table.insert(tail, ('%02X'):format(ent[j]))
                end
                print(('[fdiag]   entry[0xF0..0xFF]: %s'):format(table.concat(tail, ' ')))
            end
        end
        ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3_count + 1) * 0x100, prot[0], prot)
        return
    end

    -----------------------------------------------------------------
    -- SCANGATE: Search FFXiMain .text for instructions that modify offset 0xFC
    -- (the gate byte in Store 3 entries at entry+0xFC)
    -----------------------------------------------------------------
    if cmd == 'scangate' then
        local scan_target = args[3] or 'FFXiMain'
        local scan_base
        if scan_target == 'polcore' then
            scan_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
            if scan_base == 0 then print('[fdiag] polcore not loaded') return end
        else
            scan_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
            if scan_base == 0 then print('[fdiag] FFXiMain not loaded') return end
        end
        local sections = get_sections(scan_base)
        local text_rva, text_size
        for _, sec in ipairs(sections) do
            if sec.name == '.text' or sec.name == 'CODE' or sec.name == 'POL1' then
                if sec.vsize > 0x1000 then
                    text_rva = sec.rva
                    text_size = sec.vsize
                    break
                end
            end
        end
        if not text_rva then print('[fdiag] No .text section found!') return end
        local tp = ffi.cast('uint8_t*', scan_base + text_rva)
        print(('[fdiag] Scanning %s .text at 0x%08X, size 0x%X'):format(scan_target, scan_base + text_rva, text_size))

        -- Search for instructions that write to [reg+0xFC] (4-byte displacement)
        -- Pattern: xx xx FC 00 00 00 where xx xx encodes a write
        -- C6 80..87 FC 00 00 00 imm8 = MOV byte [reg+0xFC], imm8
        -- 80 A0..A7 FC 00 00 00 imm8 = AND byte [reg+0xFC], imm8
        -- 80 88..8F FC 00 00 00 imm8 = OR byte [reg+0xFC], imm8
        -- 88 80..87 FC 00 00 00      = MOV [reg+0xFC], al
        -- 88 88..8F FC 00 00 00      = MOV [reg+0xFC], cl  etc
        local regnames = {'eax','ecx','edx','ebx','esp','ebp','esi','edi'}
        local src_regs = {'al','cl','dl','bl','ah','ch','dh','bh'}
        local grp1 = {[0]='ADD',[1]='OR',[2]='ADC',[3]='SBB',[4]='AND',[5]='SUB',[6]='XOR',[7]='CMP'}
        local hits = {}
        for i = 0, text_size - 8 do
            local op = tp[i]
            local modrm = tp[i+1]
            local mod = bit.rshift(modrm, 6)
            local reg = bit.band(bit.rshift(modrm, 3), 7)
            local rm = bit.band(modrm, 7)
            local desc = ''
            local ilen = 0

            -- mod=2 (disp32), rm != 4 (no SIB): disp at i+2..i+5
            if mod == 2 and rm ~= 4 and tp[i+2] == 0xFC and tp[i+3] == 0x00 and tp[i+4] == 0x00 and tp[i+5] == 0x00 then
                if op == 0xC6 and reg == 0 then
                    desc = ('MOV byte [%s+0xFC], 0x%02X'):format(regnames[rm+1], tp[i+6])
                    ilen = 7
                elseif op == 0x80 then
                    desc = ('%s byte [%s+0xFC], 0x%02X'):format(grp1[reg] or '??', regnames[rm+1], tp[i+6])
                    ilen = 7
                elseif op == 0x88 then
                    desc = ('MOV [%s+0xFC], %s'):format(regnames[rm+1], src_regs[reg+1])
                    ilen = 6
                end
            end

            -- mod=1 (disp8), rm != 4 (no SIB): disp at i+2 (signed)
            if mod == 1 and rm ~= 4 and tp[i+2] == 0xFC then
                local d8 = '0xFC(-4)'
                if op == 0xC6 and reg == 0 then
                    desc = ('MOV byte [%s%s], 0x%02X'):format(regnames[rm+1], d8, tp[i+3])
                    ilen = 4
                elseif op == 0x80 then
                    desc = ('%s byte [%s%s], 0x%02X'):format(grp1[reg] or '??', regnames[rm+1], d8, tp[i+3])
                    ilen = 4
                elseif op == 0x88 then
                    desc = ('MOV [%s%s], %s'):format(regnames[rm+1], d8, src_regs[reg+1])
                    ilen = 3
                elseif op == 0xFE and (reg == 0 or reg == 1) then
                    desc = ('%s byte [%s%s]'):format(reg == 0 and 'INC' or 'DEC', regnames[rm+1], d8)
                    ilen = 3
                end
            end

            -- mod=2, rm=4 (SIB): SIB at i+2, disp at i+3..i+6
            if mod == 2 and rm == 4 and tp[i+3] == 0xFC and tp[i+4] == 0x00 and tp[i+5] == 0x00 and tp[i+6] == 0x00 then
                local sib = tp[i+2]
                local sib_base = bit.band(sib, 7)
                local sib_idx = bit.band(bit.rshift(sib, 3), 7)
                local sib_scale = bit.rshift(sib, 6)
                if op == 0xC6 and reg == 0 then
                    desc = ('MOV byte [%s+%s*%d+0xFC], 0x%02X (SIB)'):format(regnames[sib_base+1], regnames[sib_idx+1], 2^sib_scale, tp[i+7])
                    ilen = 8
                elseif op == 0x80 then
                    desc = ('%s byte [%s+%s*%d+0xFC], 0x%02X (SIB)'):format(grp1[reg] or '??', regnames[sib_base+1], regnames[sib_idx+1], 2^sib_scale, tp[i+7])
                    ilen = 8
                elseif op == 0x88 then
                    desc = ('MOV [%s+%s*%d+0xFC], %s (SIB)'):format(regnames[sib_base+1], regnames[sib_idx+1], 2^sib_scale, src_regs[reg+1])
                    ilen = 7
                end
            end

            if #desc > 0 then
                local rva = text_rva + i
                local ctx = {}
                for j = -2, ilen + 2 do
                    if i + j >= 0 and i + j < text_size then
                        table.insert(ctx, ('%02X'):format(tp[i + j]))
                    end
                end
                table.insert(hits, {rva=rva, desc=desc, ctx=table.concat(ctx, ' ')})
            end
        end
        -- Search for AND DWORD [reg+0xFC], 0xFFFFFFFE (clears bit 0 of dword)
        -- 81 A0..A7 FC 00 00 00 FE FF FF FF (disp32)
        -- 83 60..67 FC FE (disp8, sign-extended)
        for i = 0, text_size - 6 do
            -- AND DWORD [reg+disp8(-4)], sign_ext(0xFE) → 83 6x FC FE
            if tp[i] == 0x83 then
                local modrm = tp[i+1]
                local mod = bit.rshift(modrm, 6)
                local reg = bit.band(bit.rshift(modrm, 3), 7)
                local rm = bit.band(modrm, 7)
                if mod == 1 and reg == 4 and rm ~= 4 and tp[i+2] == 0xFC and tp[i+3] == 0xFE then
                    local rva = text_rva + i
                    local ctx = {}
                    for j = -4, 7 do
                        if i + j >= 0 and i + j < text_size then
                            table.insert(ctx, ('%02X'):format(tp[i + j]))
                        end
                    end
                    table.insert(hits, {rva=rva, desc=('AND dword [%s-4], 0xFFFFFFFE (clear bit 0)'):format(regnames[rm+1]), ctx=table.concat(ctx, ' ')})
                end
            end
        end
        -- SIB with disp8=0xFC: mod=01, rm=4, SIB byte, disp=0xFC
        for i = 0, text_size - 5 do
            local op = tp[i]
            local modrm = tp[i+1]
            local mod = bit.rshift(modrm, 6)
            local rm = bit.band(modrm, 7)
            local reg = bit.band(bit.rshift(modrm, 3), 7)
            if mod == 1 and rm == 4 and tp[i+3] == 0xFC then
                local sib = tp[i+2]
                local sb = bit.band(sib, 7)
                local si = bit.band(bit.rshift(sib, 3), 7)
                local ss = bit.rshift(sib, 6)
                local desc = ''
                if op == 0x88 then
                    desc = ('MOV [%s+%s*%d-4], %s (SIB,d8)'):format(regnames[sb+1], regnames[si+1], 2^ss, src_regs[reg+1])
                elseif op == 0xC6 and reg == 0 then
                    desc = ('MOV byte [%s+%s*%d-4], 0x%02X (SIB,d8)'):format(regnames[sb+1], regnames[si+1], 2^ss, tp[i+4])
                elseif op == 0x80 and reg == 4 then
                    desc = ('AND byte [%s+%s*%d-4], 0x%02X (SIB,d8)'):format(regnames[sb+1], regnames[si+1], 2^ss, tp[i+4])
                end
                if #desc > 0 then
                    local rva = text_rva + i
                    local ctx = {}
                    for j = -2, 7 do
                        if i + j >= 0 and i + j < text_size then
                            table.insert(ctx, ('%02X'):format(tp[i + j]))
                        end
                    end
                    table.insert(hits, {rva=rva, desc=desc, ctx=table.concat(ctx, ' ')})
                end
            end
        end

        print(('[fdiag] Found %d hits modifying [reg+0xFC]:'):format(#hits))
        for _, h in ipairs(hits) do
            print(('  %s+0x%06X: %s  [%s]'):format(scan_target, h.rva, h.desc, h.ctx))
        end
        return
    end

    -----------------------------------------------------------------
    -- WRITEABS: Write bytes to any writable memory address
    -- /fdiag writeabs 0x10405800 01000000  → writes 4 bytes
    -- /fdiag writeabs 0x10405808 48656C6C6F  → writes "Hello"
    -----------------------------------------------------------------
    if cmd == 'writeabs' then
        if not args[3] or not args[4] then
            print('[fdiag] Usage: /fdiag writeabs <address> <hex_bytes>')
            return
        end
        local addr = tonumber(args[3])
        local hex_str = args[4]
        if not addr or addr == 0 then
            print('[fdiag] Invalid address')
            return
        end
        -- Parse hex string to bytes
        local bytes = {}
        for i = 1, #hex_str, 2 do
            local b = tonumber(hex_str:sub(i, i + 1), 16)
            if not b then
                print(('[fdiag] Invalid hex at position %d'):format(i))
                return
            end
            table.insert(bytes, b)
        end
        local len = #bytes
        -- VirtualProtect to ensure writable
        local old_prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', addr), len, 0x40, old_prot)
        local p = ffi.cast('uint8_t*', addr)
        for i = 0, len - 1 do
            p[i] = bytes[i + 1]
        end
        -- Restore protection
        ffi.C.VirtualProtect(ffi.cast('void*', addr), len, old_prot[0], old_prot)
        print(('[fdiag] Wrote %d bytes to 0x%08X'):format(len, addr))
        -- Verify
        local verify = {}
        for i = 0, math.min(len - 1, 31) do
            table.insert(verify, ('%02X'):format(p[i]))
        end
        print('[fdiag] Verify: ' .. table.concat(verify, ' '))
        return
    end

    -----------------------------------------------------------------
    -- POPHANDLE: Populate the handle display array entry
    -- /fdiag pophandle [text]  → writes handle text into polcore array
    -- Default text: "LSB_TestHandle"
    -- Array at polcore+0x405800, entry[0] flags (bit0=valid), entry[8] text
    -----------------------------------------------------------------
    if cmd == 'pophandle' then
        local text = args[3] or 'LSB_TestHndl'
        if #text > 15 then text = text:sub(1, 15) end

        local entry_base = polcore_base + 0x405800  -- array base
        local index_addr = polcore_base + 0x07541C  -- index global

        -- Write flags: set bit 0 = valid
        local old_prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', entry_base), 40, 0x40, old_prot)

        local p = ffi.cast('uint8_t*', entry_base)
        -- Clear entire 40-byte entry first
        for i = 0, 39 do p[i] = 0 end
        -- Set flags dword: bit 0 = 1
        p[0] = 0x01
        -- Write text at entry+8
        for i = 1, #text do
            p[7 + i] = text:byte(i)
        end
        -- Null terminate
        p[8 + #text] = 0

        ffi.C.VirtualProtect(ffi.cast('void*', entry_base), 40, old_prot[0], old_prot)

        -- Set index to 0
        local idx_prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', index_addr), 4, 0x40, idx_prot)
        ffi.cast('uint32_t*', index_addr)[0] = 0
        ffi.C.VirtualProtect(ffi.cast('void*', index_addr), 4, idx_prot[0], idx_prot)

        -- Dump entry for verification
        local hex = {}
        local asc = {}
        for i = 0, 39 do
            local b = p[i]
            table.insert(hex, ('%02X'):format(b))
            if i == 7 or i == 23 then table.insert(hex, '|') end
        end
        print(('[fdiag] Handle entry at 0x%08X:'):format(entry_base))
        print('[fdiag] ' .. table.concat(hex, ' '))
        print(('[fdiag] Text: "%s" (index=%d)'):format(text, 0))
        print('[fdiag] Open /friendlist to test handle display.')
        return
    end

    -----------------------------------------------------------------
    -- TESTID: Write a test value to handle[0] to RE the ID encoding
    -- /fdiag testid <value>     → writes uint32 at handle[0]+4 (raw)
    -- /fdiag testid encode <id> → writes (id << 1 | 1) as uint64 at handle[0]+0
    -- /fdiag testid dump        → hex dump handle[0] (40 bytes)
    -- /fdiag testid clear       → zero handle[0]+0..+7 and set flag=1
    -----------------------------------------------------------------
    if cmd == 'testid' then
        local entry_base = polcore_base + 0x405800
        local old_prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', entry_base), 40, 0x40, old_prot)
        local p = ffi.cast('uint8_t*', entry_base)

        local arg = args[3]
        if arg == 'dump' then
            local hex = {}
            for i = 0, 39 do
                table.insert(hex, ('%02X'):format(p[i]))
                if i == 3 or i == 7 or i == 22 then table.insert(hex, '|') end
            end
            print('[fdiag] handle[0] (40 bytes):')
            print('[fdiag] [flags4]|[+4..+7]|[+8..+22 name]|[+23..+39]')
            print('[fdiag] ' .. table.concat(hex, ' '))
            -- Show as integers
            local flags = ffi.cast('uint32_t*', p)[0]
            local id_dw = ffi.cast('uint32_t*', p + 4)[0]
            local name = ffi.string(p + 8, 15):gsub('%z+$', '')
            print(('[fdiag] flags=0x%08X id_dw=0x%08X (%u) name="%s"'):format(flags, id_dw, id_dw, name))
            -- Show decoded account ID (uint64 >> 1)
            local u64 = ffi.cast('uint64_t*', p)[0]
            local decoded = tonumber(u64 / 2ULL)  -- right shift by 1
            print(('[fdiag] uint64=0x%016X decoded_id=%u'):format(tonumber(u64), decoded))
            -- Show handle_index
            local idx = ffi.cast('uint32_t*', polcore_base + 0x07541C)[0]
            print(('[fdiag] handle_index=%d'):format(idx))
        elseif arg == 'clear' then
            ffi.cast('uint32_t*', p)[0] = 1      -- valid flag only
            ffi.cast('uint32_t*', p + 4)[0] = 0
            print('[fdiag] handle[0]+0..+7 cleared, flag=1')
        elseif arg == 'encode' then
            -- /fdiag testid encode <account_id>
            -- Writes (account_id << 1) | 1 as uint64 at handle[0]+0
            local id = tonumber(args[4])
            if not id then
                print('[fdiag] Usage: /fdiag testid encode <account_id>')
                print('[fdiag]   Encodes as uint64 = (id << 1) | 1')
            else
                local u64 = ffi.cast('uint64_t', id) * 2ULL + 1ULL
                ffi.cast('uint64_t*', p)[0] = u64
                local lo = ffi.cast('uint32_t*', p)[0]
                local hi = ffi.cast('uint32_t*', p + 4)[0]
                print(('[fdiag] encode id=%u → uint64=0x%016X'):format(id, tonumber(u64)))
                print(('[fdiag] handle[0]+0=0x%08X handle[0]+4=0x%08X'):format(lo, hi))
                print(('[fdiag] bytes: %02X %02X %02X %02X | %02X %02X %02X %02X'):format(
                    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]))
            end
        else
            local val = tonumber(arg)
            if not val then
                print('[fdiag] Usage: /fdiag testid <number|dump|clear|encode>')
                print('[fdiag]   testid 1000       — write 1000 at +4 (raw)')
                print('[fdiag]   testid encode 1000 — write (1000<<1|1) as uint64')
                print('[fdiag]   testid dump        — hex dump handle[0]')
                print('[fdiag]   testid clear       — reset to flag=1, id=0')
            else
                ffi.cast('uint32_t*', p + 4)[0] = val
                print(('[fdiag] handle[0]+4 = %u (0x%08X)'):format(val, val))
                print(('[fdiag] bytes: %02X %02X %02X %02X'):format(p[4], p[5], p[6], p[7]))
            end
        end
        ffi.C.VirtualProtect(ffi.cast('void*', entry_base), 40, old_prot[0], old_prot)
        return
    end

    -----------------------------------------------------------------
    -- CALLFN: Directly call a polcore caller function
    -- /fdiag setglobals2 — call set_globals_v2 to derive connection-type keys
    -- Uses crypto seed at +0x99280 (must be populated by +0x44390 first)
    if cmd == 'setglobals2' then
        local seed_addr = polcore_base + 0x99280
        local data_addr = polcore_base + 0x99288
        local keys_addr = polcore_base + 0x404A88

        -- Verify crypto seed is populated (not default 00 FF 00 FF)
        local seed = ffi.cast('uint32_t*', seed_addr)
        if seed[0] == 0xFF00FF00 then
            print('[fdiag] ERROR: crypto seed is default — run xiloader with config first')
            return
        end
        print(('[fdiag] Crypto seed: 0x%08X 0x%08X'):format(seed[0], seed[1]))
        print(('[fdiag] Config data at 0x%08X'):format(data_addr))

        -- Dump keys before
        local keys = ffi.cast('uint32_t*', keys_addr)
        print(('[fdiag] Keys BEFORE: [0x404A88]=0x%08X [0x404A8C]=0x%08X'):format(keys[0], keys[1]))

        -- Call set_globals_v2(seed_ptr, data_ptr, nonce=0)
        local fn = ffi.cast('void (__cdecl*)(void*, void*, uint32_t)', polcore_base + 0x1EAB0)
        print('[fdiag] Calling set_globals_v2...')
        fn(ffi.cast('void*', seed_addr), ffi.cast('void*', data_addr), 0)

        -- Dump keys after
        print(('[fdiag] Keys AFTER: [0x404A88]=0x%08X [0x404A8C]=0x%08X'):format(keys[0], keys[1]))
        return
    end

    -- /fdiag callA  → Caller A at +1E580 (keepalive, type=5)
    -- /fdiag callB  → Caller B at +22210 (token exchange, type=8, param=0x1000)
    -- /fdiag callC  → Caller C at +28330 (befriend, type=8)
    -----------------------------------------------------------------
    if cmd == 'calla' or cmd == 'callb' or cmd == 'callc' then
        local offsets = {calla = 0x1E580, callb = 0x22210, callc = 0x28330}
        local names = {calla = 'CallerA(keepalive)', callb = 'CallerB(token)', callc = 'CallerC(befriend)'}
        local off = offsets[cmd]
        local name = names[cmd]
        local addr = polcore_base + off
        print(('[fdiag] Calling %s at polcore+0x%06X (0x%08X)...'):format(name, off, addr))
        local func = ffi.cast('int (__cdecl*)()', addr)
        local result = func()
        print(('[fdiag] %s returned slot index: %d'):format(name, result))
        if result >= 0 then
            print('[fdiag] Connection initiated! Check server for new connection.')
        else
            print('[fdiag] No slot available (returned negative).')
        end
        return
    end

    -- /fdiag friendid <index> — look up a friend's identity by index
    -- polcore+0x23DA0(index, out) fills a struct; status_update_dispatch
    -- requires the pushed record's decrypted first 8 bytes to equal
    -- out[0]/out[1], else it drops the update.
    -----------------------------------------------------------------
    if cmd == 'friendid' then
        local idxn = tonumber(args[3]) or 0
        local out = ffi.new('uint32_t[64]')
        local fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23DA0)
        local r = fn(idxn, out)
        print(('[fdiag] friendid(%d) ret=%d'):format(idxn, r))
        -- status_update_dispatch reads: +0x00/+0x04 identity,
        -- +0x10/+0x14 timestamps, +0x9C the field compared against
        -- record[0x18] as ((val >> 13) & 0x3F).
        for _, o in ipairs({0x00, 0x04, 0x10, 0x14, 0x9C}) do
            local v = tonumber(out[o/4])
            print(('   +0x%02X = 0x%08X%s'):format(o, v,
                o == 0x9C and (('   (>>13)&0x3F = 0x%02X'):format(math.floor(v/8192) % 64)) or ''))
        end
        local iv_lo = tonumber(ffi.cast('uint32_t*', polcore_base + 0xAA848)[0])
        local iv_hi = tonumber(ffi.cast('uint32_t*', polcore_base + 0xAA84C)[0])
        print(('[fdiag] IV lo=0x%08X hi=0x%08X'):format(iv_lo, iv_hi))
        return
    end

    -- /fdiag polb64 <text> — decode text with polcore's codec (FUN_100078A0)
    -- Verifies our Python encoder produces the bytes polcore actually sees.
    -----------------------------------------------------------------
    if cmd == 'polb64' then
        local txt = args[3]
        if not txt then print('[fdiag] Usage: /fdiag polb64 <text>'); return end
        local src = ffi.new('char[512]')
        ffi.copy(src, txt)
        local dst = ffi.new('uint8_t[256]')
        local fn = ffi.cast('void (__cdecl*)(void*, void*, int)', polcore_base + 0x78A0)
        fn(src, dst, #txt)
        local n = math.floor(#txt / 4) * 3
        local out = {}
        for i = 0, n - 1 do out[#out+1] = ('%02x'):format(tonumber(dst[i])) end
        print(('[fdiag] polb64 %d chars -> %d bytes'):format(#txt, n))
        for i = 1, #out, 32 do
            print('  ' .. table.concat(out, '', i, math.min(i+31, #out)))
        end
        return
    end

    -- /fdiag nickdec <text> — decode an IRC nick to its 64-bit POL id
    -- /fdiag nickenc <lo> <hi> — encode a 64-bit POL id to an IRC nick
    --
    -- polcore+0x1A390 is a bidirectional codec:
    --   decode: fn(text, 0, &id64, 0x80000000)
    --   encode: fn(0, outbuf, &id64, 0)
    -- IRC nicks on the POL push channel are encoded account ids, not names,
    -- which is why plain nicks in injected lines are ignored.
    -----------------------------------------------------------------
    if cmd == 'nickdec' then
        local txt = args[3]
        if not txt then print('[fdiag] Usage: /fdiag nickdec <text>'); return end
        local sbuf = ffi.new('char[64]')
        ffi.copy(sbuf, txt)
        local id = ffi.new('uint32_t[2]')
        local fn = ffi.cast('int (__cdecl*)(void*, void*, void*, uint32_t)', polcore_base + 0x1A390)
        local r = fn(sbuf, nil, id, 0x80000000)
        print(('[fdiag] nickdec %q -> lo=0x%08X hi=0x%08X (ret=%d)'):format(
            txt, tonumber(id[0]), tonumber(id[1]), r))
        return
    end

    if cmd == 'nickenc' then
        local lo = tonumber(args[3]) or 0
        local hi = tonumber(args[4]) or 0
        local id = ffi.new('uint32_t[2]')
        id[0] = lo; id[1] = hi
        local out = ffi.new('char[64]')
        local fn = ffi.cast('int (__cdecl*)(void*, void*, void*, uint32_t)', polcore_base + 0x1A390)
        local r = fn(nil, out, id, 0)
        print(('[fdiag] nickenc lo=0x%08X hi=0x%08X -> %q (ret=%d)'):format(lo, hi, ffi.string(out), r))
        return
    end

    -- /fdiag polstate — dump POL connection router state
    -----------------------------------------------------------------
    if cmd == 'polstate' then
        local d = function(off) return tonumber(ffi.cast('uint32_t*', polcore_base + off)[0]) end
        local st = d(0x99408)
        print(('[fdiag] router state DAT_10099408 = 0x%08X (%d)'):format(st, tonumber(ffi.cast('int32_t', st))))
        print(('[fdiag]   DAT_10099414 mode      = %d'):format(d(0x99414)))
        print(('[fdiag]   DAT_10099C80 class     = %d'):format(d(0x99C80)))
        print(('[fdiag]   DAT_10099244 initflag  = %d'):format(d(0x99244)))
        print(('[fdiag]   DAT_1009940C errcode   = 0x%08X'):format(d(0x9940C)))
        print(('[fdiag]   DAT_10099250 connslot  = 0x%08X'):format(d(0x99250)))
        print(('[fdiag]   push buf DAT_103E9290  = 0x%08X'):format(d(0x3E9290)))
        print(('[fdiag]   push state conn+0x208  = 0x%02X'):format(
            tonumber(ffi.cast('uint8_t*', polcore_base + 0x3E5AA8)[0])))
        return
    end

    -- /fdiag setconnconf [mode] — call pol_set_conn_config(mode, cfg)
    --
    -- polcore+0x448A0. Sets DAT_10099414 = mode and RESETS DAT_10099408,
    -- which is the only way to unlatch the router: it sits at -0x2C04 from an
    -- ordering race on first tick, and a negative state matches no case in its
    -- switch, so it can never re-enter on its own.
    --
    -- cfg+0x14 must point at 16 readable bytes (bit-sliced into the session
    -- seed). cfg+0x8/+0xC/+0x10 are only read when DAT_10099C80 is 0 or 2;
    -- they are pointed at a zeroed buffer anyway so a class change cannot
    -- deref null.
    -----------------------------------------------------------------
    if cmd == 'setconnconf' then
        local mode = tonumber(args[3]) or 1
        -- Module-level refs: ffi.new memory is GC-owned, and polcore keeps no
        -- copy of cfg+0x14, so these must outlive the call.
        _G.__fdiag_seed = _G.__fdiag_seed or ffi.new('uint8_t[16]')
        _G.__fdiag_pad  = _G.__fdiag_pad  or ffi.new('uint8_t[64]')
        _G.__fdiag_cfg  = _G.__fdiag_cfg  or ffi.new('uint32_t[8]')
        local padaddr = tonumber(ffi.cast('uint32_t', _G.__fdiag_pad))
        for i = 0, 7 do _G.__fdiag_cfg[i] = padaddr end
        _G.__fdiag_cfg[5] = tonumber(ffi.cast('uint32_t', _G.__fdiag_seed))
        local before = tonumber(ffi.cast('uint32_t*', polcore_base + 0x99408)[0])
        local addr = polcore_base + 0x448A0
        print(('[fdiag] pol_set_conn_config(mode=%d, cfg=0x%08X) at 0x%08X'):format(
            mode, tonumber(ffi.cast('uint32_t', _G.__fdiag_cfg)), addr))
        local fn = ffi.cast('int (__cdecl*)(int, void*)', addr)
        local r = fn(mode, _G.__fdiag_cfg)
        local after = tonumber(ffi.cast('uint32_t*', polcore_base + 0x99408)[0])
        print(('[fdiag] returned %d; state 0x%08X -> 0x%08X, mode=%d'):format(
            r, before, after, tonumber(ffi.cast('uint32_t*', polcore_base + 0x99414)[0])))
        return
    end

    -- /fdiag pumprouter [n] — step pol_msg_router (polcore+0x44A50) n times
    --
    -- Stops early on a negative state: those are terminal and match no case in
    -- the switch, so further pumping only spins.
    -----------------------------------------------------------------
    if cmd == 'pumprouter' then
        local n = tonumber(args[3]) or 1
        local fn = ffi.cast('int (__cdecl*)()', polcore_base + 0x44A50)
        local sp = ffi.cast('int32_t*', polcore_base + 0x99408)
        local last = nil
        for i = 1, n do
            local r = fn()
            local st = tonumber(sp[0])
            if st ~= last then
                print(('[fdiag] pump %d: ret=%d state=0x%08X (%d) push=0x%08X'):format(
                    i, r, st, st, tonumber(ffi.cast('uint32_t*', polcore_base + 0x3E9290)[0])))
                last = st
            end
            if st < 0 then
                print(('[fdiag] terminal state %d after %d pumps; stopping'):format(st, i))
                break
            end
        end
        print(('[fdiag] final state = %d'):format(tonumber(sp[0])))
        return
    end

    -- /fdiag callfn <addr> [arg1] [arg2] — call cdecl function at address
    -----------------------------------------------------------------
    if cmd == 'callfn' then
        local addr = tonumber(args[3])
        if not addr then
            print('[fdiag] Usage: /fdiag callfn <address> [arg1] [arg2]')
            return
        end
        local a1 = tonumber(args[4])
        local a2 = tonumber(args[5])
        if a2 then
            local fn = ffi.cast('int (__cdecl*)(int, int)', addr)
            print(('[fdiag] Calling 0x%08X(%d, %d)...'):format(addr, a1, a2))
            local r = fn(a1, a2)
            print(('[fdiag] Returned: %d (0x%08X)'):format(r, r))
        elseif a1 then
            local fn = ffi.cast('int (__cdecl*)(int)', addr)
            print(('[fdiag] Calling 0x%08X(%d)...'):format(addr, a1))
            local r = fn(a1)
            print(('[fdiag] Returned: %d (0x%08X)'):format(r, r))
        else
            local fn = ffi.cast('int (__cdecl*)()', addr)
            print(('[fdiag] Calling 0x%08X()...'):format(addr))
            local r = fn()
            print(('[fdiag] Returned: %d (0x%08X)'):format(r, r))
        end
        return
    end

    -- /fdiag spawnthread <addr> [arg] — create a thread with entry point at addr
    -----------------------------------------------------------------
    if cmd == 'spawnthread' then
        local addr = tonumber(args[3])
        if not addr then
            print('[fdiag] Usage: /fdiag spawnthread <entry_addr> [arg]')
            return
        end
        local arg = tonumber(args[4]) or 0
        local tid_buf = ffi.new('uint32_t[1]')
        local entry = ffi.cast('THREAD_START_ROUTINE', addr)
        print(('[fdiag] Creating thread: entry=0x%08X arg=0x%08X'):format(addr, arg))
        local h = ffi.C.CreateThread(nil, 0, entry, ffi.cast('void*', arg), 0, tid_buf)
        if h ~= nil then
            print(('[fdiag] Thread created: handle=0x%08X tid=%d'):format(
                tonumber(ffi.cast('uint32_t', h)), tid_buf[0]))
        else
            print('[fdiag] CreateThread FAILED')
        end
        return
    end

    -- /fdiag tickslot <idx>  → call per-slot state machine at +0x1E5D0
    -----------------------------------------------------------------
    if cmd == 'tickslot' then
        local slot_idx = tonumber(args[3])
        if not slot_idx or slot_idx < 0 or slot_idx > 3 then
            print('[fdiag] Usage: /fdiag tickslot <0-3>')
            return
        end
        -- Dump slot state before
        local desc_base = polcore_base + 0x404AD0
        local slot = ffi.cast('uint8_t*', desc_base + slot_idx * 0x338)
        print(('[fdiag] Slot %d BEFORE: inuse=%d mode=%d state=%d socket=0x%08X'):format(
            slot_idx, slot[0], slot[0x08], slot[0x09], ffi.cast('int32_t*', slot + 4)[0]))

        -- Call +0x1E5D0(slot_idx)
        local fn = ffi.cast('int (__cdecl*)(int)', polcore_base + 0x1E5D0)
        print(('[fdiag] Calling per-slot SM at polcore+0x1E5D0 with slot_idx=%d...'):format(slot_idx))
        local result = fn(slot_idx)
        print(('[fdiag] Result: %d'):format(result))

        -- Dump slot state after
        print(('[fdiag] Slot %d AFTER: inuse=%d mode=%d state=%d socket=0x%08X'):format(
            slot_idx, slot[0], slot[0x08], slot[0x09], ffi.cast('int32_t*', slot + 4)[0]))

        -- Show host bytes if changed
        local host_bytes = {}
        for j = 0, 19 do
            table.insert(host_bytes, ('%02X'):format(slot[0x24 + j]))
        end
        print(('[fdiag] host[+0x24]: %s'):format(table.concat(host_bytes, ' ')))
        return
    end

    -- /fdiag connect <port> — CallerB + write sockaddr + tickslot atomically
    -----------------------------------------------------------------
    if cmd == 'connect' then
        local port = tonumber(args[3]) or 51222
        local desc_base = polcore_base + 0x404AD0

        -- Write sockaddr FIRST (before CallerB, so state 0 handler sees it)
        local sa = ffi.cast('uint8_t*', polcore_base + 0x404AB8)
        sa[0] = 2; sa[1] = 0
        sa[2] = bit.band(bit.rshift(port, 8), 0xFF)
        sa[3] = bit.band(port, 0xFF)
        sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1
        for i = 8, 19 do sa[i] = 0 end
        print(('[fdiag] Wrote sockaddr: port=%d, IP=127.0.0.1'):format(port))

        -- CallerB
        local callerb = ffi.cast('int (__cdecl*)()', polcore_base + 0x22210)
        local slot_idx = callerb()
        print(('[fdiag] CallerB returned slot %d'):format(slot_idx))
        if slot_idx < 0 then
            print('[fdiag] No free slot!')
            return
        end

        -- Verify sockaddr still present (check if CallerB cleared it)
        local sa_check = ffi.cast('uint16_t*', polcore_base + 0x404AB8)
        if sa_check[0] == 0 then
            print('[fdiag] WARNING: sockaddr was cleared by CallerB! Rewriting...')
            sa[0] = 2; sa[1] = 0
            sa[2] = bit.band(bit.rshift(port, 8), 0xFF)
            sa[3] = bit.band(port, 0xFF)
            sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1
            for i = 8, 19 do sa[i] = 0 end
        end

        -- Tick the slot multiple times to advance through states
        local tick_fn = ffi.cast('int (__cdecl*)(int)', polcore_base + 0x1E5D0)
        for tick = 1, 5 do
            local slot = ffi.cast('uint8_t*', desc_base + slot_idx * 0x338)
            local mode = slot[0x08]
            local state = slot[0x09]
            local sock = ffi.cast('int32_t*', slot + 4)[0]
            print(('[fdiag] Tick %d: mode=%d state=%d socket=0x%08X'):format(tick, mode, state, sock))
            if slot[0] == 0 then
                print('[fdiag] Slot freed — aborting')
                break
            end

            -- Re-write sockaddr before each tick (in case it gets cleared)
            sa[0] = 2; sa[1] = 0
            sa[2] = bit.band(bit.rshift(port, 8), 0xFF)
            sa[3] = bit.band(port, 0xFF)
            sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1
            for i = 8, 19 do sa[i] = 0 end

            local result = tick_fn(slot_idx)

            -- Re-read state after tick
            local new_state = slot[0x09]
            local new_sock = ffi.cast('int32_t*', slot + 4)[0]
            print(('[fdiag] Tick %d result: %d (now state=%d sock=0x%08X)'):format(tick, result, new_state, new_sock))

            -- After create_connect (state was 3, now 4): dump conn_struct + check socket
            if state == 3 and new_state >= 4 and new_sock > 0 then
                -- Dump conn_struct
                local cs_head = ffi.cast('uint32_t*', 0x103E5820)[0]
                if cs_head ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', cs_head), 0x20) == 0 then
                    local cs = ffi.cast('uint8_t*', cs_head)
                    local hex = {}
                    for j = 0, 31 do table.insert(hex, ('%02X'):format(cs[j])) end
                    print(('[fdiag] conn_struct at 0x%08X: %s'):format(cs_head, table.concat(hex, ' ')))
                    local family = ffi.cast('uint16_t*', cs_head + 4)[0]
                    local port_net = ffi.cast('uint16_t*', cs_head + 6)[0]
                    local port_h = bit.bor(bit.lshift(bit.band(port_net, 0xFF), 8), bit.rshift(port_net, 8))
                    local ip = ('%d.%d.%d.%d'):format(cs[8], cs[9], cs[10], cs[11])
                    print(('[fdiag] conn sockaddr: family=%d port=%d ip=%s'):format(family, port_h, ip))
                else
                    print(('[fdiag] conn_struct head=0x%08X'):format(cs_head))
                end

                -- Check socket with select() and getpeername()
                local sock_h = ffi.cast('uint32_t', new_sock)
                -- select: check writable (connected) and exceptfds (error)
                local wfds = ffi.new('fd_set_t')
                local efds = ffi.new('fd_set_t')
                wfds.fd_count = 1; wfds.fd_array[0] = sock_h
                efds.fd_count = 1; efds.fd_array[0] = sock_h
                local tv = ffi.new('timeval_t', {0, 0})
                local sel_ret = ws2.select(0, nil, wfds, efds, tv)
                print(('[fdiag] select(write+except): ret=%d wfds_count=%d efds_count=%d'):format(
                    sel_ret, wfds.fd_count, efds.fd_count))
                if sel_ret < 0 then
                    print(('[fdiag] select error: WSA=%d'):format(ws2.WSAGetLastError()))
                end
                -- getpeername to see connected remote address
                local name = ffi.new('uint8_t[16]')
                local namelen = ffi.new('int[1]', {16})
                local gpn_ret = ws2.getpeername(sock_h, name, namelen)
                if gpn_ret == 0 then
                    local gpn_port = name[2] * 256 + name[3]
                    local gpn_ip = ('%d.%d.%d.%d'):format(name[4], name[5], name[6], name[7])
                    print(('[fdiag] getpeername: port=%d ip=%s'):format(gpn_port, gpn_ip))
                else
                    print(('[fdiag] getpeername failed: WSA=%d'):format(ws2.WSAGetLastError()))
                end

                -- Direct call to +0x10800 to see what it returns
                local check_fn = ffi.cast('int (__cdecl*)(uint32_t)', polcore_base + 0x10800)
                local check_ret = check_fn(sock_h)
                print(('[fdiag] check_connect(0x%X) = %d'):format(sock_h, check_ret))
            end

            if result < 0 then
                print(('[fdiag] Error %d — stopping'):format(result))
                break
            end
            if new_sock ~= -1 and new_sock ~= 0 then
                print('[fdiag] Socket created! Continuing to check...')
            end
        end

        -- Final state
        local slot = ffi.cast('uint8_t*', desc_base + slot_idx * 0x338)
        print(('[fdiag] Final: inuse=%d mode=%d state=%d socket=0x%08X'):format(
            slot[0], slot[0x08], slot[0x09], ffi.cast('int32_t*', slot + 4)[0]))
        local host_bytes = {}
        for j = 0, 19 do table.insert(host_bytes, ('%02X'):format(slot[0x24 + j])) end
        print(('[fdiag] host[+0x24]: %s'):format(table.concat(host_bytes, ' ')))
        return
    end

    -----------------------------------------------------------------
    -- PATCHCONNECT: Patch create_connect (+0x103A0) to use arg2's sockaddr
    -- for the Winsock connect() call instead of building one from arg1=0.
    --
    -- Original bytes at +0x10482 (12 bytes):
    --   89 5E 08          MOV [ESI+0x08], EBX     ; sin_addr = 0
    --   66 C7 00 02 00    MOV WORD [EAX], 2       ; sin_family = AF_INET
    --   66 89 56 06       MOV [ESI+0x06], DX      ; sin_port = htons(0)
    --
    -- At +0x10482, stack context:
    --   EAX = &conn_struct[0x04] (sockaddr for connect)
    --   ESI = conn_struct base
    --   3 pushes already on stack for connect(socket, &sockaddr, 16)
    --   arg2 (&slot.sockaddr) at [ESP+0x58]
    -----------------------------------------------------------------
    if cmd == 'patchconnect' then
        local patch_site = polcore_base + 0x10482
        local return_addr = polcore_base + 0x1048E  -- CALL connect

        -- Verify original bytes
        local ps = ffi.cast('uint8_t*', patch_site)
        local expected = {0x89, 0x5E, 0x08, 0x66, 0xC7, 0x00, 0x02, 0x00, 0x66, 0x89, 0x56, 0x06}
        local match = true
        for j = 0, 11 do
            if ps[j] ~= expected[j+1] then match = false; break end
        end
        if not match then
            local hex = {}
            for j = 0, 11 do table.insert(hex, ('%02X'):format(ps[j])) end
            print('[fdiag] Bytes at +0x10482 don\'t match expected pattern!')
            print('[fdiag] Got:      ' .. table.concat(hex, ' '))
            print('[fdiag] Expected: 89 5E 08 66 C7 00 02 00 66 89 56 06')
            print('[fdiag] Already patched or wrong version?')
            return
        end

        -- Allocate code cave (64 bytes: 32 code + 32 metadata)
        local MEM_COMMIT = 0x1000
        local MEM_RESERVE = 0x2000
        local PAGE_EXECUTE_READWRITE = 0x40
        local cave = ffi.C.VirtualAlloc(nil, 64, bit.bor(MEM_COMMIT, MEM_RESERVE), PAGE_EXECUTE_READWRITE)
        if cave == nil then
            print('[fdiag] VirtualAlloc for cave failed!')
            return
        end
        local cave_addr = tonumber(ffi.cast('uint32_t', cave))
        local cp = ffi.cast('uint8_t*', cave)

        -- Write cave code (28 bytes):
        --   MOV ECX, [ESP+0x58]     ; load arg2 (&slot.sockaddr)
        --   MOV WORD [EAX], 0x0002  ; sin_family = AF_INET
        --   MOV DX, [ECX+2]         ; slot sin_port
        --   MOV [ESI+0x06], DX      ; conn_struct sin_port
        --   MOV EDX, [ECX+4]        ; slot sin_addr (4 bytes)
        --   MOV [ESI+0x08], EDX     ; conn_struct sin_addr
        --   JMP return_addr
        local ci = 0
        local function wb(b) cp[ci] = b; ci = ci + 1 end

        -- MOV ECX, [ESP+0x58] = 8B 4C 24 58
        wb(0x8B); wb(0x4C); wb(0x24); wb(0x58)
        -- MOV WORD [EAX], 0x0002 = 66 C7 00 02 00
        wb(0x66); wb(0xC7); wb(0x00); wb(0x02); wb(0x00)
        -- MOV DX, [ECX+2] = 66 8B 51 02
        wb(0x66); wb(0x8B); wb(0x51); wb(0x02)
        -- MOV [ESI+0x06], DX = 66 89 56 06
        wb(0x66); wb(0x89); wb(0x56); wb(0x06)
        -- MOV EDX, [ECX+4] = 8B 51 04
        wb(0x8B); wb(0x51); wb(0x04)
        -- MOV [ESI+0x08], EDX = 89 56 08
        wb(0x89); wb(0x56); wb(0x08)
        -- JMP return_addr = E9 rel32
        wb(0xE9)
        local rel = return_addr - (cave_addr + ci + 4)
        ffi.cast('int32_t*', cave_addr + ci)[0] = rel
        ci = ci + 4

        -- Save original bytes at cave+32 and patch_site at cave+44
        for j = 0, 11 do ffi.cast('uint8_t*', cave_addr + 32)[j] = expected[j+1] end
        ffi.cast('uint32_t*', cave_addr + 44)[0] = patch_site

        print(('[fdiag] Cave at 0x%08X (%d bytes):'):format(cave_addr, ci))
        local hex = {}
        for j = 0, ci - 1 do table.insert(hex, ('%02X'):format(cp[j])) end
        print('[fdiag]   ' .. table.concat(hex, ' '))

        -- Patch: JMP cave (5 bytes) + 7 NOPs
        local oldProt = ffi.new('uint32_t[1]')
        if ffi.C.VirtualProtect(ffi.cast('void*', patch_site), 12, 0x40, oldProt) ~= 0 then
            ps[0] = 0xE9  -- JMP rel32
            ffi.cast('int32_t*', patch_site + 1)[0] = cave_addr - (patch_site + 5)
            for j = 5, 11 do ps[j] = 0x90 end  -- NOP
            ffi.C.VirtualProtect(ffi.cast('void*', patch_site), 12, oldProt[0], oldProt)

            -- Store cave addr for later reference
            ffi.cast('uint32_t*', polcore_base + 0x404A90)[0] = cave_addr

            print(('[fdiag] Patched +0x10482: JMP 0x%08X (7 NOPs)'):format(cave_addr))
            print('[fdiag] create_connect() will now use slot sockaddr for connect target')
            print('[fdiag] Use /fdiag connect to test')
        else
            print('[fdiag] VirtualProtect failed!')
        end
        return
    end

    -----------------------------------------------------------------
    -- PATCHCONNECT2: Extended cave — copies sockaddr from arg2 AND handles
    -- non-blocking connect WSAEWOULDBLOCK in the cave itself.
    --
    -- Patches 21 bytes at +0x10482..+0x10496 (sockaddr fill + CALL connect
    -- + TEST/JGE) with JMP to cave + NOPs. Cave does:
    --   1. Copy sin_family/sin_port/sin_addr from slot sockaddr (arg2)
    --   2. CALL connect (uses pre-pushed args on stack)
    --   3. If result >= 0 → JMP success_path (+0x104B3)
    --   4. If WSAEWOULDBLOCK → JMP success_path
    --   5. Else → JMP error_path (+0x10497)
    -----------------------------------------------------------------
    if cmd == 'patchconnect2' then
        local patch_start = polcore_base + 0x10482
        local patch_len = 21  -- +0x10482 through +0x10496
        local success_addr = polcore_base + 0x104B3
        local error_addr = polcore_base + 0x10497
        local connect_thunk = polcore_base + 0x63DA8
        local wsagle_thunk = polcore_base + 0x63D6C

        local ps = ffi.cast('uint8_t*', patch_start)

        -- Check current state: fresh (0x89) or already patched (0xE9)
        if ps[0] == 0xE9 then
            print('[fdiag] +0x10482 already has JMP (old patchconnect or patchconnect2)')
            print('[fdiag] Will overwrite with new cave + extend NOP region to 21 bytes')
        elseif ps[0] == 0x89 then
            -- Verify original bytes (first 12)
            local expected = {0x89, 0x5E, 0x08, 0x66, 0xC7, 0x00, 0x02, 0x00, 0x66, 0x89, 0x56, 0x06}
            local match = true
            for j = 0, 11 do
                if ps[j] ~= expected[j+1] then match = false; break end
            end
            if not match then
                local hex = {}
                for j = 0, 20 do table.insert(hex, ('%02X'):format(ps[j])) end
                print('[fdiag] Bytes at +0x10482 don\'t match expected!')
                print('[fdiag] Got: ' .. table.concat(hex, ' '))
                return
            end
            print('[fdiag] Original bytes verified at +0x10482')
        else
            local hex = {}
            for j = 0, 20 do table.insert(hex, ('%02X'):format(ps[j])) end
            print('[fdiag] Unexpected byte at +0x10482: ' .. ('%02X'):format(ps[0]))
            print('[fdiag] Dump: ' .. table.concat(hex, ' '))
            return
        end

        -- Allocate cave (256 bytes: ~106 code + diagnostics at +128)
        local cave = ffi.C.VirtualAlloc(nil, 256, 0x3000, 0x40)
        if cave == nil then
            print('[fdiag] VirtualAlloc failed!'); return
        end
        local cave_addr = tonumber(ffi.cast('uint32_t', cave))
        local cp = ffi.cast('uint8_t*', cave)

        local ci = 0
        local function wb(b) cp[ci] = b; ci = ci + 1 end
        local function w32(target)
            local from = cave_addr + ci + 4
            ffi.cast('int32_t*', cave_addr + ci)[0] = target - from
            ci = ci + 4
        end

        -- Diagnostic layout at cave+128..159 (AFTER code, to avoid overlap):
        --   +128: hit counter (4B)
        --   +132: EDI (socket handle at entry, 4B)
        --   +136: EAX (sockaddr ptr at entry, 4B)
        --   +140: ESI (conn_struct ptr at entry, 4B)
        --   +144: connect return (4B)
        --   +148: WSAGetLastError (4B)
        --   +152: sockaddr bytes 0-3 (family+port, 4B)
        --   +156: sockaddr bytes 4-7 (ip addr, 4B)
        local D = 128  -- diagnostic base offset

        -- PART 0: Store diagnostics: INC hit counter, store EDI, EAX, ESI
        -- INC [cave+D+0]
        wb(0xFF); wb(0x05)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 0; ci = ci + 4  -- ci=6
        -- MOV [cave+D+4], EDI  (89 3D imm32)
        wb(0x89); wb(0x3D)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 4; ci = ci + 4  -- ci=12
        -- MOV [cave+D+8], EAX  (A3 imm32)
        wb(0xA3)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 8; ci = ci + 4  -- ci=17
        -- MOV [cave+D+12], ESI  (89 35 imm32)
        wb(0x89); wb(0x35)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 12; ci = ci + 4  -- ci=23

        -- PART 1: Copy sockaddr from arg2 (slot) to conn_struct
        -- At entry: EAX=&conn_struct[4], ESI=conn_struct, EDI=socket
        -- arg2 at [ESP+0x58]
        wb(0x8B); wb(0x4C); wb(0x24); wb(0x58)  -- MOV ECX, [ESP+0x58]       ci=27
        wb(0x66); wb(0xC7); wb(0x00); wb(0x02); wb(0x00) -- MOV WORD [EAX], 2  ci=32
        wb(0x66); wb(0x8B); wb(0x51); wb(0x02)  -- MOV DX, [ECX+2]           ci=36
        wb(0x66); wb(0x89); wb(0x56); wb(0x06)  -- MOV [ESI+6], DX           ci=40
        wb(0x8B); wb(0x51); wb(0x04)             -- MOV EDX, [ECX+4]          ci=43
        wb(0x89); wb(0x56); wb(0x08)             -- MOV [ESI+8], EDX          ci=46

        -- Store filled sockaddr at cave+D+24,+D+28 for verification
        -- MOV ECX, [EAX]   (family+port, first 4 bytes of sockaddr)
        wb(0x8B); wb(0x08)                       -- MOV ECX, [EAX]            ci=48
        -- MOV [cave+D+24], ECX
        wb(0x89); wb(0x0D)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 24; ci = ci + 4  -- ci=54
        -- MOV ECX, [EAX+4]  (ip addr)
        wb(0x8B); wb(0x48); wb(0x04)             -- MOV ECX, [EAX+4]          ci=57
        -- MOV [cave+D+28], ECX
        wb(0x89); wb(0x0D)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 28; ci = ci + 4  -- ci=63

        -- PART 2: CALL connect (3 args already on stack from original code)
        wb(0xE8); w32(connect_thunk)             -- CALL connect_thunk        ci=68

        -- Store connect return at cave+D+16
        wb(0xA3)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 16; ci = ci + 4  -- ci=73

        -- PART 3: Check result
        wb(0x85); wb(0xC0)                       -- TEST EAX, EAX             ci=75
        -- JGE to success: need to calculate forward...
        -- success label will be after the error JMP
        -- For now put placeholder, fixup later
        wb(0x7D)                                 --                           ci=76
        local jge_fixup_pos = ci
        wb(0x00)                                 --                           ci=77

        -- PART 4: WSAEWOULDBLOCK check
        wb(0xE8); w32(wsagle_thunk)              -- CALL WSAGetLastError       ci=82
        -- Store WSAGetLastError result at cave+D+20
        wb(0xA3)
        ffi.cast('uint32_t*', cave_addr + ci)[0] = cave_addr + D + 20; ci = ci + 4  -- ci=87

        wb(0x3D); wb(0x33); wb(0x27); wb(0x00); wb(0x00) -- CMP EAX, 10035    ci=92
        wb(0x74)                                 --                           ci=93
        local je_fixup_pos = ci
        wb(0x00)                                 --                           ci=94

        -- PART 5: Real error
        wb(0xE9); w32(error_addr)                -- JMP error_path            ci=99

        -- PART 6: success label (ci=99)
        local success_ci = ci
        cp[jge_fixup_pos] = success_ci - (jge_fixup_pos + 1)  -- fixup JGE
        cp[je_fixup_pos] = success_ci - (je_fixup_pos + 1)    -- fixup JE
        wb(0x31); wb(0xC0)                       -- XOR EAX, EAX              ci=101
        wb(0xE9); w32(success_addr)              -- JMP success_path          ci=106

        -- Clear diagnostic slots (at cave+D through cave+D+31)
        for i = D, D + 31, 4 do
            ffi.cast('uint32_t*', cave_addr + i)[0] = 0xDEADBEEF
        end
        ffi.cast('uint32_t*', cave_addr + D)[0] = 0  -- hit counter starts at 0

        -- Print cave
        print(('[fdiag] Cave at 0x%08X (%d bytes):'):format(cave_addr, ci))
        local hex = {}
        for j = 0, ci - 1 do table.insert(hex, ('%02X'):format(cp[j])) end
        print('[fdiag]   ' .. table.concat(hex, ' '))

        -- Verify jump targets
        print(('[fdiag] CALL connect → thunk 0x%08X'):format(connect_thunk))
        print(('[fdiag] CALL WSAGetLastError → thunk 0x%08X'):format(wsagle_thunk))
        print(('[fdiag] JMP error → 0x%08X (+0x10497)'):format(error_addr))
        print(('[fdiag] JMP success → 0x%08X (+0x104B3)'):format(success_addr))

        -- Patch 21 bytes: JMP cave (5) + NOP x16
        local oldProt = ffi.new('uint32_t[1]')
        if ffi.C.VirtualProtect(ffi.cast('void*', patch_start), patch_len, 0x40, oldProt) ~= 0 then
            ps[0] = 0xE9
            ffi.cast('int32_t*', patch_start + 1)[0] = cave_addr - (patch_start + 5)
            for j = 5, patch_len - 1 do ps[j] = 0x90 end
            ffi.C.VirtualProtect(ffi.cast('void*', patch_start), patch_len, oldProt[0], oldProt)

            -- Store cave addr
            ffi.cast('uint32_t*', polcore_base + 0x404A90)[0] = cave_addr

            -- Verify patch
            local phex = {}
            for j = 0, patch_len - 1 do table.insert(phex, ('%02X'):format(ps[j])) end
            print(('[fdiag] Patched %d bytes at +0x10482: %s'):format(patch_len, table.concat(phex, ' ')))
            print('[fdiag] WSAEWOULDBLOCK now handled in cave')
            print('[fdiag] Use /fdiag connect to test')
        else
            print('[fdiag] VirtualProtect failed!')
        end
        return
    end

    -- /fdiag testsock [port] [nb] — create fresh socket, try connect to 127.0.0.1:port
    -- Pass 'nb' as 3rd arg to set non-blocking (matching polcore's setup)
    if cmd == 'testsock' then
        local port = tonumber(args[3]) or 51222
        local nonblock = (args[4] == 'nb')
        -- Create socket
        local s = ws2.socket(2, 1, 0)  -- AF_INET, SOCK_STREAM, 0
        print(('[fdiag] socket() = 0x%08X'):format(tonumber(s)))
        if s == 0xFFFFFFFF then
            print(('[fdiag] socket failed: WSA=%d'):format(ws2.WSAGetLastError()))
            return
        end
        -- Optional: set non-blocking (same as polcore's setup_socket)
        if nonblock then
            local flag = ffi.new('uint32_t[1]', {1})
            local ioret = ffi.C.VirtualProtect  -- dummy, need ioctlsocket
            -- Use the polcore ioctlsocket thunk
            ffi.cdef'int __stdcall ioctlsocket(uint32_t s, long cmd, uint32_t* argp);'
            local ioret = ws2.ioctlsocket(s, 0x8004667E, flag)  -- FIONBIO
            print(('[fdiag] ioctlsocket(FIONBIO) = %d'):format(ioret))
        end
        -- Build sockaddr
        local sa = ffi.new('uint8_t[16]')
        sa[0] = 2; sa[1] = 0  -- AF_INET
        sa[2] = bit.band(bit.rshift(port, 8), 0xFF)
        sa[3] = bit.band(port, 0xFF)
        sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1
        -- Connect
        local ret = ws2.connect(s, sa, 16)
        print(('[fdiag] connect() = %d'):format(ret))
        if ret ~= 0 then
            local err = ws2.WSAGetLastError()
            print(('[fdiag] WSAGetLastError = %d'):format(err))
            if err == 10035 then print('[fdiag] WSAEWOULDBLOCK (expected for non-blocking)') end
            if err == 10048 then print('[fdiag] WSAEADDRINUSE (unexpected!)') end
        else
            print('[fdiag] Connected OK!')
        end
        -- Check with getpeername
        local name = ffi.new('uint8_t[16]')
        local namelen = ffi.new('int[1]', {16})
        local gpn = ws2.getpeername(s, name, namelen)
        if gpn == 0 then
            print(('[fdiag] getpeername: %d.%d.%d.%d:%d'):format(
                name[4], name[5], name[6], name[7], name[2]*256+name[3]))
        end
        ws2.closesocket(s)
        print('[fdiag] Socket closed')

        -- Also test via polcore IAT thunk
        local s2 = ws2.socket(2, 1, 0)
        print(('[fdiag] IAT test: socket() = 0x%08X'):format(tonumber(s2)))
        local connect_via_iat = ffi.cast('int (__stdcall*)(uint32_t, const uint8_t*, int)',
            polcore_base + 0x63DA8)
        local sa2 = ffi.new('uint8_t[16]')
        sa2[0] = 2; sa2[1] = 0
        sa2[2] = bit.band(bit.rshift(port, 8), 0xFF)
        sa2[3] = bit.band(port, 0xFF)
        sa2[4] = 127; sa2[5] = 0; sa2[6] = 0; sa2[7] = 1
        local ret2 = connect_via_iat(s2, sa2, 16)
        print(('[fdiag] IAT connect() = %d'):format(ret2))
        if ret2 ~= 0 then
            print(('[fdiag] IAT WSAGetLastError = %d'):format(ws2.WSAGetLastError()))
        else
            print('[fdiag] IAT Connected OK!')
        end
        ws2.closesocket(s2)

        -- Test: is the thunk bind() or connect()?
        -- bind(socket, {0.0.0.0:0}, 16) should succeed
        -- connect(socket, {0.0.0.0:0}, 16) should fail
        local s3 = ws2.socket(2, 1, 0)
        print(('[fdiag] bind/connect test: socket() = 0x%08X'):format(tonumber(s3)))
        local sa3 = ffi.new('uint8_t[16]', {2,0, 0,0, 0,0,0,0})  -- {AF_INET, port=0, IP=0.0.0.0}
        local ret3 = connect_via_iat(s3, sa3, 16)
        local err3 = (ret3 ~= 0) and ws2.WSAGetLastError() or 0
        print(('[fdiag] thunk({0.0.0.0:0}) = %d, WSA=%d'):format(ret3, err3))
        if ret3 == 0 then
            -- If success with 0.0.0.0:0, it's bind (connect to 0.0.0.0 would fail)
            print('[fdiag] >>> THUNK IS BIND(), NOT CONNECT! <<<')
            -- Find the real connect thunk (next one: +0x63DAE)
            local next_thunk = polcore_base + 0x63DAE
            local nt_bytes = ffi.cast('uint8_t*', next_thunk)
            print(('[fdiag] Next thunk at +0x63DAE: %02X %02X'):format(nt_bytes[0], nt_bytes[1]))
        else
            print(('[fdiag] thunk to 0.0.0.0:0 failed → likely connect or other (%d)'):format(err3))
        end
        ws2.closesocket(s3)
        return
    end

    -- /fdiag cavediag — read diagnostic values from patchconnect2 cave
    if cmd == 'cavediag' then
        local cave_addr = ffi.cast('uint32_t*', polcore_base + 0x404A90)[0]
        if cave_addr == 0 then
            print('[fdiag] No cave installed (polcore+0x404A90 = 0)')
            return
        end
        print(('[fdiag] Cave at 0x%08X'):format(cave_addr))
        local D = 128  -- diagnostic base in cave
        local rd = function(off) return tonumber(ffi.cast('uint32_t*', cave_addr + D + off)[0]) end
        local rds = function(off) return tonumber(ffi.cast('int32_t*', cave_addr + D + off)[0]) end
        print(('[fdiag] Hit counter: %d'):format(rd(0)))
        print(('[fdiag] EDI (socket): 0x%08X'):format(rd(4)))
        print(('[fdiag] EAX (sockaddr ptr): 0x%08X'):format(rd(8)))
        print(('[fdiag] ESI (conn_struct): 0x%08X'):format(rd(12)))
        local conn_ret = rds(16)
        print(('[fdiag] connect() returned: %d'):format(conn_ret))
        print(('[fdiag] WSAGetLastError: %d'):format(rd(20)))
        -- Decode sockaddr that was passed to connect
        local sa = ffi.cast('uint8_t*', cave_addr + D + 24)
        local family = sa[0] + sa[1] * 256
        local port = sa[2] * 256 + sa[3]
        local ip = ('%d.%d.%d.%d'):format(sa[4], sa[5], sa[6], sa[7])
        print(('[fdiag] sockaddr: family=%d port=%d ip=%s'):format(family, port, ip))
        -- Dump diag area raw
        local hex = {}
        local cp = ffi.cast('uint8_t*', cave_addr + D)
        for j = 0, 31 do table.insert(hex, ('%02X'):format(cp[j])) end
        print('[fdiag] Diag raw: ' .. table.concat(hex, ' '))
        return
    end

    -- /fdiag unpatchconnect — restore original 21 bytes at +0x10482
    -----------------------------------------------------------------
    if cmd == 'unpatchconnect' then
        local patch_start = polcore_base + 0x10482
        local ps = ffi.cast('uint8_t*', patch_start)
        if ps[0] ~= 0xE9 then
            print('[fdiag] +0x10482 is not patched (first byte: ' .. ('%02X'):format(ps[0]) .. ')')
            return
        end
        -- Original 21 bytes: sockaddr fill + CALL bind + TEST/JGE
        -- +0x10482: 89 5E 08           MOV [ESI+8], EBX
        -- +0x10485: 66 C7 00 02 00     MOV WORD [EAX], 2
        -- +0x1048A: 66 89 56 06        MOV [ESI+6], DX
        -- +0x1048E: E8 15 39 05 00     CALL bind (+0x63DA8)
        -- +0x10493: 85 C0              TEST EAX, EAX
        -- +0x10495: 7D 1C              JGE +0x104B3
        local orig = {0x89,0x5E,0x08, 0x66,0xC7,0x00,0x02,0x00, 0x66,0x89,0x56,0x06,
                      0xE8,0x15,0x39,0x05,0x00, 0x85,0xC0, 0x7D,0x1C}
        local oldProt = ffi.new('uint32_t[1]')
        if ffi.C.VirtualProtect(ffi.cast('void*', patch_start), 21, 0x40, oldProt) ~= 0 then
            for j = 0, 20 do ps[j] = orig[j+1] end
            ffi.C.VirtualProtect(ffi.cast('void*', patch_start), 21, oldProt[0], oldProt)
            -- Clear cave addr
            ffi.cast('uint32_t*', polcore_base + 0x404A90)[0] = 0
            local hex = {}
            for j = 0, 20 do table.insert(hex, ('%02X'):format(ps[j])) end
            print(('[fdiag] Restored original 21 bytes at +0x10482: %s'):format(table.concat(hex, ' ')))
        else
            print('[fdiag] VirtualProtect failed!')
        end
        return
    end

    -- /fdiag freeslot N — mark descriptor slot N as free (byte[0]=0)
    -----------------------------------------------------------------
    if cmd == 'freeslot' then
        local n = tonumber(args[3])
        if not n or n < 0 or n > 3 then
            print('[fdiag] Usage: /fdiag freeslot <0-3>')
            return
        end
        local slot_addr = polcore_base + 0x404AD0 + n * 0x338
        local p = ffi.cast('uint8_t*', slot_addr)
        local old = p[0]
        p[0] = 0  -- mark as free
        -- Also reset outer mode and inner state
        p[8] = 0   -- outer mode
        p[9] = 0   -- inner state
        -- Clear socket handle
        ffi.cast('uint32_t*', slot_addr + 4)[0] = 0xFFFFFFFF
        print(('[fdiag] Slot %d: byte[0] %d→0, mode/state reset, socket=-1'):format(n, old))
        return
    end

    -- /fdiag pumpcaller <b|c> — initiate CallerB/C then drive with +0x1E5D0 every frame
    -- /fdiag pumpcaller stop — stop pumping
    -- /fdiag driveslot <N> — drive existing slot N with +0x1E5D0 every frame
    -----------------------------------------------------------------
    if cmd == 'pumpcaller' then
        local which = args[3]
        if which == 'stop' then
            pump_active = false
            print('[fdiag] Pump stopped')
            return
        end
        if which ~= 'b' and which ~= 'c' then
            print('[fdiag] Usage: /fdiag pumpcaller <b|c|stop> [crypto]')
            print('[fdiag]   crypto: init BF key instead of disabling crypto')
            return
        end
        local crypto_mode = (args[4] == 'crypto')
        -- Step 1: Call initiation function to allocate and configure slot
        local init_offsets = {b = 0x22210, c = 0x28330}
        local names = {b = 'CallerB(token)', c = 'CallerC(befriend)'}
        local init_addr = polcore_base + init_offsets[which]
        local init_func = ffi.cast('int (__cdecl*)()', init_addr)
        local slot = init_func()
        print(('[fdiag] %s → slot %d'):format(names[which], slot))
        if slot < 0 then
            print('[fdiag] No free slot! Use /fdiag freeslot N to free stale slots.')
            return
        end
        local slot_addr = polcore_base + 0x404AD0 + slot * 0x338
        local p = ffi.cast('uint8_t*', slot_addr)
        if crypto_mode then
            -- Step 1b-crypto: Init BF key for this slot instead of disabling crypto
            print(('[fdiag] Slot %d: crypto mode — initializing BF key'):format(slot))
            local ctx = p + 0x50
            local sbox_ptr = ffi.cast('uint32_t*', ctx + 0x48)[0]
            if sbox_ptr == 0 then
                local sbox = ffi.C.VirtualAlloc(nil, 0x1000, 0x3000, 0x04)
                if sbox == nil then
                    print('[fdiag] VirtualAlloc for S-box failed! Falling back to no-crypto.')
                    p[0x0B] = 0
                else
                    local sa = tonumber(ffi.cast('uint32_t', sbox))
                    local sp = ffi.cast('uint8_t*', sbox)
                    for i = 0, 0xFFF do sp[i] = 0 end
                    ffi.cast('uint32_t*', ctx + 0x48)[0] = sa
                    print(('[fdiag] Allocated S-box at 0x%08X'):format(sa))
                end
            end
            -- Call BF_init_key with default key "LSBFRIEN"
            local key_buf = ffi.new('uint8_t[8]', {0x4C, 0x53, 0x42, 0x46, 0x52, 0x49, 0x45, 0x4E})
            local bf_init = ffi.cast('void (__cdecl*)(void*, void*)', polcore_base + 0x63EB4)
            bf_init(ffi.cast('void*', ctx), ffi.cast('void*', key_buf))
            -- Verify P-array populated
            local p0 = ffi.cast('uint32_t*', ctx)[0]
            print(('[fdiag] BF_init_key done. P[0]=0x%08X crypto=0x%02X'):format(p0, p[0x0B]))
        else
            -- Step 1b: Disable crypto on the slot (BF key at +0x50 isn't initialized for CallerB/C slots)
            local old_crypto = p[0x0B]
            p[0x0B] = 0
            print(('[fdiag] Slot %d: crypto flag 0x%02X → 0x00 (disabled)'):format(slot, old_crypto))
        end
        -- Step 2: Start driving the slot with per-caller driver every frame
        -- CallerB has its own 9-mode driver at +0x22260 (modes 0-8)
        -- CallerA/C use the generic driver at +0x1E5D0 (modes 0-5)
        local driver_offsets = {b = 0x22260, c = 0x1E5D0}
        pump_driver_addr = polcore_base + driver_offsets[which]
        pump_slot = slot
        pump_count = 0
        pump_last_mode = -1
        pump_last_state = -1
        pump_active = true
        print(('[fdiag] Driving slot %d with +0x%05X every frame (max %d)'):format(slot, driver_offsets[which], pump_max))
        return
    end

    if cmd == 'driveslot' then
        local n = tonumber(args[3])
        if not n or n < 0 or n > 3 then
            print('[fdiag] Usage: /fdiag driveslot <0-3>')
            return
        end
        pump_driver_addr = polcore_base + 0x1E5D0
        pump_slot = n
        pump_count = 0
        pump_last_mode = -1
        pump_last_state = -1
        pump_active = true
        print(('[fdiag] Driving slot %d with +0x1E5D0 every frame (max %d)'):format(n, pump_max))
        return
    end

    -- /fdiag keepalive [secs|stop] — periodic CallerB refresh
    -----------------------------------------------------------------
    if cmd == 'keepalive' then
        local arg = args[3]
        if arg == 'stop' then
            keepalive_active = false
            keepalive_busy = false
            print('[fdiag] Keepalive stopped')
            return
        end
        local interval = tonumber(arg) or 30
        if interval < 5 then interval = 5 end
        keepalive_interval = interval
        keepalive_frame_count = interval * 60  -- fire immediately on first cycle
        keepalive_busy = false
        keepalive_active = true
        print(('[fdiag] Keepalive started: refreshing every %ds (first refresh immediate)'):format(keepalive_interval))
        return
    end

    -- /fdiag writeabs ADDR BYTE — write single byte to absolute address
    -----------------------------------------------------------------
    if cmd == 'writeabs' then
        local addr = tonumber(args[3])
        local val = tonumber(args[4])
        if not addr or not val then
            print('[fdiag] Usage: /fdiag writeabs <addr> <byte_value>')
            return
        end
        local p = ffi.cast('uint8_t*', addr)
        local old = p[0]
        p[0] = bit.band(val, 0xFF)
        print(('[fdiag] [0x%08X]: 0x%02X → 0x%02X'):format(addr, old, p[0]))
        return
    end

    -- /fdiag writesockaddr <port> — write sockaddr to global at 0x10404AB8
    -----------------------------------------------------------------
    if cmd == 'writesockaddr' then
        local port = tonumber(args[3])
        if not port then
            print('[fdiag] Usage: /fdiag writesockaddr <port>')
            return
        end
        local addr = ffi.cast('uint8_t*', polcore_base + 0x404AB8)
        -- Write in HOST byte order (x86 LE). create_connect byte-swaps to network order.
        -- Format matches desc+0x24: family(2B LE) + port(2B LE) + IP(4B LE) + zeros
        addr[0] = 1; addr[1] = 0  -- family marker (overwritten by create_connect to AF_INET=2)
        addr[2] = bit.band(port, 0xFF)                  -- port low byte (LE)
        addr[3] = bit.band(bit.rshift(port, 8), 0xFF)  -- port high byte (LE)
        addr[4] = 1; addr[5] = 0; addr[6] = 0; addr[7] = 0x7F  -- 127.0.0.1 in LE (0x7F000001)
        for i = 8, 19 do addr[i] = 0 end  -- sin_zero
        local bytes = {}
        for i = 0, 19 do table.insert(bytes, ('%02X'):format(addr[i])) end
        print(('[fdiag] Wrote sockaddr to 0x%08X: %s'):format(polcore_base + 0x404AB8, table.concat(bytes, ' ')))
        print(('[fdiag] Port=%d (0x%04X), IP=127.0.0.1'):format(port, port))
        return
    end

    -- /fdiag bfctx [N] — structured BF context dump at desc[N]+0x50
    -- Layout: P-array (18×u32=72B) + S-box ptr (4B) + OFB state (20B) = 96B
    -----------------------------------------------------------------
    if cmd == 'bfctx' or cmd == 'bfkey' then
        local slot_idx = tonumber(args[3]) or 0
        local desc_off = 0x404AD0
        local desc_base = polcore_base + desc_off
        local slot_size = 0x338
        local num_slots = 4

        if slot_idx < 0 or slot_idx >= num_slots then
            print('[fdiag] Slot must be 0-3')
            return
        end

        local slot = ffi.cast('uint8_t*', desc_base + slot_idx * slot_size)
        local crypto = slot[0x0B]
        local mode = slot[0x08]
        local ctx = slot + 0x50

        print(('[fdiag] Slot %d: mode=0x%02X crypto=0x%02X'):format(slot_idx, mode, crypto))
        output(hexdump(ctx, 0x60, ('desc[%d]+0x50 BF context (96B)'):format(slot_idx)))

        -- P-array: 18 × u32 at ctx+0x00..0x47
        local p_arr = ffi.cast('uint32_t*', ctx)
        local all_zero = true
        local p_vals = {}
        for i = 0, 17 do
            local v = p_arr[i]
            if v ~= 0 then all_zero = false end
            table.insert(p_vals, ('%08X'):format(v))
        end
        print(('[fdiag] P-array (18×u32): %s'):format(all_zero and 'ALL ZERO (uninitialized)' or 'POPULATED'))
        if not all_zero then
            for row = 0, 2 do
                local start = row * 6
                local line = {}
                for i = start, math.min(start + 5, 17) do
                    table.insert(line, p_vals[i + 1])
                end
                print(('[fdiag]   P[%02d-%02d]: %s'):format(start, math.min(start + 5, 17), table.concat(line, ' ')))
            end
        end

        -- S-box pointer at ctx+0x48
        local sbox_ptr = ffi.cast('uint32_t*', ctx + 0x48)[0]
        local sbox_status = 'NULL (uninitialized — will crash!)'
        if sbox_ptr ~= 0 then
            if ffi.C.IsBadReadPtr(ffi.cast('void*', sbox_ptr), 0x1000) == 0 then
                -- Check if S-box has non-zero data
                local sp = ffi.cast('uint32_t*', sbox_ptr)
                local sbox_nonzero = false
                for i = 0, 15 do
                    if sp[i] ~= 0 then sbox_nonzero = true; break end
                end
                sbox_status = sbox_nonzero and 'VALID (populated)' or 'ALLOCATED but ZERO'
            else
                sbox_status = ('DANGLING (0x%08X unreadable)'):format(sbox_ptr)
            end
        end
        print(('[fdiag] S-box ptr (ctx+0x48): 0x%08X — %s'):format(sbox_ptr, sbox_status))

        -- OFB state at ctx+0x4C..0x5F (20 bytes)
        local ofb = ctx + 0x4C
        local ofb_hex = {}
        local ofb_zero = true
        for i = 0, 19 do
            local b = ofb[i]
            if b ~= 0 then ofb_zero = false end
            table.insert(ofb_hex, ('%02X'):format(b))
        end
        print(('[fdiag] OFB state (ctx+0x4C, 20B): %s%s'):format(
            table.concat(ofb_hex, ' '), ofb_zero and ' (all zero)' or ''))
        -- OFB IV (first 8 bytes) and position (byte at +0x14)
        local iv_hex = {}
        for i = 0, 7 do table.insert(iv_hex, ('%02X'):format(ofb[i])) end
        print(('[fdiag]   IV[0:8]: %s  dec_pos: %d'):format(
            table.concat(iv_hex, ' '), ofb[0x14] or 0))

        -- Summary for all 4 slots
        print('[fdiag]')
        print('[fdiag] All slots BF context summary:')
        for i = 0, num_slots - 1 do
            local s = ffi.cast('uint8_t*', desc_base + i * slot_size)
            local c = s + 0x50
            local p0 = ffi.cast('uint32_t*', c)[0]
            local sp = ffi.cast('uint32_t*', c + 0x48)[0]
            local cr = s[0x0B]
            local m = s[0x08]
            local p_init = p0 ~= 0 and 'P:ok' or 'P:--'
            local s_init = sp ~= 0 and 'S:ok' or 'S:NULL'
            local marker = (i == slot_idx) and ' <<<' or ''
            print(('[fdiag]   [%d] mode=%02X crypto=%02X %s %s sbox=0x%08X%s'):format(
                i, m, cr, p_init, s_init, sp, marker))
        end
        return
    end

    -- /fdiag bfinit N [key_hex] — call BF_init_key (+0x63EB4) for one slot
    -- Allocates S-box (4KB) if NULL, then calls polcore's native init
    -- Default key: 4C 53 42 46 52 49 45 4E ("LSBFRIEN")
    -----------------------------------------------------------------
    if cmd == 'bfinit' then
        local slot_idx = tonumber(args[3])
        if not slot_idx or slot_idx < 0 or slot_idx > 3 then
            print('[fdiag] Usage: /fdiag bfinit <0-3> [key_hex_16chars]')
            print('[fdiag] Default key: 4C534246524945E ("LSBFRIEN")')
            return
        end

        -- Parse optional 8-byte key (16 hex chars)
        local key_buf = ffi.new('uint8_t[8]')
        if args[4] then
            local hex_str = args[4]:gsub('%s', '')
            if #hex_str ~= 16 then
                print('[fdiag] Key must be exactly 16 hex characters (8 bytes)')
                return
            end
            for i = 0, 7 do
                key_buf[i] = tonumber(hex_str:sub(i*2+1, i*2+2), 16) or 0
            end
        else
            -- Default: "LSBFRIEN" = 4C 53 42 46 52 49 45 4E
            local default_key = {0x4C, 0x53, 0x42, 0x46, 0x52, 0x49, 0x45, 0x4E}
            for i = 0, 7 do key_buf[i] = default_key[i+1] end
        end

        local key_hex = {}
        for i = 0, 7 do table.insert(key_hex, ('%02X'):format(key_buf[i])) end
        print(('[fdiag] BF init slot %d with key: %s'):format(slot_idx, table.concat(key_hex, ' ')))

        local desc_off = 0x404AD0
        local slot_size = 0x338
        local ctx = ffi.cast('uint8_t*', polcore_base + desc_off + slot_idx * slot_size + 0x50)
        local sbox_ptr_addr = ctx + 0x48

        -- Check/allocate S-box (4KB)
        local sbox_ptr = ffi.cast('uint32_t*', sbox_ptr_addr)[0]
        if sbox_ptr == 0 then
            print('[fdiag] S-box pointer is NULL — allocating 4KB...')
            local MEM_COMMIT = 0x1000
            local MEM_RESERVE = 0x2000
            local PAGE_READWRITE = 0x04
            local sbox = ffi.C.VirtualAlloc(nil, 0x1000, bit.bor(MEM_COMMIT, MEM_RESERVE), PAGE_READWRITE)
            if sbox == nil then
                print('[fdiag] VirtualAlloc for S-box failed!')
                return
            end
            local sbox_addr = tonumber(ffi.cast('uint32_t', sbox))
            -- Zero it
            local sp = ffi.cast('uint8_t*', sbox)
            for i = 0, 0xFFF do sp[i] = 0 end
            -- Store pointer
            ffi.cast('uint32_t*', sbox_ptr_addr)[0] = sbox_addr
            print(('[fdiag] Allocated S-box at 0x%08X'):format(sbox_addr))
        else
            print(('[fdiag] S-box already at 0x%08X'):format(sbox_ptr))
        end

        -- Call BF_init_key: void __cdecl bf_init_key(BF_CTX* ctx, uint8_t key[8])
        local bf_init = ffi.cast('void (__cdecl*)(void*, void*)', polcore_base + 0x63EB4)
        print('[fdiag] Calling BF_init_key...')
        bf_init(ffi.cast('void*', ctx), ffi.cast('void*', key_buf))
        print('[fdiag] BF_init_key returned.')

        -- Verify: dump P-array and S-box state after init
        local p_arr = ffi.cast('uint32_t*', ctx)
        local p_hex = {}
        local p_nonzero = false
        for i = 0, 5 do
            local v = p_arr[i]
            if v ~= 0 then p_nonzero = true end
            table.insert(p_hex, ('%08X'):format(v))
        end
        print(('[fdiag] P[0:5] after init: %s %s'):format(
            table.concat(p_hex, ' '), p_nonzero and '(populated)' or '(STILL ZERO — init failed!)'))

        local new_sbox = ffi.cast('uint32_t*', sbox_ptr_addr)[0]
        if new_sbox ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', new_sbox), 16) == 0 then
            local sv = ffi.cast('uint32_t*', new_sbox)
            print(('[fdiag] S-box[0:3]: %08X %08X %08X %08X'):format(sv[0], sv[1], sv[2], sv[3]))
        end

        -- OFB IV should now be set to key bytes
        local iv_hex = {}
        for i = 0, 7 do table.insert(iv_hex, ('%02X'):format(ctx[0x4C + i])) end
        print(('[fdiag] OFB IV after init: %s'):format(table.concat(iv_hex, ' ')))

        print('[fdiag] Done. Crypto flag (desc+0x0B) unchanged — set manually or use pumpcaller crypto.')
        return
    end

    -- /fdiag testfriend [name] — write test friend into polcore internal table + FFXiMain
    -- polcore internal table: 0x100B40D8, 200 entries × 176 bytes (0xB0)
    -- validate_friend_entry memcpy's 176B from polcore → FFXiMain, so data must be in polcore
    -----------------------------------------------------------------
    if cmd == 'testfriend' then
        local name = args[3] or 'TestFriend'

        -- polcore internal friend table: base + 0x0B40D8
        local pc_table = ffi.cast('uint8_t*', polcore_base + 0x0B40D8)
        local pc_entry = pc_table  -- entry 0

        -- Zero the 176-byte polcore entry first
        for i = 0, 0xAF do pc_entry[i] = 0 end

        -- +0x00: friend ID lo (4B)
        ffi.cast('uint32_t*', pc_entry + 0x00)[0] = 0x00001000
        -- +0x04: friend ID hi (4B)
        ffi.cast('uint32_t*', pc_entry + 0x04)[0] = 0x00000000
        -- +0x08: flags lo — bit 16 = online
        ffi.cast('uint32_t*', pc_entry + 0x08)[0] = 0x00010000
        -- +0x0C: flags hi
        ffi.cast('uint32_t*', pc_entry + 0x0C)[0] = 0x00000000
        -- +0x98: status_flags — bit 0 = valid
        ffi.cast('uint32_t*', pc_entry + 0x98)[0] = 0x00000001
        -- +0xA0: display name (up to 15 chars, within 176-byte boundary)
        local dname = ffi.cast('char*', pc_entry + 0xA0)
        local max_name = math.min(#name, 15)
        for i = 0, max_name - 1 do dname[i] = name:byte(i + 1) end
        dname[max_name] = 0

        print(('[fdiag] Wrote polcore internal entry 0 at 0x%08X'):format(
            tonumber(ffi.cast('uint32_t', ffi.cast('void*', pc_entry)))))

        -- Dump what we wrote
        for row = 0, 5 do
            local hex = {}
            for i = 0, 31 do
                table.insert(hex, ('%02X'):format(pc_entry[row * 32 + i]))
            end
            print(('[fdiag]   +0x%02X: %s'):format(row * 32, table.concat(hex, ' ')))
        end

        -- Now get FFXiMain friend data object
        local flist_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)
        local flist_obj = flist_obj_ptr[0]
        if flist_obj == 0 then
            print('[fdiag] FFXiMain friend data object is NULL!')
            return
        end
        local obj = ffi.cast('uint8_t*', flist_obj)
        local ffxi_entry = obj + 0x0A90

        -- Call populate_count_and_indices — this calls validate_friend_entry
        -- which memcpy's from polcore table → FFXiMain entry, then checks status_flags
        local pop_count = ffi.cast('void (__cdecl*)()', ffximain_base + 0x0E6730)
        pop_count()

        -- Check results
        local count_ptr = ffi.cast('int16_t*', obj + 0x132)
        print(('[fdiag] friend_count = %d'):format(count_ptr[0]))

        local surv_flags = ffi.cast('uint32_t*', ffxi_entry + 0x98)[0]
        print(('[fdiag] FFXiMain entry status_flags: 0x%08X'):format(surv_flags))

        -- Dump FFXiMain entry after populate
        print('[fdiag] FFXiMain entry 0 after populate:')
        for row = 0, 5 do
            local hex = {}
            for i = 0, 31 do
                table.insert(hex, ('%02X'):format(ffxi_entry[row * 32 + i]))
            end
            print(('[fdiag]   +0x%02X: %s'):format(row * 32, table.concat(hex, ' ')))
        end

        -- Also write char_name at +0xB4 in FFXiMain entry (outside polcore's 176B copy)
        if count_ptr[0] > 0 then
            local cname = ffi.cast('char*', ffxi_entry + 0xB4)
            for i = 0, max_name - 1 do cname[i] = name:byte(i + 1) end
            cname[max_name] = 0
            print(('[fdiag] Wrote char_name at +0xB4: "%s"'):format(name))
            print('[fdiag] Entry passed! Try /friendlist now.')
        else
            print('[fdiag] Entry failed validation.')
        end
        return
    end

    -- /fdiag smpatch — patch polcore's outer state machine to work in FFXI mode
    -- Three patches needed:
    -- 1. NOP the arg overwrite in per-frame caller (prevents arg=0 clobber)
    -- 2. Redirect arg=0 jump table entry (prevents state reset to 0 each frame)
    -- 3. Redirect mode==0 in state 0 handler (prevents error sentinel in FFXI mode)
    -- Then sets arg=1, state=0 to start the initialization flow.
    -----------------------------------------------------------------
    if cmd == 'smpatch' then
        local old_protect = ffi.new('uint32_t[1]')

        -- Patch 1: NOP "MOV [0x10099414], EAX" at polcore+0x448C8 (5 bytes: A3 14 94 09 10)
        local p1_addr = polcore_base + 0x0448C8
        local p1 = ffi.cast('uint8_t*', p1_addr)
        if p1[0] == 0xA3 and p1[1] == 0x14 and p1[2] == 0x94 then
            ffi.C.VirtualProtect(ffi.cast('void*', p1_addr), 5, 0x40, old_protect)
            for i = 0, 4 do p1[i] = 0x90 end
            ffi.C.VirtualProtect(ffi.cast('void*', p1_addr), 5, old_protect[0], old_protect)
            print('[fdiag] Patch 1: NOPped arg overwrite at +0x448C8')
        elseif p1[0] == 0x90 then
            print('[fdiag] Patch 1: already applied')
        else
            print(('[fdiag] Patch 1: UNEXPECTED bytes %02X %02X %02X — skipping'):format(p1[0], p1[1], p1[2]))
        end

        -- Patch 2: NOP the "MOV [state], EBX" (state=0) at polcore+0x4497E (6 bytes: 89 1D 08 94 09 10)
        -- This keeps the arg=0 code path (which calls the state machine) but prevents state reset.
        local p2_addr = polcore_base + 0x04497E
        local p2 = ffi.cast('uint8_t*', p2_addr)
        if p2[0] == 0x89 and p2[1] == 0x1D and p2[2] == 0x08 then
            ffi.C.VirtualProtect(ffi.cast('void*', p2_addr), 6, 0x40, old_protect)
            for i = 0, 5 do p2[i] = 0x90 end
            ffi.C.VirtualProtect(ffi.cast('void*', p2_addr), 6, old_protect[0], old_protect)
            print('[fdiag] Patch 2: NOPped state=0 write in arg=0 handler at +0x4497E')
        elseif p2[0] == 0x90 then
            print('[fdiag] Patch 2: already applied')
        else
            print(('[fdiag] Patch 2: UNEXPECTED bytes %02X %02X %02X — skipping'):format(p2[0], p2[1], p2[2]))
        end

        -- Undo wrong patch 2 if it was applied (restore jump table entry)
        local jt_addr = polcore_base + 0x044A3C
        local jt = ffi.cast('uint32_t*', jt_addr)
        local wrong_target = polcore_base + 0x044992
        local correct_target = polcore_base + 0x04497E
        if jt[0] == wrong_target then
            ffi.C.VirtualProtect(ffi.cast('void*', jt_addr), 4, 0x40, old_protect)
            jt[0] = correct_target
            ffi.C.VirtualProtect(ffi.cast('void*', jt_addr), 4, old_protect[0], old_protect)
            print('[fdiag] Patch 2b: Restored arg=0 jump table entry (undid wrong patch)')
        end

        -- Patch 3: Change JZ at polcore+0x44ACC from "74 0A" (JZ +0x0A to error)
        -- to "EB 20" (JMP +0x20 to mode==1 init path at +0x44AEE)
        local p3_addr = polcore_base + 0x044ACC
        local p3 = ffi.cast('uint8_t*', p3_addr)
        if p3[0] == 0x74 and p3[1] == 0x0A then
            ffi.C.VirtualProtect(ffi.cast('void*', p3_addr), 2, 0x40, old_protect)
            p3[0] = 0xEB  -- JMP short
            p3[1] = 0x20  -- +0x20 → 0x10044AEE (mode==1 handler)
            ffi.C.VirtualProtect(ffi.cast('void*', p3_addr), 2, old_protect[0], old_protect)
            print('[fdiag] Patch 3: Redirected mode==0 to mode==1 init path')
        elseif p3[0] == 0xEB and p3[1] == 0x20 then
            print('[fdiag] Patch 3: already applied')
        else
            print(('[fdiag] Patch 3: UNEXPECTED bytes %02X %02X — skipping'):format(p3[0], p3[1]))
        end

        -- Set arg=1 so state 17 advances to 18 (not 30)
        ffi.cast('int32_t*', polcore_base + 0x099414)[0] = 1
        print('[fdiag] Set arg [+0x99414] = 1')

        -- Reset state to 0 to start the init flow
        ffi.cast('int32_t*', polcore_base + 0x099408)[0] = 0
        print('[fdiag] Set state [+0x99408] = 0')

        print('[fdiag] State machine should now advance through init flow.')
        print('[fdiag] Monitor with "/fdiag smstate"')
        return
    end

    -- /fdiag smreset — reset polcore's outer state machine to state 0
    -- The state machine gets stuck at 0xFFFFD3FC during bootstrap because app mode is -1.
    -- After game loads, mode becomes 0 but state is already stuck. This resets it.
    -- State flow: 0→17→...→27/28 (CallerA loop)→40 (event dispatch)→41→29→30
    -- At state 40, event (5,1) is dispatched to FFXiMain, creating titlehan/flmes elements.
    -----------------------------------------------------------------
    -- /fdiag smtick — directly call the state machine function once
    -- The state machine at polcore+0x44A50 processes the current state.
    -- Signature: void __cdecl state_machine(void) — uses globals, no args
    -----------------------------------------------------------------
    if cmd == 'smtick' then
        local sm_func = ffi.cast('void (__cdecl*)()', polcore_base + 0x044A50)
        local state_before = ffi.cast('int32_t*', polcore_base + 0x099408)[0]
        print(('[fdiag] State before: %d (0x%08X)'):format(state_before,
            tonumber(ffi.cast('uint32_t', state_before))))

        local ok, err = pcall(function() sm_func() end)
        if not ok then
            print(('[fdiag] ERROR: %s'):format(tostring(err)))
        end

        local state_after = ffi.cast('int32_t*', polcore_base + 0x099408)[0]
        local last_result = ffi.cast('uint32_t*', polcore_base + 0x0996B4)[0]
        print(('[fdiag] State after: %d (0x%08X) last_result=0x%08X'):format(
            state_after, tonumber(ffi.cast('uint32_t', state_after)), last_result))
        return
    end

    if cmd == 'smreset' then
        local state_addr = polcore_base + 0x099408
        local mode_addr = polcore_base + 0x099C80
        local init_addr = polcore_base + 0x099244
        local arg_addr = polcore_base + 0x099414

        local state = ffi.cast('int32_t*', state_addr)[0]
        local mode = ffi.cast('int32_t*', mode_addr)[0]
        local init = ffi.cast('uint32_t*', init_addr)[0]
        local arg = ffi.cast('int32_t*', arg_addr)[0]

        print(('[fdiag] State machine: state=0x%08X mode=%d init=%d arg=%d'):format(
            tonumber(ffi.cast('uint32_t', state)), mode, init, arg))

        if mode ~= 0 then
            print('[fdiag] WARNING: app mode is not 0 (FFXI). State 0 may error again.')
        end

        -- Check sockaddr is active
        local sockaddr = ffi.cast('uint16_t*', polcore_base + 0x404AB8)[0]
        print(('[fdiag] sockaddr family = %d (1=active)'):format(sockaddr))
        if sockaddr ~= 1 then
            print('[fdiag] WARNING: sockaddr not active. State machine needs active sockaddr.')
        end

        local target = tonumber(args[3]) or 0
        print(('[fdiag] Resetting state to %d...'):format(target))
        ffi.cast('int32_t*', state_addr)[0] = target

        -- Verify
        local new_state = ffi.cast('int32_t*', state_addr)[0]
        print(('[fdiag] New state: %d (0x%08X)'):format(new_state,
            tonumber(ffi.cast('uint32_t', new_state))))
        print('[fdiag] State machine should advance on next frame tick.')
        print('[fdiag] Use "/fdiag smstate" to monitor progress.')
        return
    end

    -- /fdiag smstate — show current state machine state and key variables
    -----------------------------------------------------------------
    if cmd == 'smstate' then
        local state = ffi.cast('int32_t*', polcore_base + 0x099408)[0]
        local mode = ffi.cast('int32_t*', polcore_base + 0x099C80)[0]
        local arg = ffi.cast('int32_t*', polcore_base + 0x099414)[0]
        local counter = ffi.cast('int32_t*', polcore_base + 0x09941C)[0]
        local alt_state = ffi.cast('int32_t*', polcore_base + 0x09940C)[0]
        local last_result = ffi.cast('uint32_t*', polcore_base + 0x0996B4)[0]
        local conn_type = ffi.cast('int32_t*', polcore_base + 0x0993E8)[0]
        local init = ffi.cast('uint32_t*', polcore_base + 0x099244)[0]

        print(('[fdiag] SM state=%d (0x%08X) mode=%d arg=%d init=%d'):format(
            state, tonumber(ffi.cast('uint32_t', state)), mode, arg, init))
        print(('[fdiag]    counter=%d alt=0x%08X last_result=0x%08X conn_type=%d'):format(
            counter, tonumber(ffi.cast('uint32_t', alt_state)), last_result, conn_type))

        -- Decode state meaning
        if state >= 0 and state <= 41 then
            local names = {
                [0] = 'INIT/CONNECT',
                [17] = 'CHECK_ARG', [18] = 'PREPARE', [19] = 'BUILD_SESSION',
                [20] = 'CONNECT_FRIEND', [21] = 'READ_RESPONSE', [22] = 'SEND_AUTH',
                [23] = 'CHECK_HANDSHAKE', [24] = 'VERIFY', [25] = 'EXCHANGE_1',
                [26] = 'EXCHANGE_2', [27] = 'CALLER_A_SETUP', [28] = 'DRIVER_LOOP',
                [29] = 'POST_EVENT', [30] = 'IDLE/TIMEOUT', [31] = 'CLEANUP',
                [32] = 'RECOVERY', [33] = 'RECONNECT_WAIT', [39] = 'RECONNECT',
                [40] = 'DISPATCH_EVENT', [41] = 'EVENT_COMPLETE'
            }
            local name = names[state] or '(unknown)'
            print(('[fdiag]    → %s'):format(name))
        elseif state < 0 then
            print('[fdiag]    → ERROR/STUCK (negative state, out of range)')
        end

        -- Check flistmai elements
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai ~= 0 then
            local fm = ffi.cast('uint8_t*', flistmai)
            local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
            local handle_node = ffi.cast('uint32_t*', fm + 0x34)[0]
            print(('[fdiag]    flistmai sub_mgr=0x%08X handle_node=0x%08X'):format(sub_mgr, handle_node))
        end
        return
    end

    -- /fdiag flistbind — find titlehan/flmes elements and bind them to flistmai
    -- This is the missing initialization step that never happens on xiloader because
    -- polcore's state machine never reaches the friend-connected state.
    -- On retail, the init function at FFXiMain+0x1E9DC0 does this during menu setup.
    -----------------------------------------------------------------
    if cmd == 'flistbind' then
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai == 0 then
            print('[fdiag] flistmai pointer is NULL!')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        print(('[fdiag] flistmai at 0x%08X'):format(flistmai))

        -- Current state
        local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
        local handle_node = ffi.cast('uint32_t*', fm + 0x34)[0]
        print(('[fdiag]   sub_mgr (+0x08) = 0x%08X'):format(sub_mgr))
        print(('[fdiag]   handle_node (+0x34) = 0x%08X'):format(handle_node))
        print(('[fdiag]   +0x64 = 0x%08X'):format(ffi.cast('uint32_t*', fm + 0x64)[0]))

        -- Window manager at FFXiMain+0x5ECB98
        local mgr_addr = ffximain_base + 0x5ECB98

        -- find_element: int __thiscall find_element(void* mgr, const char* name)
        -- At FFXiMain+0x15D640
        local find_element = ffi.cast('uint32_t (__thiscall*)(void*, const char*)', ffximain_base + 0x15D640)

        -- Find "titlehan" element
        local titlehan_name = ffi.cast('const char*', ffximain_base + 0x37FEF4) -- "menu    titlehan"
        local titlehan_ret = find_element(ffi.cast('void*', mgr_addr), titlehan_name)
        print(('[fdiag] find_element("titlehan") = 0x%08X'):format(titlehan_ret))

        -- Find "flmes" element
        local flmes_name = ffi.cast('const char*', ffximain_base + 0x37FEE0) -- "menu    flmes"
        local flmes_ret = find_element(ffi.cast('void*', mgr_addr), flmes_name)
        print(('[fdiag] find_element("flmes") = 0x%08X'):format(flmes_ret))

        -- The real init at +0x1E9DC0 gets the titlehan element object from
        -- a container access function, then reads [element+0x12C] to get
        -- the actual handle display object. Let's examine what find_element
        -- returns and explore the object.
        if titlehan_ret ~= 0 then
            -- Dump around the returned value to understand the object
            local ptr = ffi.cast('uint8_t*', titlehan_ret)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', titlehan_ret), 16) == 0 then
                local hex = {}
                for i = 0, 31 do table.insert(hex, ('%02X'):format(ptr[i])) end
                print(('[fdiag]   titlehan obj bytes: %s'):format(table.concat(hex, ' ')))
                -- Check if there's an object at +0x12C
                if ffi.C.IsBadReadPtr(ffi.cast('void*', titlehan_ret + 0x12C), 4) == 0 then
                    local inner = ffi.cast('uint32_t*', ptr + 0x12C)[0]
                    print(('[fdiag]   titlehan[+0x12C] = 0x%08X'):format(inner))
                    if inner ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', inner), 16) == 0 then
                        local inner_ptr = ffi.cast('uint8_t*', inner)
                        local hex2 = {}
                        for i = 0, 31 do table.insert(hex2, ('%02X'):format(inner_ptr[i])) end
                        print(('[fdiag]   inner obj bytes: %s'):format(table.concat(hex2, ' ')))
                    end
                end
            end
        end

        if flmes_ret ~= 0 then
            local ptr = ffi.cast('uint8_t*', flmes_ret)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', flmes_ret), 16) == 0 then
                local hex = {}
                for i = 0, 31 do table.insert(hex, ('%02X'):format(ptr[i])) end
                print(('[fdiag]   flmes obj bytes: %s'):format(table.concat(hex, ' ')))
                -- Check +0x4C (sub_mgr needs item count at +0x4C)
                if ffi.C.IsBadReadPtr(ffi.cast('void*', flmes_ret + 0x4C), 4) == 0 then
                    local item_count = ffi.cast('int16_t*', ptr + 0x4C)[0]
                    print(('[fdiag]   flmes[+0x4C] (item count) = %d'):format(item_count))
                end
            end
        end

        -- Now try binding: set flistmai+0x34 and +0x08
        -- The init code sets +0x34 = [child+0x12C], not directly from find_element.
        -- But let's try both approaches.
        local bind = (args[3] or '') == 'bind'
        if bind then
            if titlehan_ret ~= 0 then
                -- Try using the returned element directly for +0x34
                -- The real init reads [child+0x12C], but the child might be different
                -- from what find_element returns. Let's try the direct pointer first.
                ffi.cast('uint32_t*', fm + 0x34)[0] = titlehan_ret
                ffi.cast('uint32_t*', fm + 0x64)[0] = titlehan_ret
                print(('[fdiag] Bound handle_node (+0x34/+0x64) = 0x%08X'):format(titlehan_ret))
            end
            if flmes_ret ~= 0 then
                ffi.cast('uint32_t*', fm + 0x08)[0] = flmes_ret
                print(('[fdiag] Bound sub_mgr (+0x08) = 0x%08X'):format(flmes_ret))
            end
            print('[fdiag] Bindings set. Try /flist now.')
            print('[fdiag] WARNING: /flist calls prepare_display which clears +0x34!')
            print('[fdiag] You may need to NOP the clear instruction first.')
        else
            print('[fdiag] Run "/fdiag flistbind bind" to actually bind the elements.')
        end

        return
    end

    -- /fdiag calldisplay — full sequence: add elements, prepare, set fields
    -----------------------------------------------------------------
    if cmd == 'calldisplay' then
        local wm_addr = ffximain_base + 0x5ECB98
        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)', ffximain_base + 0x15D080)
        local show_element = ffi.cast('int (__thiscall*)(void*, const char*)', ffximain_base + 0x15D640)
        local prepare_display = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1E9D60)
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai == 0 then
            print('[fdiag] flistmai is NULL!')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)

        -- Strings
        local th_str = ffi.new('char[17]'); ffi.copy(th_str, 'menu    titlehan', 16); th_str[16] = 0
        local fl_str = ffi.new('char[17]'); ffi.copy(fl_str, 'menu    flmes   ', 16); fl_str[16] = 0

        -- Step 1: Add titlehan + flmes
        local th_menu_ret = show_menu(ffi.cast('void*', wm_addr), th_str, 1, 0)
        local fl_menu_ret = show_menu(ffi.cast('void*', wm_addr), fl_str, 1, 0)
        print(('[fdiag] show_menu: titlehan=0x%08X flmes=0x%08X'):format(th_menu_ret, fl_menu_ret))

        -- Step 2: Call prepare_display
        prepare_display(ffi.cast('void*', flistmai))
        print('[fdiag] prepare_display done')

        -- Step 3: Re-add titlehan + flmes (in case prepare_display affected them)
        show_menu(ffi.cast('void*', wm_addr), th_str, 1, 0)
        show_menu(ffi.cast('void*', wm_addr), fl_str, 1, 0)

        -- Step 4: Set +0x34 from [titlehan+0x12C] (NOT element itself — crashes)
        -- The init code at +0x1E9DC0 sets +0x34 = [child+0x12C]
        -- Try show_element first (searches WM list), fall back to show_menu return
        local th_elem = show_element(ffi.cast('void*', wm_addr), th_str)
        local src_addr = (th_elem ~= 0) and th_elem or th_menu_ret
        print(('[fdiag] titlehan source for +0x12C: 0x%08X (elem=%d, menu=%d)'):format(
            src_addr, th_elem ~= 0 and 1 or 0, th_menu_ret ~= 0 and 1 or 0))
        if src_addr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', src_addr + 0x12C), 4) == 0 then
            local handle_node = ffi.cast('uint32_t*', src_addr + 0x12C)[0]
            print(('[fdiag] [src+0x12C] = 0x%08X'):format(handle_node))
            if handle_node ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', handle_node), 16) == 0 then
                ffi.cast('uint32_t*', fm + 0x34)[0] = handle_node
                print(('[fdiag] Set +0x34 = 0x%08X'):format(handle_node))
            else
                print('[fdiag] handle_node invalid or NULL, NOT setting +0x34')
            end
        else
            print('[fdiag] Cannot read [src+0x12C], NOT setting +0x34')
        end

        -- Step 5: Enable per-frame keep-alive (safe version — only every 30 frames)
        fdiag_keep_flist = true
        fdiag_keep_flist_count = 0
        fdiag_flist_th_str = th_str
        fdiag_flist_fl_str = fl_str
        print('[fdiag] Per-frame keep-alive ENABLED (30-frame interval)')
        print(('[fdiag] +0x34=0x%08X +0x49=0x%02X'):format(
            ffi.cast('uint32_t*', fm + 0x34)[0],
            ffi.cast('uint8_t*', fm + 0x49)[0]))
        return
    end

    -- /fdiag stopflist — disable per-frame keep-alive
    -----------------------------------------------------------------
    if cmd == 'stopflist' then
        fdiag_keep_flist = false
        print('[fdiag] Per-frame keep-alive DISABLED')
        return
    end

    -- /fdiag showmenu NAME — call show_menu(name, 1, 0) on WM
    -----------------------------------------------------------------
    if cmd == 'showmenu' then
        local name = args[3] or ''
        if name == '' then
            print('[fdiag] Usage: /fdiag showmenu <name>')
            return
        end
        local wm_addr = ffximain_base + 0x5ECB98
        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)', ffximain_base + 0x15D080)
        -- Build "menu    NAME" string (padded to 16 chars with spaces)
        local padded = 'menu    ' .. name
        while #padded < 16 do padded = padded .. ' ' end
        padded = padded:sub(1, 16)
        local cstr = ffi.new('char[17]')
        ffi.copy(cstr, padded, 16)
        cstr[16] = 0
        print(('[fdiag] Calling show_menu("%s", 1, 0)'):format(padded))
        local ok, ret = pcall(function()
            return show_menu(ffi.cast('void*', wm_addr), cstr, 1, 0)
        end)
        if ok then
            print(('[fdiag] show_menu returned: 0x%08X'):format(ret))
        else
            print('[fdiag] show_menu CRASHED: ' .. tostring(ret))
        end
        return
    end

    -- /fdiag listelements — dump the WM active element list
    -----------------------------------------------------------------
    if cmd == 'listelements' then
        local wm_ptr = ffi.cast('uint32_t*', ffximain_base + 0x5ECB98)
        local wm = wm_ptr[0]
        if wm == 0 then
            print('[fdiag] WM is NULL!')
            return
        end
        -- List head = [WM+0x00]
        local head = ffi.cast('uint32_t*', wm)[0]
        print(('[fdiag] WM=0x%08X, list head=0x%08X'):format(wm, head))
        local node_addr = head
        local count = 0
        local max = 200
        while node_addr ~= 0 and count < max do
            local node = ffi.cast('uint8_t*', node_addr)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', node_addr), 0x18) ~= 0 then
                print(('[fdiag] Bad node ptr: 0x%08X'):format(node_addr))
                break
            end
            local next_node = ffi.cast('uint32_t*', node)[0]
            local element = ffi.cast('uint32_t*', node + 0x10)[0]
            local skip = node[0x14]
            local name = '(null)'
            if element ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', element), 8) == 0 then
                local inner = ffi.cast('uint32_t*', element + 4)[0]
                if inner ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', inner + 0x46), 16) == 0 then
                    name = ffi.string(ffi.cast('const char*', inner + 0x46), 16)
                end
            end
            print(('[fdiag] [%3d] node=0x%08X elem=0x%08X skip=%d name="%s"'):format(
                count, node_addr, element, skip, name))
            node_addr = next_node
            count = count + 1
        end
        print(('[fdiag] Total: %d nodes'):format(count))
        return
    end

    -- /fdiag flistpatch — NOP out the MOV [ESI+0x34], 0 in prepare_display
    -- so that /flist doesn't clear our handle_node binding
    -----------------------------------------------------------------
    if cmd == 'flistpatch' then
        -- prepare_display at FFXiMain+0x1E9D60
        -- The instruction C7 46 34 00 00 00 00 (MOV [ESI+0x34], 0) is at +0x1E9DA5
        local patch_addr = ffximain_base + 0x1E9DA5
        local code = ffi.cast('uint8_t*', patch_addr)

        -- Verify current bytes
        local current = {}
        for i = 0, 6 do table.insert(current, ('%02X'):format(code[i])) end
        print(('[fdiag] Bytes at 0x%08X: %s'):format(patch_addr, table.concat(current, ' ')))

        if code[0] == 0xC7 and code[1] == 0x46 and code[2] == 0x34 then
            -- Already the expected instruction, NOP it (7 bytes)
            local old_protect = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', patch_addr), 7, 0x40, old_protect)
            for i = 0, 6 do code[i] = 0x90 end
            ffi.C.VirtualProtect(ffi.cast('void*', patch_addr), 7, old_protect[0], old_protect)
            print('[fdiag] Patched: NOPped 7-byte MOV [ESI+0x34], 0')
        elseif code[0] == 0x90 then
            print('[fdiag] Already patched (NOPs)')
        else
            print('[fdiag] Unexpected bytes — NOT patching!')
        end
        return
    end

    -- /fdiag activateflist — activate the flistmai menu in FFXiMain's menu system
    -- On retail, this is triggered by polcore event (5,1) when friend connection
    -- is established. On private servers, this event never fires because polcore's
    -- friend state machine never reaches "connected" state. Without activation,
    -- /flist silently does nothing because the menu handler is never dispatched.
    --
    -- This calls the menu manager's show_menu("menu    flistmai", 1, 0) which is
    -- exactly what the event (5,1) callback at FFXiMain+0x1EA548 does.
    -----------------------------------------------------------------
    if cmd == 'activateflist' then
        if not ffximain_base or ffximain_base == 0 then
            print('[fdiag] FFXiMain.dll not loaded!')
            return
        end

        -- Simplified: just call show_menu for flistmai (updated offsets 2026-04-02)
        local show_menu_addr = ffximain_base + 0x15E1E0
        local mgr_addr = ffximain_base + 0x5EDD10
        local name_addr = ffximain_base + 0x373060

        local name_ptr = ffi.cast('const char*', name_addr)
        local name_str = ffi.string(name_ptr, 16)
        if name_str ~= 'menu    flistmai' then
            print(('[fdiag] String mismatch: got "%s"'):format(name_str))
            return
        end

        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)', show_menu_addr)
        local ok, result = pcall(function()
            return show_menu(ffi.cast('void*', mgr_addr), name_ptr, 1, 0)
        end)
        if ok then
            print(('[fdiag] show_menu(flistmai) returned: 0x%08X'):format(result))
            -- Store result at [FFXi+0x62E9E4] if currently NULL
            local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
            if flistmai_ptr[0] == 0 and result ~= 0 then
                flistmai_ptr[0] = result
                print(('[fdiag] Set [FFXi+0x62E9E4] = 0x%08X'):format(result))
            end
        else
            print(('[fdiag] show_menu CRASHED: %s'):format(tostring(result)))
        end
        return
    end

    -----------------------------------------------------------------
    -- SHOWTITLEHAN: Register and show titlehan and flmes elements
    -- Calls show_menu for each element to add them to the render tree
    -----------------------------------------------------------------
    if cmd == 'showtitlehan' then
        if not ffximain_base or ffximain_base == 0 then
            print('[fdiag] FFXiMain.dll not loaded!')
            return
        end

        -- Safe read: check each address before dereferencing
        local addrs = {
            {ffximain_base + 0x5ECB98, 'WM object'},
            {ffximain_base + 0xA36300, 'titlehan global'},
            {polcore_base + 0x405800, 'handle array'},
        }
        for _, item in ipairs(addrs) do
            local addr, label = item[1], item[2]
            local v = ffi.cast('uint32_t*', addr)[0]
            print(('[fdiag] [0x%08X] %s = 0x%08X'):format(
                tonumber(ffi.cast('uint32_t', addr)), label, v))
        end

        -- Handle array entry
        local entry = ffi.cast('uint8_t*', polcore_base + 0x405800)
        local flags = entry[0]
        local text_start = ffi.cast('const char*', polcore_base + 0x405808)
        local text = ffi.string(text_start)
        print(('[fdiag] Handle entry: flags=0x%02X text="%s"'):format(flags, text))

        -- flistmai state
        print(('[fdiag] flistmai sub_mgr=0x%08X handle_node=0x%08X'):format(
            ffi.cast('uint32_t*', polcore_base + 0x405800 - 8)[0],
            ffi.cast('uint32_t*', polcore_base + 0x405800 - 4)[0]))
        return
    end

    -----------------------------------------------------------------
    -- TESTHANDLE: Call the polcore text getter to check if handle data returns
    -- Then optionally call the titlehan render function directly
    -----------------------------------------------------------------
    if cmd == 'testhandle' then
        -- Test the polcore text getter chain
        -- polcore+0x1CBB0: returns [polcore+0x7541C] (index)
        local get_index_fn = ffi.cast('int (__cdecl*)()', polcore_base + 0x1CBB0)
        local ok, idx_or_err = pcall(function() return get_index_fn() end)
        if not ok then
            print('[fdiag] get_index CRASHED: ' .. tostring(idx_or_err))
            return
        end
        print(('[fdiag] get_index returned: %d (0x%08X)'):format(idx_or_err, idx_or_err))

        -- polcore+0x1CC40: copies entry to buffer
        -- Signature: int __cdecl copy_entry(int index, uint8_t* buffer)
        local copy_entry_fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x1CC40)
        local buf = ffi.new('uint8_t[40]')
        for i = 0, 39 do buf[i] = 0xCC end
        local ok2, ret = pcall(function() return copy_entry_fn(idx_or_err, buf) end)
        if not ok2 then
            print('[fdiag] copy_entry CRASHED: ' .. tostring(ret))
            return
        end
        print(('[fdiag] copy_entry returned: %d'):format(ret))

        -- Dump entry
        local hex = {}
        for i = 0, 39 do table.insert(hex, ('%02X'):format(buf[i])) end
        print('[fdiag] Entry: ' .. table.concat(hex, ' '))

        -- Check flag bit 0
        local flags = buf[0]
        if bit.band(flags, 1) == 0 then
            print('[fdiag] Flag bit 0 NOT set — text getter would return -1 (no display)')
        else
            -- Show text at entry+8
            local text_parts = {}
            for i = 8, 22 do
                if buf[i] == 0 then break end
                table.insert(text_parts, string.char(buf[i]))
            end
            print(('[fdiag] Handle text: "%s" (flag bit0 set)'):format(table.concat(text_parts)))
        end

        -- Try calling the full text_getter at FFXiMain+0x0F1650
        print('[fdiag] Calling full text_getter at FFXiMain+0x0F1650...')
        local text_getter_fn = ffi.cast('int (__cdecl*)(void*)', ffximain_base + 0x0F1650)
        local out_buf = ffi.new('uint8_t[16]')
        for i = 0, 15 do out_buf[i] = 0 end
        local ok3, tg_ret = pcall(function() return text_getter_fn(out_buf) end)
        if not ok3 then
            print('[fdiag] text_getter CRASHED: ' .. tostring(tg_ret))
        else
            local out_text = ffi.string(out_buf)
            print(('[fdiag] text_getter returned: %d, text: "%s"'):format(tg_ret, out_text))
        end

        return
    end

    -----------------------------------------------------------------
    -- HANDLERENDER: Toggle per-frame titlehan render + text overlay
    -- /fdiag handlerender on  — keep titlehan registered + show overlay
    -- /fdiag handlerender off — stop
    -----------------------------------------------------------------
    if cmd == 'handlerender' then
        local subcmd = args[3] or 'toggle'
        if subcmd == 'on' then
            handle_render_active = true
            -- Create Ashita text overlay for handle display
            if handle_font then
                handle_font:destroy()
                handle_font = nil
            end
            -- Read handle text from polcore array
            local entry = ffi.cast('uint8_t*', polcore_base + 0x405808)
            local text = ffi.string(entry)
            handle_font = fonts.new({
                visible = true,
                font_family = 'Arial',
                font_height = 14,
                bold = true,
                color = 0xFFFFFF00,  -- yellow
                color_outline = 0xFF000000,
                position_x = 260,
                position_y = 85,
                text = 'Handle: ' .. text,
                background = {
                    visible = true,
                    color = 0x80000000,
                },
            })
            print(('[fdiag] Handle overlay: "%s" at (260, 85)'):format(text))
            print('[fdiag] Handle render ON.')
        elseif subcmd == 'off' then
            handle_render_active = false
            if handle_font then
                handle_font:destroy()
                handle_font = nil
            end
            print('[fdiag] Handle render OFF.')
        else
            handle_render_active = not handle_render_active
            if not handle_render_active and handle_font then
                handle_font:destroy()
                handle_font = nil
            end
            print(('[fdiag] Handle render %s.'):format(handle_render_active and 'ON' or 'OFF'))
        end
        return
    end

    -- /fdiag flistdump — dump flistmai display array and related structures
    -----------------------------------------------------------------
    if cmd == 'flistdump' then
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai == 0 then
            print('[fdiag] flistmai is NULL!')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        local slots = ffi.cast('int32_t*', fm + 0x50)[0]
        local disp_idx = ffi.cast('int32_t*', fm + 0x54)[0]
        local param = fm[0x58]
        local arr_ptr = ffi.cast('uint32_t*', fm + 0x5C)[0]
        print(('[fdiag] flistmai=0x%08X slots=%d disp_idx=%d param=%d arr_ptr=0x%08X'):format(
            flistmai, slots, disp_idx, param, arr_ptr))

        -- Dump flistmai header (first 0x80 bytes)
        print('[fdiag] flistmai header:')
        for row = 0, 7 do
            local hex = {}
            for i = 0, 15 do
                table.insert(hex, ('%02X'):format(fm[row * 16 + i]))
            end
            print(('[fdiag]   +0x%02X: %s'):format(row * 16, table.concat(hex, ' ')))
        end

        -- Dump display array entries
        if arr_ptr ~= 0 then
            -- Try to figure out entry size by dumping raw bytes
            local arr = ffi.cast('uint8_t*', arr_ptr)
            local dump_bytes = math.min(slots * 128, 2048)  -- guess 128 bytes per entry, cap at 2KB
            print(('[fdiag] Display array raw (%d bytes):'):format(dump_bytes))
            for row = 0, math.floor(dump_bytes / 16) - 1 do
                local hex = {}
                local asc = {}
                for i = 0, 15 do
                    local b = arr[row * 16 + i]
                    table.insert(hex, ('%02X'):format(b))
                    table.insert(asc, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
                end
                print(('[fdiag]   +0x%03X: %s  %s'):format(row * 16, table.concat(hex, ' '), table.concat(asc)))
            end
        end
        return
    end

    -- /fdiag retailfmt — write retail-format entries to Array 2a then populate
    -----------------------------------------------------------------
    if cmd == 'retailfmt' then
        local arr2a_base = polcore_base + 0xB40D8
        local old_prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', arr2a_base), 200 * 0xB0, 0x40, old_prot)

        -- Entry 0 (Obl — OFFLINE): Use retail Crosis format
        local e0 = ffi.cast('uint8_t*', arr2a_base)
        for j = 0, 0xAF do e0[j] = 0 end
        -- +0x00: 8-byte ID (retail: 97 6F 54 90 6B 65 EC 60)
        local id0 = {0x97, 0x6F, 0x54, 0x90, 0x6B, 0x65, 0xEC, 0x60}
        for j = 0, 7 do e0[j] = id0[j+1] end
        -- +0x08: flags (retail offline: 00 00 00 60)
        e0[0x08] = 0x00; e0[0x09] = 0x00; e0[0x0A] = 0x00; e0[0x0B] = 0x60
        -- +0x0C: 01 00 00 00
        e0[0x0C] = 0x01
        -- +0x14: timestamp (retail: 6A F2 AA 69)
        e0[0x14] = 0x6A; e0[0x15] = 0xF2; e0[0x16] = 0xAA; e0[0x17] = 0x69
        -- +0x98: retail value (99 63 11 00)
        e0[0x98] = 0x99; e0[0x99] = 0x63; e0[0x9A] = 0x11; e0[0x9B] = 0x00
        -- +0xA0: name
        local n0 = 'Obl'
        for j = 0, #n0 - 1 do e0[0xA0 + j] = n0:byte(j + 1) end
        print('[fdiag] Entry 0 (Obl) written in retail OFFLINE format')

        -- Entry 1 (CharB — ONLINE): Use retail CharB format
        local e1 = ffi.cast('uint8_t*', arr2a_base + 0xB0)
        for j = 0, 0xAF do e1[j] = 0 end
        -- +0x00: 8-byte ID (retail: 74 D4 4B 93 6B 65 C0 60)
        local id1 = {0x74, 0xD4, 0x4B, 0x93, 0x6B, 0x65, 0xC0, 0x60}
        for j = 0, 7 do e1[j] = id1[j+1] end
        -- +0x08: flags (retail online: 10 00 00 80)
        e1[0x08] = 0x10; e1[0x09] = 0x00; e1[0x0A] = 0x00; e1[0x0B] = 0x80
        -- +0x0C: 00 00 00 00 (for online)
        -- +0x14: timestamp (retail: 6A F2 AA 69)
        e1[0x14] = 0x6A; e1[0x15] = 0xF2; e1[0x16] = 0xAA; e1[0x17] = 0x69
        -- +0x98: retail value (2D 92 22 00)
        e1[0x98] = 0x2D; e1[0x99] = 0x92; e1[0x9A] = 0x22; e1[0x9B] = 0x00
        -- +0xA0: name
        local n1 = 'CharB'
        for j = 0, #n1 - 1 do e1[0xA0 + j] = n1:byte(j + 1) end
        print('[fdiag] Entry 1 (CharB) written in retail ONLINE format')

        ffi.C.VirtualProtect(ffi.cast('void*', arr2a_base), 200 * 0xB0, old_prot[0], old_prot)

        -- Call populate
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai ~= 0 then
            local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
            populate(ffi.cast('void*', flistmai), 0)
            print('[fdiag] populate_friend_data called.')
        end

        -- Check Store 3 results
        local flist_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)
        local flist_obj = flist_obj_ptr[0]
        if flist_obj ~= 0 then
            local obj = ffi.cast('uint8_t*', flist_obj)
            local count = ffi.cast('int16_t*', obj + 0x132)[0]
            print(('[fdiag] Store 3 count: %d'):format(count))
            for i = 0, math.min(count, 4) - 1 do
                local e = ffi.cast('uint8_t*', flist_obj + 0x0A90 + i * 0x100)
                local flags = ffi.cast('uint32_t*', e + 0x08)[0]
                local status = ffi.cast('uint32_t*', e + 0x98)[0]
                local nbuf = {}
                for j = 0, 14 do
                    local b = e[0xA0 + j]
                    if b == 0 then break end
                    nbuf[#nbuf+1] = string.char(b)
                end
                print(('[fdiag]   [%d] flags=0x%08X status=0x%08X name="%s"'):format(
                    i, flags, status, table.concat(nbuf)))
            end
        end
        return
    end

    -- /fdiag forceonline [index] — enable per-frame Store 3 patching for online bit
    -----------------------------------------------------------------
    if cmd == 'forceonline' then
        local idx = tonumber(args[3]) or 1
        fdiag_force_online_idx = idx
        fdiag_force_online = not fdiag_force_online
        print(('[fdiag] Per-frame online patching for index %d: %s'):format(
            idx, fdiag_force_online and 'ENABLED' or 'DISABLED'))
        return
    end

    -- /fdiag setonline [index] [bit] — set online bit in Array 2a+0x08, then populate & check
    -----------------------------------------------------------------
    if cmd == 'setonline' then
        local idx = tonumber(args[3]) or 1
        local test_bit = tonumber(args[4]) or 22

        -- Set bit in Array 2a
        local arr2a = ffi.cast('uint8_t*', polcore_base + 0xB40D8 + idx * 0xB0)
        local old_flags = ffi.cast('uint32_t*', arr2a + 0x08)[0]
        local old_prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', arr2a + 0x08), 4, 0x40, old_prot)
        ffi.cast('uint32_t*', arr2a + 0x08)[0] = bit.bor(old_flags, bit.lshift(1, test_bit))
        ffi.C.VirtualProtect(ffi.cast('void*', arr2a + 0x08), 4, old_prot[0], old_prot)
        local new_flags = ffi.cast('uint32_t*', arr2a + 0x08)[0]
        print(('[fdiag] Array2a[%d]+0x08: 0x%08X → 0x%08X (set bit %d)'):format(idx, old_flags, new_flags, test_bit))

        -- Call populate_friend_data
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai ~= 0 then
            local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
            populate(ffi.cast('void*', flistmai), 0)
            print('[fdiag] populate_friend_data called.')
        end

        -- Check Store 3 result
        local flist_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)
        local flist_obj = flist_obj_ptr[0]
        if flist_obj ~= 0 then
            local obj = ffi.cast('uint8_t*', flist_obj)
            local count = ffi.cast('int16_t*', obj + 0x132)[0]
            if idx < count then
                local e = ffi.cast('uint8_t*', flist_obj + 0x0A90 + idx * 0x100)
                local s3_flags = ffi.cast('uint32_t*', e + 0x08)[0]
                print(('[fdiag] Store3[%d]+0x08: 0x%08X'):format(idx, s3_flags))
            end
        end

        -- Also set in Store 3 directly (belt and suspenders)
        if flist_obj ~= 0 then
            local obj = ffi.cast('uint8_t*', flist_obj)
            local count = ffi.cast('int16_t*', obj + 0x132)[0]
            if idx < count then
                local e = ffi.cast('uint8_t*', flist_obj + 0x0A90 + idx * 0x100)
                local s3f = ffi.cast('uint32_t*', e + 0x08)[0]
                ffi.C.VirtualProtect(ffi.cast('void*', e + 0x08), 4, 0x40, old_prot)
                ffi.cast('uint32_t*', e + 0x08)[0] = bit.bor(s3f, bit.lshift(1, test_bit))
                ffi.C.VirtualProtect(ffi.cast('void*', e + 0x08), 4, old_prot[0], old_prot)
                local new_s3f = ffi.cast('uint32_t*', e + 0x08)[0]
                print(('[fdiag] Store3[%d]+0x08 post-patch: 0x%08X'):format(idx, new_s3f))
            end
        end
        return
    end

    -- /fdiag tracetype [index] — trace Type 5/6 decision for a Store3 entry
    -----------------------------------------------------------------
    if cmd == 'tracetype' then
        local idx = tonumber(args[3]) or 2
        local store3_obj = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if store3_obj == 0 then print('[fdiag] Store3 NULL') return end

        local s3_base = store3_obj + 0x0A90
        local ent = ffi.cast('uint8_t*', s3_base + idx * 0x100)
        local flags = ffi.cast('uint32_t*', ent + 0x08)[0]
        local flags_hi = ffi.cast('uint32_t*', ent + 0x0C)[0]
        print(('[fdiag] S3[%d] at 0x%08X, flags=0x%08X:%08X'):format(idx, tonumber(ffi.cast('uint32_t', ent)), flags, flags_hi))

        -- Check #1: (flags >> 16) & 1 (bit 16 = online)
        local check1_fn = ffi.cast('int (__cdecl*)(void*)', ffximain_base + 0x0E7420)
        local c1 = bit.band(check1_fn(ffi.cast('void*', ent)), 0xFF)
        print(('[fdiag]   check1 (0x0E7420, bit16): %d'):format(c1))

        -- Check #2: returns pointer, test al
        local check2_fn = ffi.cast('int (__cdecl*)(void*)', ffximain_base + 0x0E7480)
        local c2_raw = check2_fn(ffi.cast('void*', ent))
        local c2_al = bit.band(c2_raw, 0xFF)
        print(('[fdiag]   check2 (0x0E7480, ptr): raw=0x%08X al=0x%02X (pass=%s)'):format(
            c2_raw, c2_al, c2_al ~= 0 and 'YES' or 'NO'))

        -- type5_check (0x0E7510)
        local t5_fn = ffi.cast('int (__cdecl*)(void*)', ffximain_base + 0x0E7510)
        local t5 = bit.band(t5_fn(ffi.cast('void*', ent)), 0xFF)
        print(('[fdiag]   type5_check (0x0E7510): %d'):format(t5))

        -- Now call populate and check display entry type
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai ~= 0 then
            local fm = ffi.cast('uint8_t*', flistmai)
            -- Enrich first
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', ent), 0x100, 0x40, prot)
            ent[0xFC] = 0x41  -- gate byte
            -- Copy zone to +0xD8 (display reads zone name from +0xD8, enrichment writes +0xE0)
            -- Mask off 0x4000 (XI flag) so zone name lookup gets raw zone ID
            local zid = ffi.cast('uint16_t*', ent + 0xE0)[0]
            if zid ~= 0 then ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid, 0x3FFF) end
            ffi.C.VirtualProtect(ffi.cast('void*', ent), 0x100, prot[0], prot)

            local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
            populate(ffi.cast('void*', flistmai), fm[0x58])

            -- Read display entry types from 0x88-stride array
            local arr2_ptr = ffi.cast('uint32_t*', fm + 0x60)[0]
            local disp_idx = ffi.cast('int32_t*', fm + 0x54)[0]
            print(('[fdiag]   After populate: disp_idx=%d'):format(disp_idx))
            if arr2_ptr ~= 0 then
                for di = 0, math.min(disp_idx, 7) - 1 do
                    local de = ffi.cast('uint8_t*', arr2_ptr + di * 0x88)
                    local dtype = de[0]
                    local dcat = ffi.cast('uint16_t*', de + 0x02)[0]
                    local daccid = ffi.cast('uint32_t*', de + 0x08)[0]
                    local dname = ''
                    for j = 0, 14 do
                        if de[0x10 + j] == 0 then break end
                        dname = dname .. string.char(de[0x10 + j])
                    end
                    print(('[fdiag]   disp[%d] type=0x%02X cat=%d accid=0x%04X name="%s"'):format(
                        di, dtype, dcat, daccid, dname))
                end
            end
        end
        return
    end

    -- /fdiag forcetype5 — populate, then force online entries to type 5
    -----------------------------------------------------------------
    if cmd == 'forcetype5' then
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai == 0 then print('[fdiag] flistmai NULL') return end
        local fm = ffi.cast('uint8_t*', flistmai)

        -- Enrich Store3 first
        local store3_obj = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if store3_obj ~= 0 then
            local s3c = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
            local s3_base = store3_obj + 0x0A90
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, 0x40, prot)
            local enrich_fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23E60)
            for ei = 0, s3c do
                local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
                local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
                if bit.band(efl, 0x2000) ~= 0 then
                    local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                    enrich_fn(a2i, ffi.cast('void*', ent))
                    ent[0xFC] = 0x41
                    local zid = ffi.cast('uint16_t*', ent + 0xE0)[0]
                    if zid ~= 0 then ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid, 0x3FFF) end
                end
            end
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, prot[0], prot)
        end

        -- Call populate
        local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
        populate(ffi.cast('void*', flistmai), fm[0x58])
        print('[fdiag] populate_friend_data called.')

        -- Now scan display entries and force type 0x01 → 0x05
        local arr2_ptr = ffi.cast('uint32_t*', fm + 0x60)[0]
        local disp_idx = ffi.cast('int32_t*', fm + 0x54)[0]
        if arr2_ptr ~= 0 then
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', arr2_ptr), disp_idx * 0x88, 0x40, prot)
            for di = 0, disp_idx - 1 do
                local de = ffi.cast('uint8_t*', arr2_ptr + di * 0x88)
                local dtype = de[0]
                local dname = ''
                for j = 0, 14 do
                    if de[0x10 + j] == 0 then break end
                    dname = dname .. string.char(de[0x10 + j])
                end
                print(('[fdiag]   disp[%d] type=0x%02X name="%s"'):format(di, dtype, dname))
                if dtype == 0x01 then
                    de[0] = 0x05
                    print(('[fdiag]   → forced type 0x01 → 0x05 for "%s"'):format(dname))
                end
            end
            ffi.C.VirtualProtect(ffi.cast('void*', arr2_ptr), disp_idx * 0x88, prot[0], prot)
        end
        return
    end

    -- /fdiag arr2hex [index] — hex dump Array 2 entry (both arrays)
    -----------------------------------------------------------------
    if cmd == 'arr2hex' then
        local idx = tonumber(args[3]) or 0
        print(('[fdiag] Array 2 hex dump, index %d'):format(idx))

        -- Array 2a: polcore+0xB40D8 (200 entries × 0xB0)
        local arr2a = ffi.cast('uint8_t*', polcore_base + 0xB40D8 + idx * 0xB0)
        print('[fdiag] === Array 2a (polcore+0xB40D8) ===')
        for row = 0, 10 do
            local hex = {}
            for i = 0, 15 do
                table.insert(hex, ('%02X'):format(arr2a[row * 16 + i]))
            end
            print(('[fdiag]   +0x%02X: %s'):format(row * 16, table.concat(hex, ' ')))
        end

        -- Array 2b: polcore+0xAFC18 (second array, same format)
        local arr2b = ffi.cast('uint8_t*', polcore_base + 0xAFC18 + idx * 0xB0)
        print('[fdiag] === Array 2b (polcore+0xAFC18) ===')
        for row = 0, 10 do
            local hex = {}
            for i = 0, 15 do
                table.insert(hex, ('%02X'):format(arr2b[row * 16 + i]))
            end
            print(('[fdiag]   +0x%02X: %s'):format(row * 16, table.concat(hex, ' ')))
        end

        -- Array 1: polcore+0x403080 (64 entries × 0x68)
        if idx < 64 then
            local arr1 = ffi.cast('uint8_t*', polcore_base + 0x403080 + idx * 0x68)
            print('[fdiag] === Array 1 (polcore+0x403080) ===')
            for row = 0, 6 do
                local hex = {}
                local bytes = (row == 6) and 8 or 16
                for i = 0, bytes - 1 do
                    table.insert(hex, ('%02X'):format(arr1[row * 16 + i]))
                end
                print(('[fdiag]   +0x%02X: %s'):format(row * 16, table.concat(hex, ' ')))
            end
        end

        -- Store 3 entry
        local flist_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)
        local flist_obj = flist_obj_ptr[0]
        if flist_obj ~= 0 then
            local obj = ffi.cast('uint8_t*', flist_obj)
            local count = ffi.cast('int16_t*', obj + 0x132)[0]
            print(('[fdiag] Store 3: count=%d'):format(count))
            if idx < count then
                local e = ffi.cast('uint8_t*', flist_obj + 0x0A90 + idx * 0x100)
                print('[fdiag] === Store 3 entry ===')
                for row = 0, 15 do
                    local hex = {}
                    for i = 0, 15 do
                        table.insert(hex, ('%02X'):format(e[row * 16 + i]))
                    end
                    print(('[fdiag]   +0x%02X: %s'):format(row * 16, table.concat(hex, ' ')))
                end
            end
        end
        return
    end

    -- /fdiag friendsync — copy CallerB friend_data (+0x403080, 64x104B) to FFXiMain-readable
    -- array (+0xB40D8, 200x176B), then call populate_friend_data
    -----------------------------------------------------------------
    if cmd == 'friendsync' then
        -- Source: polcore+0x403080, 64 entries × 0x68 (104) bytes
        -- Dest:   polcore+0xB40D8,  200 entries × 0xB0 (176) bytes
        -- Also:   Handle array +0x405800 (64×40B), Status array +0xAE528 (200×0xA8)
        -- Mapping:
        --   src+0x04 (u32 accid)  → dst+0x00 (u32 id_lo)
        --   src+0x08 (u32 flags)  → dst+0x08 (u32 flags)
        --   src+0x10 (u32 hndidx) → dst+0x10 (handle routing)
        --   src+0x18 (15B char)   → dst+0xA0 (15B display name)
        --   src+0x27 (15B nick)   → handle_array[idx]+0x08 (handle text)
        --   src+0x00 bit0 (valid) → dst+0x98 bit0 (valid)

        local src_base  = polcore_base + 0x403080
        local dst_base  = polcore_base + 0x0B40D8
        local hnd_base  = polcore_base + 0x405800
        local stat_base = polcore_base + 0xAE528
        local old_prot  = ffi.new('uint32_t[1]')
        local old_prot2 = ffi.new('uint32_t[1]')
        local old_prot3 = ffi.new('uint32_t[1]')

        ffi.C.VirtualProtect(ffi.cast('void*', dst_base),  200 * 0xB0, 0x40, old_prot)
        ffi.C.VirtualProtect(ffi.cast('void*', hnd_base),  64 * 40,    0x40, old_prot2)
        ffi.C.VirtualProtect(ffi.cast('void*', stat_base), 200 * 0xA8, 0x40, old_prot3)

        local count = 0
        for i = 0, 63 do
            local src = ffi.cast('uint8_t*', src_base + i * 0x68)
            local dst = ffi.cast('uint8_t*', dst_base + i * 0xB0)

            if bit.band(src[0], 1) ~= 0 then
                for j = 0, 0xAF do dst[j] = 0 end
                for j = 0, 3 do dst[j] = src[4 + j] end           -- accid → id lo
                for j = 0, 3 do dst[8 + j] = src[8 + j] end       -- flags
                for j = 0, 3 do dst[0x10 + j] = src[0x10 + j] end -- handle index routing
                -- Ensure bit 13 for online
                local flags = ffi.cast('uint32_t*', dst + 8)[0]
                if bit.band(flags, 0x2000) == 0 and bit.band(flags, 0x10000) ~= 0 then
                    ffi.cast('uint32_t*', dst + 8)[0] = bit.bor(flags, 0x2000)
                    flags = bit.bor(flags, 0x2000)
                end
                for j = 0, 14 do dst[0xA0 + j] = src[0x18 + j] end -- charname → display name
                dst[0x98] = 1  -- valid

                -- Handle array: write nickname
                local handle_idx = bit.band(src[0x10], 0x3F)
                if handle_idx == 0 then handle_idx = i end
                if handle_idx > 0 and handle_idx < 64 then
                    local hnd = ffi.cast('uint8_t*', hnd_base + handle_idx * 40)
                    hnd[0] = bit.bor(hnd[0], 1)
                    for j = 0, 14 do hnd[8 + j] = src[0x28 + j] end
                end

                -- Status array: populate for online friends (charname, zone)
                if bit.band(flags, 0x2000) ~= 0 then
                    local stat = ffi.cast('uint8_t*', stat_base + i * 0xA8)
                    for j = 0, 0xA7 do stat[j] = 0 end
                    for j = 0, 3 do stat[j] = src[4 + j] end            -- accid
                    ffi.cast('uint32_t*', stat + 4)[0] = 0x01            -- flags
                    for j = 0, 14 do stat[0x18 + j] = src[0x18 + j] end -- charname
                end

                local name_buf = {}
                for j = 0, 14 do
                    if src[0x18 + j] == 0 then break end
                    name_buf[#name_buf+1] = string.char(src[0x18 + j])
                end
                local nick_buf = {}
                for j = 0, 14 do
                    if src[0x28 + j] == 0 then break end
                    nick_buf[#nick_buf+1] = string.char(src[0x28 + j])
                end
                local accid = ffi.cast('uint32_t*', src + 4)[0]
                count = count + 1
                print(('[fdiag] Synced friend[%d]: accid=%d char="%s" nick="%s" hnd_idx=%d'):format(
                    i, accid, table.concat(name_buf), table.concat(nick_buf), handle_idx))
            end
        end

        ffi.C.VirtualProtect(ffi.cast('void*', stat_base), 200 * 0xA8, old_prot3[0], old_prot3)
        ffi.C.VirtualProtect(ffi.cast('void*', hnd_base),  64 * 40,    old_prot2[0], old_prot2)
        ffi.C.VirtualProtect(ffi.cast('void*', dst_base),  200 * 0xB0, old_prot[0], old_prot)
        print(('[fdiag] Synced %d friend(s) from +0x403080 to +0xB40D8'):format(count))

        -- Now call populate_friend_data to rebuild the display
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai ~= 0 then
            local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
            local fm = ffi.cast('uint8_t*', flistmai)
            local param = fm[0x58]
            populate(ffi.cast('void*', flistmai), param)
            local slots = ffi.cast('int32_t*', fm + 0x50)[0]
            print(('[fdiag] populate_friend_data done. slots=%d'):format(slots))
        else
            print('[fdiag] flistmai is NULL, cannot populate')
        end
        return
    end

    -- /fdiag scanpopulate — scan populate_friend_data code for type values and +0xB0 references
    -----------------------------------------------------------------
    if cmd == 'scanpopulate' then
        local range_arg = args[3]
        local func_start, func_end
        if range_arg == 'wide' then
            func_start = ffximain_base + 0x1E9000
            func_end = ffximain_base + 0x1EA600
        else
            func_start = ffximain_base + 0x1E9830
            func_end = ffximain_base + 0x1E9D60
        end
        local func_len = func_end - func_start
        local p = ffi.cast('uint8_t*', func_start)
        print(('[fdiag] Scanning populate_friend_data: 0x%08X..0x%08X (%d bytes)'):format(
            func_start, func_end, func_len))

        -- Search for byte sequence B0 00 00 00 (disp32 = 0xB0, references to +0xB0)
        local b0_hits = {}
        for i = 0, func_len - 4 do
            if p[i] == 0xB0 and p[i+1] == 0x00 and p[i+2] == 0x00 and p[i+3] == 0x00 then
                -- Check if preceded by a modrm byte suggesting [reg+disp32]
                local ctx = {}
                local cs = math.max(0, i - 4)
                for j = cs, math.min(func_len - 1, i + 7) do
                    table.insert(ctx, ('%02X'):format(p[j]))
                end
                table.insert(b0_hits, {off = i, ctx = table.concat(ctx, ' ')})
            end
        end
        print(('[fdiag] References to disp32=0xB0: %d'):format(#b0_hits))
        for _, h in ipairs(b0_hits) do
            print(('[fdiag]   +0x%04X (abs 0x%08X): %s'):format(h.off, func_start + h.off, h.ctx))
        end

        -- Search for MOV byte [reg+X], 5 patterns: C6 XX XX 05 (disp8) or C6 XX XX XX XX XX 05 (disp32)
        -- Also search for PUSH 5 (6A 05) and MOV reg, 5 (B8+r 05 00 00 00)
        local type5_hits = {}
        for i = 0, func_len - 2 do
            -- C6 mod/rm ... 05 (MOV byte [mem], 5)
            if p[i] == 0xC6 and i + 3 < func_len then
                local modrm = p[i+1]
                local mod = bit.rshift(modrm, 6)
                if mod == 1 then -- [reg+disp8]
                    if p[i+3] == 0x05 then
                        local ctx = {}
                        local cs = math.max(0, i - 2)
                        for j = cs, math.min(func_len - 1, i + 5) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(type5_hits, {off = i, ctx = table.concat(ctx, ' '), kind = 'MOV byte [reg+disp8], 5'})
                    end
                elseif mod == 2 then -- [reg+disp32]
                    if i + 7 < func_len and p[i+6] == 0x05 then
                        local ctx = {}
                        local cs = math.max(0, i - 2)
                        for j = cs, math.min(func_len - 1, i + 8) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(type5_hits, {off = i, ctx = table.concat(ctx, ' '), kind = 'MOV byte [reg+disp32], 5'})
                    end
                end
            end
            -- 6A 05 (PUSH 5)
            if p[i] == 0x6A and p[i+1] == 0x05 then
                local ctx = {}
                local cs = math.max(0, i - 4)
                for j = cs, math.min(func_len - 1, i + 5) do
                    table.insert(ctx, ('%02X'):format(p[j]))
                end
                table.insert(type5_hits, {off = i, ctx = table.concat(ctx, ' '), kind = 'PUSH 5'})
            end
        end
        print(('[fdiag] Type value 5 references: %d'):format(#type5_hits))
        for _, h in ipairs(type5_hits) do
            print(('[fdiag]   +0x%04X (abs 0x%08X): [%s] %s'):format(h.off, func_start + h.off, h.kind, h.ctx))
        end

        -- Also dump all MOV byte [mem], imm8 to see ALL type assignments
        local mov_byte_hits = {}
        for i = 0, func_len - 3 do
            if p[i] == 0xC6 then
                local modrm = p[i+1]
                local mod = bit.rshift(modrm, 6)
                local reg = bit.band(bit.rshift(modrm, 3), 7)
                if reg == 0 then -- /0 = MOV
                    local imm, desc
                    if mod == 1 then
                        imm = p[i+3]
                        desc = ('[reg+0x%02X]'):format(p[i+2])
                    elseif mod == 2 then
                        local disp = ffi.cast('int32_t*', p + i + 2)[0]
                        imm = p[i+6]
                        desc = ('[reg+0x%X]'):format(disp)
                    end
                    if imm and (imm >= 1 and imm <= 7) then
                        local ctx = {}
                        for j = i, math.min(func_len - 1, i + 7) do
                            table.insert(ctx, ('%02X'):format(p[j]))
                        end
                        table.insert(mov_byte_hits, {off = i, imm = imm, desc = desc, ctx = table.concat(ctx, ' ')})
                    end
                end
            end
        end
        print(('[fdiag] MOV byte [mem], 1-7 (type assignments): %d'):format(#mov_byte_hits))
        for _, h in ipairs(mov_byte_hits) do
            print(('[fdiag]   +0x%04X: MOV byte %s, %d  (%s)'):format(h.off, h.desc, h.imm, h.ctx))
        end

        -- Dump CALL instructions to identify sub-functions
        local call_hits = {}
        for i = 0, func_len - 5 do
            if p[i] == 0xE8 then
                local rel = ffi.cast('int32_t*', p + i + 1)[0]
                local target = func_start + i + 5 + rel
                table.insert(call_hits, {off = i, target = target})
            end
        end
        print(('[fdiag] CALL instructions: %d'):format(#call_hits))
        for _, h in ipairs(call_hits) do
            local tgt_off = h.target - ffximain_base
            print(('[fdiag]   +0x%04X: CALL FFXiMain+0x%06X (abs 0x%08X)'):format(h.off, tgt_off, h.target))
        end

        return
    end

    -- /fdiag flistpop — call populate_friend_data to rebuild display arrays from polcore data
    -- Must run testfriend first to populate the raw friend data object
    -----------------------------------------------------------------
    if cmd == 'flistpop' then
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai == 0 then
            print('[fdiag] flistmai pointer is NULL!')
            return
        end
        print(('[fdiag] flistmai at 0x%08X'):format(flistmai))

        -- populate_friend_data is at FFXiMain+0x1E9830 (absolute 0x044A9830)
        -- Signature: void __thiscall populate(flistmai* this, int param)
        -- param comes from this->field_0x58
        local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
        local fm = ffi.cast('uint8_t*', flistmai)
        local param = fm[0x58]

        local store3_obj = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))

        -- Diagnostic: test the strncpy function directly vs via enrich
        if store3_obj ~= 0 and polcore_base ~= 0 then
            local s3c = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
            local s3_base = store3_obj + 0x0A90
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, 0x40, prot)

            for ei = 0, s3c do
                local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
                local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
                if bit.band(efl, 0x2000) ~= 0 then
                    local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                    local tbl = ffi.cast('uint8_t*', polcore_base + 0x3FC920 + a2i * 0x84)
                    local src = tbl + 0x04  -- charname at table+0x04 (confirmed via disasm)
                    local dst = ent + 0xB4

                    -- Test 2: Via native enrich function (now reads charname from table+0x04)
                    for j = 0, 23 do dst[j] = 0xCC end
                    local enrich = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23E60)
                    enrich(a2i, ffi.cast('void*', ent))
                    local t2 = {}
                    for j = 0, 7 do t2[#t2+1] = ('%02X'):format(dst[j]) end
                    local marker = ffi.cast('uint32_t*', ent + 0xB0)[0]
                    print(('[fdiag]   VIA ENRICH: dst: %s marker=0x%08X'):format(
                        table.concat(t2, ' '), marker))
                end
            end
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, prot[0], prot)
        end

        print(('[fdiag] Calling populate_friend_data(0x%08X, %d)...'):format(flistmai, param))
        populate(ffi.cast('void*', flistmai), param)
        print('[fdiag] populate_friend_data returned.')

        -- Re-enrich after populate (populate zeros +0xB4)
        if store3_obj ~= 0 and polcore_base ~= 0 then
            local s3c = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
            local s3_base = store3_obj + 0x0A90
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, 0x40, prot)
            local enrich_fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23E60)
            for ei = 0, s3c do
                local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
                local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
                if bit.band(efl, 0x2000) ~= 0 then
                    local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                    enrich_fn(a2i, ffi.cast('void*', ent))
                end
            end
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, prot[0], prot)
        end

        -- Check results
        local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
        local arr_ptr = ffi.cast('uint32_t*', fm + 0x5C)[0]
        local slots = ffi.cast('int32_t*', fm + 0x50)[0]
        local disp_idx = ffi.cast('int32_t*', fm + 0x54)[0]
        print(('[fdiag] After populate: sub_mgr=0x%08X array_ptr=0x%08X slots=%d disp_idx=%d'):format(
            sub_mgr, arr_ptr, slots, disp_idx))

        if arr_ptr ~= 0 then
            print('[fdiag] Display array allocated! Try /flist now.')
        else
            print('[fdiag] Display array still NULL — populate may have found no valid entries.')
        end
        return
    end

    -----------------------------------------------------------------
    -- FIXFLIST: One-shot fix to make /flist work
    -- 1. NOP the handle_node clearing in prepare_display
    -- 2. Restore handle_node from backup (+0x64 → +0x34)
    -- 3. Show flistmai in WM (if not already visible)
    -- 4. Enrich Store 3 + clean struct region (BEFORE populate)
    -- 5. populate_friend_data to build display arrays
    -- 6. Re-enrich + clean (restore anything populate touched)
    -----------------------------------------------------------------
    if cmd == 'fixflist' then
        local flistmai_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)
        local flistmai = flistmai_ptr[0]
        if flistmai == 0 then
            print('[fdiag] FAIL: flistmai is NULL')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        print(('[fdiag] flistmai at 0x%08X'):format(flistmai))

        -- Step 1: NOP the MOV [ESI+0x34], 0 in prepare_display (+0x1E9DA5)
        local patch_addr = ffximain_base + 0x1E9DA5
        local code = ffi.cast('uint8_t*', patch_addr)
        if code[0] == 0xC7 and code[1] == 0x46 and code[2] == 0x34 then
            local old_protect = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', patch_addr), 7, 0x40, old_protect)
            for i = 0, 6 do code[i] = 0x90 end
            ffi.C.VirtualProtect(ffi.cast('void*', patch_addr), 7, old_protect[0], old_protect)
            print('[fdiag] Step 1: NOPped handle_node clear (7 bytes at +0x1E9DA5)')
        elseif code[0] == 0x90 then
            print('[fdiag] Step 1: Already patched (NOPs)')
        else
            print('[fdiag] Step 1: UNEXPECTED bytes, skipping patch')
        end

        -- Step 2: Restore handle_node from backup
        local hn_backup = ffi.cast('uint32_t*', fm + 0x64)[0]
        local hn_current = ffi.cast('uint32_t*', fm + 0x34)[0]
        if hn_backup ~= 0 and hn_current == 0 then
            ffi.cast('uint32_t*', fm + 0x34)[0] = hn_backup
            print(('[fdiag] Step 2: Restored handle_node +0x34 = 0x%08X (from +0x64)'):format(hn_backup))
        elseif hn_current ~= 0 then
            print(('[fdiag] Step 2: handle_node already set: 0x%08X'):format(hn_current))
        else
            -- Try getting from the child element table
            local get_child = ffi.cast('uint32_t (__cdecl*)(int)', ffximain_base + 0x1C7390)
            local child_ptr_addr = get_child(1)
            if child_ptr_addr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', child_ptr_addr), 4) == 0 then
                local child = ffi.cast('uint32_t*', child_ptr_addr)[0]
                if child ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', child + 0x12C), 4) == 0 then
                    local hn = ffi.cast('uint32_t*', child + 0x12C)[0]
                    if hn ~= 0 then
                        ffi.cast('uint32_t*', fm + 0x34)[0] = hn
                        ffi.cast('uint32_t*', fm + 0x64)[0] = hn
                        print(('[fdiag] Step 2: Extracted handle_node from child[1]+0x12C = 0x%08X'):format(hn))
                    else
                        print('[fdiag] Step 2: FAIL: child[1]+0x12C is NULL')
                    end
                else
                    print('[fdiag] Step 2: FAIL: child[1] object invalid')
                end
            else
                print('[fdiag] Step 2: FAIL: No backup and no child element')
            end
        end

        -- Step 3: Show flistmai in WM
        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)', ffximain_base + 0x15D080)
        local wm_addr = ffximain_base + 0x5ECB98
        local flistmai_str = ffi.cast('const char*', ffximain_base + 0x37FF30) -- "menu    flistmai"
        local sm_ret = show_menu(ffi.cast('void*', wm_addr), flistmai_str, 1, 0)
        print(('[fdiag] Step 3: show_menu(flistmai) = 0x%08X'):format(sm_ret))

        -- Step 4: Enrich Store 3 BEFORE populate (so gate/charname are set for populate)
        local store3_obj = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if store3_obj ~= 0 then
            local s3c = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
            local s3_base = store3_obj + 0x0A90
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, 0x40, prot)
            local enrich_fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23E60)
            for ei = 0, s3c do
                local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
                local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
                if bit.band(efl, 0x2000) ~= 0 then
                    local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                    enrich_fn(a2i, ffi.cast('void*', ent))
                    -- Clean up struct region: zero 0xCC-0xFF, restore only zone+gate
                    local zid_pre = ffi.cast('uint16_t*', ent + 0xE0)[0]
                    for j = 0xCC, 0xFF do ent[j] = 0 end
                    ffi.cast('uint16_t*', ent + 0xE0)[0] = zid_pre
                    ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid_pre, 0x3FFF)  -- raw zone ID for name lookup
                    ent[0xFC] = 0x41  -- gate: bit 0 (charname) + bit 6 (zone)
                end
            end
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, prot[0], prot)
            print(('[fdiag] Step 4: Enriched + cleaned %d Store 3 entries'):format(s3c))
        end

        -- Step 5: populate_friend_data (now runs with enriched Store 3 data)
        fm[0x49] = 1  -- enable flag
        local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
        local param = fm[0x58]

        -- Diagnostic: check Store 3 BEFORE populate
        if store3_obj ~= 0 then
            local s3c = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
            local s3_base = store3_obj + 0x0A90
            for ei = 0, s3c do
                local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
                if bit.band(ffi.cast('uint32_t*', ent + 0x98)[0], 1) ~= 0 then
                    local cn = ffi.string(ffi.cast('char*', ent + 0xB4), 15):gsub('%z+$', '')
                    local nick = ffi.string(ffi.cast('char*', ent + 0xA0), 15):gsub('%z+$', '')
                    local zid = ffi.cast('uint16_t*', ent + 0xE0)[0]
                    local marker = ffi.cast('uint32_t*', ent + 0xB0)[0]
                    local gate = ent[0xFC]
                    print(('[fdiag]   PRE-POP S3[%d] nick="%s" cn="%s" zone=%d marker=0x%X gate=0x%02X'):format(
                        ei, nick, cn, zid, marker, gate))
                end
            end
        end

        -- Zero arr2 entries before populate to see exactly what populate writes
        local arr2_ptr = ffi.cast('uint32_t*', fm + 0x60)[0]
        if arr2_ptr ~= 0 then
            local arr2_bytes = ffi.cast('uint8_t*', arr2_ptr)
            for j = 0, 8 * 0x88 - 1 do arr2_bytes[j] = 0 end
        end

        populate(ffi.cast('void*', flistmai), param)
        print(('[fdiag] Step 5: populate_friend_data called (param=%d)'):format(param))

        -- Dump arr2 entries showing which bytes populate wrote (non-zero)
        if arr2_ptr ~= 0 then
            local arr2_bytes = ffi.cast('uint8_t*', arr2_ptr)
            for slot = 0, 7 do
                local base = slot * 0x88
                local has_data = false
                for j = 0, 0x87 do
                    if arr2_bytes[base + j] ~= 0 then has_data = true break end
                end
                if has_data then
                    local fields = {}
                    for off = 0, 0x87, 4 do
                        local dw = ffi.cast('uint32_t*', arr2_bytes + base + off)[0]
                        if dw ~= 0 then
                            table.insert(fields, ('+%02X=%08X'):format(off, dw))
                        end
                    end
                    local txt = {}
                    for j = 0x10, 0x2F do
                        local b = arr2_bytes[base + j]
                        if b >= 0x20 and b < 0x7F then txt[#txt+1] = string.char(b)
                        elseif b == 0 then txt[#txt+1] = '.'
                        else txt[#txt+1] = '?' end
                    end
                    print(('[fdiag]   arr2[%d] %s text="%s"'):format(slot, table.concat(fields, ' '), table.concat(txt)))
                end
            end
        end

        -- Step 6: Re-enrich + cleanup again (in case populate touched Store 3)
        if store3_obj ~= 0 then
            local s3c = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
            local s3_base = store3_obj + 0x0A90
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, 0x40, prot)
            local enrich_fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23E60)
            for ei = 0, s3c do
                local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
                local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
                if bit.band(efl, 0x2000) ~= 0 then
                    local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                    enrich_fn(a2i, ffi.cast('void*', ent))
                    -- Clean up struct region again
                    local zid_pre = ffi.cast('uint16_t*', ent + 0xE0)[0]
                    for j = 0xCC, 0xFF do ent[j] = 0 end
                    ffi.cast('uint16_t*', ent + 0xE0)[0] = zid_pre
                    ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid_pre, 0x3FFF)  -- raw zone ID for name lookup
                    ent[0xFC] = 0x41
                end
            end
            ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3c + 1) * 0x100, prot[0], prot)
            print(('[fdiag] Step 6: Re-enriched + cleaned Store 3 entries'):format())
        end

        -- Final diagnostic
        local hn = ffi.cast('uint32_t*', fm + 0x34)[0]
        local arr = ffi.cast('uint32_t*', fm + 0x5C)[0]
        local arr2 = ffi.cast('uint32_t*', fm + 0x60)[0]
        local slots = ffi.cast('int32_t*', fm + 0x50)[0]
        local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
        print(('[fdiag] Result: hn=0x%08X arr=0x%08X arr2=0x%08X slots=%d sub_mgr=0x%08X'):format(
            hn, arr, arr2, slots, sub_mgr))
        if hn ~= 0 and arr ~= 0 then
            print('[fdiag] SUCCESS! Try /flist in game now.')
        elseif hn ~= 0 and arr == 0 then
            print('[fdiag] PARTIAL: handle_node set but no display arrays (no valid Store 3 entries?)')
        else
            print('[fdiag] INCOMPLETE: handle_node still NULL')
        end
        return
    end

    -- /fdiag bootdiag — dump post-bootstrap SM state and key memory regions
    -- Used after game boot to diagnose why CallerB doesn't fire natively
    -----------------------------------------------------------------
    if cmd == 'bootdiag' then
        print('[fdiag] === POST-BOOTSTRAP DIAGNOSTIC ===')

        -- SM state variables
        local state = ffi.cast('int32_t*', polcore_base + 0x099408)[0]
        local mode = ffi.cast('int32_t*', polcore_base + 0x099C80)[0]
        local arg = ffi.cast('int32_t*', polcore_base + 0x099414)[0]
        local alt = ffi.cast('int32_t*', polcore_base + 0x09940C)[0]
        local counter = ffi.cast('int32_t*', polcore_base + 0x09941C)[0]
        local conn_type = ffi.cast('int32_t*', polcore_base + 0x0993E8)[0]
        local canary = ffi.cast('uint32_t*', polcore_base + 0x0996BC)[0]
        local gate = ffi.cast('uint32_t*', polcore_base + 0x09A5D0)[0]
        local init = ffi.cast('uint32_t*', polcore_base + 0x099244)[0]

        print(('[fdiag] SM: state=%d alt=0x%08X mode=%d arg=%d init=%d'):format(
            state, tonumber(ffi.cast('uint32_t', alt)), mode, arg, init))
        print(('[fdiag] SM: counter=%d conn_type=%d canary=%d gate=%d'):format(
            counter, conn_type, canary, gate))

        -- Sockaddr
        local sockaddr_family = ffi.cast('uint16_t*', polcore_base + 0x404AB8)[0]
        local sockaddr_port = ffi.cast('uint16_t*', polcore_base + 0x404ABA)[0]
        local sockaddr_ip = ffi.cast('uint32_t*', polcore_base + 0x404ABC)[0]
        print(('[fdiag] sockaddr: family=%d port=%d ip=0x%08X'):format(
            sockaddr_family, sockaddr_port, sockaddr_ip))

        -- Descriptor slots
        local desc_base = polcore_base + 0x404AD0
        for i = 0, 3 do
            local slot = ffi.cast('uint8_t*', desc_base + i * 0x338)
            local inuse = slot[0]
            local omode = slot[0x08]
            local istate = slot[0x09]
            local crypto = slot[0x0B]
            local sock = ffi.cast('int32_t*', slot + 4)[0]
            if inuse ~= 0 or sock ~= -1 then
                print(('[fdiag] slot[%d]: inuse=%d mode=%d state=%d crypto=%d sock=%d'):format(
                    i, inuse, omode, istate, crypto, sock))
            end
        end

        -- Per-frame counter regions (mode 0 helpers read these)
        local function dump_region(name, offset, count)
            local p = ffi.cast('uint32_t*', polcore_base + offset)
            local vals = {}
            for i = 0, count - 1 do
                table.insert(vals, ('%08X'):format(tonumber(ffi.cast('uint32_t', p[i]))))
            end
            print(('[fdiag] %s: %s'):format(name, table.concat(vals, ' ')))
        end

        dump_region('counter_470E0', 0x470E0, 4)
        dump_region('counter_47150', 0x47150, 4)
        dump_region('counter_47340', 0x47340, 4)
        dump_region('config_99288', 0x99288, 5)

        -- Init flag
        local init_flag = ffi.cast('uint32_t*', polcore_base + 0x0AFBD8)[0]
        print(('[fdiag] CreateFriendList init flag [+0xAFBD8] = %d'):format(init_flag))

        -- Session keys
        local key1 = ffi.cast('uint32_t*', polcore_base + 0x0AA848)[0]
        local key2 = ffi.cast('uint32_t*', polcore_base + 0x0AA84C)[0]
        print(('[fdiag] Session keys: key1=0x%08X key2=0x%08X'):format(key1, key2))

        print('[fdiag] === END DIAGNOSTIC ===')
        return
    end

    -- /fdiag findref <module> <target_addr> [max_hits] — scan module .text for dword references
    -- Searches for 4-byte LE encodings of target_addr in the module's code section
    -----------------------------------------------------------------
    if cmd == 'findref' then
        local mod_name = args[3]
        local target_arg = args[4]
        local max_hits = tonumber(args[5]) or 50
        if not mod_name or not target_arg then
            print('[fdiag] Usage: /fdiag findref <scan_module> <target_addr|target_module+offset> [max_hits]')
            print('[fdiag] Example: /fdiag findref FFXiMain.dll 0x045EE880')
            print('[fdiag] Example: /fdiag findref FFXiMain.dll FFXiMain.dll+0x51E880')
            return
        end

        -- Parse target: either absolute addr or module+offset
        local target
        local plus_pos = target_arg:find('+')
        if plus_pos then
            local tmod = target_arg:sub(1, plus_pos - 1)
            local toff = tonumber(target_arg:sub(plus_pos + 1))
            if not toff then
                print('[fdiag] Invalid offset in module+offset syntax')
                return
            end
            local tbase = ffi.C.GetModuleHandleA(tmod)
            if tbase == 0 then
                print(('[fdiag] Target module %s not loaded'):format(tmod))
                return
            end
            target = tbase + toff
            print(('[fdiag] Resolved %s+0x%X = 0x%08X'):format(tmod, toff, target))
        else
            target = tonumber(target_arg)
        end
        if not target then
            print('[fdiag] Invalid target address')
            return
        end

        local mod_base = ffi.C.GetModuleHandleA(mod_name)
        if mod_base == 0 then
            print(('[fdiag] Module %s not loaded'):format(mod_name))
            return
        end
        print(('[fdiag] Scanning %s (base=0x%08X) for refs to 0x%08X'):format(mod_name, mod_base, target))

        -- Parse PE header to find .text section
        local base = ffi.cast('uint8_t*', mod_base)
        local e_lfanew = ffi.cast('uint32_t*', base + 0x3C)[0]
        local pe = base + e_lfanew
        local num_sections = ffi.cast('uint16_t*', pe + 6)[0]
        local opt_hdr_size = ffi.cast('uint16_t*', pe + 20)[0]
        local section_start = pe + 24 + opt_hdr_size

        -- Collect all sections to scan
        local sections = {}
        for i = 0, num_sections - 1 do
            local sec = section_start + i * 40
            local name_bytes = {}
            for j = 0, 7 do
                local b = sec[j]
                if b == 0 then break end
                table.insert(name_bytes, string.char(b))
            end
            local sec_name = table.concat(name_bytes)
            local virt_size = ffi.cast('uint32_t*', sec + 8)[0]
            local virt_addr = ffi.cast('uint32_t*', sec + 12)[0]
            local characteristics = ffi.cast('uint32_t*', sec + 36)[0]

            if virt_size > 0 then
                table.insert(sections, {
                    name = sec_name,
                    start = mod_base + virt_addr,
                    size = virt_size,
                    chars = characteristics
                })
                print(('[fdiag] Section "%s": VA=0x%08X size=0x%X'):format(
                    sec_name, mod_base + virt_addr, virt_size))
            end
        end

        if #sections == 0 then
            local img_size = ffi.cast('uint32_t*', pe + 24 + 56)[0]
            table.insert(sections, { name = '<image>', start = mod_base, size = img_size, chars = 0 })
            print(('[fdiag] No sections found, scanning entire image (0x%X bytes)'):format(img_size))
        end

        -- Search for 4-byte LE encoding of target address in each section
        local target_bytes = ffi.new('uint8_t[4]')
        target_bytes[0] = bit.band(target, 0xFF)
        target_bytes[1] = bit.band(bit.rshift(target, 8), 0xFF)
        target_bytes[2] = bit.band(bit.rshift(target, 16), 0xFF)
        target_bytes[3] = bit.band(bit.rshift(target, 24), 0xFF)

        local hits = 0
        local results = {}
        for _, sec in ipairs(sections) do
            local p = ffi.cast('uint8_t*', sec.start)
            -- Skip sections that might be unreadable
            if ffi.C.IsBadReadPtr(ffi.cast('void*', sec.start), sec.size) ~= 0 then
                print(('[fdiag] Skipping unreadable section "%s"'):format(sec.name))
            else
                for off = 0, sec.size - 4 do
                    if p[off] == target_bytes[0] and p[off+1] == target_bytes[1]
                       and p[off+2] == target_bytes[2] and p[off+3] == target_bytes[3] then
                        hits = hits + 1
                        local abs_addr = sec.start + off
                        local rel_off = abs_addr - mod_base
                        -- Read surrounding bytes for context (8 before, 4 match, 8 after = 20 bytes)
                        local ctx = {}
                        for j = -8, 11 do
                            local idx = off + j
                            if idx >= 0 and idx < sec.size then
                                table.insert(ctx, ('%02X'):format(p[idx]))
                            end
                        end
                        table.insert(results, ('[fdiag]   #%d [%s] +0x%X (0x%08X): %s'):format(
                            hits, sec.name, rel_off, abs_addr, table.concat(ctx, ' ')))
                        if hits >= max_hits then break end
                    end
                end
            end
            if hits >= max_hits then break end
        end

        print(('[fdiag] Found %d references to 0x%08X:'):format(hits, target))
        for _, line in ipairs(results) do print(line) end
        if hits == 0 then
            print('[fdiag] No references found. Target may use indirect addressing or different base.')
        end
        return
    end

    -- /fdiag syncstatus — populate status tables from Array 1, enrich Store 3, refresh display
    -- This is the "status update protocol" substitute. On retail, separate connections
    -- continuously update the 0x84-stride status table with charname/zone data.
    -- We populate it from the friend records in Array 1 (set by CallerB mode 6).
    -----------------------------------------------------------------
    if cmd == 'syncstatus' then
        local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
        local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
        if polcore_base == 0 or ffximain_base == 0 then
            print('[fdiag] Modules not loaded')
            return
        end

        local store3_obj = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if store3_obj == 0 then
            print('[fdiag] Store 3 object is NULL — open /flist first')
            return
        end

        local src_base  = polcore_base + 0x403080   -- Array 1 (friend_data)
        local stbl_base = polcore_base + 0x3FC920   -- Status table (0x84 stride)
        local hnd_base  = polcore_base + 0x405800   -- Handle array
        local s3_base   = store3_obj + 0x0A90
        local s3_count  = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]

        -- Step 1: Populate 0x84-stride status table from Array 1 (friend_data)
        -- IMPORTANT: Write at a2i index (Array 2 index from Store 3 bits 20-27),
        -- not friend_data index, because the enrichment function reads at a2i.
        -- Build a mapping: friend_data index → a2i from Store 3 entries.
        local fd_to_a2i = {}
        for ei = 0, s3_count do
            local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
            local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
            if bit.band(efl, 0x2000) ~= 0 then
                local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                -- Match Store 3 entry to friend_data by comparing friend ID
                local s3_fid = ffi.cast('uint16_t*', ent + 0x00)[0]
                for fi = 1, 63 do
                    local fsrc = ffi.cast('uint8_t*', src_base + fi * 0x68)
                    if bit.band(fsrc[0], 1) ~= 0 then
                        local fd_fid = ffi.cast('uint16_t*', fsrc + 0x02)[0]
                        if fd_fid == s3_fid or fi == a2i then
                            fd_to_a2i[fi] = a2i
                            break
                        end
                    end
                end
            end
        end
        local old_prot_t = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', stbl_base), 200 * 0x84, 0x40, old_prot_t)
        local sync_count = 0
        for i = 1, 63 do  -- entry 0 = player, entries 1+ = friends
            local src = ffi.cast('uint8_t*', src_base + i * 0x68)
            if bit.band(src[0], 1) ~= 0 then
                local flags = ffi.cast('uint32_t*', src + 0x08)[0]
                if bit.band(flags, 0x2000) ~= 0 then  -- online entries only
                    local tbl_idx = fd_to_a2i[i] or i  -- use a2i if known, fallback to i
                    local tbl = ffi.cast('uint8_t*', stbl_base + tbl_idx * 0x84)
                    for j = 0, 0x83 do tbl[j] = 0 end
                    -- +0x00: marker DWORD (bit 0=charname gate, bit 6=zone gate)
                    ffi.cast('uint32_t*', tbl + 0x00)[0] = 0x00000041
                    -- +0x04: charname (24 bytes, null-terminated)
                    local cn = ffi.string(src + 0x18, 15):gsub('%z+$', '')
                    for j = 1, math.min(#cn, 15) do
                        tbl[0x04 + j - 1] = cn:byte(j)
                    end
                    -- +0x1C: struct (WORDs, struct_copy stops at zero WORD)
                    -- Fill 25 WORDs with non-zero, then zero terminator at index 25.
                    -- Index 22 (struct+0x2C) maps to entry+0xF8 which populate checks
                    -- (nonzero → cat2/type3). Use 0x0100 so low byte = 0x00.
                    for j = 0, 24 do
                        ffi.cast('uint16_t*', tbl + 0x1C + j * 2)[0] = (j == 22) and 0x0100 or 0x0101
                    end
                    ffi.cast('uint16_t*', tbl + 0x1C + 25 * 2)[0] = 0x0000
                    -- +0x30 (struct+0x14): zone_id WORD | 0x4000 (XI game active flag)
                    -- Bit 14 (0x4000) = "in FFXI" flag, checked by type5_check for XI icon
                    -- Zone is at friend_data+0x0E (high u16 of flags_hi dword at +0x0C)
                    local zid = ffi.cast('uint16_t*', src + 0x0E)[0]
                    if zid > 0 then
                        ffi.cast('uint16_t*', tbl + 0x30)[0] = bit.bor(zid, 0x4000)
                    end
                    -- +0x4C (struct+0x30): gate byte
                    tbl[0x4C] = 0x41  -- bit 0 (charname) + bit 6 (zone)
                    sync_count = sync_count + 1
                    print(('[fdiag] Status[%d→%d]: "%s" zone=%d'):format(i, tbl_idx, cn, zid))
                end
            end
        end
        ffi.C.VirtualProtect(ffi.cast('void*', stbl_base), 200 * 0x84, old_prot_t[0], old_prot_t)
        print(('[fdiag] Populated %d status table entries'):format(sync_count))

        -- Step 2: Enrich Store 3 entries (reads Array 2 + status table → Store 3)
        -- After enrichment, clean struct region (0xCC-0xFF) to avoid 0x0101 interference
        local enrich_fn = ffi.cast('int (__cdecl*)(int, void*)', polcore_base + 0x23E60)
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3_count + 1) * 0x100, 0x40, prot)
        local enriched = 0
        for ei = 0, s3_count do
            local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
            local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
            if bit.band(efl, 0x2000) ~= 0 then
                local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                enrich_fn(a2i, ffi.cast('void*', ent))
                -- Clean struct region: zero 0xCC-0xFF, restore only zone+gate
                local zid_pre = ffi.cast('uint16_t*', ent + 0xE0)[0]
                for j = 0xCC, 0xFF do ent[j] = 0 end
                ffi.cast('uint16_t*', ent + 0xE0)[0] = zid_pre
                ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid_pre, 0x3FFF)  -- raw zone ID for name lookup
                ent[0xFC] = 0x41  -- gate: bit 0 (charname) + bit 6 (zone)
                -- Set game type = 1 (FFXI) in flags_hi bits 1-10
                -- game_type_check (0x0E7350) extracts (flags_hi >> 1) & 0x3FF
                local fhi = ffi.cast('uint16_t*', ent + 0x0C)
                fhi[0] = bit.bor(bit.band(fhi[0], 0xF800), 0x0002)  -- preserve high bits, set game_type=1
                enriched = enriched + 1
            end
        end
        print(('[fdiag] Enriched %d Store 3 entries (pre-populate)'):format(enriched))

        -- Step 3: Call populate_friend_data to refresh display arrays
        local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
        if flistmai ~= 0 then
            local fm = ffi.cast('uint8_t*', flistmai)
            local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
            populate(ffi.cast('void*', flistmai), fm[0x58])
            local slots = ffi.cast('int32_t*', fm + 0x50)[0]
            print(('[fdiag] populate_friend_data: slots=%d'):format(slots))

            -- Step 3b: Manually inject XI icon into render buffers
            -- populate_friend_data doesn't set type=2 because flags_hi was 0 when it ran
            -- (our enrichment sets flags_hi BEFORE populate, but native bridge may overwrite)
            -- So we directly write the XI icon into each online friend's render buffer.
            -- Only inject for category 5 (Type 5 = fully online with charname+zone).
            local render_base = ffi.cast('uint32_t*', flistmai + 0x5C)[0]
            local icon_ptr_ptr = ffi.cast('uint32_t*', flistmai + 0x8C)[0]
            local icon_array_base = 0
            if icon_ptr_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', icon_ptr_ptr), 4) == 0 then
                icon_array_base = ffi.cast('uint32_t*', icon_ptr_ptr)[0]
            end
            if render_base ~= 0 and icon_array_base ~= 0 then
                local xi_icon = ffi.cast('uint32_t*', icon_array_base)[0]  -- game type 1, index 0
                local inject_count = 0
                for ri = 0, slots - 1 do
                    local rb = ffi.cast('uint8_t*', render_base + ri * 0x54)
                    -- Check display entry category via pointer at render_buffer+0x48
                    local disp_ptr = ffi.cast('uint32_t*', rb + 0x48)[0]
                    if disp_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', disp_ptr), 1) == 0 then
                        local category = ffi.cast('uint8_t*', disp_ptr)[0]
                        if category == 5 then  -- Type 5 = online with charname+zone
                            rb[2] = 0x0E  -- position
                            ffi.cast('uint32_t*', rb + 0x10)[0] = 0x80808080  -- color for type 2
                            ffi.cast('uint32_t*', rb + 0x30)[0] = xi_icon  -- icon resource
                            inject_count = inject_count + 1
                        end
                    end
                end
                print(('[fdiag] Injected XI icon into %d render buffer(s) (icon=0x%08X)'):format(inject_count, xi_icon))
            end
        end

        -- Step 4: Re-enrich + clean struct region (in case populate touched Store 3)
        s3_count = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_obj) + 0x132)[0]
        enriched = 0
        for ei = 0, s3_count do
            local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
            local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
            if bit.band(efl, 0x2000) ~= 0 then
                local a2i = bit.band(bit.rshift(efl, 20), 0xFF)
                enrich_fn(a2i, ffi.cast('void*', ent))
                -- Clean struct region
                local zid_pre = ffi.cast('uint16_t*', ent + 0xE0)[0]
                for j = 0xCC, 0xFF do ent[j] = 0 end
                ffi.cast('uint16_t*', ent + 0xE0)[0] = zid_pre
                ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid_pre, 0x3FFF)  -- raw zone ID for name lookup
                ent[0xFC] = 0x41
                -- Set game type = 1 (FFXI) in flags_hi bits 1-10
                local fhi = ffi.cast('uint16_t*', ent + 0x0C)
                fhi[0] = bit.bor(bit.band(fhi[0], 0xF800), 0x0002)
                enriched = enriched + 1
            end
        end
        ffi.C.VirtualProtect(ffi.cast('void*', s3_base), (s3_count + 1) * 0x100, prot[0], prot)
        print(('[fdiag] Re-enriched %d Store 3 entries (post-populate)'):format(enriched))

        -- Step 5: Write player handle to handle_array[0] + friend charnames to handle_array[1..63]
        local old_prot_h = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', hnd_base), 64 * 40, 0x40, old_prot_h)
        local player_name = AshitaCore:GetMemoryManager():GetParty():GetMemberName(0)
        if player_name and #player_name > 0 then
            local hnd0 = ffi.cast('uint8_t*', hnd_base)
            hnd0[0] = bit.bor(hnd0[0], 1)
            for j = 0, 14 do hnd0[8 + j] = 0 end
            for j = 1, math.min(#player_name, 15) do
                hnd0[8 + j - 1] = player_name:byte(j)
            end
            print(('[fdiag] Player handle: "%s"'):format(player_name))
        end
        -- Write friend charnames to handle_array entries (rendering reads from here)
        local handle_wrote = 0
        for i = 1, 63 do
            local src = ffi.cast('uint8_t*', src_base + i * 0x68)
            if bit.band(src[0], 1) ~= 0 then
                local cn = ffi.string(src + 0x18, 15):gsub('%z+$', '')
                if #cn > 0 then
                    local hnd = ffi.cast('uint8_t*', hnd_base + i * 40)
                    hnd[0] = bit.bor(hnd[0], 1)  -- valid flag
                    for j = 0, 14 do hnd[8 + j] = 0 end
                    for j = 1, math.min(#cn, 15) do
                        hnd[8 + j - 1] = cn:byte(j)
                    end
                    handle_wrote = handle_wrote + 1
                    print(('[fdiag] Handle[%d]: "%s"'):format(i, cn))
                end
            end
        end
        print(('[fdiag] Wrote %d friend handle entries'):format(handle_wrote))
        ffi.C.VirtualProtect(ffi.cast('void*', hnd_base), 64 * 40, old_prot_h[0], old_prot_h)

        -- Diagnostic dump
        for ei = 0, math.min(s3_count, 5) do
            local entry = ffi.cast('uint8_t*', s3_base + ei * 0x100)
            local efl = ffi.cast('uint32_t*', entry + 0x08)[0]
            local efl_hi = ffi.cast('uint32_t*', entry + 0x0C)[0]
            local nbuf = {}
            for j = 0, 14 do
                local b = entry[0xA0 + j]
                if b == 0 then break end
                nbuf[#nbuf+1] = string.char(b)
            end
            local cn_buf = {}
            for j = 0, 14 do
                local b = entry[0xB4 + j]
                if b == 0 then break end
                cn_buf[#cn_buf+1] = string.char(b)
            end
            local zid_raw = ffi.cast('uint16_t*', entry + 0xE0)[0]
            local fc = entry[0xFC]
            local marker = ffi.cast('uint32_t*', entry + 0xB0)[0]
            -- Compute what 0x0E7350 would return: SHRD helper with CL=33 (>=32 branch)
            -- Result = (flags_hi >> (33-32)) & 0x3FF = (flags_hi >> 1) & 0x3FF
            local shrd_result = bit.band(bit.rshift(efl_hi, 1), 0x3FF)
            print(('[fdiag]   S3[%d] flags=0x%08X:%08X nick="%s" charname="%s" zone=%d(0x%04X) marker=0x%X gate=0x%02X gameType=%d'):format(
                ei, efl_hi, efl, table.concat(nbuf), table.concat(cn_buf), bit.band(zid_raw, 0x3FFF), zid_raw, marker, fc, shrd_result))
        end

        -- Enable per-frame gate keeper to continuously re-enrich
        -- (native game loop clears +0xFC every frame)
        gate_keeper_active = true
        print('[fdiag] Gate keeper enabled (per-frame re-enrichment)')
        return
    end

    -----------------------------------------------------------------
    -- MEMDUMP: Dump hex at arbitrary address
    -- Usage: /fdiag memdump <addr_hex> [size]
    -- e.g.: /fdiag memdump ffximain+0x370268 128
    -----------------------------------------------------------------
    if cmd == 'memdump' then
        local addr_str = args[3] or ''
        local size = tonumber(args[4]) or 64
        if addr_str == '' then
            print('[fdiag] Usage: /fdiag memdump <addr> [size]')
            print('  addr can be: 0x12345678, ffximain+0x1234, polcore+0x1234')
            return
        end
        local addr = 0
        local lo = addr_str:lower()
        if lo:match('^ffximain') then
            local off = tonumber(lo:match('%+(0x%x+)')) or tonumber(lo:match('%+(%d+)'))
            addr = ffximain_base + (off or 0)
        elseif lo:match('^polcore') then
            local off = tonumber(lo:match('%+(0x%x+)')) or tonumber(lo:match('%+(%d+)'))
            addr = polcore_base + (off or 0)
        else
            addr = tonumber(addr_str)
        end
        if not addr or addr == 0 then
            print('[fdiag] Invalid address: ' .. addr_str)
            return
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), size) ~= 0 then
            print(('[fdiag] Bad read ptr: 0x%08X size=%d'):format(addr, size))
            return
        end
        local p = ffi.cast('uint8_t*', addr)
        print(('[fdiag] Memory dump at 0x%08X (%d bytes):'):format(addr, size))
        for row = 0, size - 1, 16 do
            local hex = {}
            local asc = {}
            for col = 0, 15 do
                local i = row + col
                if i < size then
                    local b = p[i]
                    table.insert(hex, ('%02X'):format(b))
                    table.insert(asc, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
                end
            end
            print(('  +%04X: %-48s %s'):format(row, table.concat(hex, ' '), table.concat(asc)))
        end
        return
    end

    -----------------------------------------------------------------
    -- XIICON: Diagnose XI icon pipeline for friend list entries
    -- Checks 0x0E7350 (game type), 0x0E75B0 (icon path), icon arrays
    -----------------------------------------------------------------
    if cmd == 'xiicon' then
        local store3_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if store3_ptr == 0 then
            print('[fdiag] Store 3 is NULL')
            return
        end
        local store3_obj = ffi.cast('uint8_t*', store3_ptr)
        local s3_count = ffi.cast('uint16_t*', store3_obj + 0x132)[0]
        local s3_base = store3_ptr + 0x0A90
        print(('[fdiag] XI Icon diagnostic — Store 3 obj=0x%08X base=0x%08X count=%d'):format(store3_ptr, s3_base, s3_count))

        -- Get flistmai pointer
        local flistmai_ptr_addr = ffximain_base + 0x62E9E4
        local flistmai = ffi.cast('uint32_t*', flistmai_ptr_addr)[0]
        print(('[fdiag] flistmai = 0x%08X'):format(flistmai))

        if flistmai ~= 0 then
            -- Dump icon arrays at flistmai+0x68 (online icons) and flistmai+0x8C (game icons)
            local online_icon_base = flistmai + 0x68
            local game_icon_base_ptr = ffi.cast('uint32_t*', flistmai + 0x8C)[0]
            print(('[fdiag] Online icon array at flistmai+0x68 = 0x%08X'):format(online_icon_base))
            print(('[fdiag] Game icon array ptr at flistmai+0x8C = 0x%08X'):format(game_icon_base_ptr))

            -- Dump online icon array (5 entries: indices 0-4)
            for i = 0, 4 do
                local icon_val = ffi.cast('uint32_t*', online_icon_base + i * 4)[0]
                print(('[fdiag]   OnlineIcon[%d] = 0x%08X'):format(i, icon_val))
            end

            -- Dump game icon array (14 entries, accessed as [idx*4-4] for idx 1-14)
            if game_icon_base_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', game_icon_base_ptr), 14 * 4) == 0 then
                for i = 0, 13 do
                    local icon_val = ffi.cast('uint32_t*', game_icon_base_ptr + i * 4)[0]
                    print(('[fdiag]   GameIcon[%d] = 0x%08X'):format(i + 1, icon_val))
                end
            else
                print('[fdiag]   Game icon array not readable')
            end

            -- Also check flistmai+0x88 — might be the actual game icon pointer
            local alt_ptr = ffi.cast('uint32_t*', flistmai + 0x88)[0]
            print(('[fdiag] flistmai+0x88 = 0x%08X'):format(alt_ptr))
        end

        -- Call 0x0E7350 and 0x0E75B0 on each Store 3 entry
        local fn_game_type = ffi.cast('int32_t (__cdecl*)(uint8_t*)', ffximain_base + 0x0E7350)
        local fn_icon_path = ffi.cast('int32_t (__cdecl*)(uint8_t*)', ffximain_base + 0x0E75B0)

        for ei = 0, math.min(s3_count, 5) do
            local entry = ffi.cast('uint8_t*', s3_base + ei * 0x100)
            local flags_lo = ffi.cast('uint32_t*', entry + 0x08)[0]
            local flags_hi = ffi.cast('uint32_t*', entry + 0x0C)[0]

            -- Call the actual functions
            local game_type = fn_game_type(entry)
            local icon_path = fn_icon_path(entry)

            -- Manual computation for comparison: SHRD helper >= 32 branch → (flags_hi >> 1) & 0x3FF
            local shrd_result = bit.band(bit.rshift(flags_hi, 1), 0x3FF)

            -- Check entry+0xB0 bit 6 (marker for icon path)
            local marker_byte = entry[0xB0]
            local marker_bit6 = bit.band(marker_byte, 0x40) ~= 0

            -- Check entry+0xE0 bit 14
            local e0_val = ffi.cast('uint32_t*', entry + 0xE0)[0]
            local e0_bit14 = bit.band(e0_val, 0x4000) ~= 0

            print(('[fdiag]   S3[%d] flags=0x%08X:%08X gameType(fn)=%d gameType(calc)=%d iconPath(fn)=%d marker[B0]=0x%02X(bit6=%s) e0=0x%08X(bit14=%s)'):format(
                ei, flags_hi, flags_lo, game_type, shrd_result, icon_path,
                marker_byte, tostring(marker_bit6), e0_val, tostring(e0_bit14)))
        end
        return
    end

    -----------------------------------------------------------------
    -- MENUTBL: Dump menu table entries, searching for specific names
    -- Usage: /fdiag menutbl [name]  (e.g., /fdiag menutbl titlehan)
    -----------------------------------------------------------------
    if cmd == 'menutbl' then
        local search = args[3] and args[3]:lower() or nil
        local table_start = ffximain_base + 0x370268
        local entry_size = 0x2C
        local max_entries = 300
        local found = 0
        for i = 0, max_entries - 1 do
            local entry_addr = table_start + i * entry_size
            local p = ffi.cast('uint8_t*', entry_addr)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', entry_addr), entry_size) ~= 0 then
                print(('[fdiag] Bad read at entry %d'):format(i))
                break
            end
            if p[0] == 0 then
                print(('[fdiag] Table ends at entry %d'):format(i))
                break
            end
            local name = ffi.string(ffi.cast('const char*', entry_addr), 16)
            local show = (not search) or name:lower():find(search, 1, true)
            if show then
                found = found + 1
                -- Dump full 0x2C bytes
                local hex = {}
                for j = 0, entry_size - 1 do
                    table.insert(hex, ('%02X'):format(p[j]))
                end
                -- Extract key fields after 16-byte name
                local w16 = ffi.cast('uint32_t*', entry_addr + 16)[0]
                local w20 = ffi.cast('uint32_t*', entry_addr + 20)[0]
                local w24 = ffi.cast('uint32_t*', entry_addr + 24)[0]
                local w28 = ffi.cast('uint32_t*', entry_addr + 28)[0]
                local w32 = ffi.cast('uint32_t*', entry_addr + 32)[0]
                local w36 = ffi.cast('uint32_t*', entry_addr + 36)[0]
                local w40 = ffi.cast('uint32_t*', entry_addr + 40)[0]
                print(('[fdiag] [%3d] "%s" +10:%08X +14:%08X +18:%08X +1C:%08X +20:%08X +24:%08X +28:%08X'):format(
                    i, name, w16, w20, w24, w28, w32, w36, w40))
                if search then
                    -- Show raw hex for searched entry
                    print(('[fdiag]       raw: %s'):format(table.concat(hex, ' ')))
                end
            end
        end
        print(('[fdiag] Displayed %d entries'):format(found))
        return
    end

    -----------------------------------------------------------------
    -- FLISTDIAG: Comprehensive check of all /flist prerequisites
    -----------------------------------------------------------------
    if cmd == 'flistdiag' then
        print('[fdiag] === /flist diagnostic ===')

        -- 1. Store 3 object
        local store3_obj = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        print(('[fdiag] Store3 ptr: 0x%08X'):format(store3_obj))
        if store3_obj == 0 then
            print('[fdiag] FAIL: Store 3 is NULL')
            return
        end
        local s3 = ffi.cast('uint8_t*', store3_obj)
        local s3_count = ffi.cast('uint16_t*', s3 + 0x132)[0]
        print(('[fdiag] Store3 count: %d (at obj+0x132)'):format(s3_count))

        -- 2. Dump each Store 3 entry's key fields
        local s3_base = store3_obj + 0x0A90
        for i = 0, math.min(s3_count, 9) do
            local ent = ffi.cast('uint8_t*', s3_base + i * 0x100)
            local flags = ffi.cast('uint32_t*', ent + 0x08)[0]
            local valid98 = ffi.cast('uint32_t*', ent + 0x98)[0]
            local f8 = ent[0xF8]
            local fc = ent[0xFC]
            local nick = ffi.string(ffi.cast('char*', ent + 0xA0), 15):gsub('%z+$', '')
            local cn = ffi.string(ffi.cast('char*', ent + 0xB4), 15):gsub('%z+$', '')

            -- Evaluate populate checks
            local skip = (bit.band(valid98, 1) == 0)
            local cat = 'SKIP(invalid)'
            if not skip then
                if f8 ~= 0 then cat = 'cat2(type3)'
                elseif bit.band(flags, 0x10000000) ~= 0 then cat = 'cat3(pending)'
                elseif bit.band(flags, 0xE000) == 0x8000 then cat = 'cat4(ignored)'
                else
                    local v = bit.band(bit.rshift(flags, 13), 7)
                    if v >= 1 and v <= 3 then cat = ('cat0(ONLINE,v=%d)'):format(v)
                    else cat = 'cat1(OFFLINE)'
                    end
                end
            end

            print(('[fdiag]   S3[%d] flags=0x%08X valid98=0x%X f8=0x%02X fc=0x%02X nick="%s" cn="%s" → %s'):format(
                i, flags, valid98, f8, fc, nick, cn, cat))
        end

        -- 3. Index table (obj+0x0832, entries are 2-byte indices)
        local idx_base = ffi.cast('uint16_t*', s3 + 0x0832)
        local idx_parts = {}
        for i = 0, math.min(s3_count, 9) do
            table.insert(idx_parts, ('%d'):format(idx_base[i]))
        end
        print(('[fdiag] Index table: [%s]'):format(table.concat(idx_parts, ', ')))

        -- 4. flistmai state
        local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
        print(('[fdiag] flistmai: 0x%08X'):format(flistmai))
        if flistmai ~= 0 then
            local fm = ffi.cast('uint8_t*', flistmai)
            local slots = ffi.cast('int32_t*', fm + 0x50)[0]
            local disp_idx = ffi.cast('int32_t*', fm + 0x54)[0]
            local param = fm[0x58]
            local arr_ptr = ffi.cast('uint32_t*', fm + 0x5C)[0]
            local arr2_ptr = ffi.cast('uint32_t*', fm + 0x60)[0]
            local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
            local handle_node = ffi.cast('uint32_t*', fm + 0x34)[0]
            print(('[fdiag]   slots=%d disp_idx=%d param=0x%02X(%d) arr_ptr=0x%08X arr2_ptr=0x%08X'):format(
                slots, disp_idx, param, param, arr_ptr, arr2_ptr))
            print(('[fdiag]   sub_mgr=0x%08X handle_node=0x%08X'):format(sub_mgr, handle_node))

            -- Raw header dump
            local hdr = {}
            for j = 0x48, 0x67 do
                table.insert(hdr, ('%02X'):format(fm[j]))
            end
            print(('[fdiag]   fm[0x48..0x67]: %s'):format(table.concat(hdr, ' ')))
        end

        -- 4b. Call type5 check function directly for online entries
        local type5_fn = ffi.cast('int (__cdecl*)(void*)', ffximain_base + 0x0E7510)
        for i = 0, math.min(s3_count, 9) do
            local ent = ffi.cast('uint8_t*', s3_base + i * 0x100)
            local flags = ffi.cast('uint32_t*', ent + 0x08)[0]
            if bit.band(flags, 0x2000) ~= 0 then
                local fc = ent[0xFC]
                local detail = bit.band(bit.rshift(flags, 17), 7)
                local idx_off = 0x1E + detail * 16
                local entry_val = ent[idx_off]
                local s3_cmp = ffi.cast('uint16_t*', s3 + 0x130)[0]
                local result = bit.band(type5_fn(ffi.cast('void*', ent)), 0xFF)
                print(('[fdiag]   S3[%d] type5_check: fc=0x%02X detail=%d entry[0x%02X]=0x%02X s3[0x130]=0x%04X → result=%d'):format(
                    i, fc, detail, idx_off, entry_val, s3_cmp, result))
            end
        end

        -- 5. Array 2 check (first 3 entries)
        local a2_base = polcore_base + 0xB40D8
        print(('[fdiag] Array2 base: 0x%08X'):format(a2_base))
        for i = 0, 2 do
            local a2 = ffi.cast('uint8_t*', a2_base + i * 0xB0)
            local a2_flags = ffi.cast('uint32_t*', a2 + 0x08)[0]
            local a2_valid = ffi.cast('uint32_t*', a2 + 0x98)[0]
            local a2_name = ffi.string(ffi.cast('char*', a2 + 0xA0), 15):gsub('%z+$', '')
            print(('[fdiag]   A2[%d] flags=0x%08X valid=0x%X name="%s"'):format(i, a2_flags, a2_valid, a2_name))
        end

        -- 6. SM state
        local sm_state = ffi.cast('int32_t*', polcore_base + 0x99408)[0]
        local sm_mode = ffi.cast('uint32_t*', polcore_base + 0x99C80)[0]
        local sm_gate = ffi.cast('uint32_t*', polcore_base + 0x9A5D0)[0]
        print(('[fdiag] SM: state=%d mode=%d gate=0x%X'):format(sm_state, sm_mode, sm_gate))

        -- 7. titlehan/flmes elements
        local find_element = ffi.cast('uint32_t (__thiscall*)(void*, const char*)', ffximain_base + 0x15D640)
        local mgr_addr = ffximain_base + 0x5ECB98
        local th_str = ffi.cast('const char*', ffximain_base + 0x37FEF4)
        local fl_str = ffi.cast('const char*', ffximain_base + 0x37FEE0)
        local th_ret = find_element(ffi.cast('void*', mgr_addr), th_str)
        local fl_ret = find_element(ffi.cast('void*', mgr_addr), fl_str)
        print(('[fdiag] titlehan element: 0x%08X'):format(th_ret))
        print(('[fdiag] flmes element: 0x%08X'):format(fl_ret))

        -- 8. Handle array (entry 0)
        local hnd = ffi.cast('uint8_t*', polcore_base + 0x405800)
        local hnd_valid = hnd[0]
        local hnd_text = ffi.string(ffi.cast('char*', hnd + 8), 15):gsub('%z+$', '')
        print(('[fdiag] Handle[0] valid=0x%02X text="%s"'):format(hnd_valid, hnd_text))

        print('[fdiag] === end diagnostic ===')
        return
    end

    -- DUMPFLMES: Comprehensive dump of the flmes (Messages table) element.
    -- Run while /flist Messages tab is open to see the live data source.
    if cmd == 'dumpflmes' then
        print('[fdiag] === flmes (Messages table) dump ===')

        -- 1. flistmai state
        local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
        if flistmai == 0 then
            print('[fdiag] flistmai is NULL')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
        print(('[fdiag] flistmai=0x%08X sub_mgr(+0x08)=0x%08X'):format(flistmai, sub_mgr))

        -- 2. Find flmes via find_element (WM lookup)
        local find_element = ffi.cast('uint32_t (__thiscall*)(void*, const char*)', ffximain_base + 0x15D640)
        local mgr_addr = ffximain_base + 0x5ECB98
        local flmes_name = ffi.cast('const char*', ffximain_base + 0x37FEE0)
        local flmes_ptr = find_element(ffi.cast('void*', mgr_addr), flmes_name)
        print(('[fdiag] find_element("flmes")=0x%08X'):format(flmes_ptr))

        -- Determine which pointer to use (sub_mgr if set, else find_element result)
        local fl = 0
        if sub_mgr ~= 0 then
            fl = sub_mgr
            print('[fdiag] Using sub_mgr as flmes source')
        elseif flmes_ptr ~= 0 then
            fl = flmes_ptr
            print('[fdiag] Using find_element result as flmes source')
        else
            print('[fdiag] flmes not found via either method')
            return
        end

        -- 3. Full hex dump of flmes element (0x00-0x1FF)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', fl), 0x200) ~= 0 then
            print('[fdiag] Cannot read flmes at 0x%08X (0x200 bytes)')
            return
        end
        local p = ffi.cast('uint8_t*', fl)
        for row = 0, 0x1F0, 16 do
            local hex = {}
            local ascii = {}
            for i = 0, 15 do
                table.insert(hex, ('%02X'):format(p[row + i]))
                local b = p[row + i]
                table.insert(ascii, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
            end
            print(('[fdiag]   +%04X: %s  %s'):format(row, table.concat(hex, ' '), table.concat(ascii)))
        end

        -- 4. Key fields analysis
        local vtable = ffi.cast('uint32_t*', p)[0]
        local item_count = ffi.cast('int16_t*', p + 0x4C)[0]
        print(('[fdiag] vtable=0x%08X item_count(+0x4C)=%d'):format(vtable, item_count))

        -- 5. Follow all DWORD-aligned pointers in first 0x100 bytes
        print('[fdiag] Pointer-like DWORDs in flmes:')
        for off = 0, 0xFC, 4 do
            local dw = ffi.cast('uint32_t*', p + off)[0]
            -- Check if it looks like a heap/module pointer (0x00400000-0x7FFFFFFF range)
            if dw >= 0x00400000 and dw < 0x80000000 then
                local label = ''
                if dw >= ffximain_base and dw < ffximain_base + 0x800000 then
                    label = (' (FFXiMain+0x%06X)'):format(dw - ffximain_base)
                end
                local readable = ffi.C.IsBadReadPtr(ffi.cast('void*', dw), 4) == 0
                if readable then
                    local val = ffi.cast('uint32_t*', dw)[0]
                    print(('[fdiag]   +0x%02X: 0x%08X → [0x%08X]%s'):format(off, dw, val, label))
                else
                    print(('[fdiag]   +0x%02X: 0x%08X (unreadable)%s'):format(off, dw, label))
                end
            end
        end

        -- 6. Dump flistmai[0x00-0xFF] for context
        print('[fdiag] flistmai context:')
        for row = 0, 0xF0, 16 do
            local hex = {}
            for i = 0, 15 do
                table.insert(hex, ('%02X'):format(fm[row + i]))
            end
            print(('[fdiag]   fm+%04X: %s'):format(row, table.concat(hex, ' ')))
        end

        -- 7. Look at the menu table entry for flmes
        local table_start = ffximain_base + 0x370268
        local entry_size = 0x2C
        for i = 0, 299 do
            local ea = table_start + i * entry_size
            local ep = ffi.cast('uint8_t*', ea)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', ea), entry_size) ~= 0 or ep[0] == 0 then
                break
            end
            local name = ffi.string(ffi.cast('const char*', ea), 16)
            if name:find('flmes', 1, true) then
                local hex = {}
                for j = 0, entry_size - 1 do table.insert(hex, ('%02X'):format(ep[j])) end
                print(('[fdiag] menutbl[%d] "%s": %s'):format(i, name, table.concat(hex, ' ')))
                -- Extract handler addresses (relative offsets in the entry)
                for j = 16, entry_size - 4, 4 do
                    local w = ffi.cast('uint32_t*', ea + j)[0]
                    if w ~= 0 then
                        local lbl = ''
                        if w >= ffximain_base and w < ffximain_base + 0x800000 then
                            lbl = (' (FFXiMain+0x%06X)'):format(w - ffximain_base)
                        end
                        print(('[fdiag]   menutbl +%02X: 0x%08X%s'):format(j, w, lbl))
                    end
                end
            end
        end

        print('[fdiag] === end flmes dump ===')
        return
    end

    -- BINDFLMES: Call show_menu for flmes and bind to flistmai+0x08
    if cmd == 'bindflmes' then
        local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
        if flistmai == 0 then
            print('[fdiag] flistmai is NULL')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        local wm_addr = ffximain_base + 0x5ECB98
        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)', ffximain_base + 0x15D080)
        local fl_str = ffi.new('char[17]'); ffi.copy(fl_str, 'menu    flmes   ', 16); fl_str[16] = 0
        local fl_ret = show_menu(ffi.cast('void*', wm_addr), fl_str, 1, 0)
        print(('[fdiag] show_menu("flmes") = 0x%08X'):format(fl_ret))
        if fl_ret ~= 0 then
            ffi.cast('uint32_t*', fm + 0x08)[0] = fl_ret
            print(('[fdiag] Bound flistmai+0x08 (sub_mgr) = 0x%08X'):format(fl_ret))
            -- Dump flmes object header
            if ffi.C.IsBadReadPtr(ffi.cast('void*', fl_ret), 0x50) == 0 then
                local ptr = ffi.cast('uint8_t*', fl_ret)
                local hex = {}
                for i = 0, 0x4F do table.insert(hex, ('%02X'):format(ptr[i])) end
                print(('[fdiag] flmes[0x00..0x4F]: %s'):format(table.concat(hex, ' ')))
            end
        else
            print('[fdiag] show_menu returned 0 — flmes element not found in WM')
        end
        return
    end

    -----------------------------------------------------------------
    -- DUMPMSG: Comprehensive dump of the message object at
    -- [FFXiMain+0x62EE1C] — all fields, both arrays, counts.
    -- Usage: /fdiag dumpmsg
    -----------------------------------------------------------------
    if cmd == 'dumpmsg' then
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then
            print('[fdiag] Message object ptr is NULL')
            return
        end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        print(('[fdiag] Message object at 0x%08X'):format(msg_obj_ptr))

        -- Dump every dword in the 0x78-byte object
        print('[fdiag] Full object dump (0x78 bytes):')
        for off = 0, 0x74, 4 do
            local val = ffi.cast('uint32_t*', obj + off)[0]
            local label = ''
            if off == 0x00 then label = ' vtable' end
            if off == 0x04 then label = ' unk04' end
            if off == 0x08 then label = ' ui_elem' end
            if off == 0x0C then label = ' unk0C' end
            if off == 0x10 then label = ' unk10' end
            if off == 0x14 then label = ' unk14' end
            if off == 0x18 then label = ' max_items_18' end
            if off == 0x1C then label = ' unk1C' end
            if off == 0x20 then label = ' unk20' end
            if off == 0x24 then label = ' unk24' end
            if off == 0x28 then label = ' unk28' end
            if off == 0x2C then label = ' unk2C' end
            if off == 0x30 then label = ' unk30' end
            if off == 0x34 then label = ' unk34' end
            if off == 0x38 then label = ' render_arr_38' end
            if off == 0x3C then label = ' unk3C' end
            if off == 0x40 then label = ' unk40' end
            if off == 0x44 then label = ' unk44' end
            if off == 0x48 then label = ' unk48' end
            if off == 0x4C then label = ' unk4C' end
            if off == 0x50 then label = ' max_items_50' end
            if off == 0x54 then label = ' count_54' end
            if off == 0x58 then label = ' unk58' end
            if off == 0x5C then label = ' unk5C' end
            if off == 0x60 then label = ' unk60' end
            if off == 0x64 then label = ' refresh_flag_64' end
            if off == 0x68 then label = ' render_arr_68' end
            if off == 0x6C then label = ' data_arr_6C' end
            if off == 0x70 then label = ' unk70' end
            if off == 0x74 then label = ' unk74' end
            print(('[fdiag]   +0x%02X: 0x%08X (%d)%s'):format(off, val, val, label))
        end

        -- Dump render array entries (obj+0x68, stride 0x54)
        local render_68 = ffi.cast('uint32_t*', obj + 0x68)[0]
        local render_38 = ffi.cast('uint32_t*', obj + 0x38)[0]
        local data_6c = ffi.cast('uint32_t*', obj + 0x6C)[0]
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        local max50 = ffi.cast('uint32_t*', obj + 0x50)[0]

        -- Dump render array at +0x68
        if render_68 ~= 0 then
            print(('[fdiag] Render array +0x68 = 0x%08X, count=%d, max=%d'):format(render_68, count, max50))
            local arr = ffi.cast('uint8_t*', render_68)
            for i = 0, math.min(count + 1, max50 - 1, 7) do
                local entry = arr + i * 0x54
                if ffi.C.IsBadReadPtr(ffi.cast('void*', entry), 0x54) ~= 0 then break end
                local hex = {}
                for j = 0, math.min(0x53, 47) do table.insert(hex, ('%02X'):format(entry[j])) end
                -- Extract text at +0x08 (32 bytes)
                local txt = ffi.string(ffi.cast('char*', entry + 0x08), 32):gsub('%z+$', '')
                print(('[fdiag]   render68[%d]: %s'):format(i, table.concat(hex, ' ')))
                print(('[fdiag]     text@+08: "%s"'):format(txt))
            end
        else
            print('[fdiag] Render array +0x68 is NULL')
        end

        -- Dump render array at +0x38 (if different)
        if render_38 ~= 0 and render_38 ~= render_68 then
            print(('[fdiag] Render array +0x38 = 0x%08X (DIFFERENT from +0x68)'):format(render_38))
            local arr = ffi.cast('uint8_t*', render_38)
            for i = 0, math.min(count + 1, 7) do
                local entry = arr + i * 0x54
                if ffi.C.IsBadReadPtr(ffi.cast('void*', entry), 0x54) ~= 0 then break end
                local hex = {}
                for j = 0, math.min(0x53, 47) do table.insert(hex, ('%02X'):format(entry[j])) end
                local txt = ffi.string(ffi.cast('char*', entry + 0x08), 32):gsub('%z+$', '')
                print(('[fdiag]   render38[%d]: %s'):format(i, table.concat(hex, ' ')))
                print(('[fdiag]     text@+08: "%s"'):format(txt))
            end
        elseif render_38 == render_68 then
            print(('[fdiag] +0x38 and +0x68 are SAME pointer (0x%08X)'):format(render_38))
        end

        -- Dump data array at +0x6C
        if data_6c ~= 0 then
            print(('[fdiag] Data array +0x6C = 0x%08X'):format(data_6c))
            local arr = ffi.cast('uint8_t*', data_6c)
            for i = 0, math.min(count + 1, max50 - 1, 7) do
                local entry = arr + i * 0x50
                if ffi.C.IsBadReadPtr(ffi.cast('void*', entry), 0x50) ~= 0 then break end
                local hex = {}
                for j = 0, 0x4F do table.insert(hex, ('%02X'):format(entry[j])) end
                print(('[fdiag]   data[%d]: %s'):format(i, table.concat(hex, ' ')))
            end
        else
            print('[fdiag] Data array +0x6C is NULL')
        end

        -- Dump insertion function code at FFXiMain+0x1FF012 (first 64 bytes)
        print('[fdiag] Insertion func (FFXiMain+0x1FF012):')
        local ifunc = ffi.cast('uint8_t*', ffximain_base + 0x1FF012)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', ifunc), 64) == 0 then
            for off = 0, 48, 16 do
                local hex = {}
                for j = 0, 15 do table.insert(hex, ('%02X'):format(ifunc[off + j])) end
                print(('[fdiag]   +%02X: %s'):format(off, table.concat(hex, ' ')))
            end
        end

        -- Dump slot allocator code at FFXiMain+0x1FED70 (first 64 bytes)
        print('[fdiag] Slot allocator (FFXiMain+0x1FED70):')
        local sfunc = ffi.cast('uint8_t*', ffximain_base + 0x1FED70)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', sfunc), 64) == 0 then
            for off = 0, 48, 16 do
                local hex = {}
                for j = 0, 15 do table.insert(hex, ('%02X'):format(sfunc[off + j])) end
                print(('[fdiag]   +%02X: %s'):format(off, table.concat(hex, ' ')))
            end
        end

        -- Dump vtable entries
        local vt = ffi.cast('uint32_t*', obj + 0x00)[0]
        if vt ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', vt), 32) == 0 then
            local vtp = ffi.cast('uint32_t*', vt)
            print('[fdiag] Vtable entries:')
            for i = 0, 7 do
                print(('[fdiag]   vt[%d] = 0x%08X (FFXiMain+0x%06X)'):format(
                    i, vtp[i], vtp[i] - ffximain_base))
            end
        end

        -- Dump surrounding globals for context
        local ctx = ffi.cast('uint8_t*', ffximain_base + 0x62EE1C)
        print('[fdiag] Globals around FFXiMain+0x62EE1C:')
        for off = -0x10, 0x30, 4 do
            if ffi.C.IsBadReadPtr(ffi.cast('void*', ctx + off), 4) == 0 then
                print(('[fdiag]   +0x%X: 0x%08X'):format(0x62EE1C + off, ffi.cast('uint32_t*', ctx + off)[0]))
            end
        end
        return
    end

    -----------------------------------------------------------------
    -----------------------------------------------------------------
    -- ADDMSG: Complete message injection — insert + color patch + vt[1]
    -- Calls native message_insert, patches colors to white, updates UI.
    -- Usage: /fdiag addmsg [from] [to_or_subject]
    -----------------------------------------------------------------
    if cmd == 'addmsg' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or 'Friend request'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]

        -- Step 1: Allocate and build source struct + descriptor
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local mem = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        -- Layout: 0x000=source, 0x040=descriptor, 0x080=textbuf, 0x0A0=sender, 0x0C0=subject
        local src = base
        local desc = base + 0x40
        local sender_buf = base + 0x0A0
        local subj_buf = base + 0x0C0

        for i = 0, math.min(#sender - 1, 14) do sender_buf[i] = string.byte(sender, i + 1) end
        for i = 0, math.min(#subject - 1, 14) do subj_buf[i] = string.byte(subject, i + 1) end

        -- Descriptor
        ffi.cast('uint32_t*', desc)[0] = ba + 0x80        -- textbuf ptr
        ffi.cast('uint32_t*', desc + 0x14)[0] = 0x0F      -- max text len
        ffi.cast('uint32_t*', desc + 0x18)[0] = 0x0F
        ffi.cast('uint32_t*', desc + 0x30)[0] = os.time()
        ffi.cast('uint32_t*', desc + 0x34)[0] = os.time()

        -- Source struct
        src[0] = 0x20; src[1] = 0x25; src[2] = 0x25; src[3] = 0x01; src[4] = 0x01
        ffi.cast('uint32_t*', src + 0x08)[0] = ba + 0x0A0  -- sender ptr
        ffi.cast('uint32_t*', src + 0x0C)[0] = ba + 0x0C0  -- subject ptr
        ffi.cast('uint32_t*', src + 0x18)[0] = ba + 0x40   -- descriptor ptr

        -- Step 2: Call message_insert
        local insert_fn = ffi.cast('bool (__cdecl*)(void*, int, int, int, void*)', ffximain_base + 0x1FF010)
        local ok, result = pcall(function()
            return insert_fn(ffi.cast('void*', msg_obj_ptr), 0, 0, 0, ffi.cast('void*', ba))
        end)
        if not ok then
            print(('[fdiag] INSERT ERROR: %s'):format(tostring(result)))
            return
        end

        local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
        if count_after <= count_before then
            print('[fdiag] Insert failed (count unchanged)')
            return
        end

        -- Step 3: Patch colors on the new entry
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local entry_idx = count_after - 1
        local entry = ffi.cast('uint8_t*', render_arr + entry_idx * 0x54)
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, 0x04, prot)
        ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF  -- color[1] sender
        ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF  -- color[2] subject
        ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF  -- color[4] date
        entry[0] = 0x20  -- fix position[0]
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, prot[0], prot)

        -- Step 4: Call vt[1] to update UI element
        local vtable = ffi.cast('uint32_t*', ffi.cast('uint32_t*', obj)[0])
        local vt1 = ffi.cast('void (__thiscall*)(void*)', vtable[1])
        vt1(ffi.cast('void*', msg_obj_ptr))

        print(('[fdiag] Message added: from="%s" to="%s" count=%d'):format(
            sender, subject, count_after))
        return
    end

    -- REFRESHMSG: Configurable refresh with step control.
    -- Usage: /fdiag refreshmsg [steps]
    --   steps = combination of: v (vt1), f (flag), r (secondary refresh)
    --   Default: vfr (all steps). Use "v" for vt1 only, "vf" for vt1+flag, etc.
    -- Usage: /fdiag refreshmsg
    -----------------------------------------------------------------
    -- REFRESHMSG: Configurable refresh with step control.
    -- Usage: /fdiag refreshmsg [steps]
    --   steps = combination of: v (vt1), f (flag), r (secondary refresh)
    --   Default: vfr (all steps). Use "v" for vt1 only, "vf" for vt1+flag, etc.
    if cmd == 'refreshmsg' then
        local steps = args[3] or 'vfr'
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local prot = ffi.new('uint32_t[1]')
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]

        -- Always sync +0x20 to count
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, 0x04, prot)
        local old20 = ffi.cast('uint16_t*', obj + 0x20)[0]
        ffi.cast('uint16_t*', obj + 0x20)[0] = count
        print(('[fdiag] obj+0x20: %d → %d'):format(old20, count))

        if steps:find('f') then
            local old64 = obj[0x64]
            obj[0x64] = 1
            print(('[fdiag] obj[0x64]: %d → 1'):format(old64))
        end
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, prot[0], prot)

        if steps:find('v') then
            local vtable = ffi.cast('uint32_t*', ffi.cast('uint32_t*', obj)[0])
            local vt1_addr = vtable[1]
            print(('[fdiag] Calling vt[1] at 0x%08X'):format(vt1_addr))
            local vt1 = ffi.cast('void (__thiscall*)(void*)', vt1_addr)
            vt1(ffi.cast('void*', msg_obj_ptr))
            print('[fdiag] vt[1] done')
        end

        if steps:find('r') then
            local global_ptr = ffi.cast('uint32_t*', ffximain_base + 0x576088)[0]
            if global_ptr ~= 0 then
                local func = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x21F9D0)
                func(ffi.cast('void*', global_ptr), 0x10)
                print(('[fdiag] Secondary refresh(0x%08X, 0x10)'):format(global_ptr))
            end
        end

        print(('[fdiag] After: count=%d visible=%d steps=%s'):format(
            ffi.cast('uint32_t*', obj + 0x54)[0],
            ffi.cast('uint16_t*', obj + 0x20)[0],
            steps))
        return
    end

    -----------------------------------------------------------------
    -- COLORMSG: Patch render entry colors to visible + call vt[1].
    -- No refresh flag. Tests if visible colors make text appear.
    -- Usage: /fdiag colormsg [entry_index]
    -----------------------------------------------------------------
    if cmd == 'colormsg' then
        local idx = tonumber(args[3]) or 1
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local entry = ffi.cast('uint8_t*', render_arr + idx * 0x54)
        local prot = ffi.new('uint32_t[1]')

        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, 0x04, prot)
        -- Set visible colors for text columns (white)
        ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF  -- color[1] sender
        ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF  -- color[2] subject
        ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF  -- color[4] date
        -- Also try setting position[0] to 0x20 (like entry 0 has)
        entry[0] = 0x20
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, prot[0], prot)
        print(('[fdiag] Patched entry %d colors to visible'):format(idx))

        -- Call vt[1] only (no refresh flag)
        local vtable = ffi.cast('uint32_t*', ffi.cast('uint32_t*', obj)[0])
        local vt1 = ffi.cast('void (__thiscall*)(void*)', vtable[1])
        vt1(ffi.cast('void*', msg_obj_ptr))
        print('[fdiag] vt[1] called')

        -- Verify entry still exists
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] count=%d'):format(count))
        return
    end

    -----------------------------------------------------------------
    -- INJECTMSG: Directly populate msg_obj arrays (NO native calls)
    -- Usage: /fdiag injectmsg [sender] [subject]
    -- Writes to render+data arrays with all required fields.
    -- Does NOT call message_insert or vt[1].
    -----------------------------------------------------------------
    if cmd == 'injectmsg' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or "Let's be friends!"

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        local max_e = ffi.cast('uint32_t*', obj + 0x18)[0]
        if count >= max_e then print('[fdiag] Full'); return end

        local render_base = ffi.cast('uint32_t*', obj + 0x68)[0]
        local data_base = ffi.cast('uint32_t*', obj + 0x6C)[0]
        if render_base == 0 or data_base == 0 then print('[fdiag] No arrays'); return end

        -- Allocate persistent text storage (4KB block)
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local mem = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local tb = ffi.cast('uint8_t*', mem)
        ffi.fill(tb, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        -- Layout: 0x00=sender(16B) 0x10=type(8B) 0x20=date(16B) 0x30=desc(0x40B) 0x70=textbuf(16B)
        for i = 0, math.min(#sender - 1, 14) do tb[i] = string.byte(sender, i + 1) end
        local typelbl = '[FOK]'
        for i = 0, #typelbl - 1 do tb[0x10 + i] = string.byte(typelbl, i + 1) end
        local datestr = os.date('%m/%d %H:%M')
        for i = 0, math.min(#datestr - 1, 14) do tb[0x20 + i] = string.byte(datestr, i + 1) end

        -- Descriptor at +0x30: text_buf_ptr, max_lens, timestamps
        ffi.cast('uint32_t*', tb + 0x30)[0] = ba + 0x70       -- text_buf pointer
        ffi.cast('uint32_t*', tb + 0x44)[0] = 0x0F             -- max_len1
        ffi.cast('uint32_t*', tb + 0x48)[0] = 0x0F             -- max_len2
        ffi.cast('uint32_t*', tb + 0x60)[0] = os.time()        -- timestamp hash
        ffi.cast('uint32_t*', tb + 0x64)[0] = os.time()        -- timestamp

        -- Write textbuf content (body / copy of sender for text_buf)
        for i = 0, math.min(#subject - 1, 14) do tb[0x70 + i] = string.byte(subject, i + 1) end

        -- === DATA ARRAY entry (stride 0x50) ===
        local dentry = ffi.cast('uint8_t*', data_base + count * 0x50)
        local dprot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', dentry), 0x50, PAGE_RW, dprot)

        -- data+0x08: text_buf_ptr (descriptor's text buffer) — KEY FIELD
        ffi.cast('uint32_t*', dentry + 0x08)[0] = ba + 0x70
        -- data+0x10: sender text (inline 16B)
        for i = 0, 15 do dentry[0x10 + i] = tb[i] end
        -- data+0x20: type label (inline 8B)
        for i = 0, 7 do dentry[0x20 + i] = tb[0x10 + i] end
        -- data+0x30: date text (inline 16B)
        for i = 0, 15 do dentry[0x30 + i] = tb[0x20 + i] end
        -- data+0x04: descriptor pointer (for refresh validation?)
        ffi.cast('uint32_t*', dentry + 0x04)[0] = ba + 0x30

        ffi.C.VirtualProtect(ffi.cast('void*', dentry), 0x50, dprot[0], dprot)

        -- === RENDER BUFFER entry (stride 0x54) ===
        local rentry = ffi.cast('uint8_t*', render_base + count * 0x54)
        local rprot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', rentry), 0x54, PAGE_RW, rprot)

        -- Positions
        rentry[0] = 0x20   -- col0: icon
        rentry[1] = 0x25   -- col1: from
        rentry[2] = 0x25   -- col2: to/subject
        rentry[3] = 0x01   -- col3: type
        rentry[4] = 0x01   -- col4: date

        -- Colors (all visible white)
        for c = 0, 7 do
            ffi.cast('uint32_t*', rentry + 0x08 + c * 4)[0] = 0xFFFFFFFF
        end

        -- Data pointers
        ffi.cast('uint32_t*', rentry + 0x28)[0] = ba + 0x10         -- col0: type label
        ffi.cast('uint32_t*', rentry + 0x2C)[0] = ba + 0x00         -- col1: sender
        ffi.cast('uint32_t*', rentry + 0x30)[0] = ba + 0x10         -- col2: type (dup)
        ffi.cast('uint32_t*', rentry + 0x34)[0] = ba + 0x10         -- col3: type
        ffi.cast('uint32_t*', rentry + 0x38)[0] = ba + 0x20         -- col4: date

        -- Metadata
        ffi.cast('uint32_t*', rentry + 0x48)[0] = tonumber(ffi.cast('uint32_t', dentry))  -- data_entry ptr
        ffi.cast('uint32_t*', rentry + 0x4C)[0] = os.time()   -- timestamp (render+0x4C)
        ffi.cast('uint32_t*', rentry + 0x50)[0] = 1           -- flags

        ffi.C.VirtualProtect(ffi.cast('void*', rentry), 0x54, rprot[0], rprot)

        -- Increment counts
        local cprot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, PAGE_RW, cprot)
        ffi.cast('uint32_t*', obj + 0x54)[0] = count + 1       -- total count
        ffi.cast('uint16_t*', obj + 0x20)[0] = count + 1       -- visible count (uint16!)
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, cprot[0], cprot)

        print(('[fdiag] Injected: sender="%s" count=%d render=0x%08X data=0x%08X'):format(
            sender, count + 1,
            tonumber(ffi.cast('uint32_t', rentry)),
            tonumber(ffi.cast('uint32_t', dentry))))
        print('[fdiag] Navigate AWAY from Messages tab, then back to test')
        return
    end

    -----------------------------------------------------------------
    -- SHOWMSGLIST: Call show_menu to find/activate the msglist UI element
    -- and bind it to msg_obj+0x08.
    -- Updated offsets: WM at FFXi+0x5EDD10, show_menu at FFXi+0x15E1E0
    -----------------------------------------------------------------
    if cmd == 'showmsglist' then
        local wm_addr = ffximain_base + 0x5EDD10
        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)',
            ffximain_base + 0x15E1E0)
        local name_ptr = ffi.cast('const char*', ffximain_base + 0x384224)
        local name_str = ffi.string(name_ptr, 16)
        print(('[fdiag] name: "%s"'):format(name_str))
        if name_str ~= 'menu    msglist ' then
            print('[fdiag] String mismatch! Aborting.'); return
        end
        print(('[fdiag] show_menu(WM=0x%08X, msglist, 1, 0)...'):format(wm_addr))
        local ok, result = pcall(function()
            return show_menu(ffi.cast('void*', wm_addr), name_ptr, 1, 0)
        end)
        if not ok then
            print(('[fdiag] CRASH: %s'):format(tostring(result))); return
        end
        print(('[fdiag] show_menu returned: 0x%08X'):format(result))
        if result ~= 0 then
            local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
            if msg_obj_ptr ~= 0 then
                local obj = ffi.cast('uint8_t*', msg_obj_ptr)
                local prot = ffi.new('uint32_t[1]')
                ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x200, 0x04, prot)
                ffi.cast('uint32_t*', obj + 0x08)[0] = result
                ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x200, prot[0], prot)
                print(('[fdiag] Bound msg_obj+0x08 = 0x%08X'):format(result))

                print('[fdiag] show_menu alone is not enough. Need full init.')
                print('[fdiag] Trying full flistmai init at +0x200710...')

                -- Call the full init function at +0x200710
                -- __thiscall(this, arg1, arg2, arg3), RET 0x0C
                -- From the constructor code: args come from stack (caller pushes 3 args)
                -- We pass 0,0,0 as placeholder args
                local init_fn = ffi.cast('bool (__thiscall*)(void*, int, int, int)',
                    ffximain_base + 0x200710)
                local ok2, res2 = pcall(function()
                    return init_fn(ffi.cast('void*', msg_obj_ptr), 0, 0, 0)
                end)
                if ok2 then
                    print(('[fdiag] Init returned: %s'):format(tostring(res2)))
                    -- Check what changed
                    local new_vt = ffi.cast('uint32_t*', obj)[0]
                    local new_ui = ffi.cast('uint32_t*', obj + 0x08)[0]
                    local new_cnt = ffi.cast('uint32_t*', obj + 0x54)[0]
                    print(('[fdiag] After init: vt=0x%08X ui=0x%08X count=%d'):format(
                        new_vt, new_ui, new_cnt))
                else
                    print(('[fdiag] Init CRASHED: %s'):format(tostring(res2)))
                end
            else
                print('[fdiag] msg_obj is NULL')
            end
        else
            print('[fdiag] show_menu returned 0 — not found')
        end
        return
    end

    -----------------------------------------------------------------
    -- CREATEMSGOBJ: Allocate a msg_obj + insert a test entry via native fn
    -- Usage: /fdiag createmsgobj
    -- Creates msg_obj with REAL vtable, render/data arrays.
    -- Does NOT call message_insert. Use injectmsg after to add entries.
    -----------------------------------------------------------------
    if cmd == 'createmsgobj' then
        local msg_obj_ptr_loc = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)
        if msg_obj_ptr_loc[0] ~= 0 then
            print(('[fdiag] msg_obj already exists at 0x%08X'):format(msg_obj_ptr_loc[0]))
            return
        end

        -- Allocate: msg_obj(0x78) + render(15*0x54) + data(15*0x50)
        local MEM_COMMIT = 0x1000
        local MEM_RESERVE = 0x2000
        local PAGE_RW = 0x04
        local total = 0x78 + (15 * 0x54) + (15 * 0x50)
        local mem = ffi.C.VirtualAlloc(nil, total, bit.bor(MEM_COMMIT, MEM_RESERVE), PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, total, 0)

        local obj = base
        local render = base + 0x78
        local data = render + (15 * 0x54)

        -- Use REAL vtable from .rdata (FFXiMain+0x338AE0)
        ffi.cast('uint32_t*', obj + 0x00)[0] = ffximain_base + 0x338AE0   -- real vtable
        -- obj+0x08 = NULL (no UI element — skip vt[1])
        ffi.cast('uint16_t*', obj + 0x18)[0] = 15          -- max_items
        ffi.cast('uint32_t*', obj + 0x1C)[0] = 1           -- unk1C
        ffi.cast('uint16_t*', obj + 0x20)[0] = 0           -- visible count
        ffi.cast('uint32_t*', obj + 0x38)[0] = tonumber(ffi.cast('uint32_t', render))  -- render dup
        ffi.cast('uint32_t*', obj + 0x50)[0] = 8           -- max_display
        ffi.cast('uint32_t*', obj + 0x54)[0] = 0           -- count
        ffi.cast('uint32_t*', obj + 0x64)[0] = 0           -- refresh_flag
        ffi.cast('uint32_t*', obj + 0x68)[0] = tonumber(ffi.cast('uint32_t', render))
        ffi.cast('uint32_t*', obj + 0x6C)[0] = tonumber(ffi.cast('uint32_t', data))

        -- Store globally
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', msg_obj_ptr_loc), 4, 0x04, prot)
        msg_obj_ptr_loc[0] = tonumber(ffi.cast('uint32_t', obj))
        ffi.C.VirtualProtect(ffi.cast('void*', msg_obj_ptr_loc), 4, prot[0], prot)

        print(('[fdiag] msg_obj=0x%08X vt=0x%08X render=0x%08X data=0x%08X'):format(
            msg_obj_ptr_loc[0], ffximain_base + 0x338AE0,
            tonumber(ffi.cast('uint32_t', render)),
            tonumber(ffi.cast('uint32_t', data))))
        print('[fdiag] Use /fdiag injectmsg to add entries')
        return
    end

    -----------------------------------------------------------------
    -- RESETMSG: Reset message count back to 1 (undo bad injections)
    -- Usage: /fdiag resetmsg
    -----------------------------------------------------------------
    if cmd == 'resetmsg' then
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local prot = ffi.new('uint32_t[1]')
        local old = ffi.cast('uint32_t*', obj + 0x54)[0]
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, 0x04, prot)
        ffi.cast('uint32_t*', obj + 0x54)[0] = 1
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, prot[0], prot)
        print(('[fdiag] count reset: %d → 1'):format(old))
        return
    end

    -----------------------------------------------------------------
    -- INJECTMSG: Inject a message into the Messages table.
    --
    -- Render entry layout (0x54 bytes):
    --   +0x00-0x07: positions[8] (byte per column)
    --   +0x08-0x27: colors[8]    (dword per column, at +0x08+col*4)
    --   +0x28-0x47: data_ptrs[8] (dword per column, at +0x28+col*4)
    --   +0x48:      data_array_link (ptr to data array entry)
    --   +0x4C:      misc
    --   +0x50:      flag
    --
    -- Strategy: Clone entry 0 for safe base, then allocate external
    -- text buffers and point data_ptrs to them. Use visible colors
    -- (0xFFFFFFFF white) instead of 0x80808080 (invisible/empty).
    --
    -- Usage: /fdiag injectmsg [sender] [subject] [date]
    -----------------------------------------------------------------
    if cmd == 'injectmsg' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or 'Hello!'
        local datestr = args[5] or '03/09'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then
            print('[fdiag] Message object ptr is NULL')
            return
        end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        local max50 = ffi.cast('uint32_t*', obj + 0x50)[0]
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local data_arr = ffi.cast('uint32_t*', obj + 0x6C)[0]

        print(('[fdiag] Before: count=%d max=%d render=0x%08X data=0x%08X'):format(
            count, max50, render_arr, data_arr))

        if render_arr == 0 then
            print('[fdiag] Render array is NULL')
            return
        end
        if count >= max50 then
            print(('[fdiag] Message list full (%d/%d)'):format(count, max50))
            return
        end

        -- Allocate persistent text buffers (VirtualAlloc so they survive)
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local text_mem = ffi.C.VirtualAlloc(nil, 256, MEM_COMMIT, PAGE_RW)
        if text_mem == nil then
            print('[fdiag] VirtualAlloc failed')
            return
        end
        local tmem = ffi.cast('uint8_t*', text_mem)
        -- Layout: 0x00-0x1F = sender (32B), 0x20-0x3F = subject (32B), 0x40-0x5F = date (32B)
        ffi.fill(tmem, 256, 0)
        for i = 0, math.min(#sender - 1, 30) do tmem[i] = string.byte(sender, i + 1) end
        for i = 0, math.min(#subject - 1, 30) do tmem[0x20 + i] = string.byte(subject, i + 1) end
        for i = 0, math.min(#datestr - 1, 30) do tmem[0x40 + i] = string.byte(datestr, i + 1) end
        local tmem_addr = tonumber(ffi.cast('uint32_t', text_mem))
        print(('[fdiag] Text buffers at 0x%08X: sender="%s" subj="%s" date="%s"'):format(
            tmem_addr, sender, subject, datestr))

        local prot = ffi.new('uint32_t[1]')
        local entry0 = ffi.cast('uint8_t*', render_arr)
        local entry = ffi.cast('uint8_t*', render_arr + count * 0x54)
        local entry_addr = tonumber(ffi.cast('uint32_t', entry))

        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, 0x04, prot)

        -- Clone entry 0 as safe base (preserves data_ptr[0] and structure)
        ffi.copy(entry, entry0, 0x54)

        -- Fix +0x48 linkage to this entry's data slot
        if data_arr ~= 0 then
            ffi.cast('uint32_t*', entry + 0x48)[0] = data_arr + count * 0x50
        end

        -- Set column positions (from insertion function analysis)
        entry[1] = 0x25  -- col 1 position = 37
        entry[2] = 0x25  -- col 2 position = 37
        entry[3] = 1     -- col 3 position = 1
        entry[4] = 1     -- col 4 position = 1

        -- Set data_ptrs to external text buffers
        ffi.cast('uint32_t*', entry + 0x2C)[0] = tmem_addr         -- data_ptr[1] = sender
        ffi.cast('uint32_t*', entry + 0x30)[0] = tmem_addr + 0x20  -- data_ptr[2] = subject
        ffi.cast('uint32_t*', entry + 0x38)[0] = tmem_addr + 0x40  -- data_ptr[4] = date

        -- Try multiple color strategies:
        -- A) White text (0xFFFFFFFF)
        -- B) Keep 0x80808080 for cols where entry 0 uses it
        -- C) Try specific game colors
        -- Start with 0xFFFFFFFF for columns 1,2,4
        ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF  -- color[1] = white
        ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF  -- color[2] = white
        ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF  -- color[4] = white

        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, prot[0], prot)

        -- Increment count
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, 0x04, prot)
        ffi.cast('uint32_t*', obj + 0x54)[0] = count + 1
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, prot[0], prot)
        print(('[fdiag] count: %d → %d'):format(count, count + 1))

        -- Dump final entry
        local hex = {}
        for j = 0, 0x53 do table.insert(hex, ('%02X'):format(entry[j])) end
        print(('[fdiag] Entry: %s'):format(table.concat(hex, ' ')))

        -- Dump key fields
        for col = 0, 4 do
            local pos = entry[col]
            local color = ffi.cast('uint32_t*', entry + 0x08 + col * 4)[0]
            local dptr = ffi.cast('uint32_t*', entry + 0x28 + col * 4)[0]
            print(('[fdiag]   col[%d]: pos=%d color=0x%08X dptr=0x%08X'):format(col, pos, color, dptr))
        end
        return
    end

    -----------------------------------------------------------------
    -- INJECTMSG2: Full inject — clone entry 0, set text + visible colors,
    -- increment count, update +0x20, NO refresh functions.
    -- The insertion function uses 0x80808080 (invisible) for all colors.
    -- We set visible colors and text pointers to make text appear.
    -- Usage: /fdiag injectmsg2 [sender] [subject] [date]
    -----------------------------------------------------------------
    if cmd == 'injectmsg2' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or 'Hello!'
        local datestr = args[5] or '03/09'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        local max50 = ffi.cast('uint32_t*', obj + 0x50)[0]
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local data_arr = ffi.cast('uint32_t*', obj + 0x6C)[0]
        print(('[fdiag] Before: count=%d max=%d render=0x%08X data=0x%08X'):format(
            count, max50, render_arr, data_arr))
        if count >= max50 then
            print('[fdiag] Full'); return
        end

        -- Allocate persistent text buffers
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local text_mem = ffi.C.VirtualAlloc(nil, 256, MEM_COMMIT, PAGE_RW)
        if text_mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local tmem = ffi.cast('uint8_t*', text_mem)
        ffi.fill(tmem, 256, 0)
        -- Layout: 0x00 = sender (32B), 0x20 = subject (32B), 0x40 = date (32B)
        for i = 0, math.min(#sender - 1, 30) do tmem[i] = string.byte(sender, i + 1) end
        for i = 0, math.min(#subject - 1, 30) do tmem[0x20 + i] = string.byte(subject, i + 1) end
        for i = 0, math.min(#datestr - 1, 30) do tmem[0x40 + i] = string.byte(datestr, i + 1) end
        local tmem_addr = tonumber(ffi.cast('uint32_t', text_mem))
        print(('[fdiag] Text at 0x%08X: sender="%s" subj="%s" date="%s"'):format(
            tmem_addr, sender, subject, datestr))

        local prot = ffi.new('uint32_t[1]')
        local entry0 = ffi.cast('uint8_t*', render_arr)
        local entry = ffi.cast('uint8_t*', render_arr + count * 0x54)
        local data0 = ffi.cast('uint8_t*', data_arr)
        local data1 = ffi.cast('uint8_t*', data_arr + count * 0x50)

        -- Clone render entry 0 → new entry (preserves data_ptr[0] descriptor)
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, 0x04, prot)
        ffi.copy(entry, entry0, 0x54)

        -- Set column positions (mimic what insertion function does)
        -- col 0 = 0x20 (32) — icon/status (already from clone)
        -- col 1 = 0x25 (37) — sender name
        -- col 2 = 0x25 (37) — subject
        -- col 3 = 0x01 (1)  — unknown
        -- col 4 = 0x01 (1)  — date
        entry[1] = 0x25
        entry[2] = 0x25
        entry[3] = 0x01
        entry[4] = 0x01

        -- Set VISIBLE colors for text columns (0xFFFFFFFF = white)
        -- col 0 keeps 0x80808080 (icon handled differently)
        ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF  -- color[1] = white (sender)
        ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF  -- color[2] = white (subject)
        ffi.cast('uint32_t*', entry + 0x14)[0] = 0x80808080  -- color[3] = invisible
        ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF  -- color[4] = white (date)

        -- Set data_ptrs to text buffers
        -- The display_text function sets data_ptr[col] = pointer to text
        -- Insertion function uses render+0x10 for col1, render+0x20 for col2, render+0x30 for date
        -- We use external buffers instead
        ffi.cast('uint32_t*', entry + 0x2C)[0] = tmem_addr          -- data_ptr[1] = sender
        ffi.cast('uint32_t*', entry + 0x30)[0] = tmem_addr + 0x20   -- data_ptr[2] = subject
        ffi.cast('uint32_t*', entry + 0x38)[0] = tmem_addr + 0x40   -- data_ptr[4] = date

        -- Fix data array link
        ffi.cast('uint32_t*', entry + 0x48)[0] = data_arr + count * 0x50
        -- Clear flag
        entry[0x50] = 0

        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, prot[0], prot)

        -- Clone data entry 0 → new data entry
        ffi.C.VirtualProtect(ffi.cast('void*', data1), 0x50, 0x04, prot)
        ffi.copy(data1, data0, 0x50)
        ffi.C.VirtualProtect(ffi.cast('void*', data1), 0x50, prot[0], prot)

        -- Increment count and visible count (no refresh!)
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, 0x04, prot)
        ffi.cast('uint32_t*', obj + 0x54)[0] = count + 1
        ffi.cast('uint16_t*', obj + 0x20)[0] = count + 1
        ffi.C.VirtualProtect(ffi.cast('void*', obj), 0x78, prot[0], prot)

        print(('[fdiag] Injected entry %d with visible colors'):format(count))
        print(('[fdiag] count: %d → %d, visible: → %d'):format(count, count + 1, count + 1))

        -- Dump the entry
        local hex = {}
        for j = 0, 0x53 do table.insert(hex, ('%02X'):format(entry[j])) end
        print(('[fdiag] Entry: %s'):format(table.concat(hex, ' ')))
        for col = 0, 4 do
            local pos = entry[col]
            local color = ffi.cast('uint32_t*', entry + 0x08 + col * 4)[0]
            local dptr = ffi.cast('uint32_t*', entry + 0x28 + col * 4)[0]
            print(('[fdiag]   col[%d]: pos=%d color=0x%08X dptr=0x%08X'):format(col, pos, color, dptr))
        end
        return
    end

    -----------------------------------------------------------------
    -- CALLINSERT: Call the native message_insert at FFXiMain+0x1FF010
    -- Signature: bool __cdecl(msg_obj*, icon_type_16, mode, unk, source*)
    -- source[0x00-0x07] = positions, source[0x08] = sender text ptr,
    -- source[0x0C] = subject text ptr, source[0x18] = descriptor ptr
    -- descriptor[0x00] = text buffer ptr (writable, 15+ bytes)
    -- descriptor[0x04] = copied to render[0x0C] (temp, gets overwritten)
    -- descriptor[0x34] = timestamp for date formatting
    -- Usage: /fdiag callinsert [sender] [subject]
    -----------------------------------------------------------------
    if cmd == 'callinsert' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or 'Hello!'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)

        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] Before: count=%d'):format(count_before))

        -- Allocate all memory in one block: source struct + descriptor + text buffers
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local mem = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local base_addr = tonumber(ffi.cast('uint32_t', mem))
        print(('[fdiag] Allocated 4K at 0x%08X'):format(base_addr))

        -- Layout within our allocated block:
        -- 0x000: source struct (0x20 bytes)
        -- 0x040: descriptor (0x40 bytes)
        -- 0x080: text buffer for descriptor[0x00] (32 bytes)
        -- 0x0A0: sender text (16 bytes)
        -- 0x0C0: subject text (16 bytes)

        local src = base                          -- source struct
        local desc = base + 0x40                  -- descriptor
        local textbuf = base + 0x80              -- text buffer (written by insertion fn)
        local sender_buf = base + 0x0A0          -- sender text
        local subj_buf = base + 0x0C0            -- subject text

        -- Fill sender text (15 bytes max)
        for i = 0, math.min(#sender - 1, 14) do sender_buf[i] = string.byte(sender, i + 1) end
        -- Fill subject text (15 bytes max)
        for i = 0, math.min(#subject - 1, 14) do subj_buf[i] = string.byte(subject, i + 1) end

        -- Build descriptor
        -- [0x00] = text buffer pointer (writable, insertion fn copies sender here)
        ffi.cast('uint32_t*', desc)[0] = base_addr + 0x80       -- textbuf
        -- [0x04] = second value (goes to render[0x0C] temporarily)
        ffi.cast('uint32_t*', desc + 0x04)[0] = 0               -- will be overwritten by display_text
        -- [0x14] = 15 (max text length, seen in existing descriptor)
        ffi.cast('uint32_t*', desc + 0x14)[0] = 0x0F
        -- [0x18] = 15
        ffi.cast('uint32_t*', desc + 0x18)[0] = 0x0F
        -- [0x30] = timestamp hash (used for render[0x4C])
        ffi.cast('uint32_t*', desc + 0x30)[0] = os.time()
        -- [0x34] = timestamp for date formatting
        ffi.cast('uint32_t*', desc + 0x34)[0] = os.time()

        -- Build source struct
        -- [0x00-0x07] = position bytes
        src[0] = 0x20   -- col 0 position (icon)
        src[1] = 0x25   -- col 1 position (sender)
        src[2] = 0x25   -- col 2 position (subject)
        src[3] = 0x01   -- col 3
        src[4] = 0x01   -- col 4 (date)
        -- [0x08] = pointer to sender text
        ffi.cast('uint32_t*', src + 0x08)[0] = base_addr + 0x0A0
        -- [0x0C] = pointer to subject text
        ffi.cast('uint32_t*', src + 0x0C)[0] = base_addr + 0x0C0
        -- [0x18] = pointer to descriptor
        ffi.cast('uint32_t*', src + 0x18)[0] = base_addr + 0x40

        print(('[fdiag] Source: sender="%s" subject="%s"'):format(sender, subject))
        print(('[fdiag] desc=0x%08X textbuf=0x%08X'):format(base_addr + 0x40, base_addr + 0x80))

        -- Call message_insert:
        --   bool __cdecl message_insert(msg_obj*, icon_type_16, mode, unk, source_struct*)
        local insert_fn = ffi.cast(
            'bool (__cdecl*)(void*, int, int, int, void*)',
            ffximain_base + 0x1FF010
        )

        print('[fdiag] Calling message_insert...')
        local ok, result = pcall(function()
            return insert_fn(
                ffi.cast('void*', msg_obj_ptr),  -- arg1: msg_obj
                0,                                -- arg2: icon_type (0 = none)
                0,                                -- arg3: mode (0 = normal insert)
                0,                                -- arg4: unknown
                ffi.cast('void*', base_addr)      -- arg5: source struct
            )
        end)

        if not ok then
            print(('[fdiag] CRASH/ERROR: %s'):format(tostring(result)))
        else
            print(('[fdiag] Result: %s'):format(tostring(result)))
        end

        local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
        local visible = ffi.cast('uint16_t*', obj + 0x20)[0]
        print(('[fdiag] After: count=%d visible=%d'):format(count_after, visible))

        -- Dump the new entry if count increased
        if count_after > count_before then
            local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
            local entry = ffi.cast('uint8_t*', render_arr + count_before * 0x54)
            local hex = {}
            for j = 0, 0x53 do table.insert(hex, ('%02X'):format(entry[j])) end
            print(('[fdiag] New entry: %s'):format(table.concat(hex, ' ')))

            -- Check text buffer after insertion (sender text should be there)
            local tbuf = ffi.cast('uint8_t*', base_addr + 0x80)
            local txt = {}
            for j = 0, 14 do
                if tbuf[j] >= 0x20 and tbuf[j] < 0x7F then
                    table.insert(txt, string.char(tbuf[j]))
                else break end
            end
            print(('[fdiag] Text buffer: "%s"'):format(table.concat(txt)))
        end
        return
    end

    -----------------------------------------------------------------
    -- CALLVT4: Manually call vt[4] (render function) on msg_obj from main thread.
    -- Tests whether the rendering code actually draws entries when called directly.
    -- Usage: /fdiag msginject on|off [sender] [subject] [date]
    -----------------------------------------------------------------
    if cmd == 'msginject' then
        local mode = args[3]
        if mode == 'off' then
            msginject_active = false
            print('[fdiag] Message injection OFF')
        else
            msginject_active = true
            if args[4] then msginject_sender = args[4] end
            if args[5] then msginject_subject = args[5] end
            if args[6] then msginject_date = args[6] end
            msginject_textbuf = nil  -- force re-alloc with new text
            print(('[fdiag] Message injection ON: from="%s" subj="%s" date="%s"'):format(
                msginject_sender, msginject_subject, msginject_date))
        end
        return
    end

    -- Usage: /fdiag callinit — call full_init +0x200710 on msg_obj (main thread)
    -----------------------------------------------------------------
    if cmd == 'callinit' then
        -- Use NATIVE msg_obj at [FFXi+0x62FF94] (created by game constructor)
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if msg_obj_ptr == 0 then
            print('[fdiag] Native msg_obj at +0x62FF94 is NULL')
            return
        end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        -- Dump pre-state
        print(('[fdiag] Before: +0x08=0x%08X +0x1C=%d +0x30=0x%08X +0x74=0x%08X'):format(
            ffi.cast('uint32_t*', obj+0x08)[0],
            ffi.cast('int16_t*', obj+0x1C)[0],
            ffi.cast('uint32_t*', obj+0x30)[0],
            ffi.cast('uint32_t*', obj+0x74)[0]))
        local fn = ffi.cast('void (__thiscall*)(void*, int, int, int)', ffximain_base + 0x200710)
        -- Parse optional args: /fdiag callinit [arg1_hex] [arg2_hex] [arg3]
        local a1 = tonumber(args[3] or '0') or 0
        local a2 = tonumber(args[4] or '0') or 0
        local a3 = tonumber(args[5] or '0') or 0
        print(('[fdiag] Calling full_init +0x200710(msg_obj=0x%08X, 0x%X, 0x%X, %d)...'):format(msg_obj_ptr, a1, a2, a3))
        local ok, err = pcall(function() fn(ffi.cast('void*', msg_obj_ptr), a1, a2, a3) end)
        if ok then
            print(('[fdiag] OK! +0x08=0x%08X +0x1C=%d +0x30=0x%08X +0x74=0x%08X'):format(
                ffi.cast('uint32_t*', obj+0x08)[0],
                ffi.cast('int16_t*', obj+0x1C)[0],
                ffi.cast('uint32_t*', obj+0x30)[0],
                ffi.cast('uint32_t*', obj+0x74)[0]))
        else
            print(('[fdiag] CRASHED: %s'):format(tostring(err)))
        end
        return
    end

    -----------------------------------------------------------------
    -- VT1NATIVE: Call vt[1] on the native msg_obj at +0x62FF94
    -- Updates the scroll list UI element with current visible count
    -----------------------------------------------------------------
    if cmd == 'vt1native' then
        local obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if obj_ptr == 0 then print('[fdiag] Native obj NULL'); return end
        local obj = ffi.cast('uint8_t*', obj_ptr)
        local cnt = ffi.cast('uint32_t*', obj + 0x54)[0]
        local vis = ffi.cast('uint16_t*', obj + 0x20)[0]
        local ui = ffi.cast('uint32_t*', obj + 0x08)[0]
        print(('[fdiag] Native obj=0x%08X count=%d vis=%d ui=0x%08X'):format(obj_ptr, cnt, vis, ui))
        if ui == 0 then print('[fdiag] No UI element, run callinit first'); return end
        local vt1 = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1F63E0)
        local ok, err = pcall(function() vt1(ffi.cast('void*', obj_ptr)) end)
        if ok then print('[fdiag] vt[1] OK') else print(('[fdiag] vt[1] CRASHED: %s'):format(tostring(err))) end
        return
    end

    -----------------------------------------------------------------
    -- ADDMSG2: Like addmsg but uses a trampoline to set ESI = native msg_obj
    -- before calling +0x1FF010. This is needed because +0x1FF010 reads ESI
    -- (set by the prologue at +0x1FEF10) which is random when called from fdiag.
    -- Usage: /fdiag realinsert — call +0x1FF690 on the REAL msg_obj at [FFXi+0x62FF90]
    -- This stores data at +0x1D0/D4/D8, sets inner case, shows msgline panel
    -----------------------------------------------------------------
    if cmd == 'realinsert' then
        local real_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF90)[0]
        if real_ptr == 0 then print('[fdiag] Real msg_obj at +0x62FF90 is NULL'); return end

        -- Allocate text buffers
        local mem = ffi.C.VirtualAlloc(nil, 256, 0x3000, 0x04)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local tb = ffi.cast('uint8_t*', mem)
        ffi.fill(tb, 256, 0)
        local tba = tonumber(ffi.cast('uint32_t', mem))

        local sender = args[3] or 'CharB'
        local subject = args[4] or 'FriendReq'
        for i = 0, math.min(#sender-1, 14) do tb[i] = string.byte(sender, i+1) end
        for i = 0, math.min(#subject-1, 14) do tb[0x20+i] = string.byte(subject, i+1) end

        print(('[fdiag] Calling +0x1FF690(real_obj=0x%08X, 0x%08X, 0x%08X, 0)'):format(
            real_ptr, tba, tba + 0x20))

        -- __thiscall(real_obj, data1, data2, type), RET 0x0C
        local fn = ffi.cast('bool (__thiscall*)(void*, void*, void*, int)',
            ffximain_base + 0x1FF690)
        local ok, ret = pcall(function()
            return fn(ffi.cast('void*', real_ptr),
                      ffi.cast('void*', tba),
                      ffi.cast('void*', tba + 0x20), 0)
        end)
        if ok then
            print(('[fdiag] OK ret=%s'):format(tostring(ret)))
            -- Check what changed
            local obj = ffi.cast('uint8_t*', real_ptr)
            print(('[fdiag] +0x14=%d +0x1D0=0x%08X +0x1D4=0x%08X +0x1D8=0x%08X'):format(
                ffi.cast('uint16_t*', obj + 0x14)[0],
                ffi.cast('uint32_t*', obj + 0x1D0)[0],
                ffi.cast('uint32_t*', obj + 0x1D4)[0],
                ffi.cast('uint32_t*', obj + 0x1D8)[0]))
        else
            print(('[fdiag] CRASHED: %s'):format(tostring(ret)))
        end
        return
    end

    -- Usage: /fdiag callfn6 — call dispatch table entry [6] (+0x130AA0) on render entry 1
    -- This is the per-entry insertion function found in the March 10 binary
    -----------------------------------------------------------------
    if cmd == 'callfn6' then
        local native_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if native_ptr == 0 then print('[fdiag] No native msg_obj'); return end
        local obj = ffi.cast('uint8_t*', native_ptr)
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        if render_arr == 0 then print('[fdiag] No render array'); return end

        local entry1 = render_arr + 1 * 0x54
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] Calling +0x130AA0(msg_obj=0x%08X, entry=0x%08X, 0) count=%d'):format(
            native_ptr, entry1, count))

        -- __thiscall(msg_obj, render_entry, arg2=0), RET 8
        local fn = ffi.cast('bool (__thiscall*)(void*, void*, int)', ffximain_base + 0x130AA0)
        local ok, ret = pcall(function()
            return fn(ffi.cast('void*', native_ptr), ffi.cast('void*', entry1), 0)
        end)
        if ok then
            local new_count = ffi.cast('uint32_t*', obj + 0x54)[0]
            print(('[fdiag] OK ret=%s count=%d->%d'):format(tostring(ret), count, new_count))
            -- Call vt[1]
            local vt1 = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1F63E0)
            vt1(ffi.cast('void*', native_ptr))
            print('[fdiag] vt[1] OK')
        else
            print(('[fdiag] CRASHED: %s'):format(tostring(ret)))
        end
        return
    end

    -- Usage: /fdiag addmsg2 [sender] [subject]
    -----------------------------------------------------------------
    if cmd == 'addmsg2' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or 'FriendReq'

        local native_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if native_ptr == 0 then print('[fdiag] No native msg_obj'); return end
        local obj = ffi.cast('uint8_t*', native_ptr)
        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] native=0x%08X count=%d'):format(native_ptr, count_before))

        -- Build source struct (same as addmsg)
        local mem = ffi.C.VirtualAlloc(nil, 4096, 0x1000, 0x04)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        for i = 0, math.min(#sender-1, 14) do base[0xA0+i] = string.byte(sender, i+1) end
        for i = 0, math.min(#subject-1, 14) do base[0xC0+i] = string.byte(subject, i+1) end

        ffi.cast('uint32_t*', base + 0x40)[0] = ba + 0x80
        ffi.cast('uint32_t*', base + 0x54)[0] = 0x0F
        ffi.cast('uint32_t*', base + 0x58)[0] = 0x0F
        ffi.cast('uint32_t*', base + 0x70)[0] = os.time()
        ffi.cast('uint32_t*', base + 0x74)[0] = os.time()

        base[0] = 0x20; base[1] = 0x25; base[2] = 0x25; base[3] = 0x01; base[4] = 0x01
        ffi.cast('uint32_t*', base + 0x08)[0] = ba + 0xA0
        ffi.cast('uint32_t*', base + 0x0C)[0] = ba + 0xC0
        ffi.cast('uint32_t*', base + 0x18)[0] = ba + 0x40

        -- Create trampoline: MOV ESI, native_ptr; RET
        -- Then we call: trampoline() to set ESI, followed by insert_fn()
        -- Actually, need a single call that sets ESI and calls +0x1FF010.
        -- Trampoline code:
        --   BE xx xx xx xx    MOV ESI, native_ptr (5 bytes)
        --   E9 xx xx xx xx    JMP +0x1FF010 (5 bytes, relative)
        -- Total: 10 bytes
        local tramp = ffi.C.VirtualAlloc(nil, 64, 0x3000, 0x40) -- RWX
        if tramp == nil then print('[fdiag] Trampoline alloc failed'); return end
        local tb = ffi.cast('uint8_t*', tramp)
        local tramp_addr = tonumber(ffi.cast('uint32_t', tramp))

        -- MOV ESI, native_ptr (BE + 4 byte LE)
        tb[0] = 0xBE  -- MOV ESI, imm32
        ffi.cast('uint32_t*', tb + 1)[0] = native_ptr

        -- JMP rel32 to +0x1FF010
        local target = ffximain_base + 0x1FF010
        local jmp_from = tramp_addr + 10  -- address after the JMP instruction
        local rel = target - jmp_from
        tb[5] = 0xE9  -- JMP rel32
        ffi.cast('int32_t*', tb + 6)[0] = rel

        print(('[fdiag] Trampoline at 0x%08X, target=0x%08X'):format(tramp_addr, target))

        -- Call trampoline as cdecl with same args as addmsg
        -- Stack: msg_obj, icon_type=0, mode=0, unk=0, source
        local call_fn = ffi.cast('bool (__cdecl*)(void*, int, int, int, void*)', tramp)
        local ok, result = pcall(function()
            return call_fn(ffi.cast('void*', native_ptr), 0, 0, 0, ffi.cast('void*', ba))
        end)

        if not ok then
            print(('[fdiag] CRASHED: %s'):format(tostring(result)))
            return
        end

        local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] Result: %s, count: %d -> %d'):format(tostring(result), count_before, count_after))

        if count_after > count_before then
            -- Patch colors
            local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
            local entry = ffi.cast('uint8_t*', render_arr + (count_after - 1) * 0x54)
            ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF
            ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF
            ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF
            entry[0] = 0x20

            -- Call vt[1]
            local vt1 = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1F63E0)
            vt1(ffi.cast('void*', native_ptr))
            print('[fdiag] Colors patched + vt[1] called!')
        end
        return
    end

    -----------------------------------------------------------------
    -- INSERTMSG: Insert a message into the native msg_obj linked list + rebuild
    -- 1. Clone head node from tab 1's linked list
    -- 2. Insert clone as new head
    -- 3. Increment tab count
    -- 4. Call +0x2002F0 to rebuild display arrays from linked list
    -- Usage: /fdiag insertmsg
    -----------------------------------------------------------------
    if cmd == 'insertmsg' then
        local native_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if native_ptr == 0 then print('[fdiag] No native msg_obj'); return end
        local obj = ffi.cast('uint8_t*', native_ptr)

        -- Get message store at +0x74
        local store = ffi.cast('uint32_t*', obj + 0x74)[0]
        if store == 0 then print('[fdiag] No message store at +0x74'); return end
        local sp = ffi.cast('uint8_t*', store)

        -- Tab 1 at store+0x30: +0x0C=head, +0x10=tail, +0x1C=count, +0x20=count_dup
        local tab1 = sp + 0x30
        local head_ptr = ffi.cast('uint32_t*', tab1 + 0x0C)[0]
        local tail_ptr = ffi.cast('uint32_t*', tab1 + 0x10)[0]
        local count = ffi.cast('uint32_t*', tab1 + 0x1C)[0]
        print(('[fdiag] Tab1: head=0x%08X tail=0x%08X count=%d'):format(head_ptr, tail_ptr, count))

        if head_ptr == 0 then print('[fdiag] Empty list, cannot clone'); return end

        -- Allocate new node (0x30 bytes)
        local new_mem = ffi.C.VirtualAlloc(nil, 0x30, 0x3000, 0x04)
        if new_mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local new_node = ffi.cast('uint8_t*', new_mem)
        local new_addr = tonumber(ffi.cast('uint32_t', new_mem))

        -- Clone head node
        local head = ffi.cast('uint8_t*', head_ptr)
        ffi.copy(new_node, head, 0x30)
        print(('[fdiag] Cloned head node to 0x%08X'):format(new_addr))

        -- Modify: new_node->next = old_head, new_node->prev = NULL
        ffi.cast('uint32_t*', new_node + 0x00)[0] = head_ptr  -- next = old head
        ffi.cast('uint32_t*', new_node + 0x04)[0] = 0         -- prev = NULL (new head)

        -- Set old_head->prev = new_node
        ffi.cast('uint32_t*', head + 0x04)[0] = new_addr

        -- Update tab head pointer
        ffi.cast('uint32_t*', tab1 + 0x0C)[0] = new_addr

        -- Increment counts (at +0x1C and +0x20)
        ffi.cast('uint32_t*', tab1 + 0x1C)[0] = count + 1
        ffi.cast('uint32_t*', tab1 + 0x20)[0] = count + 1

        print(('[fdiag] Inserted node. New count=%d'):format(count + 1))

        -- Now call +0x2002F0 to rebuild display arrays from linked list
        -- Signature: __thiscall(this=msg_obj, arg1, arg2, arg3), RET 0x0C
        local rebuild = ffi.cast('bool (__thiscall*)(void*, int, int, int)',
            ffximain_base + 0x2002F0)
        print('[fdiag] Calling rebuild +0x2002F0...')
        local ok, ret = pcall(function()
            return rebuild(ffi.cast('void*', native_ptr), 0, 0, 0)
        end)
        if ok then
            local new_count = ffi.cast('uint32_t*', obj + 0x54)[0]
            local vis = ffi.cast('uint16_t*', obj + 0x20)[0]
            print(('[fdiag] Rebuild OK (ret=%s). Display: count=%d vis=%d'):format(
                tostring(ret), new_count, vis))
        else
            print(('[fdiag] Rebuild CRASHED: %s'):format(tostring(ret)))
        end
        return
    end

    -- Usage: /fdiag disptext — call display_text for each column of render entry 1
    -----------------------------------------------------------------
    if cmd == 'disptext' then
        local obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if obj_ptr == 0 then print('[fdiag] NULL native obj'); return end
        local obj = ffi.cast('uint8_t*', obj_ptr)
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        if render_arr == 0 then print('[fdiag] NULL render arr'); return end

        local entry1 = ffi.cast('uint8_t*', render_arr + 1 * 0x54)
        -- Ensure text buf exists
        if msginject_textbuf == nil then
            msginject_textbuf = ffi.C.VirtualAlloc(nil, 256, 0x3000, 0x04)
            ffi.fill(msginject_textbuf, 256, 0)
            msginject_textbuf_addr = tonumber(ffi.cast('uint32_t', msginject_textbuf))
            local tb = ffi.cast('uint8_t*', msginject_textbuf)
            local s = 'CharB'
            for i = 0, #s-1 do tb[i] = string.byte(s, i+1) end
            local su = 'FriendReq'
            for i = 0, #su-1 do tb[0x20+i] = string.byte(su, i+1) end
            local d = '04-02'
            for i = 0, #d-1 do tb[0x40+i] = string.byte(d, i+1) end
        end
        local tba = msginject_textbuf_addr

        -- display_text: __stdcall(col, pos, data_ptr, color) ECX=render_entry
        local dt = ffi.cast('void (__stdcall*)(int, int, void*, uint32_t)', ffximain_base + 0x1F4650)

        print(('[fdiag] Calling display_text on entry1=0x%08X'):format(tonumber(ffi.cast('uint32_t', entry1))))

        local ok, err = pcall(function()
            -- Set ECX to entry1 by using __thiscall wrapper
            -- Actually display_text is __stdcall, ECX set separately
            -- In LuaJIT FFI we can't set ECX directly for stdcall...
            -- Let me use a thiscall wrapper instead
            local dt2 = ffi.cast('void (__thiscall*)(void*, int, int, void*, uint32_t)', ffximain_base + 0x1F4650)
            -- Col 1 (From): pos=0x25, data=sender
            dt2(ffi.cast('void*', entry1), 1, 0x25, ffi.cast('void*', tba), 0xFFFFFFFF)
            -- Col 2 (To): pos=0x25, data=subject
            dt2(ffi.cast('void*', entry1), 2, 0x25, ffi.cast('void*', tba + 0x20), 0xFFFFFFFF)
            -- Col 3 (Type): pos=0x01, data=type label
            dt2(ffi.cast('void*', entry1), 3, 0x01, ffi.cast('void*', tba + 0x20), 0xFFFFFFFF)
            -- Col 4 (Date): pos=0x01, data=date
            dt2(ffi.cast('void*', entry1), 4, 0x01, ffi.cast('void*', tba + 0x40), 0xFFFFFFFF)
        end)
        if ok then
            print('[fdiag] display_text OK')
            -- Also call vt[1]
            local vt1 = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1F63E0)
            vt1(ffi.cast('void*', obj_ptr))
            print('[fdiag] vt[1] OK')
        else
            print(('[fdiag] display_text CRASHED: %s'):format(tostring(err)))
        end
        return
    end

    -- Usage: /fdiag callvt4
    -----------------------------------------------------------------
    if cmd == 'callvt4' then
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local vt = ffi.cast('uint32_t*', obj)[0]
        local vt4_addr = ffi.cast('uint32_t*', vt + 16)[0]  -- vt[4]
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        local vis = ffi.cast('uint16_t*', obj + 0x20)[0]
        local disp = ffi.cast('uint32_t*', obj + 0x38)[0]
        print(('[fdiag] msg_obj=0x%08X vt4=0x%08X count=%d vis=%d disp=0x%08X'):format(
            msg_obj_ptr, vt4_addr, count, vis, disp))
        print(('[fdiag]   +0x1C=%d +0x28=%d +0x2C=%d +0x46=0x%02X'):format(
            ffi.cast('int16_t*', obj + 0x1C)[0],
            ffi.cast('int16_t*', obj + 0x28)[0],
            ffi.cast('int8_t*', obj + 0x2C)[0],
            obj[0x46]))
        local fn = ffi.cast('void (__thiscall*)(void*)', vt4_addr)
        print('[fdiag] Calling vt[4]...')
        local ok, err = pcall(function() fn(ffi.cast('void*', msg_obj_ptr)) end)
        if ok then
            print('[fdiag] vt[4] returned OK')
        else
            print(('[fdiag] vt[4] CRASHED: %s'):format(tostring(err)))
        end
        return
    end

    -----------------------------------------------------------------
    -- FULLINJECT: Complete injection into NATIVE msg_obj:
    -- 1. Create sub-object with fake vtable (for prepare_string)
    -- 2. Set native obj +0x1C = sub-object
    -- 3. Restore prepare_string JZ (unpatch)
    -- 4. Call message_insert at +0x1FEF10 with icon_type=17
    -- 5. Patch render entry colors to 0xFFFFFFFF
    -- 6. Call vt[1]
    -- Usage: /fdiag fullinject [sender] [subject]
    -----------------------------------------------------------------
    if cmd == 'fullinject' then
        local sender = args[3] or 'CharB'
        local subject = args[4] or 'Friend req'

        -- Get native msg_obj
        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
        if msg_obj_ptr == 0 then print('[fdiag] Native obj NULL'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] Native obj=0x%08X count=%d'):format(msg_obj_ptr, count_before))

        -- Step 1: Create sub-object (0x800 bytes, RWX)
        local sub = ffi.C.VirtualAlloc(nil, 0x800, 0x3000, 0x40)
        if sub == nil then print('[fdiag] VirtualAlloc failed'); return end
        ffi.fill(sub, 0x800, 0)
        local sub_addr = tonumber(ffi.cast('uint32_t', sub))
        local sub_bytes = ffi.cast('uint8_t*', sub)
        -- RET 4 at sub+0x700
        sub_bytes[0x700] = 0xC2; sub_bytes[0x701] = 0x04; sub_bytes[0x702] = 0x00
        -- Fake vtable at sub+0x710, all entries = RET 4
        local ret4_addr = sub_addr + 0x700
        local vt = ffi.cast('uint32_t*', sub_bytes + 0x710)
        for i = 0, 7 do vt[i] = ret4_addr end
        ffi.cast('uint32_t*', sub)[0] = sub_addr + 0x710  -- vtable ptr
        sub_bytes[0x1D5] = 0x4D  -- 'M' sentinel for get_string return
        sub_bytes[0x1D6] = 0x01  -- \x01 at +0x54 preserves count=1 after strcpy
        print(('[fdiag] Sub-object at 0x%08X'):format(sub_addr))

        -- Step 2: Set native obj +0x1C = sub-object
        ffi.cast('uint32_t*', obj + 0x1C)[0] = sub_addr

        -- Step 3: Restore prepare_string JZ (EB→74)
        local ps_addr = ffi.cast('uint8_t*', ffximain_base + 0x1FE9F9)
        ps_addr[0] = 0x74  -- restore JZ

        -- Step 4: Ensure [manager+0x80] = native obj
        local mgr = ffi.cast('uint32_t*', ffximain_base + 0x35F1C4)[0]
        if mgr ~= 0 then
            local prot = ffi.new('uint32_t[1]')
            ffi.C.VirtualProtect(ffi.cast('void*', mgr + 0x80), 4, 0x04, prot)
            ffi.cast('uint32_t*', mgr + 0x80)[0] = msg_obj_ptr
            ffi.C.VirtualProtect(ffi.cast('void*', mgr + 0x80), 4, prot[0], prot)
        end

        -- Step 5: Build source struct
        local mem = ffi.C.VirtualAlloc(nil, 4096, 0x1000, 0x04)
        if mem == nil then print('[fdiag] VirtualAlloc2 failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        for i = 0, math.min(#sender-1, 14) do base[0xA0+i] = string.byte(sender, i+1) end
        for i = 0, math.min(#subject-1, 14) do base[0xC0+i] = string.byte(subject, i+1) end

        ffi.cast('uint32_t*', base + 0x40)[0] = ba + 0x80
        ffi.cast('uint32_t*', base + 0x54)[0] = 0x0F
        ffi.cast('uint32_t*', base + 0x58)[0] = 0x0F
        ffi.cast('uint32_t*', base + 0x70)[0] = os.time()
        ffi.cast('uint32_t*', base + 0x74)[0] = os.time()

        base[0] = 0x20; base[1] = 0x25; base[2] = 0x25; base[3] = 0x01; base[4] = 0x01
        ffi.cast('uint32_t*', base + 0x08)[0] = ba + 0xA0
        ffi.cast('uint32_t*', base + 0x0C)[0] = ba + 0xC0
        ffi.cast('uint32_t*', base + 0x18)[0] = ba + 0x40

        -- Step 6: Call message_insert
        local fn = ffi.cast('int (__thiscall*)(void*, int, void*)',
            ffximain_base + 0x1FEF10)
        print(('[fdiag] Calling +0x1FEF10(this=0x%08X, 17, src=0x%08X)...'):format(msg_obj_ptr, ba))
        local ok, ret = pcall(function()
            return fn(ffi.cast('void*', msg_obj_ptr), 17, ffi.cast('void*', ba))
        end)
        if not ok then
            print(('[fdiag] CRASHED: %s'):format(tostring(ret)))
            return
        end

        local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
        print(('[fdiag] Result: %s count: %d -> %d'):format(tostring(ret), count_before, count_after))

        if count_after > count_before then
            -- Step 7: Patch colors on new entry
            local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
            local entry = ffi.cast('uint8_t*', render_arr + (count_after - 1) * 0x54)
            ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF  -- sender
            ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF  -- subject
            ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF  -- date
            entry[0] = 0x20  -- fix position[0]
            print('[fdiag] Colors patched to white')

            -- Step 8: Call vt[1]
            local vt1 = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1F63E0)
            vt1(ffi.cast('void*', msg_obj_ptr))
            print(('[fdiag] vt[1] called. Message injected!'):format())
        else
            print('[fdiag] Insertion FAILED (count unchanged)')
        end
        return
    end

    -----------------------------------------------------------------
    -- NATIVEINSERT: Call the REAL message_insert entry at +0x1FEF10
    -- as __thiscall(ECX=msg_obj, icon_type=17, source_ptr) from main thread.
    -- icon_type=17 → case 5 → insertion path.
    -- Requires [FFXi+0x35F1C4]+0x80 to be non-NULL (set via writemem first).
    -- Usage: /fdiag nativeinsert [sender] [subject]
    -----------------------------------------------------------------
    if cmd == 'nativeinsert' then
        local sender = args[3] or 'NativeTest'
        local subject = args[4] or 'It works!'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]

        -- Check prerequisites
        local g1 = ffi.cast('uint32_t*', ffximain_base + 0x4DED90)[0]
        local g2 = ffi.cast('uint32_t*', ffximain_base + 0x35F1C4)[0]
        local mgr80 = 0
        if g2 ~= 0 then mgr80 = ffi.cast('uint32_t*', g2 + 0x80)[0] end
        local sub_obj = ffi.cast('uint32_t*', obj + 0x1C)[0]
        print(('[fdiag] Prerequisites: global1=0x%08X mgr=0x%08X mgr+80=0x%08X sub=0x%08X'):format(g1, g2, mgr80, sub_obj))
        if g1 == 0 then print('[fdiag] FAIL: [FFXi+0x4DED90] is NULL'); return end
        if mgr80 == 0 then
            -- Auto-set [mgr+0x80] = msg_obj
            if g2 ~= 0 then
                local prot = ffi.new('uint32_t[1]')
                ffi.C.VirtualProtect(ffi.cast('void*', g2 + 0x80), 4, 0x04, prot)
                ffi.cast('uint32_t*', g2 + 0x80)[0] = msg_obj_ptr
                ffi.C.VirtualProtect(ffi.cast('void*', g2 + 0x80), 4, prot[0], prot)
                mgr80 = msg_obj_ptr
                print(('[fdiag] Auto-set [mgr+0x80] = 0x%08X'):format(msg_obj_ptr))
            else
                print('[fdiag] FAIL: manager is NULL'); return
            end
        end
        -- sub_obj check removed: prepare_string patched (JZ→JMP at +0x1FE9F9) skips get_string
        if sub_obj == 0 then print('[fdiag] NOTE: sub_obj NULL (prepare_string patched to skip)') end

        -- Allocate source struct
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local mem = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        -- Fill text
        for i = 0, math.min(#sender - 1, 14) do base[0xA0 + i] = string.byte(sender, i + 1) end
        for i = 0, math.min(#subject - 1, 14) do base[0xC0 + i] = string.byte(subject, i + 1) end

        -- Descriptor at +0x40
        ffi.cast('uint32_t*', base + 0x40)[0] = ba + 0x80   -- text_buf
        ffi.cast('uint32_t*', base + 0x54)[0] = 0x0F        -- max_len
        ffi.cast('uint32_t*', base + 0x58)[0] = 0x0F        -- max_len
        ffi.cast('uint32_t*', base + 0x70)[0] = os.time()   -- timestamp hash
        ffi.cast('uint32_t*', base + 0x74)[0] = os.time()   -- timestamp

        -- Source struct at +0x00
        base[0] = 0x20  base[1] = 0x25  base[2] = 0x25
        base[3] = 0x01  base[4] = 0x01
        ffi.cast('uint32_t*', base + 0x08)[0] = ba + 0xA0   -- sender ptr
        ffi.cast('uint32_t*', base + 0x0C)[0] = ba + 0xC0   -- subject ptr
        ffi.cast('uint32_t*', base + 0x18)[0] = ba + 0x40   -- descriptor ptr

        -- Call REAL entry at +0x1FEF10: __thiscall(ECX=msg_obj, int icon_type, void* source)
        -- Function uses RET 8 (2 stack args). FFI handles this for __thiscall.
        local fn = ffi.cast('int (__thiscall*)(void*, int, void*)',
            ffximain_base + 0x1FEF10)

        print(('[fdiag] Calling +0x1FEF10(this=0x%08X, 17, src=0x%08X)...'):format(
            msg_obj_ptr, ba))

        local ok, ret = pcall(function()
            return fn(ffi.cast('void*', msg_obj_ptr), 17, ffi.cast('void*', ba))
        end)

        if ok then
            local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
            local visible = ffi.cast('uint16_t*', obj + 0x20)[0]
            print(('[fdiag] Result: %s, count: %d -> %d, visible: %d'):format(
                tostring(ret), count_before, count_after, visible))
        else
            print(('[fdiag] CRASHED: %s'):format(tostring(ret)))
        end
        return
    end

    -----------------------------------------------------------------
    -- FOLLOWPTR: Follow a pointer and dump what it points to.
    -- Usage: /fdiag followptr <addr_hex> [size]
    -----------------------------------------------------------------
    if cmd == 'followptr' then
        local addr = tonumber(args[3])
        local sz = tonumber(args[4]) or 64
        if not addr then
            print('[fdiag] Usage: /fdiag followptr <addr_hex> [size]')
            return
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), sz) ~= 0 then
            print(('[fdiag] Address 0x%08X is not readable'):format(addr))
            return
        end
        local p = ffi.cast('uint8_t*', addr)
        print(('[fdiag] Memory at 0x%08X (%d bytes):'):format(addr, sz))
        for row = 0, sz - 1, 16 do
            local hex = {}
            local ascii = {}
            for j = 0, 15 do
                if row + j < sz then
                    table.insert(hex, ('%02X'):format(p[row + j]))
                    local b = p[row + j]
                    table.insert(ascii, (b >= 0x20 and b < 0x7F) and string.char(b) or '.')
                else
                    table.insert(hex, '  ')
                    table.insert(ascii, ' ')
                end
            end
            print(('  %04X: %s  %s'):format(row, table.concat(hex, ' '), table.concat(ascii)))
        end
        return
    end

    -----------------------------------------------------------------
    -- DUMPMSGCODE: Dump more code at message-related functions
    -- Usage: /fdiag dumpmsgcode [offset] [size]
    -- Default: dumps 0x1FF012 (insertion), 0x1FED70 (slot alloc),
    --          0x1FF2F0 (init), 0x1FD764 (constructor)
    -----------------------------------------------------------------
    if cmd == 'dumpmsgcode' then
        local custom_off = tonumber(args[3])
        local custom_size = tonumber(args[4]) or 128

        local targets = {}
        if custom_off then
            table.insert(targets, {custom_off, custom_size, 'custom'})
        else
            table.insert(targets, {0x1FF012, 128, 'insertion'})
            table.insert(targets, {0x1FED70, 128, 'slot_alloc'})
            table.insert(targets, {0x1FF2F0, 128, 'init'})
            table.insert(targets, {0x1FD764, 128, 'constructor'})
            table.insert(targets, {0x1FE09A, 64, 'refresh_setter_A'})
            table.insert(targets, {0x1FE970, 64, 'refresh_setter_B'})
        end

        for _, t in ipairs(targets) do
            local off, sz, name = t[1], t[2], t[3]
            local addr = ffximain_base + off
            print(('[fdiag] %s at FFXiMain+0x%X (0x%08X), %d bytes:'):format(name, off, addr, sz))
            local p = ffi.cast('uint8_t*', addr)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', p), sz) == 0 then
                for row = 0, sz - 1, 16 do
                    local hex = {}
                    for j = 0, 15 do
                        if row + j < sz then
                            table.insert(hex, ('%02X'):format(p[row + j]))
                        end
                    end
                    print(('[fdiag]   +%03X: %s'):format(row, table.concat(hex, ' ')))
                end
            else
                print('[fdiag]   (unreadable)')
            end
        end
        return
    end

    -----------------------------------------------------------------
    -- PATCHTYPE: Change a display entry's type byte while /flist is open.
    -- Usage: /fdiag patchtype <disp_index> <new_type>
    -- Example: /fdiag patchtype 1 3  (change disp[1] from type 2 to type 3)
    -----------------------------------------------------------------
    if cmd == 'patchtype' then
        local idx = tonumber(args[3])
        local new_type = tonumber(args[4])
        if not idx or not new_type then
            print('[fdiag] Usage: /fdiag patchtype <index> <type>')
            return
        end
        local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
        if flistmai == 0 then
            print('[fdiag] flistmai is NULL')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        local arr2_ptr = ffi.cast('uint32_t*', fm + 0x60)[0]
        local slots = ffi.cast('int32_t*', fm + 0x50)[0]
        if arr2_ptr == 0 or idx >= slots then
            print(('[fdiag] Invalid: arr2=0x%08X slots=%d idx=%d'):format(arr2_ptr, slots, idx))
            return
        end
        local entry = ffi.cast('uint8_t*', arr2_ptr + idx * 0x88)
        local old_type = entry[0]
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x88, 0x04, prot)
        entry[0] = new_type
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x88, prot[0], prot)
        local name = ffi.string(ffi.cast('char*', entry + 0x10), 15):gsub('%z+$', '')
        print(('[fdiag] disp[%d] type %d→%d name="%s"'):format(idx, old_type, new_type, name))
        -- Dump the patched entry
        local hex = {}
        for j = 0, 0x87 do table.insert(hex, ('%02X'):format(entry[j])) end
        print(('[fdiag] raw: %s'):format(table.concat(hex, ' ')))
        return
    end

    -----------------------------------------------------------------
    -- TESTMSG: Set entry[0xF8]=1 on first valid S3 entry, call populate,
    --          then dump display arrays looking for type 3 (cat 2) entries.
    -- Usage: /fdiag testmsg [index] — default=first valid entry
    -----------------------------------------------------------------
    if cmd == 'testmsg' then
        local s3_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
        if s3_ptr == 0 then
            print('[fdiag] Store 3 not initialized')
            return
        end
        local s3_count = ffi.cast('uint16_t*', s3_ptr + 0x132)[0]
        local s3_base = ffi.cast('uint8_t*', s3_ptr + 0x0A90)
        print(('[fdiag] Store 3: count=%d'):format(s3_count))

        -- Find target entry (specific index or first valid)
        local target_idx = tonumber(args[3]) or -1
        if target_idx < 0 then
            for ei = 0, s3_count do
                local ent = s3_base + ei * 0x100
                local valid = ffi.cast('uint32_t*', ent + 0x98)[0]
                if bit.band(valid, 1) ~= 0 then
                    target_idx = ei
                    break
                end
            end
        end
        if target_idx < 0 then
            print('[fdiag] No valid S3 entries found')
            return
        end

        -- Set [0xF8] = 1 on target entry
        local ent = s3_base + target_idx * 0x100
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', ent), 0x100, 0x04, prot)
        local old_f8 = ffi.cast('uint32_t*', ent + 0xF8)[0]
        ffi.cast('uint32_t*', ent + 0xF8)[0] = 1
        local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
        local name = ffi.string(ffi.cast('char*', ent + 0xA0), 15):gsub('%z+$', '')
        print(('[fdiag] S3[%d] set 0xF8=1 (was %d) flags=0x%08X name="%s"'):format(
            target_idx, old_f8, efl, name))
        ffi.C.VirtualProtect(ffi.cast('void*', ent), 0x100, prot[0], prot)

        -- Call populate_friend_data
        local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
        if flistmai == 0 then
            print('[fdiag] flistmai is NULL')
            return
        end
        local fm = ffi.cast('uint8_t*', flistmai)
        local populate = ffi.cast('void (__thiscall*)(void*, int)', ffximain_base + 0x1E9830)
        populate(ffi.cast('void*', flistmai), fm[0x58])

        -- Check if [0xF8] was consumed
        local f8_after = ffi.cast('uint32_t*', ent + 0xF8)[0]
        print(('[fdiag] After populate: S3[%d] 0xF8=%d (consumed=%s)'):format(
            target_idx, f8_after, f8_after == 0 and 'YES' or 'NO'))

        -- Dump ALL display entries looking for type 3
        local arr2_ptr = ffi.cast('uint32_t*', fm + 0x60)[0]
        local slots = ffi.cast('int32_t*', fm + 0x50)[0]
        print(('[fdiag] Display array: ptr=0x%08X slots=%d'):format(arr2_ptr, slots))
        if arr2_ptr ~= 0 and slots > 0 then
            local arr2 = ffi.cast('uint8_t*', arr2_ptr)
            local type_counts = {}
            for i = 0, slots - 1 do
                local entry = arr2 + i * 0x88
                local etype = entry[0]
                type_counts[etype] = (type_counts[etype] or 0) + 1
                -- Print all entries that are type 3 or have non-zero type
                if etype ~= 0 then
                    -- Try to extract name from display entry
                    local dname = ''
                    if ffi.C.IsBadReadPtr(ffi.cast('void*', entry + 4), 20) == 0 then
                        dname = ffi.string(ffi.cast('char*', entry + 4), 20):gsub('%z+$', '')
                    end
                    -- Also dump first 32 bytes for analysis
                    local hex = {}
                    for j = 0, 31 do table.insert(hex, ('%02X'):format(entry[j])) end
                    if etype == 3 then
                        print(('[fdiag]   *** TYPE 3 *** disp[%d]: %s name="%s"'):format(
                            i, table.concat(hex, ' '), dname))
                    elseif i < 10 or etype >= 3 then
                        print(('[fdiag]   disp[%d] type=%d: %s name="%s"'):format(
                            i, etype, table.concat(hex, ' '), dname))
                    end
                end
            end
            print('[fdiag] Type counts:')
            for t, c in pairs(type_counts) do
                print(('[fdiag]   type %d: %d entries'):format(t, c))
            end
        end

        -- Also dump render array for type 3
        local arr_ptr = ffi.cast('uint32_t*', fm + 0x5C)[0]
        if arr_ptr ~= 0 and slots > 0 then
            local arr = ffi.cast('uint8_t*', arr_ptr)
            local found_t3 = false
            for i = 0, slots - 1 do
                local rentry = arr + i * 0x54
                -- Check if this render entry references a type 3 display entry
                local disp_ptr = ffi.cast('uint32_t*', rentry + 0x48)[0]
                if disp_ptr ~= 0 then
                    local dp = ffi.cast('uint8_t*', disp_ptr)
                    if ffi.C.IsBadReadPtr(ffi.cast('void*', disp_ptr), 1) == 0 and dp[0] == 3 then
                        found_t3 = true
                        local hex = {}
                        for j = 0, 0x53 do table.insert(hex, ('%02X'):format(rentry[j])) end
                        print(('[fdiag]   render[%d] → type 3: %s'):format(i, table.concat(hex, ' ')))
                    end
                end
            end
            if not found_t3 then
                print('[fdiag] No type 3 entries in render array')
            end
        end

        -- Check sub_mgr / flmes state
        local sub_mgr = ffi.cast('uint32_t*', fm + 0x08)[0]
        print(('[fdiag] flistmai sub_mgr=0x%08X'):format(sub_mgr))
        if sub_mgr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', sub_mgr + 0x4C), 2) == 0 then
            local msg_count = ffi.cast('int16_t*', sub_mgr + 0x4C)[0]
            print(('[fdiag] flmes item_count=+0x4C=%d'):format(msg_count))
        end
        return
    end

    -----------------------------------------------------------------
    -- ADDMSGX: Configurable message injection for Phase 0 experiments
    -- Tests icon_type mapping (0/1/2 → NRM/FOK/FNO), body text,
    -- and color modes.
    -- Usage: /fdiag addmsgx <icon_type> [from] [subject] [body] [colormode]
    --   icon_type: 0, 1, 2
    --   colormode: "white" (0xFFFFFFFF) or "80" (0x80808080 retail)
    -----------------------------------------------------------------
    if cmd == 'addmsgx' then
        local icon_type = tonumber(args[3]) or 0
        local sender = args[4] or 'CharB'
        local subject = args[5] or 'Hello!'
        local body = args[6] or ''
        local colormode = args[7] or 'white'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]

        -- Allocate composite allocation (source + descriptor + buffers)
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local mem = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        -- Layout (composite allocation):
        -- 0x000: source struct (positions + ptrs)
        -- 0x040: descriptor (text_buf_ptr, max_len, timestamp)
        -- 0x080: text_buf (body text — potential body location)
        -- 0x0A0: sender text (15B)
        -- 0x0C0: subject text (15B)
        -- 0x100: extended body text (256B, for Exp 0d)
        local src = base
        local desc = base + 0x40
        local sender_buf = base + 0x0A0
        local subj_buf = base + 0x0C0

        for i = 0, math.min(#sender - 1, 14) do sender_buf[i] = string.byte(sender, i + 1) end
        for i = 0, math.min(#subject - 1, 14) do subj_buf[i] = string.byte(subject, i + 1) end

        -- Write body to text_buf at +0x80 (Exp 0c: text_buf as body)
        if #body > 0 then
            local body_buf = base + 0x80
            local body_len = math.min(#body, 200)
            for i = 0, body_len - 1 do body_buf[i] = string.byte(body, i + 1) end
            -- Increase max_len fields to accommodate body
            ffi.cast('uint32_t*', desc + 0x14)[0] = math.max(0x0F, body_len + 1)
            ffi.cast('uint32_t*', desc + 0x18)[0] = math.max(0x0F, body_len + 1)
            print(('[fdiag] Body at +0x80 (%dB): "%s"'):format(body_len, body))
        else
            ffi.cast('uint32_t*', desc + 0x14)[0] = 0x0F
            ffi.cast('uint32_t*', desc + 0x18)[0] = 0x0F
        end

        -- Descriptor
        ffi.cast('uint32_t*', desc)[0] = ba + 0x80        -- text_buf_ptr
        ffi.cast('uint32_t*', desc + 0x30)[0] = os.time()
        ffi.cast('uint32_t*', desc + 0x34)[0] = os.time()

        -- Source struct
        src[0] = 0x20; src[1] = 0x25; src[2] = 0x25; src[3] = 0x01; src[4] = 0x01
        ffi.cast('uint32_t*', src + 0x08)[0] = ba + 0x0A0  -- sender ptr
        ffi.cast('uint32_t*', src + 0x0C)[0] = ba + 0x0C0  -- subject ptr
        ffi.cast('uint32_t*', src + 0x18)[0] = ba + 0x40   -- descriptor ptr

        -- Call message_insert with specified icon_type
        local insert_fn = ffi.cast('bool (__cdecl*)(void*, int, int, int, void*)', ffximain_base + 0x1FF010)
        local ok, result = pcall(function()
            return insert_fn(ffi.cast('void*', msg_obj_ptr), icon_type, 0, 0, ffi.cast('void*', ba))
        end)
        if not ok then
            print(('[fdiag] INSERT ERROR: %s'):format(tostring(result)))
            return
        end

        local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
        if count_after <= count_before then
            print('[fdiag] Insert failed (count unchanged)')
            return
        end

        -- Patch colors based on colormode
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local entry_idx = count_after - 1
        local entry = ffi.cast('uint8_t*', render_arr + entry_idx * 0x54)
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, 0x04, prot)

        local text_color = (colormode == '80') and 0x80808080 or 0xFFFFFFFF
        ffi.cast('uint32_t*', entry + 0x0C)[0] = text_color  -- color[1] sender
        ffi.cast('uint32_t*', entry + 0x10)[0] = text_color  -- color[2] subject
        ffi.cast('uint32_t*', entry + 0x18)[0] = text_color  -- color[4] date
        entry[0] = 0x20  -- fix position[0]
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, prot[0], prot)

        -- Call vt[1] to update UI
        local vtable = ffi.cast('uint32_t*', ffi.cast('uint32_t*', obj)[0])
        local vt1 = ffi.cast('void (__thiscall*)(void*)', vtable[1])
        vt1(ffi.cast('void*', msg_obj_ptr))

        -- Dump data entry type field to verify icon_type mapping
        local data_arr = ffi.cast('uint32_t*', obj + 0x6C)[0]
        local type_val = 'N/A'
        if data_arr ~= 0 then
            local dentry = ffi.cast('uint8_t*', data_arr + entry_idx * 0x50)
            type_val = tostring(ffi.cast('uint32_t*', dentry + 0x48)[0])
        end

        print(('[fdiag] addmsgx: icon_type=%d type_lookup=%s from="%s" subj="%s" color=%s count=%d'):format(
            icon_type, type_val, sender, subject, colormode, count_after))

        -- Dump text_buf contents after insertion (did insertion overwrite our body?)
        if #body > 0 then
            local tbuf = ffi.cast('uint8_t*', ba + 0x80)
            local txt = {}
            for j = 0, math.min(#body, 30) do
                if tbuf[j] >= 0x20 and tbuf[j] < 0x7F then
                    table.insert(txt, string.char(tbuf[j]))
                elseif tbuf[j] == 0 and j > 0 then break
                end
            end
            print(('[fdiag] text_buf after insert: "%s"'):format(table.concat(txt)))
        end
        return
    end

    -----------------------------------------------------------------
    -- DUMPMSGSRC: Dump full source/descriptor for existing message entry.
    -- Follows text_buf_ptr from data_arr to find body location.
    -- Usage: /fdiag dumpmsgsrc [entry_index]
    -----------------------------------------------------------------
    if cmd == 'dumpmsgsrc' then
        local idx = tonumber(args[3]) or 0

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count = ffi.cast('uint32_t*', obj + 0x54)[0]
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local data_arr = ffi.cast('uint32_t*', obj + 0x6C)[0]
        local default_desc = ffi.cast('uint32_t*', obj + 0x74)[0]

        print(('[fdiag] msg_obj=0x%08X count=%d idx=%d'):format(msg_obj_ptr, count, idx))
        print(('[fdiag] render=0x%08X data=0x%08X default_desc=0x%08X'):format(render_arr, data_arr, default_desc))

        if idx >= count then
            print(('[fdiag] Index %d >= count %d'):format(idx, count))
            return
        end

        -- Dump data array entry (stride 0x50)
        if data_arr ~= 0 then
            local dentry = ffi.cast('uint8_t*', data_arr + idx * 0x50)
            print('[fdiag] === Data Array Entry ===')
            output(hexdump(dentry, 0x50, ('data_arr[%d]'):format(idx)))

            -- Follow text_buf_ptr at data_entry+0x08
            local tbuf_ptr = ffi.cast('uint32_t*', dentry + 0x08)[0]
            print(('[fdiag] text_buf_ptr (data+0x08) = 0x%08X'):format(tbuf_ptr))
            if tbuf_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', tbuf_ptr), 256) == 0 then
                -- Dump the text buffer and surrounding memory
                -- The text_buf is at composite+0x80, descriptor at composite+0x40
                -- So descriptor = text_buf_ptr - 0x40
                local desc_guess = tbuf_ptr - 0x40
                -- Source struct = text_buf_ptr - 0x80
                local src_guess = tbuf_ptr - 0x80

                print(('[fdiag] Guessed descriptor at 0x%08X, source at 0x%08X'):format(desc_guess, src_guess))

                -- Dump from source_struct through body area (0x100 bytes)
                if ffi.C.IsBadReadPtr(ffi.cast('void*', src_guess), 0x100) == 0 then
                    print('[fdiag] === Composite Allocation (source → descriptor → text_buf → sender → subject) ===')
                    output(hexdump(ffi.cast('uint8_t*', src_guess), 0x100, 'composite'))

                    -- Annotate key fields
                    local cp = ffi.cast('uint8_t*', src_guess)
                    local sender_ptr = ffi.cast('uint32_t*', cp + 0x08)[0]
                    local subj_ptr = ffi.cast('uint32_t*', cp + 0x0C)[0]
                    local desc_ptr = ffi.cast('uint32_t*', cp + 0x18)[0]
                    print(('[fdiag] source.sender_ptr=0x%08X subj_ptr=0x%08X desc_ptr=0x%08X'):format(
                        sender_ptr, subj_ptr, desc_ptr))

                    -- Read descriptor fields
                    local dp = ffi.cast('uint8_t*', desc_guess)
                    local tbp = ffi.cast('uint32_t*', dp + 0x00)[0]
                    local ml1 = ffi.cast('uint32_t*', dp + 0x14)[0]
                    local ml2 = ffi.cast('uint32_t*', dp + 0x18)[0]
                    local tsh = ffi.cast('uint32_t*', dp + 0x30)[0]
                    local ts = ffi.cast('uint32_t*', dp + 0x34)[0]
                    print(('[fdiag] desc: tbuf_ptr=0x%08X max_len1=%d max_len2=%d ts_hash=0x%X ts=%d'):format(
                        tbp, ml1, ml2, tsh, ts))

                    -- Read text at sender/subject offsets
                    local sn = ffi.string(ffi.cast('char*', src_guess + 0xA0), 15):gsub('%z+$', '')
                    local sb = ffi.string(ffi.cast('char*', src_guess + 0xC0), 15):gsub('%z+$', '')
                    local tb = ffi.string(ffi.cast('char*', src_guess + 0x80), 15):gsub('%z+$', '')
                    print(('[fdiag] sender="%s" subject="%s" textbuf="%s"'):format(sn, sb, tb))
                end

                -- Also dump beyond +0xD0 to look for body (Exp 0d)
                if ffi.C.IsBadReadPtr(ffi.cast('void*', src_guess + 0x100), 0x100) == 0 then
                    print('[fdiag] === Beyond +0x100 (Exp 0d exploration) ===')
                    output(hexdump(ffi.cast('uint8_t*', src_guess + 0x100), 0x80, 'beyond_0x100'))
                end
            end
        end

        -- Dump render array entry (stride 0x54)
        if render_arr ~= 0 then
            local rentry = ffi.cast('uint8_t*', render_arr + idx * 0x54)
            print('[fdiag] === Render Array Entry ===')
            output(hexdump(rentry, 0x54, ('render_arr[%d]'):format(idx)))

            -- Annotate
            for col = 0, 4 do
                local pos = rentry[col]
                local color = ffi.cast('uint32_t*', rentry + 0x08 + col * 4)[0]
                local dptr = ffi.cast('uint32_t*', rentry + 0x28 + col * 4)[0]
                local dstr = ''
                if dptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', dptr), 16) == 0 then
                    dstr = ffi.string(ffi.cast('char*', dptr), 15):gsub('%z+$', '')
                end
                print(('[fdiag]   col[%d] pos=%d color=0x%08X data=0x%08X "%s"'):format(
                    col, pos, color, dptr, dstr))
            end

            -- data_arr link
            local dal = ffi.cast('uint32_t*', rentry + 0x48)[0]
            print(('[fdiag]   data_arr_link=0x%08X misc=0x%08X flag=%d'):format(
                dal, ffi.cast('uint32_t*', rentry + 0x4C)[0], rentry[0x50]))
        end

        -- Dump default descriptor for comparison
        if default_desc ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', default_desc), 0x40) == 0 then
            print('[fdiag] === Default Descriptor (obj+0x74) ===')
            output(hexdump(ffi.cast('uint8_t*', default_desc), 0x40, 'default_desc'))
        end
        return
    end

    -----------------------------------------------------------------
    -- CLICKWATCH: Monitor profile server for connections when
    -- clicking a message (Exp 0g). Checks if any TCP conn is attempted.
    -- Usage: /fdiag clickwatch
    -- Just prints current server state — user clicks, then runs again.
    -----------------------------------------------------------------
    -----------------------------------------------------------------
    -- TESTCLICK: Create a message entry with a FULL COPY of the
    -- default descriptor (including sub-descriptor pointers).
    -- Tests if click-to-read works when desc has valid UI refs.
    -- Usage: /fdiag testclick [sender] [subject]
    -----------------------------------------------------------------
    if cmd == 'testclick' then
        local sender = args[3] or 'TestClick'
        local subject = args[4] or 'ClickMe'

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr == 0 then print('[fdiag] NULL msg_obj'); return end
        local obj = ffi.cast('uint8_t*', msg_obj_ptr)
        local count_before = ffi.cast('uint32_t*', obj + 0x54)[0]

        -- Get default descriptor
        local default_desc_ptr = ffi.cast('uint32_t*', obj + 0x74)[0]
        if default_desc_ptr == 0 then print('[fdiag] NULL default desc'); return end
        local default_desc = ffi.cast('uint8_t*', default_desc_ptr)

        -- Allocate composite allocation
        local MEM_COMMIT = 0x1000
        local PAGE_RW = 0x04
        local mem = ffi.C.VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_RW)
        if mem == nil then print('[fdiag] VirtualAlloc failed'); return end
        local base = ffi.cast('uint8_t*', mem)
        ffi.fill(base, 4096, 0)
        local ba = tonumber(ffi.cast('uint32_t', mem))

        -- Layout:
        -- 0x000: source struct (0x20 bytes)
        -- 0x040: descriptor (0xB0 bytes — full copy of default, 3 sections × 0x38)
        -- 0x100: text_buf (256 bytes for body text)
        -- 0x200: sender text (16 bytes)
        -- 0x210: subject text (16 bytes)
        local src = base
        local desc = base + 0x40
        local text_buf = base + 0x100
        local sender_buf = base + 0x200
        local subj_buf = base + 0x210

        -- Copy full default descriptor (0xB0 bytes covers 3 sections)
        local desc_copy_len = 0xB0
        if ffi.C.IsBadReadPtr(ffi.cast('void*', default_desc_ptr), desc_copy_len) == 0 then
            ffi.copy(desc, default_desc, desc_copy_len)
            print(('[fdiag] Copied %d bytes from default desc 0x%08X'):format(desc_copy_len, default_desc_ptr))
        else
            print('[fdiag] Cannot read default descriptor!')
            return
        end

        -- Override section 0 fields with our data
        ffi.cast('uint32_t*', desc)[0] = ba + 0x100       -- text_buf_ptr → our body buf
        ffi.cast('uint32_t*', desc + 0x14)[0] = 0x0F      -- max_len_1
        ffi.cast('uint32_t*', desc + 0x18)[0] = 0x0F      -- max_len_2
        ffi.cast('uint32_t*', desc + 0x30)[0] = os.time()  -- timestamp_hash
        ffi.cast('uint32_t*', desc + 0x34)[0] = os.time()  -- timestamp

        -- Write body text to text_buf
        local body_text = 'This is the message body from testclick!'
        for i = 0, math.min(#body_text - 1, 254) do
            text_buf[i] = string.byte(body_text, i + 1)
        end

        -- Write sender/subject
        for i = 0, math.min(#sender - 1, 14) do sender_buf[i] = string.byte(sender, i + 1) end
        for i = 0, math.min(#subject - 1, 14) do subj_buf[i] = string.byte(subject, i + 1) end

        -- Source struct
        src[0] = 0x20; src[1] = 0x25; src[2] = 0x25; src[3] = 0x01; src[4] = 0x01
        ffi.cast('uint32_t*', src + 0x08)[0] = ba + 0x200  -- sender ptr
        ffi.cast('uint32_t*', src + 0x0C)[0] = ba + 0x210  -- subject ptr
        ffi.cast('uint32_t*', src + 0x18)[0] = ba + 0x40   -- descriptor ptr

        -- Call message_insert
        local insert_fn = ffi.cast('bool (__cdecl*)(void*, int, int, int, void*)', ffximain_base + 0x1FF010)
        local ok, result = pcall(function()
            return insert_fn(ffi.cast('void*', msg_obj_ptr), 0, 0, 0, ffi.cast('void*', ba))
        end)
        if not ok then
            print(('[fdiag] INSERT ERROR: %s'):format(tostring(result)))
            return
        end

        local count_after = ffi.cast('uint32_t*', obj + 0x54)[0]
        if count_after <= count_before then
            print('[fdiag] Insert failed (count unchanged)')
            return
        end

        -- Patch colors to white
        local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
        local entry_idx = count_after - 1
        local entry = ffi.cast('uint8_t*', render_arr + entry_idx * 0x54)
        local prot = ffi.new('uint32_t[1]')
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, 0x04, prot)
        ffi.cast('uint32_t*', entry + 0x0C)[0] = 0xFFFFFFFF
        ffi.cast('uint32_t*', entry + 0x10)[0] = 0xFFFFFFFF
        ffi.cast('uint32_t*', entry + 0x18)[0] = 0xFFFFFFFF
        entry[0] = 0x20
        ffi.C.VirtualProtect(ffi.cast('void*', entry), 0x54, prot[0], prot)

        -- Call vt[1] to update UI
        local vtable = ffi.cast('uint32_t*', ffi.cast('uint32_t*', obj)[0])
        local vt1 = ffi.cast('void (__thiscall*)(void*)', vtable[1])
        vt1(ffi.cast('void*', msg_obj_ptr))

        -- Dump the descriptor's sub-desc pointers to verify they were copied
        print(('[fdiag] testclick: entry=%d from="%s" subj="%s"'):format(entry_idx, sender, subject))
        print(('[fdiag] desc+0x04=0x%08X desc+0x08=0x%08X desc+0x3C=0x%08X'):format(
            ffi.cast('uint32_t*', desc + 0x04)[0],
            ffi.cast('uint32_t*', desc + 0x08)[0],
            ffi.cast('uint32_t*', desc + 0x3C)[0]))
        print('[fdiag] Click this message to test native click-to-read!')
        return
    end

    if cmd == 'clickwatch' then
        print('[fdiag] Click a message entry, then check profile_test_server.py logs.')
        print('[fdiag] If no new connection appears in server logs, client does NOT')
        print('[fdiag] make a network call on click (matching retail protocol doc).')
        print('[fdiag] Also monitoring msg_obj state...')

        local msg_obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62EE1C)[0]
        if msg_obj_ptr ~= 0 then
            local obj = ffi.cast('uint8_t*', msg_obj_ptr)
            local count = ffi.cast('uint32_t*', obj + 0x54)[0]
            local visible = ffi.cast('uint16_t*', obj + 0x20)[0]
            local refresh = obj[0x64]
            print(('[fdiag] msg_obj: count=%d visible=%d refresh_flag=%d'):format(count, visible, refresh))
        end
        return
    end

    -----------------------------------------------------------------
    -- SCANPUMP: Scan per-frame sub-functions for descriptor array refs
    -- Searches for references to descriptor base, stride 0x338,
    -- and calls to known driver functions
    -----------------------------------------------------------------
    if cmd == 'scanpump' then
        local scan_size = tonumber(args[3]) or 512
        print('[fdiag] === NATIVE PUMP SCAN ===')
        print(('[fdiag] polcore base: 0x%08X'):format(polcore_base))

        local desc_base_addr = polcore_base + 0x404AD0
        local generic_driver = polcore_base + 0x1E5D0
        local callerB_driver = polcore_base + 0x22260

        -- Encode 4-byte LE values to search for
        local function encode_le32(val)
            return {
                bit.band(val, 0xFF),
                bit.band(bit.rshift(val, 8), 0xFF),
                bit.band(bit.rshift(val, 16), 0xFF),
                bit.band(bit.rshift(val, 24), 0xFF)
            }
        end

        local desc_bytes = encode_le32(desc_base_addr)
        local stride_bytes_32 = encode_le32(0x338)
        local stride_bytes_16 = { 0x38, 0x03 }

        -- Sub-functions to scan
        local targets = {
            { off = 0x47150,  name = 'mode0_fn1' },
            { off = 0x47340,  name = 'mode0_fn2' },
            { off = 0x470E0,  name = 'mode0_fn3' },
            { off = 0x46350,  name = 'common_crypto' },
            { off = 0x46EE0,  name = 'common_fn2' },
            { off = 0x126B0,  name = 'common_fn3' },
            { off = 0x448A0,  name = 'per_frame' },
            { off = 0x44A50,  name = 'SM_func' },
            { off = 0x1E5D0,  name = 'generic_driver' },
            { off = 0x22260,  name = 'callerB_driver' },
        }

        for _, t in ipairs(targets) do
            local addr = polcore_base + t.off
            local p = ffi.cast('uint8_t*', addr)
            if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), scan_size) ~= 0 then
                print(('[fdiag] +0x%05X %-16s UNREADABLE'):format(t.off, t.name))
            else
                local hits = {}

                -- Scan for descriptor base reference
                for i = 0, scan_size - 4 do
                    if p[i] == desc_bytes[1] and p[i+1] == desc_bytes[2]
                       and p[i+2] == desc_bytes[3] and p[i+3] == desc_bytes[4] then
                        table.insert(hits, ('+%03X: DESC_BASE (0x%08X)'):format(i, desc_base_addr))
                    end
                end

                -- Scan for stride 0x338 as 32-bit immediate
                for i = 0, scan_size - 4 do
                    if p[i] == stride_bytes_32[1] and p[i+1] == stride_bytes_32[2]
                       and p[i+2] == stride_bytes_32[3] and p[i+3] == stride_bytes_32[4] then
                        table.insert(hits, ('+%03X: STRIDE_32 (0x338)'):format(i))
                    end
                end

                -- Scan for stride 0x338 as 16-bit (in ADD/LEA with 16-bit disp)
                for i = 0, scan_size - 2 do
                    if p[i] == stride_bytes_16[1] and p[i+1] == stride_bytes_16[2] then
                        -- Check it's not part of the 32-bit stride we already found
                        local is_32 = false
                        if i >= 2 and p[i-2] == 0 and p[i-1] == 0 then is_32 = true end
                        if not is_32 then
                            table.insert(hits, ('+%03X: STRIDE_16? (38 03)'):format(i))
                        end
                    end
                end

                -- Scan for CALL to generic driver (E8 + rel32)
                for i = 0, scan_size - 5 do
                    if p[i] == 0xE8 then
                        local rel = p[i+1] + p[i+2]*256 + p[i+3]*65536 + p[i+4]*16777216
                        if rel >= 0x80000000 then rel = rel - 0x100000000 end
                        local target_addr = addr + i + 5 + rel
                        if target_addr == generic_driver then
                            table.insert(hits, ('+%03X: CALL generic_driver (+0x1E5D0)'):format(i))
                        elseif target_addr == callerB_driver then
                            table.insert(hits, ('+%03X: CALL callerB_driver (+0x22260)'):format(i))
                        end
                    end
                end

                -- Scan for CALL to any of the other known functions
                local known_fns = {
                    [polcore_base + 0x47150] = '+0x47150',
                    [polcore_base + 0x47340] = '+0x47340',
                    [polcore_base + 0x470E0] = '+0x470E0',
                    [polcore_base + 0x46350] = '+0x46350',
                    [polcore_base + 0x46EE0] = '+0x46EE0',
                    [polcore_base + 0x126B0] = '+0x126B0',
                    [polcore_base + 0x448A0] = '+0x448A0',
                    [polcore_base + 0x44A50] = '+0x44A50',
                }
                for i = 0, scan_size - 5 do
                    if p[i] == 0xE8 then
                        local rel = p[i+1] + p[i+2]*256 + p[i+3]*65536 + p[i+4]*16777216
                        if rel >= 0x80000000 then rel = rel - 0x100000000 end
                        local target_addr = addr + i + 5 + rel
                        if known_fns[target_addr] then
                            table.insert(hits, ('+%03X: CALL %s'):format(i, known_fns[target_addr]))
                        end
                    end
                end

                -- Report
                if #hits > 0 then
                    print(('[fdiag] +0x%05X %-16s ** %d HITS **'):format(t.off, t.name, #hits))
                    for _, h in ipairs(hits) do
                        print('    ' .. h)
                    end
                else
                    print(('[fdiag] +0x%05X %-16s (no matches in %dB)'):format(t.off, t.name, scan_size))
                end
            end
        end

        -- Also scan wider: look for ANY function in polcore that refs descriptor base
        -- Scan the code section (functions go up to ~+0x4A000)
        print('[fdiag] --- Broad scan: polcore code for DESC_BASE refs ---')
        local code_start = polcore_base + 0x1000  -- skip PE header
        local code_size = 0x4A000
        local code_p = ffi.cast('uint8_t*', code_start)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', code_start), code_size) == 0 then
            local found = 0
            for i = 0, code_size - 4 do
                if code_p[i] == desc_bytes[1] and code_p[i+1] == desc_bytes[2]
                   and code_p[i+2] == desc_bytes[3] and code_p[i+3] == desc_bytes[4] then
                    -- Find which function this belongs to (nearest lower target)
                    local fn_off = code_start + i - polcore_base
                    print(('  [+0x%05X] refs DESC_BASE'):format(fn_off))
                    found = found + 1
                end
            end
            if found == 0 then
                print('  (no DESC_BASE refs in first 0x50000 bytes)')
            else
                print(('  Total: %d references'):format(found))
            end
        else
            print('  Code region unreadable')
        end

        -- Scan for stride 0x338 references in code
        print('[fdiag] --- Broad scan: polcore code for 0x338 stride ---')
        if ffi.C.IsBadReadPtr(ffi.cast('void*', code_start), code_size) == 0 then
            local found = 0
            for i = 0, code_size - 4 do
                if code_p[i] == stride_bytes_32[1] and code_p[i+1] == stride_bytes_32[2]
                   and code_p[i+2] == stride_bytes_32[3] and code_p[i+3] == stride_bytes_32[4] then
                    local fn_off = code_start + i - polcore_base
                    print(('  [+0x%05X] refs 0x338 (32-bit)'):format(fn_off))
                    found = found + 1
                end
            end
            -- Also scan for 0x338 as 16-bit immediate (common in ADD reg, imm16)
            for i = 0, code_size - 2 do
                if code_p[i] == 0x38 and code_p[i+1] == 0x03 then
                    -- Filter: next two bytes should NOT be 00 00 (that's a 32-bit match)
                    local is_32 = (i + 2 < code_size and code_p[i+2] == 0 and i + 3 < code_size and code_p[i+3] == 0)
                    if not is_32 then
                        -- Check if preceded by an opcode that takes imm16 (81, 69, etc)
                        -- Just report all for now
                        local fn_off = code_start + i - polcore_base
                        -- Only report if nearby a known instruction (ADD/SUB/CMP/LEA patterns)
                        if i > 0 then
                            local prev = code_p[i-1]
                            -- 81 xx = ADD/SUB/CMP r/m32, imm32 (but we're matching 16-bit part)
                            -- 66 81 = ADD/SUB with 16-bit operand prefix
                            -- Actually just check: is previous byte part of ModRM for 81?
                            if i > 1 and code_p[i-2] == 0x81 then
                                print(('  [+0x%05X] refs 0x338 (imm32 in 81-grp)'):format(fn_off - 2))
                                found = found + 1
                            end
                        end
                    end
                end
            end
            if found == 0 then
                print('  (no 0x338 refs found)')
            else
                print(('  Total: %d references'):format(found))
            end
        end

        return
    end

    print('[fdiag] Done.')
end

ashita.events.register('command', 'fdiag_cmd', function(e)
    local args = e.command:args()
    if #args == 0 or args[1] ~= '/fdiag' then return end
    e.blocked = true
    dispatch_fdiag(args)
end)

-- HTTP request handler
handle_http = function(path)
    if path == '/ping' then return 'pong' end

    if path == '/reload' then
        AshitaCore:GetChatManager():QueueCommand(1, '/addon reload fdiag')
        return 'reloading...'
    end

    if path == '/shutdown' then
        AshitaCore:GetChatManager():QueueCommand(1, '/shutdown')
        return 'shutting down'
    end

    -- URL decode %XX sequences
    local decoded = path:gsub('%%(%x%x)', function(h)
        return string.char(tonumber(h, 16))
    end)

    -- Parse /exec/cmd/arg1/arg2...
    local parts = {}
    for part in decoded:gmatch('[^/]+') do
        table.insert(parts, part)
    end

    if parts[1] == 'exec' and #parts >= 2 then
        local fargs = {'/fdiag'}
        for i = 2, #parts do
            table.insert(fargs, parts[i])
        end

        _capture_mode = true
        _capture_lines = {}
        local ok, err = pcall(dispatch_fdiag, fargs)
        _capture_mode = false

        if not ok then
            table.insert(_capture_lines, '[fdiag] ERROR: ' .. tostring(err))
        end
        return table.concat(_capture_lines, '\n')
    end

    -- /cmd/<command> — queue any game command (e.g., /cmd/shutdown)
    if parts[1] == 'cmd' and #parts >= 2 then
        local cmd_str = '/' .. table.concat(parts, ' ', 2)
        AshitaCore:GetChatManager():QueueCommand(1, cmd_str)
        return 'queued: ' .. cmd_str
    end

    if path == '/screenshot' then
        return '__BINARY_BMP__'
    end

    -- /dumpmod/<name> — fast bulk dump of a loaded module to disk.
    -- Uses PE header SizeOfImage; writes runtime memory (with .text unpacked,
    -- etc.) directly in 64KB chunks. Returns the output path.
    if parts[1] == 'dumpmod' and #parts >= 2 then
        local modname = parts[2]
        local handle = ffi.C.GetModuleHandleA(modname)
        if handle == 0 then
            return '[fdiag] dumpmod: module not loaded: ' .. modname
        end
        local base = tonumber(handle)

        -- Read DOS header e_lfanew (offset 0x3C) to find PE header
        if ffi.C.IsBadReadPtr(ffi.cast('void*', base + 0x3C), 4) ~= 0 then
            return '[fdiag] dumpmod: cannot read e_lfanew at base+0x3C'
        end
        local e_lfanew = tonumber(ffi.cast('uint32_t*', base + 0x3C)[0])

        -- IMAGE_OPTIONAL_HEADER.SizeOfImage is at:
        --   base + e_lfanew + 4 (PE\0\0 sig) + 20 (IMAGE_FILE_HEADER) + 0x38 (offset within IMAGE_OPTIONAL_HEADER32)
        --   = base + e_lfanew + 0x50
        local soi_addr = base + e_lfanew + 0x50
        if ffi.C.IsBadReadPtr(ffi.cast('void*', soi_addr), 4) ~= 0 then
            return '[fdiag] dumpmod: cannot read SizeOfImage'
        end
        local size = tonumber(ffi.cast('uint32_t*', soi_addr)[0])
        if size == 0 or size > 0x10000000 then  -- 256MB sanity
            return string.format('[fdiag] dumpmod: implausible SizeOfImage: %d', size)
        end

        local out_dir = AshitaCore:GetInstallPath() .. 'dumps\\'
        -- Ensure dir exists (no-op if already there).
        pcall(function()
            os.execute('mkdir "' .. out_dir:sub(1, -2) .. '" >nul 2>&1')
        end)

        local base_name = modname:lower():gsub('%.dll$', '')
        local stamp     = os.date('%Y-%m-%d_%H%M%S')
        local out_path  = string.format('%s%s_dumped_%s_%08X.bin', out_dir, base_name, stamp, base)

        local f, ferr = io.open(out_path, 'wb')
        if not f then
            return '[fdiag] dumpmod: failed to open output file: ' .. tostring(ferr)
        end

        local p = ffi.cast('uint8_t*', base)
        local CHUNK = 0x10000  -- 64 KB
        local written = 0
        while written < size do
            local n = math.min(CHUNK, size - written)
            -- Skip pages that aren't readable rather than crashing.
            if ffi.C.IsBadReadPtr(ffi.cast('void*', base + written), n) == 0 then
                f:write(ffi.string(p + written, n))
            else
                f:write(string.rep('\0', n))
            end
            written = written + n
        end
        f:close()

        return string.format('[fdiag] dumpmod: %s base=0x%08X size=%d (%.2f MB) -> %s',
            modname, base, size, size / (1024 * 1024), out_path)
    end

    -- /rawread/ADDR/LEN — return raw bytes for big bulk reads (max 4MB/call).
    -- Same memory access as readabs but no formatted output overhead.
    if parts[1] == 'rawread' and #parts >= 3 then
        local addr = tonumber(parts[2])
        local len  = tonumber(parts[3])
        if not addr or not len or len <= 0 or len > 0x400000 then
            return '[fdiag] rawread: bad args (addr, len; max 4MB)'
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), len) ~= 0 then
            return string.format('[fdiag] rawread: unreadable at 0x%08X +%d', addr, len)
        end
        return '__BINARY_RAW__' .. ffi.string(ffi.cast('char*', addr), len)
    end

    -- /pokedword/ADDR/HEXVAL — write a single dword to ADDR (bypasses page prot).
    -- Used for live diffing candidate flags without a build/redeploy cycle.
    if parts[1] == 'pokedword' and #parts >= 3 then
        local addr = tonumber(parts[2])
        local val  = tonumber(parts[3])
        if not addr or not val then
            return '[fdiag] pokedword: bad args (addr, val as decimal or 0xHEX)'
        end
        if ffi.C.IsBadReadPtr(ffi.cast('void*', addr), 4) ~= 0 then
            return string.format('[fdiag] pokedword: unreadable at 0x%08X', addr)
        end
        local old = tonumber(ffi.cast('uint32_t*', addr)[0])
        -- Change page protection to RW via VirtualProtect
        ffi.cdef([[int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);]])
        local oldProt = ffi.new('unsigned long[1]', 0)
        ffi.C.VirtualProtect(ffi.cast('void*', addr), 4, 0x40, oldProt)  -- PAGE_EXECUTE_READWRITE
        ffi.cast('uint32_t*', addr)[0] = val
        ffi.C.VirtualProtect(ffi.cast('void*', addr), 4, oldProt[0], oldProt)
        return string.format('[fdiag] pokedword: 0x%08X: 0x%08X -> 0x%08X', addr, old, val)
    end

    return 'Endpoints: /ping, /reload, /exec/<cmd>/<args...>, /cmd/<command>, /screenshot, /dumpmod/<name>, /rawread/ADDR/LEN, /pokedword/ADDR/VAL'
end

-- Screenshot capture using D3D8 (adapted from observer addon)
local d3d8_ok, d3d8 = pcall(require, 'd3d8')
local screenshot_cache = nil
local screenshot_cache_time = 0

local function capture_screenshot_bmp()
    if not d3d8_ok then return nil end
    local now = os.clock()
    if screenshot_cache and (now - screenshot_cache_time) < 1 then
        return screenshot_cache
    end

    local dev = d3d8.get_device()
    if dev == nil then return nil end

    local hr, backbuf = dev:GetBackBuffer(0, 0)
    if hr ~= ffi.C.S_OK then return nil end

    local hr2, desc = backbuf:GetDesc()
    if hr2 ~= ffi.C.S_OK then backbuf:Release(); return nil end

    local w = tonumber(desc.Width)
    local h = tonumber(desc.Height)

    local hr3, surface = dev:CreateImageSurface(w, h, desc.Format)
    if hr3 ~= ffi.C.S_OK then backbuf:Release(); return nil end

    local hr4 = dev:CopyRects(backbuf, nil, 0, surface, nil)
    backbuf:Release()
    if hr4 ~= ffi.C.S_OK then surface:Release(); return nil end

    local hr5, lock = surface:LockRect(nil, ffi.C.D3DLOCK_READONLY)
    if hr5 ~= ffi.C.S_OK then surface:Release(); return nil end

    local pitch = tonumber(lock.Pitch)
    local pBits = ffi.cast('uint8_t*', lock.pBits)

    local row_stride = bit.band(w * 3 + 3, bit.bnot(3))
    local pixel_size = row_stride * h
    local file_size = 54 + pixel_size
    local buf = ffi.new('uint8_t[?]', file_size)

    -- BMP header
    buf[0] = 0x42; buf[1] = 0x4D
    local function w32(off, val)
        buf[off] = bit.band(val, 0xFF)
        buf[off+1] = bit.band(bit.rshift(val, 8), 0xFF)
        buf[off+2] = bit.band(bit.rshift(val, 16), 0xFF)
        buf[off+3] = bit.band(bit.rshift(val, 24), 0xFF)
    end
    local function w16(off, val)
        buf[off] = bit.band(val, 0xFF)
        buf[off+1] = bit.band(bit.rshift(val, 8), 0xFF)
    end
    w32(2, file_size); w32(10, 54); w32(14, 40)
    w32(18, w); w32(22, h); w16(26, 1); w16(28, 24)

    for y = 0, h - 1 do
        local src = pBits + y * pitch
        local dst = buf + 54 + (h - 1 - y) * row_stride
        for x = 0, w - 1 do
            local s = src + x * 4
            local d = dst + x * 3
            d[0] = s[0]; d[1] = s[1]; d[2] = s[2]
        end
    end

    surface:UnlockRect()
    surface:Release()

    screenshot_cache = ffi.string(buf, file_size)
    screenshot_cache_time = now
    return screenshot_cache
end

-- Pump connection driver in d3d_present (every frame)
ashita.events.register('d3d_present', 'fdiag_pump', function()
    if not pump_active then return end
    pump_count = pump_count + 1

    -- Call the driver: int __cdecl driver(int slot_index)
    local driver = ffi.cast('int (__cdecl*)(int)', pump_driver_addr)
    local ret = driver(pump_slot)

    -- Monitor descriptor changes
    local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
    if polcore_base ~= 0 and pump_slot >= 0 and pump_slot <= 3 then
        local slot_addr = polcore_base + 0x404AD0 + pump_slot * 0x338
        local p = ffi.cast('uint8_t*', slot_addr)
        local mode = p[8]
        local state = p[9]

        -- Report on mode/state changes
        if mode ~= pump_last_mode or state ~= pump_last_state then
            local sock = tonumber(ffi.cast('uint32_t*', slot_addr + 4)[0])
            print(('[fdiag] PUMP[%d]: ret=%d mode=%d→%d state=%d→%d sock=0x%08X'):format(
                pump_count, ret, pump_last_mode, mode, pump_last_state, state, sock))
            pump_last_mode = mode
            pump_last_state = state
        end

        -- Report every 120 frames (2 sec) regardless
        if pump_count % 120 == 0 then
            local sock = tonumber(ffi.cast('uint32_t*', slot_addr + 4)[0])
            print(('[fdiag] PUMP[%d]: ret=%d mode=%d state=%d sock=0x%08X'):format(
                pump_count, ret, mode, state, sock))
        end

        -- Stop if mode reaches done state (6+) or byte[0] becomes 0
        if p[0] == 0 then
            print(('[fdiag] PUMP[%d]: Slot freed (byte[0]=0). Stopping.'):format(pump_count))
            pump_active = false

            -- Auto-sync: populate status tables and enrich Store 3.
            -- Native mode 7 post-processing already handled:
            --   Array 1 → Array 2 (basic fields + nickname)
            --   pop_count/enrichment → Store 3 (accid, flags, nickname)
            -- We just need to fill in the status tables (charname, zone, gate)
            -- and re-enrich Store 3 to pick up that data.
            local ok, err = pcall(function()
                dispatch_fdiag({'/fdiag', 'syncstatus'})
            end)
            if not ok then
                print(('[fdiag] Auto-sync error: %s'):format(tostring(err)))
            end

            -- Signal keepalive that this cycle is done
            if keepalive_busy then
                keepalive_busy = false
                keepalive_frame_count = 0
                print('[fdiag] Keepalive: friend list updated')
            end

            return
        end
    end

    -- Stop conditions
    if pump_count >= pump_max then
        print(('[fdiag] PUMP: Max frames (%d) reached. Stopping.'):format(pump_max))
        pump_active = false
        if keepalive_busy then
            keepalive_busy = false
            keepalive_frame_count = 0
            print('[fdiag] Keepalive: pump timed out, will retry next cycle')
        end
    end
end)

-- Keepalive: periodically fire CallerB to refresh friend data from server
ashita.events.register('d3d_present', 'fdiag_keepalive', function()
    if not keepalive_active then return end
    if keepalive_busy then return end  -- wait for current pump to finish

    keepalive_frame_count = keepalive_frame_count + 1
    local target_frames = keepalive_interval * 60  -- ~60 fps
    if keepalive_frame_count < target_frames then return end

    -- Time to refresh: initiate CallerB + pump
    local ok, err = pcall(function()
        local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
        if polcore_base == 0 then return end

        -- Check sockaddr is set (required for connection)
        local sa = ffi.cast('uint16_t*', polcore_base + 0x404AB8)
        if sa[0] == 0 then
            print('[fdiag] Keepalive: sockaddr not set, skipping')
            keepalive_frame_count = 0
            return
        end

        -- Check no pump already running
        if pump_active then
            keepalive_frame_count = 0
            return
        end

        -- Initiate CallerB
        local callerb = ffi.cast('int (__cdecl*)()', polcore_base + 0x22210)
        local slot = callerb()
        if slot < 0 then
            print('[fdiag] Keepalive: no free slot, retrying next cycle')
            keepalive_frame_count = 0
            return
        end

        -- Disable crypto on slot (BF key not initialized for CallerB slots)
        local slot_addr = polcore_base + 0x404AD0 + slot * 0x338
        local p = ffi.cast('uint8_t*', slot_addr)
        p[0x0B] = 0

        -- Start pump (CallerB driver at +0x22260)
        pump_driver_addr = polcore_base + 0x22260
        pump_slot = slot
        pump_count = 0
        pump_last_mode = -1
        pump_last_state = -1
        pump_active = true
        keepalive_busy = true

        print(('[fdiag] Keepalive: CallerB → slot %d, pumping...'):format(slot))
    end)
    if not ok then
        print(('[fdiag] Keepalive error: %s'):format(tostring(err)))
        keepalive_frame_count = 0
    end
end)

-- Per-frame gate keeper: directly write gate byte + marker to Store 3 entries.
-- The native game loop clears these fields. Instead of calling the heavy enrichment
-- function (which does struct_copy with overflow risk), we write targeted fields directly.
-- Runs every frame for maximum reliability.
ashita.events.register('d3d_beginscene', 'fdiag_gate_keeper', function()
    if not gate_keeper_active then return end

    local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
    if ffximain_base == 0 then return end
    local store3_ptr = ffi.cast('uint32_t*', ffximain_base + 0x4DD600)[0]
    if store3_ptr == 0 then return end

    local s3_count = ffi.cast('uint16_t*', ffi.cast('uint8_t*', store3_ptr) + 0x132)[0]
    if s3_count == 0 then return end

    local s3_base = store3_ptr + 0x0A90

    for ei = 0, s3_count do
        local ent = ffi.cast('uint8_t*', s3_base + ei * 0x100)
        local efl = ffi.cast('uint32_t*', ent + 0x08)[0]
        if bit.band(efl, 0x2000) ~= 0 then
            -- Restore marker (gate bits: b0=charname, b6=zone)
            ffi.cast('uint32_t*', ent + 0xB0)[0] = 0x00000041
            -- Restore gate byte (Check3: b0=charname, b6=zone)
            ent[0xFC] = 0x41
            -- Ensure entry+0xF8 stays zero (nonzero → Cat2/type3)
            ent[0xF8] = 0
            -- Set game type = 1 (FFXI) in flags_hi bits 1-10
            local fhi = ffi.cast('uint16_t*', ent + 0x0C)
            fhi[0] = bit.bor(bit.band(fhi[0], 0xF800), 0x0002)
            -- Copy zone ID from +0xE0 to +0xD8 (display reads zone name from +0xD8)
            -- Mask off 0x4000 (XI flag) so zone name lookup gets raw zone ID
            local zid = ffi.cast('uint16_t*', ent + 0xE0)[0]
            if zid ~= 0 then ffi.cast('uint16_t*', ent + 0xD8)[0] = bit.band(zid, 0x3FFF) end
        end
    end

    -- Also inject XI icon into render buffers (type=2) every frame
    -- Only for category 5 (Type 5 = fully online) entries
    local flistmai = ffi.cast('uint32_t*', ffximain_base + 0x62E9E4)[0]
    if flistmai ~= 0 then
        local fm = ffi.cast('uint8_t*', flistmai)
        local slots = ffi.cast('int32_t*', fm + 0x50)[0]
        local render_base = ffi.cast('uint32_t*', flistmai + 0x5C)[0]
        local icon_ptr_ptr = ffi.cast('uint32_t*', flistmai + 0x8C)[0]
        if render_base ~= 0 and icon_ptr_ptr ~= 0 and
           ffi.C.IsBadReadPtr(ffi.cast('void*', icon_ptr_ptr), 4) == 0 then
            local icon_array_base = ffi.cast('uint32_t*', icon_ptr_ptr)[0]
            if icon_array_base ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', icon_array_base), 4) == 0 then
                local xi_icon = ffi.cast('uint32_t*', icon_array_base)[0]
                for ri = 0, math.min(slots, 63) - 1 do
                    local rb = ffi.cast('uint8_t*', render_base + ri * 0x54)
                    local disp_ptr = ffi.cast('uint32_t*', rb + 0x48)[0]
                    if disp_ptr ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', disp_ptr), 1) == 0 then
                        local category = ffi.cast('uint8_t*', disp_ptr)[0]
                        if category == 5 then
                            rb[2] = 0x0E
                            ffi.cast('uint32_t*', rb + 0x10)[0] = 0x80808080
                            ffi.cast('uint32_t*', rb + 0x30)[0] = xi_icon
                        end
                    end
                end
            end
        end
    end
end)

-- Per-frame flist keep-alive: re-add titlehan/flmes to WM periodically
fdiag_keep_flist = false
fdiag_keep_flist_count = 0
ashita.events.register('d3d_present', 'fdiag_flist_keepalive', function()
    if not fdiag_keep_flist then return end
    fdiag_keep_flist_count = (fdiag_keep_flist_count or 0) + 1
    if fdiag_keep_flist_count % 30 ~= 0 then return end  -- every 30 frames (~0.5 sec)
    local ok, err = pcall(function()
        local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
        if ffximain_base == 0 then return end
        local wm_addr = ffximain_base + 0x5ECB98
        local show_menu = ffi.cast('int (__thiscall*)(void*, const char*, int, int)', ffximain_base + 0x15D080)
        if fdiag_flist_th_str then
            show_menu(ffi.cast('void*', wm_addr), fdiag_flist_th_str, 1, 0)
        end
        if fdiag_flist_fl_str then
            show_menu(ffi.cast('void*', wm_addr), fdiag_flist_fl_str, 1, 0)
        end
    end)
    if not ok then
        print('[fdiag] keep-alive error: ' .. tostring(err))
        fdiag_keep_flist = false
    end
end)

-- Auto-bind flmes disabled — show_menu breaks /flist UI
-- Messages are accessed via Communications menu, not /flist

-- Handle render: update overlay text each frame
ashita.events.register('d3d_present', 'fdiag_handlerender', function()
    if not handle_render_active then return end
    -- Font update happens via fonts library automatically
end)

-- MSG_INJECT: Per-frame message injection into native msg_obj
-- Injects after the game rebuilds display arrays each frame.
-- Enabled by /fdiag msginject on, disabled by /fdiag msginject off
-- GLOBALS (shared between command handler and event handler)
msginject_active = false
msginject_sender = 'CharB'
msginject_subject = 'Friend req'
msginject_date = '04/02'
msginject_textbuf = nil
msginject_textbuf_addr = 0

local msginject_dbg_count = 0
ashita.events.register('d3d_present', 'fdiag_msginject', function()
    if not msginject_active then return end

    local ok2, err2 = pcall(function()

    local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
    if ffximain_base == 0 then return end

    local obj_ptr = ffi.cast('uint32_t*', ffximain_base + 0x62FF94)[0]
    if obj_ptr == 0 then return end
    local obj = ffi.cast('uint8_t*', obj_ptr)
    if ffi.cast('uint32_t*', obj + 0x08)[0] == 0 then return end

    local render_arr = ffi.cast('uint32_t*', obj + 0x68)[0]
    if render_arr == 0 then return end

    -- Always write our entry at FIXED index 1 (after template at 0)
    local rend = ffi.cast('uint8_t*', render_arr + 1 * 0x54)
    if ffi.C.IsBadWritePtr(ffi.cast('void*', rend), 0x54) ~= 0 then return end

    -- Allocate text buffers once
    if msginject_textbuf == nil then
        msginject_textbuf = ffi.C.VirtualAlloc(nil, 256, 0x3000, 0x04)
        if msginject_textbuf == nil then return end
        msginject_textbuf_addr = tonumber(ffi.cast('uint32_t', msginject_textbuf))
        local tb = ffi.cast('uint8_t*', msginject_textbuf)
        ffi.fill(tb, 256, 0)
        for i = 0, math.min(#msginject_sender-1, 14) do tb[i] = string.byte(msginject_sender, i+1) end
        for i = 0, math.min(#msginject_subject-1, 14) do tb[0x20+i] = string.byte(msginject_subject, i+1) end
        for i = 0, math.min(#msginject_date-1, 14) do tb[0x40+i] = string.byte(msginject_date, i+1) end
    end

    -- Write render entry 1
    rend[0] = 0x20; rend[1] = 0x25; rend[2] = 0x25; rend[3] = 0x01; rend[4] = 0x01
    for c = 0, 7 do ffi.cast('uint32_t*', rend + 0x08 + c*4)[0] = 0xFFFFFFFF end
    local tba = msginject_textbuf_addr
    ffi.cast('uint32_t*', rend + 0x2C)[0] = tba
    ffi.cast('uint32_t*', rend + 0x30)[0] = tba + 0x20
    ffi.cast('uint32_t*', rend + 0x38)[0] = tba + 0x40

    -- Always keep count=2, visible=2 (template + our entry)
    local count = ffi.cast('uint32_t*', obj + 0x54)[0]
    if count < 2 then
        ffi.cast('uint32_t*', obj + 0x54)[0] = 2
        ffi.cast('uint16_t*', obj + 0x20)[0] = 2
        -- Call vt[1] to push visible count to UI element
        local vt1 = ffi.cast('void (__thiscall*)(void*)', ffximain_base + 0x1F63E0)
        vt1(ffi.cast('void*', obj_ptr))
    end

    msginject_dbg_count = msginject_dbg_count + 1
    if msginject_dbg_count <= 3 then
        print(('[fdiag] msginject frame %d: count=%d render=0x%08X'):format(
            msginject_dbg_count, count, render_arr))
    end

    end)
    if not ok2 and msginject_dbg_count < 3 then
        print(('[fdiag] msginject ERROR: %s'):format(tostring(err2)))
        msginject_dbg_count = msginject_dbg_count + 1
    end
end)

-- Watch polling in d3d_present (every ~60 frames = 1 second)
ashita.events.register('d3d_present', 'fdiag_watch', function()
    if not watch_active then return end
    watch_tick = watch_tick + 1
    if watch_tick % 60 ~= 0 then return end

    local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
    if ffximain_base == 0 then return end

    local mgr_addr = ffximain_base + 0x51E880
    if ffi.C.IsBadReadPtr(ffi.cast('void*', mgr_addr), 4) ~= 0 then return end

    local val = ffi.cast('uint32_t*', mgr_addr)[0]
    if val ~= watch_last_val then
        local secs = watch_tick / 60
        print(('[fdiag] WATCH [%ds]: FriendMgr 0x%08X -> 0x%08X'):format(secs, watch_last_val, val))
        watch_last_val = val
        if val ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', val), 128) == 0 then
            print('[fdiag] WATCH: FriendMgr populated!')
            for _, line in ipairs(hexdump(val, 128, 'Friend manager object')) do
                print(line)
            end
        end
    end

    -- Monitor connection manager at base+0x3CDC28
    local cmgr_addr = ffximain_base + 0x3CDC28
    if ffi.C.IsBadReadPtr(ffi.cast('void*', cmgr_addr), 4) == 0 then
        local cmgr_val = ffi.cast('uint32_t*', cmgr_addr)[0]
        if cmgr_val ~= watch_last_cmgr then
            local secs = watch_tick / 60
            print(('[fdiag] WATCH [%ds]: ConnMgr 0x%08X -> 0x%08X'):format(secs, watch_last_cmgr, cmgr_val))
            watch_last_cmgr = cmgr_val
            if cmgr_val ~= 0 and ffi.C.IsBadReadPtr(ffi.cast('void*', cmgr_val), 64) == 0 then
                print('[fdiag] WATCH: ConnMgr populated!')
                for _, line in ipairs(hexdump(cmgr_val, 64, 'ConnMgr header')) do
                    print(line)
                end
            end
        end
    end

    -- Also monitor descriptor slots 1-3 mode bytes
    local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
    if polcore_base == 0 then return end
    local desc_base = polcore_base + 0x404AD0
    local slot_size = 0x338
    if ffi.C.IsBadReadPtr(ffi.cast('void*', desc_base), slot_size * 4) ~= 0 then return end

    for i = 1, 3 do
        local slot = ffi.cast('uint8_t*', desc_base + i * slot_size)
        local mode = slot[0x08]
        if mode ~= watch_last_slots[i] then
            local secs = watch_tick / 60
            local state = slot[0x09]
            local enable = slot[0xDE]
            print(('[fdiag] WATCH [%ds]: Slot %d mode 0x%02X -> 0x%02X (state=0x%02X enable=0x%02X)'):format(
                secs, i, watch_last_slots[i], mode, state, enable))
            watch_last_slots[i] = mode
        end
    end
end)

-- Auto-patches DISABLED — xiloader friend.cpp handles these now.
-- Use /fdiag patchauth, /fdiag patchtype5 etc. for manual patching if needed.
--[[ DISABLED AUTO-PATCHES
do
    local polcore_base = tonumber(ffi.C.GetModuleHandleA('polcore.dll'))
    if polcore_base ~= 0 then
        local mode_addr = find_auth_mode_addr(polcore_base)
        if mode_addr and ffi.C.IsBadReadPtr(ffi.cast('void*', mode_addr), 48) == 0 then
            local old_mode = ffi.cast('uint32_t*', mode_addr)[0]
            ffi.cast('uint32_t*', mode_addr)[0] = 1

            -- Skip mask16 name write — leave mask16 at whatever xiloader/polcore set
            -- (character name mask was interfering with connection type determination)

            print(('[fdiag] AUTO-PATCH: g_auth_mode %d -> 1 (no mask16 write)'):format(old_mode))
        else
            print('[fdiag] AUTO-PATCH: Could not find g_auth_mode pattern')
        end

        -- NOTE: Instance #2 patch (JE->NOP NOP) now handled by xiloader in SetAuthMode().
        -- Use /fdiag patchauth2 for manual debugging if needed.
    end
end

-- Auto-patch: NOP the gate bit check in type5_check (FFXiMain+0x0E7510)
-- and NOP the two JZ instructions that skip the Type 5/6 builder in populate_friend_data
do
    local ffximain_base = tonumber(ffi.C.GetModuleHandleA('FFXiMain.dll'))
    if ffximain_base ~= 0 then
        local prot = ffi.new('uint32_t[1]')

        -- 1. NOP the JZ in type5_check at +0x0E7510+0x0D (gate bit check)
        --    Original: 74 30 (JZ +0x30) → 90 90 (NOP NOP)
        local t5_jz = ffi.cast('uint8_t*', ffximain_base + 0x0E751D)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', t5_jz), 2) == 0 then
            ffi.C.VirtualProtect(ffi.cast('void*', t5_jz), 2, 0x40, prot)
            if t5_jz[0] == 0x74 or t5_jz[0] == 0x90 then
                t5_jz[0] = 0x90; t5_jz[1] = 0x90
                print('[fdiag] AUTO-PATCH: type5_check gate bit JZ → NOP NOP')
            end
            ffi.C.VirtualProtect(ffi.cast('void*', t5_jz), 2, prot[0], prot)
        end

        -- 2. NOP the JZ after check #1 in populate_friend_data (+0x1E9830+0x1DF)
        --    Original: 74 2D (JZ +0x2D) → 90 90
        local pop_jz1 = ffi.cast('uint8_t*', ffximain_base + 0x1E9A0F)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', pop_jz1), 2) == 0 then
            ffi.C.VirtualProtect(ffi.cast('void*', pop_jz1), 2, 0x40, prot)
            if pop_jz1[0] == 0x74 or pop_jz1[0] == 0x90 then
                pop_jz1[0] = 0x90; pop_jz1[1] = 0x90
                print('[fdiag] AUTO-PATCH: populate check1 JZ → NOP NOP')
            end
            ffi.C.VirtualProtect(ffi.cast('void*', pop_jz1), 2, prot[0], prot)
        end

        -- 3. NOP the JZ after check #2 in populate_friend_data (+0x1E9830+0x1EC)
        --    Original: 74 20 (JZ +0x20) → 90 90
        local pop_jz2 = ffi.cast('uint8_t*', ffximain_base + 0x1E9A1C)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', pop_jz2), 2) == 0 then
            ffi.C.VirtualProtect(ffi.cast('void*', pop_jz2), 2, 0x40, prot)
            if pop_jz2[0] == 0x74 or pop_jz2[0] == 0x90 then
                pop_jz2[0] = 0x90; pop_jz2[1] = 0x90
                print('[fdiag] AUTO-PATCH: populate check2 JZ → NOP NOP')
            end
            ffi.C.VirtualProtect(ffi.cast('void*', pop_jz2), 2, prot[0], prot)
        end

        -- 4. Ensure +0x087 is JNZ (revert any previous JMP patch)
        local icon_jnz = ffi.cast('uint8_t*', ffximain_base + 0x1E96A7)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', icon_jnz), 2) == 0 then
            ffi.C.VirtualProtect(ffi.cast('void*', icon_jnz), 2, 0x40, prot)
            if icon_jnz[0] == 0xEB then
                icon_jnz[0] = 0x75
                print('[fdiag] AUTO-PATCH: reverted +0x087 JMP → JNZ')
            end
            ffi.C.VirtualProtect(ffi.cast('void*', icon_jnz), 2, prot[0], prot)
        end

        -- 5. (disabled — redirecting Path A epilogue to +0x14A breaks online icon)
        local pathA_end = ffi.cast('uint8_t*', ffximain_base + 0x1E971B)
        if ffi.C.IsBadReadPtr(ffi.cast('void*', pathA_end), 2) == 0 then
            ffi.C.VirtualProtect(ffi.cast('void*', pathA_end), 2, 0x40, prot)
            if pathA_end[0] == 0xEB then
                pathA_end[0] = 0x5F; pathA_end[1] = 0x5E
                print('[fdiag] AUTO-PATCH: reverted +0x0FB → POP EDI/POP ESI')
            end
            ffi.C.VirtualProtect(ffi.cast('void*', pathA_end), 2, prot[0], prot)
        end
    end
end
--]] -- END DISABLED AUTO-PATCHES

-- NOTE: patchlogin cave from addon is USELESS — addons load after bootstrap.
-- State machine +0x44FCC fires during PlayOnline bootstrap, before addons load.
-- To hook bootstrap, must patch from xiloader.
-- CallerB/CallerC CAN be called post-login from addon (tested, works with zero globals).

-- Character name mask patch DISABLED — was potentially interfering with connection types
-- local name_patched = false
-- ashita.events.register('d3d_present', 'fdiag_namepatch', function() ... end)

-- HTTP server setup
-- NOTE: luasocket's bind()/listen() return (nil, err) on failure rather than throwing,
-- so the old pcall wrapper silently missed bind/listen failures. http_server then
-- remained a tcp{master} (never promoted to tcp{server}) and accept() crashed with
-- "bad self (tcp{server} expected)". Explicit status checks per-step fix this.
if socket_ok then
    local sock, err = lsocket.tcp()
    if not sock then
        print(('[fdiag] HTTP tcp() failed: %s'):format(tostring(err)))
    else
        sock:setoption('reuseaddr', true)
        local ok, bind_err
        for attempt = 0, HTTP_PORT_TRIES - 1 do
            HTTP_PORT = HTTP_PORT_BASE + attempt
            ok, bind_err = sock:bind('127.0.0.1', HTTP_PORT)
            if ok then break end
            -- luasocket will not re-bind a socket that failed; make a new one.
            sock:close()
            sock = socket.tcp()
        end
        if not ok then
            print(('[fdiag] HTTP bind failed on ports %d-%d: %s'):format(
                HTTP_PORT_BASE, HTTP_PORT_BASE + HTTP_PORT_TRIES - 1, tostring(bind_err)))
            sock:close()
        else
            local lok, listen_err = sock:listen(5)
            if not lok then
                print(('[fdiag] HTTP listen failed: %s'):format(tostring(listen_err)))
                sock:close()
            else
                sock:settimeout(0)
                http_server = sock
                print(('[fdiag] HTTP server on port %d'):format(HTTP_PORT))
            end
        end
    end
else
    print('[fdiag] socket library not available, HTTP disabled')
end

-- HTTP polling in d3d_present
ashita.events.register('d3d_present', 'fdiag_http', function()
    if not http_server then return end

    -- Accept new connections — guard with pcall so a single bad state doesn't
    -- crash the addon on every frame (and get it unloaded).
    local acc_ok, client = pcall(function() return http_server:accept() end)
    if not acc_ok then
        print(('[fdiag] accept failed, disabling HTTP: %s'):format(tostring(client)))
        pcall(function() http_server:close() end)
        http_server = nil
        return
    end
    if client then
        client:settimeout(0.1)
        table.insert(http_clients, {sock = client, buf = '', time = os.clock()})
    end

    -- Process pending clients
    local i = 1
    while i <= #http_clients do
        local c = http_clients[i]
        local remove = false

        -- Try to read data
        local data, err, partial = c.sock:receive('*l')
        local line = data or partial
        if line and #line > 0 then
            c.buf = c.buf .. line .. '\n'
        end

        -- Check for complete HTTP request (first line with GET)
        local req_path = c.buf:match('GET ([^ ]+)')
        if req_path then
            local body = handle_http(req_path)
            local resp
            if body == '__BINARY_BMP__' then
                local bmp = capture_screenshot_bmp()
                if bmp then
                    resp = 'HTTP/1.1 200 OK\r\nContent-Type: image/bmp\r\n'
                        .. 'Connection: close\r\nContent-Length: ' .. #bmp .. '\r\n\r\n' .. bmp
                else
                    resp = 'HTTP/1.1 500 Error\r\nContent-Type: text/plain\r\n'
                        .. 'Connection: close\r\n\r\nScreenshot capture failed\n'
                end
            elseif body:sub(1, 14) == '__BINARY_RAW__' then
                local raw = body:sub(15)
                resp = 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                    .. 'Connection: close\r\nContent-Length: ' .. #raw .. '\r\n\r\n' .. raw
            else
                resp = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n'
                    .. 'Connection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n' .. body .. '\n'
            end
            c.sock:send(resp)
            c.sock:close()
            remove = true
        elseif err == 'closed' then
            c.sock:close()
            remove = true
        elseif os.clock() - c.time > 2 then
            c.sock:close()
            remove = true
        end

        if remove then
            table.remove(http_clients, i)
        else
            i = i + 1
        end
    end
end)

-- Cleanup on unload
ashita.events.register('unload', 'fdiag_http_cleanup', function()
    if http_server then
        http_server:close()
        http_server = nil
    end
    for _, c in ipairs(http_clients) do
        pcall(function() c.sock:close() end)
    end
    http_clients = {}
end)

print('[fdiag] Loaded (auto-patches DISABLED — xiloader handles them). Commands:')
print('  /fdiag desc       - dump descriptor array (connection slots)')
print('  /fdiag enable N   - enable slot N')
print('  /fdiag clone S D  - copy slot S config to D')
print('  /fdiag dumpslot N - hex dump slot N')
print('  /fdiag authdata   - show g_auth_mode (interpreted)')
print('  /fdiag authblock  - raw hex dump g_auth_mode 48B')
print('  /fdiag setbyte O V - write byte at g_auth_mode+O')
print('  /fdiag dumpcode O [S] - hex dump polcore code at offset')
print('  /fdiag findauth   - scan for MOV BYTE [EDI],01/02 in polcore')
print('  /fdiag patch      - re-apply mode=1 + char name mask')
print('  /fdiag watch      - poll friend mgr + slots for changes')
print('  /fdiag polconn    - dump polConnection object')

-- Keepalive disabled — xiloader friend.cpp handles keepalive now
keepalive_interval = 30
keepalive_frame_count = 0
keepalive_busy = false
keepalive_active = false
print('[fdiag] Keepalive DISABLED (xiloader friend.cpp handles it)')
