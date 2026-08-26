/*
===========================================================================

Copyright (c) 2010-2015 Darkstar Dev Teams
Copyright (c) 2021-2026 LandSandBoat Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#define NOMINMAX 1 // Interferes with std::numeric_limits

#include "defines.h"

#include <ctime>
#include <cctype>
#include <set>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <intrin.h>

#include "console.h"
#include "functions.h"
#include "helpers.h"
#include "network.h"

#include "argparse/argparse.hpp"
#include <nlohmann/json.hpp>

#include "friend.h"

using json = nlohmann::json;

/* Global Variables */
namespace globals
{
    xiloader::Language     g_Language          = xiloader::Language::English; // The language of the loader to be used for polcore.
    std::string            g_ServerAddress     = "127.0.0.1";                 // The server address to connect to.
    uint16_t               g_ServerPort        = 51220;                       // The server lobby server port to connect to.
    uint16_t               g_LoginDataPort     = 54230;                       // Login server data port to connect to
    uint16_t               g_LoginViewPort     = 54001;                       // Login view port to connect to
    uint16_t               g_LoginAuthPort     = 54231;                       // Login auth port to connect to
    std::string            g_Username          = "";                          // The username being logged in with.
    std::string            g_Password          = "";                          // The password being logged in with.
    std::string            g_OtpCode           = "";                          // The OTP code the user input
    char                   g_SessionHash[16]   = {};                          // Session hash sent from auth
    uint32_t               g_AccountId         = 0;                           // Account ID from auth (for profile server credential injection)
    std::string            g_Email             = "";                          // Email, currently unused
    std::array<uint8_t, 3> g_VersionNumber     = { 2, 1, 1 };                 // xiloader version number sent to auth server. Must be x.x.x with single characters for 'x'. Remember to also change in xiloader.rc.in
    bool                   g_FirstLogin        = false;                       // set to true when --user --pass are both set to allow for autologin
    std::string            g_TrustToken        = "";                          // trust token loaded from disk or received from server
    bool                   g_TrustThisComputer = false;                       // user checkbox / CLI flag for "trust this computer"

    char* g_CharacterList = NULL;  // Pointer to the character list data being sent from the server.
    bool  g_IsRunning     = false; // Flag to determine if the network threads should hault.
    bool  g_Hide          = false; // Determines whether or not to hide the console window after FFXI starts.
    bool  g_EnableFriends = false; // Enable friend list system (requires profile server). Off by default.
    bool  g_EnablePolPush = true;  // Live friend status via polcore's POL push channel. Follows --friends; --no-pol-push disables for debugging.

    /* Hairpin Fix Variables */
    DWORD g_NewServerAddress;     // Hairpin server address to be overriden with.
    DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.
};

namespace sslState
{
    // mbed tls state
    mbedtls_net_context               server_fd = {};
    mbedtls_entropy_context           entropy   = {};
    mbedtls_ctr_drbg_context          ctr_drbg  = {};
    mbedtls_ssl_context               ssl       = {};
    mbedtls_ssl_config                conf      = {};
    mbedtls_x509_crt                  cacert    = {};
    std::unique_ptr<mbedtls_x509_crt> ca_chain  = {};
};

/**
 * @brief Detour function definitions.
 */
extern "C"
{
    hostent*(WINAPI __stdcall* Real_gethostbyname)(const char* name)       = gethostbyname;
    int(WINAPI* Real_send)(SOCKET s, const char* buf, int len, int flags)  = send;
    int(WINAPI* Real_recv)(SOCKET s, char* buf, int len, int flags)        = recv;
    int(WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
    HANDLE(WINAPI* Real_CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess,
        DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile) = CreateFileA;
    HANDLE(WINAPI* Real_FindFirstFileA)(LPCSTR lpFileName,
        LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
    BOOL(WINAPI* Real_MoveFileA)(LPCSTR lpExistingFileName,
        LPCSTR lpNewFileName) = MoveFileA;
    BOOL(WINAPI* Real_DeleteFileA)(LPCSTR lpFileName) = DeleteFileA;
    BOOL(WINAPI* Real_MoveFileExA)(LPCSTR lpExistingFileName,
        LPCSTR lpNewFileName, DWORD dwFlags) = MoveFileExA;
    BOOL(WINAPI* Real_CreateDirectoryA)(LPCSTR lpPathName,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes) = CreateDirectoryA;
    BOOL(WINAPI* Real_CreateDirectoryExA)(LPCSTR lpTemplateDirectory, LPCSTR lpNewDirectory,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes) = CreateDirectoryExA;
    BOOL(WINAPI* Real_RemoveDirectoryA)(LPCSTR lpPathName) = RemoveDirectoryA;
    DWORD(WINAPI* Real_GetFileAttributesA)(LPCSTR lpFileName) = GetFileAttributesA;
    BOOL(WINAPI* Real_SetFileAttributesA)(LPCSTR lpFileName,
        DWORD dwFileAttributes) = SetFileAttributesA;
    BOOL(WINAPI* Real_CopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName,
        BOOL bFailIfExists) = CopyFileA;
    HANDLE(WINAPI* Real_CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess,
        DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile) = CreateFileW;
}

/**
 * @brief Hairpin fix codecave.
 */
__declspec(naked) void HairpinFixCave(void)
{
    __asm mov eax, globals::g_NewServerAddress
    __asm mov [edx + 0x012E90], eax
    __asm mov [edx], eax
    __asm jmp globals::g_HairpinReturnAddress
}

/**
 * @brief Applies the hairpin fix modifications.
 *
 * @param lpParam       Thread param object.
 *
 * @return Non-important return.
 */
DWORD ApplyHairpinFixThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    do
    {
        /* Sleep until we find FFXiMain loaded.. */
        Sleep(100);
    } while (GetModuleHandleA("FFXiMain.dll") == NULL);

    /* Convert server address.. */
    xiloader::network::ResolveHostname(globals::g_ServerAddress.c_str(), &globals::g_NewServerAddress);

    // Locate the main hairpin location..
    //
    // As of 07.08.2013:
    //      8B 82 902E0100        - mov eax, [edx+00012E90]
    //      89 02                 - mov [edx], eax <-- edit this

    auto hairpinAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x82\xFF\xFF\xFF\xFF\x89\x02\x8B\x0D", "xx????xxxx");
    if (hairpinAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate main hairpin hack address!");
        return 0;
    }

    // Locate zoning IP change address..
    //
    // As of 07.08.2013
    //      74 08                 - je FFXiMain.dll+E5E72
    //      8B 0D 68322B03        - mov ecx, [FFXiMain.dll+463268]
    //      89 01                 - mov [ecx], eax <-- edit this
    //      8B 46 0C              - mov eax, [esi+0C]
    //      85 C0                 - test eax, eax

    auto zoneChangeAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x0D\xFF\xFF\xFF\xFF\x89\x01\x8B\x46", "xx????xxxx");
    if (zoneChangeAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate zone change hairpin address!");
        return 0;
    }

    /* Apply the hairpin fix.. */
    auto caveDest = ((int)HairpinFixCave - ((int)hairpinAddress)) - 5;
    globals::g_HairpinReturnAddress = hairpinAddress + 0x08;

    *(BYTE*)(hairpinAddress + 0x00) = 0xE9; // jmp
    *(UINT*)(hairpinAddress + 0x01) = caveDest;
    *(BYTE*)(hairpinAddress + 0x05) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x06) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x07) = 0x90; // nop

    /* Apply zone ip change patch.. */
    memset((LPVOID)(zoneChangeAddress + 0x06), 0x90, 2);

    xiloader::console::output(xiloader::color::success, "Hairpin fix applied!");
    return 0;
}

/**
 * @brief gethostbyname detour callback.
 *
 * @param name The hostname to obtain information of.
 *
 * @return Hostname information object.
 */
hostent* __stdcall Mine_gethostbyname(const char* name)
{
    xiloader::console::output(xiloader::color::debug, "Resolving host: %s", name);

    if (!strcmp("ffxi00.pol.com", name))
    {
        return Real_gethostbyname(globals::g_ServerAddress.c_str());
    }

    /* Any ppNNN.pol.com is the PlayOnline profile/push server. polcore builds
     * the name at runtime with the format "pp%03d.pol.com" (polcore+0x75430),
     * and the index is computed, not always 000 -- matching only the literal
     * pp000 let other indices escape to real DNS. */
    if (!_strnicmp(name, "pp", 2) && isdigit((unsigned char)name[2]) &&
        isdigit((unsigned char)name[3]) && isdigit((unsigned char)name[4]) &&
        !_stricmp(name + 5, ".pol.com"))
    {
        return Real_gethostbyname("127.0.0.1");
    }

    return Real_gethostbyname(name);
}

// This function's purpose is to identify a command byte and identify if it is meant for the lobby dataport or not.
// This way, we know we want to send.
bool isLobbyCommand(const char* buffer, SOCKET socket)
{
    struct sockaddr_in sin;
    int                addrlen = sizeof(sin);

    getpeername(socket, reinterpret_cast<struct sockaddr*>(&sin), &addrlen);

    auto port = ntohs(sin.sin_port);

    if (port != globals::g_LoginDataPort && port != globals::g_LoginViewPort)
    {
        return false;
    }

    auto command = buffer[8];
    // See https://github.com/atom0s/XiPackets/tree/main/lobby
    // Command bytes information, based on what the client visually reports when waiting for a response:
    // 0x07: Request login to character with account id and character id. Login verifies this and will notify if possible: "Notifying lobby server of current selections."
    // 0x14: Request character deletion, login will delete if enabled. "Deleting from lobby server"
    // 0x1F: Request character list, login server only replies with "0x01": "Acquiring Player Data"
    // 0x21: Notify server character was created clientside (no effect in login server): "Registering character name onto the lobby server"
    // 0x22: Notify server of character wishing to be created and login creates the character: "Checking name and Gold World Pass"
    // 0x24: Client requesting server name: "Acquiring FINAL FANTASY XI server data"
    // 0x26: Send version information to login, login replies with expansion/features bitmask: "Setting up connection."
    // 0x28: Client sending character rename information if character was renamed by a GM (Not yet implemented in login)
    // 0x2B: GM command to move character to a new world? See https://github.com/atom0s/XiPackets/blob/main/lobby/C2S_0x002B_RequestMoveGMChr.md
    if
        (command == 0x07 ||
         command == 0x14 ||
         command == 0x1F ||
         command == 0x21 ||
         command == 0x22 ||
         command == 0x24 ||
         command == 0x26 ||
         command == 0x28 ||
         command == 0x2B)
    {
        // Check for magic numbers (XIFF command)
        if (buffer[4] == 0x49 && buffer[5] == 0x58 && buffer[6] == 0x46 && buffer[7] == 0x46)
        {
            return true;
        }
    }

    return false;
}

/**
 * @brief send detour callback. https://man7.org/linux/man-pages/man2/send.2.html
 */
int WINAPI Mine_send(SOCKET s, const char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore = ret;

    // check for lobby specific commands
    if (isLobbyCommand(buf, s))
    {
        // always send server provided session hash in packets with XIFF commands and is a lobby command
        std::memcpy((char*)buf + 12, globals::g_SessionHash, 16);
    }

    if (globals::g_EnableFriends)
        friend_system::on_send(s, buf, len);

    return Real_send(s, buf, len, flags);
}

/**
 * @brief recv detour callback. https://man7.org/linux/man-pages/man2/recv.2.html
 */
int WINAPI Mine_recv(SOCKET s, char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore = ret;

    // xiloader::console::output(xiloader::color::lightblue, "recv %i", len);
    return Real_recv(s, buf, len, flags);
}
/**
 * @brief connect detour callback. https://man7.org/linux/man-pages/man2/connect.2.html
 */
int WINAPI Mine_connect(SOCKET s, const sockaddr* name, int namelen)
{
    /* Per-connect logging is suppressed: each polcore SM opens a fresh socket
     * per op (~6 connects per 30s NotifPickup cycle). Log each DISTINCT
     * destination once instead, which is enough to spot a new channel (the POL
     * push connection) without flooding. */
    if (name != nullptr && namelen >= (int)sizeof(sockaddr_in) &&
        name->sa_family == AF_INET)
    {
        const sockaddr_in* sin = (const sockaddr_in*)name;
        uint64_t key = ((uint64_t)sin->sin_addr.s_addr << 16) | ntohs(sin->sin_port);
        static std::set<uint64_t> s_seen;
        static std::mutex s_mtx;
        bool fresh = false;
        {
            std::lock_guard<std::mutex> lk(s_mtx);
            fresh = s_seen.insert(key).second;
        }
        if (fresh)
        {
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, (void*)&sin->sin_addr, ip, sizeof(ip));
            xiloader::console::output(xiloader::color::debug,
                "Connect: new destination %s:%u", ip, (unsigned)ntohs(sin->sin_port));
        }
    }
    return Real_connect(s, name, namelen);
}

/**
 * @brief CreateFileA hook -- redirects message file paths to a local directory.
 *
 * polcore reads/writes message body files at
 * PlayOnlineViewer\pub\homeNN\msg\r\{a|b}\<encoded_filename>. Paths
 * containing \msg\r\ are redirected to a local directory next to xiloader so
 * message files can be created without write access to Program Files and
 * without modifying polcore's internal path globals.
 */
static std::string s_LocalMsgDir;
static uint32_t    s_LocalMsgDirAccid = 0;  /* the accid baked into s_LocalMsgDir */

/* Lazy init of the msg redirect base. Per-account isolation: each account's
 * inbox/outbox files live under <ashita-root>\msg\<accid>\... so multiboxed
 * xiloader instances on the same machine don't see each other's mail.
 *
 * We re-initialize if g_AccountId changes (e.g., a re-login), since the
 * same xiloader process never serves two accounts in practice but the
 * accid may be 0 on the very first call (rare; would only happen if a
 * msg-path API is hit before VerifyAccount completes). In that case we
 * stamp a `_no_accid` subdir so the bug is obvious in logs and on disk. */
static void EnsureMsgDir()
{
    uint32_t accid = globals::g_AccountId;
    if (!s_LocalMsgDir.empty() && s_LocalMsgDirAccid == accid)
        return;

    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos)
        exeDir = exeDir.substr(0, lastSlash);
    /* exe -> bootloader dir -> Ashita root. */
    lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos)
        exeDir = exeDir.substr(0, lastSlash);

    char acctSeg[32] = {};
    if (accid != 0)
        wsprintfA(acctSeg, "%u", accid);
    else
        strcpy_s(acctSeg, "_no_accid");

    s_LocalMsgDir = exeDir + "\\msg\\" + acctSeg;
    s_LocalMsgDirAccid = accid;

    /* r\a, r\b, s\b subdirectories. */
    std::filesystem::create_directories(s_LocalMsgDir + "\\r\\a");
    std::filesystem::create_directories(s_LocalMsgDir + "\\r\\b");
    std::filesystem::create_directories(s_LocalMsgDir + "\\s\\b");

    xiloader::console::output(xiloader::color::debug,
        "MsgHook: local msg dir = %s (accid=%u)",
        s_LocalMsgDir.c_str(), accid);
}

HANDLE WINAPI Mine_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (lpFileName != nullptr)
    {
        const char* msgMarker = strstr(lpFileName, "\\msg\\");
        if (msgMarker != nullptr)
        {
            EnsureMsgDir();

            /* Caller IP inside polcore.dll = native msg-file write path. */
            void* retAddr = _ReturnAddress();
            HMODULE hPolcore = GetModuleHandleA("polcore.dll");
            const char* caller = "xiloader";
            uintptr_t rva = 0;
            if (hPolcore != nullptr)
            {
                uintptr_t base = (uintptr_t)hPolcore;
                uintptr_t ip   = (uintptr_t)retAddr;
                if (ip >= base && ip < base + 0x500000)
                {
                    caller = "polcore";
                    rva = ip - base;
                }
            }

            /* Skip "\msg" but keep the "\" so the joined path is well-formed. */
            std::string relPath(msgMarker + 4);
            std::string redirected;
            /* Idempotency: if the path already starts with our per-account
             * msg dir, leave it alone (see RedirectMsgPathA for context). */
            if (_strnicmp(lpFileName, s_LocalMsgDir.c_str(), s_LocalMsgDir.size()) == 0)
            {
                redirected = lpFileName;
            }
            else
            {
                redirected = s_LocalMsgDir + relPath;
            }

            /* Ensure parent directory exists. */
            std::filesystem::path rp(redirected);
            std::filesystem::create_directories(rp.parent_path());

            xiloader::console::output(xiloader::color::debug,
                "MsgHook: CreateFileA from %s+0x%X access=0x%08X disp=%u -> '%s'",
                caller, (unsigned)rva, dwDesiredAccess, dwCreationDisposition,
                redirected.c_str());

            return Real_CreateFileA(redirected.c_str(), dwDesiredAccess, dwShareMode,
                lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                hTemplateFile);
        }
    }

    return Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
        hTemplateFile);
}

/**
 * @brief FindFirstFileA hook -- redirects message directory scans to local dir.
 */
HANDLE WINAPI Mine_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    if (lpFileName != nullptr)
    {
        const char* msgMarker = strstr(lpFileName, "\\msg\\");
        if (msgMarker != nullptr)
        {
            EnsureMsgDir();
            std::string relPath(msgMarker + 4);
            std::string redirected;
            if (_strnicmp(lpFileName, s_LocalMsgDir.c_str(), s_LocalMsgDir.size()) == 0)
            {
                redirected = lpFileName;
            }
            else
            {
                redirected = s_LocalMsgDir + relPath;
            }

            std::filesystem::path rp(redirected);
            std::filesystem::create_directories(rp.parent_path());

            /* Caller RVA -- /a/ scan callers identify the polcore code that
             * filters already-read messages out of the inbox. */
            void* retAddr = _ReturnAddress();
            HMODULE hPolcore = GetModuleHandleA("polcore.dll");
            const char* caller = "xiloader";
            uintptr_t rva = 0;
            if (hPolcore != nullptr)
            {
                uintptr_t base = (uintptr_t)hPolcore;
                uintptr_t ip   = (uintptr_t)retAddr;
                if (ip >= base && ip < base + 0x500000)
                {
                    caller = "polcore";
                    rva = ip - base;
                }
            }

            return Real_FindFirstFileA(redirected.c_str(), lpFindFileData);
        }
    }
    return Real_FindFirstFileA(lpFileName, lpFindFileData);
}

/**
 * @brief MoveFileA hook -- redirects message file moves (unread->read) to local dir.
 */
BOOL WINAPI Mine_MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)
{
    std::string existRedirected, newRedirected;
    bool redirectExist = false, redirectNew = false;

    if (lpExistingFileName != nullptr)
    {
        const char* m = strstr(lpExistingFileName, "\\msg\\");
        if (m != nullptr)
        {
            EnsureMsgDir();
            if (_strnicmp(lpExistingFileName, s_LocalMsgDir.c_str(), s_LocalMsgDir.size()) == 0)
                existRedirected = lpExistingFileName;
            else
                existRedirected = s_LocalMsgDir + std::string(m + 4);
            redirectExist = true;
        }
    }
    if (lpNewFileName != nullptr)
    {
        const char* m = strstr(lpNewFileName, "\\msg\\");
        if (m != nullptr)
        {
            EnsureMsgDir();
            if (_strnicmp(lpNewFileName, s_LocalMsgDir.c_str(), s_LocalMsgDir.size()) == 0)
                newRedirected = lpNewFileName;
            else
                newRedirected = s_LocalMsgDir + std::string(m + 4);
            std::filesystem::path rp(newRedirected);
            std::filesystem::create_directories(rp.parent_path());
            redirectNew = true;
        }
    }

    void* ret_ip = _ReturnAddress();
    uint32_t ret_rva = 0;
    HMODULE polcore = GetModuleHandleA("polcore.dll");
    if (polcore && (uintptr_t)ret_ip >= (uintptr_t)polcore && (uintptr_t)ret_ip < (uintptr_t)polcore + 0x800000)
        ret_rva = (uint32_t)((uintptr_t)ret_ip - (uintptr_t)polcore);
    xiloader::console::output(xiloader::color::warning,
        "MsgHook: MoveFileA from polcore+0x%X '%s' -> '%s'",
        ret_rva,
        redirectExist ? existRedirected.c_str() : (lpExistingFileName ? lpExistingFileName : "(null)"),
        redirectNew ? newRedirected.c_str() : (lpNewFileName ? lpNewFileName : "(null)"));

    return Real_MoveFileA(
        redirectExist ? existRedirected.c_str() : lpExistingFileName,
        redirectNew ? newRedirected.c_str() : lpNewFileName);
}

/**
 * @brief DeleteFileA hook -- redirects msg file deletes to local dir.
 *
 * polcore deletes /msg/r/b/<file> after copying to /msg/r/a/ on dismiss.
 * Without redirect the delete targets the original POL path (not on disk)
 * and silently fails, so the next inbox enumeration re-renders the row.
 */
BOOL WINAPI Mine_DeleteFileA(LPCSTR lpFileName)
{
    std::string redirected;
    bool redirect = false;

    if (lpFileName != nullptr)
    {
        const char* m = strstr(lpFileName, "\\msg\\");
        if (m != nullptr)
        {
            EnsureMsgDir();
            if (_strnicmp(lpFileName, s_LocalMsgDir.c_str(), s_LocalMsgDir.size()) == 0)
                redirected = lpFileName;
            else
                redirected = s_LocalMsgDir + std::string(m + 4);
            redirect = true;

            void* ret_ip = _ReturnAddress();
            uint32_t ret_rva = 0;
            HMODULE polcore = GetModuleHandleA("polcore.dll");
            if (polcore && (uintptr_t)ret_ip >= (uintptr_t)polcore && (uintptr_t)ret_ip < (uintptr_t)polcore + 0x800000)
                ret_rva = (uint32_t)((uintptr_t)ret_ip - (uintptr_t)polcore);
            xiloader::console::output(xiloader::color::warning,
                "MsgHook: DeleteFileA from polcore+0x%X '%s' (redirected from '%s')",
                ret_rva, redirected.c_str(), lpFileName);
        }
    }
    return Real_DeleteFileA(redirect ? redirected.c_str() : lpFileName);
}

/**
 * @brief Redirect helper -- if path contains "\msg\", returns true with the
 * local-redirected path written to `out`. Otherwise returns false.
 */
static bool RedirectMsgPathA(LPCSTR path, std::string& out)
{
    if (path == nullptr) return false;
    const char* m = strstr(path, "\\msg\\");
    if (m == nullptr) return false;
    EnsureMsgDir();
    /* Idempotency: if the path is already rooted under our per-account
     * msg dir, leave it alone. Otherwise we double-stamp the accid subdir
     * (e.g. <root>\msg\1000\1000\r\b\<file>). This happens because friend.cpp
     * builds paths from get_local_msg_dir() (which doesn't know the accid)
     * and the file APIs we hook here see a path containing "\msg\" -- without
     * this check we'd prepend the per-account dir a second time when the
     * caller is already passing a previously-redirected absolute path. */
    if (_strnicmp(path, s_LocalMsgDir.c_str(), s_LocalMsgDir.size()) == 0)
    {
        out = path;
        return true;
    }
    out = s_LocalMsgDir + std::string(m + 4);
    return true;
}

/**
 * @brief Caller IP -> "polcore+0xN" / "FFXi+0xN" / "xiloader+0xN" string.
 * Used so msg-hook log lines identify which DLL invoked the API.
 */
static void GetCallerLocation(void* retAddr, char* out, size_t outSize)
{
    HMODULE pol = GetModuleHandleA("polcore.dll");
    HMODULE ffxi = GetModuleHandleA("FFXiMain.dll");
    HMODULE self = GetModuleHandleA("xiloader.exe");
    uintptr_t ip = (uintptr_t)retAddr;
    if (pol && ip >= (uintptr_t)pol && ip < (uintptr_t)pol + 0x800000) {
        wsprintfA(out, "polcore+0x%X", (unsigned)(ip - (uintptr_t)pol));
        out[outSize - 1] = 0;
        return;
    }
    if (ffxi && ip >= (uintptr_t)ffxi && ip < (uintptr_t)ffxi + 0x1000000) {
        wsprintfA(out, "FFXi+0x%X", (unsigned)(ip - (uintptr_t)ffxi));
        out[outSize - 1] = 0;
        return;
    }
    if (self && ip >= (uintptr_t)self && ip < (uintptr_t)self + 0x800000) {
        wsprintfA(out, "xiloader+0x%X", (unsigned)(ip - (uintptr_t)self));
        out[outSize - 1] = 0;
        return;
    }
    wsprintfA(out, "0x%08X", (unsigned)ip);
    out[outSize - 1] = 0;
}

/**
 * @brief MoveFileExA hook -- extension of MoveFileA with replace/delay flags.
 * Polcore imports both MoveFileA and MoveFileExA; redirect msg paths the same.
 */
BOOL WINAPI Mine_MoveFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags)
{
    std::string existR, newR;
    bool redirectExist = RedirectMsgPathA(lpExistingFileName, existR);
    bool redirectNew   = RedirectMsgPathA(lpNewFileName, newR);
    if (redirectNew) {
        std::filesystem::path rp(newR);
        std::filesystem::create_directories(rp.parent_path());
    }
    if (redirectExist || redirectNew) {
        char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
        xiloader::console::output(xiloader::color::warning,
            "MsgHook: MoveFileExA from %s flags=0x%X '%s' -> '%s'",
            loc, dwFlags,
            redirectExist ? existR.c_str() : (lpExistingFileName ? lpExistingFileName : "(null)"),
            redirectNew   ? newR.c_str()   : (lpNewFileName ? lpNewFileName : "(null)"));
    }
    return Real_MoveFileExA(
        redirectExist ? existR.c_str() : lpExistingFileName,
        redirectNew   ? newR.c_str()   : lpNewFileName,
        dwFlags);
}

/**
 * @brief CreateDirectoryA hook -- FFXi creates msg subdirs for first-launch
 * setup. Redirect to local msg root.
 */
BOOL WINAPI Mine_CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    std::string redirected;
    if (RedirectMsgPathA(lpPathName, redirected))
    {
        char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
        xiloader::console::output(xiloader::color::warning,
            "MsgHook: CreateDirectoryA from %s '%s' (redirected from '%s')",
            loc, redirected.c_str(), lpPathName);
        return Real_CreateDirectoryA(redirected.c_str(), lpSecurityAttributes);
    }
    return Real_CreateDirectoryA(lpPathName, lpSecurityAttributes);
}

/**
 * @brief CreateDirectoryExA hook -- polcore variant. Redirect msg paths.
 * Template path is just for ACL inheritance, no redirect needed there.
 */
BOOL WINAPI Mine_CreateDirectoryExA(LPCSTR lpTemplateDirectory, LPCSTR lpNewDirectory,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    std::string redirected;
    if (RedirectMsgPathA(lpNewDirectory, redirected))
    {
        char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
        xiloader::console::output(xiloader::color::warning,
            "MsgHook: CreateDirectoryExA from %s '%s' (redirected from '%s')",
            loc, redirected.c_str(), lpNewDirectory);
        return Real_CreateDirectoryExA(lpTemplateDirectory, redirected.c_str(), lpSecurityAttributes);
    }
    return Real_CreateDirectoryExA(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes);
}

/**
 * @brief RemoveDirectoryA hook -- redirect msg path removals.
 */
BOOL WINAPI Mine_RemoveDirectoryA(LPCSTR lpPathName)
{
    std::string redirected;
    if (RedirectMsgPathA(lpPathName, redirected))
    {
        char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
        xiloader::console::output(xiloader::color::warning,
            "MsgHook: RemoveDirectoryA from %s '%s' (redirected from '%s')",
            loc, redirected.c_str(), lpPathName);
        return Real_RemoveDirectoryA(redirected.c_str());
    }
    return Real_RemoveDirectoryA(lpPathName);
}

/**
 * @brief GetFileAttributesA hook -- common existence check. Without redirect,
 * polcore/FFXi looks at the original POL path which doesn't exist locally,
 * gets INVALID_FILE_ATTRIBUTES back, and may take the wrong code path.
 */
DWORD WINAPI Mine_GetFileAttributesA(LPCSTR lpFileName)
{
    std::string redirected;
    if (RedirectMsgPathA(lpFileName, redirected))
        return Real_GetFileAttributesA(redirected.c_str());
    return Real_GetFileAttributesA(lpFileName);
}

/**
 * @brief SetFileAttributesA hook -- used to clear read-only / set archive.
 * Redirect msg paths so the bit toggles the real local file, not the
 * non-existent POL path.
 */
BOOL WINAPI Mine_SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)
{
    std::string redirected;
    if (RedirectMsgPathA(lpFileName, redirected))
    {
        char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
        xiloader::console::output(xiloader::color::warning,
            "MsgHook: SetFileAttributesA from %s attr=0x%X '%s' (redirected from '%s')",
            loc, dwFileAttributes, redirected.c_str(), lpFileName);
        return Real_SetFileAttributesA(redirected.c_str(), dwFileAttributes);
    }
    return Real_SetFileAttributesA(lpFileName, dwFileAttributes);
}

/**
 * @brief CopyFileA hook -- FFXiMain imports CopyFileA. Redirect both src and
 * dst when in msg paths.
 */
BOOL WINAPI Mine_CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)
{
    std::string existR, newR;
    bool redirectExist = RedirectMsgPathA(lpExistingFileName, existR);
    bool redirectNew   = RedirectMsgPathA(lpNewFileName, newR);
    if (redirectNew) {
        std::filesystem::path rp(newR);
        std::filesystem::create_directories(rp.parent_path());
    }
    if (redirectExist || redirectNew) {
        char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
        xiloader::console::output(xiloader::color::warning,
            "MsgHook: CopyFileA from %s '%s' -> '%s'",
            loc,
            redirectExist ? existR.c_str() : (lpExistingFileName ? lpExistingFileName : "(null)"),
            redirectNew   ? newR.c_str()   : (lpNewFileName ? lpNewFileName : "(null)"));
    }
    return Real_CopyFileA(
        redirectExist ? existR.c_str() : lpExistingFileName,
        redirectNew   ? newR.c_str()   : lpNewFileName,
        bFailIfExists);
}

/**
 * @brief CreateFileW hook -- FFXiMain imports CreateFileW. Convert wide path
 * to ANSI, check for "\msg\", redirect if matched. msg paths in this engine
 * are pure ASCII so the round-trip is lossless.
 */
HANDLE WINAPI Mine_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (lpFileName != nullptr)
    {
        char narrow[MAX_PATH * 2] = {};
        int n = WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, narrow, sizeof(narrow), nullptr, nullptr);
        if (n > 0)
        {
            std::string redirected;
            if (RedirectMsgPathA(narrow, redirected))
            {
                wchar_t wide[MAX_PATH * 2] = {};
                int wn = MultiByteToWideChar(CP_ACP, 0, redirected.c_str(), -1, wide,
                    (int)(sizeof(wide) / sizeof(wide[0])));
                if (wn > 0)
                {
                    std::filesystem::path rp(redirected);
                    std::filesystem::create_directories(rp.parent_path());

                    char loc[64]; GetCallerLocation(_ReturnAddress(), loc, sizeof(loc));
                    xiloader::console::output(xiloader::color::warning,
                        "MsgHook: CreateFileW from %s access=0x%08X disp=%u -> '%s'",
                        loc, dwDesiredAccess, dwCreationDisposition, redirected.c_str());

                    return Real_CreateFileW(wide, dwDesiredAccess, dwShareMode,
                        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                        hTemplateFile);
                }
            }
        }
    }
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

/**
 * @brief Locates profile server port addresses and sets the profile server port
 *
 * @return Failed to find the patterns or succeeded to write
 */
bool SetProfileServerPort(uint16_t profileServerPort)
{
    const char* module                   = (globals::g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        profileServerPortAddress = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x66\xC7\x46\x26\x14\xC8\x88\x46\x09\x8D\x46\x24", "xxxxxxxxxxx");
    if (profileServerPortAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate profileServerPortAddress!");
        return false;
    }

    auto profileServerPortAddress2 = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x66\xC7\x05\xBA\x4A\x3F\x04\x14\xC8", "xxxxx??xx"); // This pattern changed slightly on a few month old polcore, it used to be a total match but some bytes changed.
    if (profileServerPortAddress2 == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate profileServerPortAddress2!");
        return false;
    }

    *((uint16_t*)(profileServerPortAddress + 4))  = profileServerPort;
    *((uint16_t*)(profileServerPortAddress2 + 7)) = profileServerPort;


    return true;
}

/**
 * @brief Locates the INET mutex function call inside of polcore.dll
 *
 * @return The pointer to the function call.
 */
inline DWORD FindINETMutex(void)
{
    const char* module = (globals::g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    return (*(DWORD*)(result - 4) + (result));
}

/**
 * @brief Locates the PlayOnline connection object inside of polcore.dll
 *
 * @return Pointer to the pol connection object.
 */
inline DWORD FindPolConn(void)
{
    const char* module = (globals::g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
    return (*(DWORD*)(result - 10));
}

/**
 * @brief Locates the current character information block.
 *
 * @return Pointer to the character information table.
 */
inline LPVOID FindCharacters(void** commFuncs)
{
    LPVOID lpCharTable = NULL;
    memcpy(&lpCharTable, (char*)commFuncs[0xD3] + 31, sizeof(lpCharTable));
    return lpCharTable;
}

// Source: https://curl.se/mail/lib-2019-06/0057.html
std::unique_ptr<mbedtls_x509_crt> extract_cert(PCCERT_CONTEXT certificateContext)
{
    // TODO: add delete!
    std::unique_ptr<mbedtls_x509_crt> certificate(new mbedtls_x509_crt);
    mbedtls_x509_crt_init(certificate.get());
    mbedtls_x509_crt_parse(certificate.get(), certificateContext->pbCertEncoded, certificateContext->cbCertEncoded);
    return std::move(certificate);
}

// Source: https://curl.se/mail/lib-2019-06/0057.html
std::unique_ptr<mbedtls_x509_crt> build_windows_ca_chain()
{
    std::unique_ptr<mbedtls_x509_crt> ca_chain = NULL;
    HCERTSTORE        certificateStore         = NULL;

    if (certificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"Root"))
    {
        std::unique_ptr<mbedtls_x509_crt> previousCertificate = NULL;
        std::unique_ptr<mbedtls_x509_crt> currentCertificate  = NULL;
        PCCERT_CONTEXT                    certificateContext  = NULL;

        if (certificateContext = CertEnumCertificatesInStore(certificateStore, certificateContext))
        {
            if (certificateContext->dwCertEncodingType & X509_ASN_ENCODING)
            {
                ca_chain            = extract_cert(certificateContext);
                previousCertificate = std::move(ca_chain);
            }

            while (certificateContext = CertEnumCertificatesInStore(certificateStore, certificateContext))
            {
                if (certificateContext->dwCertEncodingType & X509_ASN_ENCODING)
                {
                    currentCertificate        = extract_cert(certificateContext);
                    previousCertificate->next = currentCertificate.get();
                    previousCertificate       = std::move(currentCertificate);
                }
            }

            if (!CertCloseStore(certificateStore, 0))
            {
                return NULL;
            }
        }
    }
    else
    {
        return NULL;
    }

    return ca_chain;
}

/**
 * @brief Main program entrypoint.
 *
 * @param argc      The count of arguments being passed to this application on launch.
 * @param argv      Pointer to array of argument data.
 *
 * @return 1 on error, 0 on success.
 */
int __cdecl main(int argc, char* argv[])
{
    argparse::ArgumentParser args("xiloader", "0.0");

    // NOTE: .append() is used to allow multiple arguments to be passed to the same option.
    //     : Otherwise it will throw on repeated arguments (normally accidental).

    args.add_argument("--server")
        .help("The server address to connect to.")
        .append();

    args.add_argument("--user", "--username")
        .help("The username being logged in with.")
        .append();

    args.add_argument("--pass", "--password")
        .help("The password being logged in with.")
        .append();

    args.add_argument("--otp", "--otp-code")
        .help("The otp code being logged in with.")
        .append();

    args.add_argument("--email", "--email")
        .help("The email being logged in with.")
        .append();

    args.add_argument("--serverport")
        .scan<'i', uint16_t>()
        .help("(optional) The server's lobby port to connect to.")
        .append();

    args.add_argument("--dataport")
        .scan<'i', uint16_t>()
        .help("(optional) The login server data port to connect to.")
        .append();

    args.add_argument("--viewport")
        .scan<'i', uint16_t>()
        .help("(optional) The login view port to connect to.")
        .append();

    args.add_argument("--authport")
        .scan<'i', uint16_t>()
        .help("(optional) The login auth port to connect to.")
        .append();

    args.add_argument("--lang")
        .help("(optional) The language of your FFXI install: JP/US/EU (0/1/2).")
        .append();

    args.add_argument("--hairpin")
        .implicit_value(true)
        .help("(optional) Use this if connecting to a local server which you have exposed publicly. This should not have to be used if you are connecting to a remote server.")
        .append();

    args.add_argument("--hide")
        .implicit_value(true)
        .help("(optional) Determines whether or not to hide the console window after FFXI starts.")
        .append();

    args.add_argument("--trust")
        .implicit_value(true)
        .help("(optional) Trust this computer for 30 days, skipping 2FA on subsequent logins.")
        .append();

    args.add_argument("--friends")
        .implicit_value(true)
        .default_value(false)
        .help("(optional) Enable friend list system (requires profile server).");

    args.add_argument("--no-friends")
        .implicit_value(true)
        .default_value(false)
        .help("(optional) Disable friend list system (default).");

    args.add_argument("--no-pol-push")
        .implicit_value(true)
        .default_value(false)
        .help("(optional) Disable the POL push channel (live friend status). Diagnostic only.");

    args.add_argument("--json", "--json-file")
        .help("(optional) The json file to load arguments in from")
        .append();

    try
    {
        args.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << args;
        std::exit(1);
    }

    globals::g_ServerAddress = args.is_used("--server") ? args.get<std::string>("--server") : globals::g_ServerAddress;
    globals::g_ServerPort    = args.is_used("--serverport") ? args.get<uint16_t>("--serverport") : globals::g_ServerPort;

    globals::g_LoginDataPort = args.is_used("--dataport") ? args.get<uint16_t>("--dataport") : globals::g_LoginDataPort;
    globals::g_LoginViewPort = args.is_used("--viewport") ? args.get<uint16_t>("--viewport") : globals::g_LoginViewPort;
    globals::g_LoginAuthPort = args.is_used("--authport") ? args.get<uint16_t>("--authport") : globals::g_LoginAuthPort;

    globals::g_Username = args.is_used("--user") ? args.get<std::string>("--user") : globals::g_Username;
    globals::g_Password = args.is_used("--pass") ? args.get<std::string>("--pass") : globals::g_Password;
    globals::g_OtpCode  = args.is_used("--otp") ? args.get<std::string>("--otp") : globals::g_OtpCode;
    globals::g_Email    = args.is_used("--email") ? args.get<std::string>("--email") : globals::g_Email;

    std::string jsonFilename = args.is_used("--json") ? args.get<std::string>("--json") : std::string {};

    if (args.is_used("--user") && args.is_used("--pass"))
    {
        globals::g_FirstLogin = true;
    }

    auto setLanguage = [&](std::string language)
    {
        if (!language.empty())
        {
            if (!_strnicmp(language.c_str(), "JP", 2) || !_strnicmp(language.c_str(), "0", 1))
            {
                globals::g_Language = xiloader::Language::Japanese;
            }
            if (!_strnicmp(language.c_str(), "US", 2) || !_strnicmp(language.c_str(), "1", 1))
            {
                globals::g_Language = xiloader::Language::English;
            }
            if (!_strnicmp(language.c_str(), "EU", 2) || !_strnicmp(language.c_str(), "2", 1))
            {
                globals::g_Language = xiloader::Language::European;
            }
        }
    };

    if (args.is_used("--lang"))
    {
        std::string language = args.get<std::string>("--lang");

        setLanguage(language);
    }

    bool bUseHairpinFix = args.is_used("--hairpin") ? args.get<bool>("--hairpin") : false;

    globals::g_Hide = args.is_used("--hide") ? args.get<bool>("--hide") : globals::g_Hide;

    globals::g_TrustThisComputer = args.is_used("--trust") ? args.get<bool>("--trust") : globals::g_TrustThisComputer;

    if (args.is_used("--friends"))
        globals::g_EnableFriends = true;
    if (args.is_used("--no-friends"))
        globals::g_EnableFriends = false;
    if (args.is_used("--no-pol-push"))
        globals::g_EnablePolPush = false;

    /* Live friend status is part of the friend list, not a separate feature:
     * it only runs when the friend system does. --no-pol-push stays as a
     * diagnostic lever for isolating push-related faults. */
    globals::g_EnablePolPush = globals::g_EnablePolPush && globals::g_EnableFriends;


    bool readInJsonArgs = false;
    if (!jsonFilename.empty())
    {
        std::string extension = ".json";

        bool endsInJsonExtension = std::equal(extension.rbegin(), extension.rend(), jsonFilename.rbegin());

        if (endsInJsonExtension && std::filesystem::exists(jsonFilename))
        {
            std::ifstream jsonFile(jsonFilename);
            json          jsonData = json::parse(jsonFile, nullptr, false);

            jsonFile.close();

            if (jsonData.is_discarded()) // not valid json
            {
                xiloader::console::output(xiloader::color::error, "--json was specified but the file at the input arg is not valid json");
                return 1;
            }
            else
            {
                readInJsonArgs = true;

                auto maybeUsername = jsonGet<std::string>(jsonData, "username");
                auto maybePassword = jsonGet<std::string>(jsonData, "password");

                globals::g_Username = maybeUsername.value_or(globals::g_Username);
                globals::g_Password = maybePassword.value_or(globals::g_Password);

                // Set autologin if it isn't set already
                if (maybeUsername.has_value() && maybePassword.has_value())
                {
                    globals::g_FirstLogin = true;
                }

                globals::g_ServerAddress = jsonGet<std::string>(jsonData, "server").value_or(globals::g_ServerAddress);
                globals::g_ServerPort    = jsonGet<uint16_t>(jsonData, "serverport").value_or(globals::g_ServerPort);

                globals::g_LoginDataPort = jsonGet<uint16_t>(jsonData, "dataport").value_or(globals::g_LoginDataPort);
                globals::g_LoginViewPort = jsonGet<uint16_t>(jsonData, "viewport").value_or(globals::g_LoginViewPort);
                globals::g_LoginAuthPort = jsonGet<uint16_t>(jsonData, "authport").value_or(globals::g_LoginAuthPort);

                // try string and int
                auto maybeOtpString = jsonGet<std::string>(jsonData, "otp");
                auto maybeOtpInt    = jsonGet<uint32_t>(jsonData, "otp");

                if (maybeOtpString.has_value())
                {
                    globals::g_OtpCode = maybeOtpString.value();
                }
                else if (maybeOtpInt.has_value())
                {
                    globals::g_OtpCode = std::to_string(maybeOtpInt.value());
                }

                globals::g_OtpCode = jsonGet<std::string>(jsonData, "otp").value_or(globals::g_OtpCode);
                globals::g_Email   = jsonGet<std::string>(jsonData, "email").value_or(globals::g_Email);

                bUseHairpinFix               = jsonGet<bool>(jsonData, "hairpin").value_or(bUseHairpinFix);
                globals::g_Hide              = jsonGet<bool>(jsonData, "hide").value_or(globals::g_Hide);
                globals::g_TrustThisComputer = jsonGet<bool>(jsonData, "trust_this_computer").value_or(globals::g_TrustThisComputer);
                globals::g_EnableFriends     = jsonGet<bool>(jsonData, "friends").value_or(globals::g_EnableFriends);
                globals::g_EnablePolPush     = jsonGet<bool>(jsonData, "pol_push").value_or(globals::g_EnablePolPush);

                std::string language = jsonGet<std::string>(jsonData, "language").value_or({});

                setLanguage(language);
            }
        }
        else
        {
            xiloader::console::output(xiloader::color::error, "--json was specified but the file at the input arg does not exist.");
            return 1;
        }
    }

    std::array<uint8_t, 3> version = globals::g_VersionNumber;

    /* Output the banner.. */
    time_t currentTime = time(NULL);
    int currentYear = localtime(&currentTime)->tm_year + 1900;  // Year is returned as the number of years since 1900.
    xiloader::console::output(xiloader::color::lightred, "==========================================================");
    xiloader::console::output(xiloader::color::lightgreen, "DarkStar Boot Loader (c) 2015 DarkStar Team");
    xiloader::console::output(xiloader::color::lightgreen, "LandSandBoat Boot Loader (c) 2021-%d LandSandBoat Team (v%u.%u.%u)", currentYear, version[0], version[1], version[2]);
    xiloader::console::output(xiloader::color::lightblue, "Using %s", MBEDTLS_VERSION_STRING_FULL); // this prints "Using Mbed TLS #.#.#"
    xiloader::console::output(xiloader::color::lightpurple, "Git Repo   : https://github.com/LandSandBoat/xiloader");
    xiloader::console::output(xiloader::color::lightpurple, "Bug Reports: https://github.com/LandSandBoat/xiloader/issues");
    xiloader::console::output(xiloader::color::lightred, "==========================================================");

    if (readInJsonArgs)
    {
        xiloader::console::output(xiloader::color::info, "Read in arguments from json file.");
    }

    /* Initialize Winsock */
    WSADATA wsaData = { 0 };
    auto ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize winsock, error code: %d", ret);
        return 1;
    }

    /* Initialize COM */
    auto hResult = CoInitialize(NULL);
    if (hResult != S_OK && hResult != S_FALSE)
    {
        /* Cleanup Winsock */
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to initialize COM, error code: %d", hResult);
        return 1;
    }

    /* Attach detour for gethostbyname.. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourAttach(&(PVOID&)Real_send, Mine_send);
    DetourAttach(&(PVOID&)Real_recv, Mine_recv);
    DetourAttach(&(PVOID&)Real_connect, Mine_connect);
    DetourAttach(&(PVOID&)Real_CreateFileA, Mine_CreateFileA);
    DetourAttach(&(PVOID&)Real_FindFirstFileA, Mine_FindFirstFileA);
    DetourAttach(&(PVOID&)Real_MoveFileA, Mine_MoveFileA);
    DetourAttach(&(PVOID&)Real_DeleteFileA, Mine_DeleteFileA);
    DetourAttach(&(PVOID&)Real_MoveFileExA, Mine_MoveFileExA);
    DetourAttach(&(PVOID&)Real_CreateDirectoryA, Mine_CreateDirectoryA);
    DetourAttach(&(PVOID&)Real_CreateDirectoryExA, Mine_CreateDirectoryExA);
    DetourAttach(&(PVOID&)Real_RemoveDirectoryA, Mine_RemoveDirectoryA);
    DetourAttach(&(PVOID&)Real_GetFileAttributesA, Mine_GetFileAttributesA);
    DetourAttach(&(PVOID&)Real_SetFileAttributesA, Mine_SetFileAttributesA);
    DetourAttach(&(PVOID&)Real_CopyFileA, Mine_CopyFileA);
    DetourAttach(&(PVOID&)Real_CreateFileW, Mine_CreateFileW);
    if (DetourTransactionCommit() != NO_ERROR)
    {
        /* Cleanup COM and Winsock */
        CoUninitialize();
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to detour function 'gethostbyname'. Cannot continue!");
        return 1;
    }

    // init mbed tls
    mbedtls_net_init(&sslState::server_fd);
    mbedtls_ssl_init(&sslState::ssl);
    mbedtls_ssl_config_init(&sslState::conf);
    mbedtls_x509_crt_init(&sslState::cacert);
    mbedtls_ctr_drbg_init(&sslState::ctr_drbg);
    mbedtls_entropy_init(&sslState::entropy);

    const char* pers = "xiloader";

    if ((ret = mbedtls_ctr_drbg_seed(&sslState::ctr_drbg, mbedtls_entropy_func, &sslState::entropy,
                                     (const unsigned char*)pers,
                                     strlen(pers))) != 0)
    {
        xiloader::console::output(xiloader::color::error, "mbedtls_ctr_drbg_seed failed!");
        return 1;
    }

    sslState::ca_chain = build_windows_ca_chain();

    /* Attempt to resolve the server address.. */
    ULONG ulAddress = 0;

    xiloader::console::output(xiloader::color::info, "Resolving '%s' ...", globals::g_ServerAddress.c_str());

    if (xiloader::network::ResolveHostname(globals::g_ServerAddress.c_str(), &ulAddress))
    {
        globals::g_ServerAddress = inet_ntoa(*((struct in_addr*)&ulAddress));

        xiloader::console::output(xiloader::color::info, "Resolved server address to '%s:%d'", globals::g_ServerAddress.c_str(), globals::g_LoginAuthPort);

        /* Attempt to create socket to server..*/
        xiloader::datasocket sock;
        SOCKET               polsock;
        std::string          authport   = std::to_string(globals::g_LoginAuthPort);
        std::string          loginport  = std::to_string(globals::g_LoginDataPort);
        std::string          serverport = std::to_string(globals::g_ServerPort);

        if (xiloader::network::CreateAuthConnection(&sock, authport.c_str()))
        {
            /* Attempt to verify the users account info.. */
            while (!xiloader::network::VerifyAccount(&sock))
                Sleep(10);

            /* Attempt to create connection to the login server.. */
            if (!xiloader::network::CreateConnection(&sock, loginport.c_str()))
            {
                sock.s  = INVALID_SOCKET;
                int err = WSAGetLastError();
                xiloader::console::output(xiloader::color::error, "Failed to initialize connection to server on port %s, winsock error: %d", loginport.c_str(), err);
            }

            /* Attempt to create listening server for POL thread*/
            if (!xiloader::network::CreateListenServer(&polsock, IPPROTO_TCP, serverport.c_str()))
            {
                polsock = INVALID_SOCKET;
                int err = WSAGetLastError();
                xiloader::console::output(xiloader::color::error, "Failed to initialize listen server on port %s, winsock error: %d", serverport.c_str(), err);
            }

            // Check if sockets are invalid
            if (sock.s != INVALID_SOCKET && polsock != INVALID_SOCKET)
            {
                /* Start hairpin hack thread if required.. */
                if (bUseHairpinFix)
                {
                    // TODO: this is not terminated? Does it need to be?
                    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApplyHairpinFixThread, NULL, 0, NULL);
                }

                struct sockaddr_in pol_sin;
                int                pol_len           = sizeof(pol_sin);
                unsigned short     profileServerPort = 0;

                if (getsockname(polsock, (struct sockaddr*)&pol_sin, &pol_len) == 0)
                {
                    profileServerPort = ntohs(pol_sin.sin_port);
                }

                /* Create listen servers.. */
                globals::g_IsRunning = true;

                /* Suppress polcore's internal debug output from leaking into
                 * the console window. Anything we want logged goes through
                 * xiloader::console::output which still writes xiloader.log. */
                {
                    FILE* dummy = nullptr;
                    freopen_s(&dummy, "NUL", "w", stdout);
                }
                HANDLE hFFXiServer   = CreateThread(NULL, 0, xiloader::network::FFXiServer, &sock, 0, NULL);
                HANDLE hPolServer    = CreateThread(NULL, 0, xiloader::network::PolServer, &polsock, 0, NULL);

                /* Attempt to create polcore instance..*/
                IPOLCoreCom* polcore = NULL;
                if (CoCreateInstance(xiloader::CLSID_POLCoreCom[globals::g_Language], NULL, 0x17, xiloader::IID_IPOLCoreCom[globals::g_Language], (LPVOID*)&polcore) != S_OK)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
                }
                else
                {
                    /* _pcnt N (N in [1..3]) is the player-count arg POL
                     * passes at game launch. FFXi's FUN_047121E0 parses it
                     * via FUN_04611F40 -> struct[+0xC] -> arg1 of FUN_046FFFD0
                     * (friend system init). Without _pcnt, FUN_046FFFD0 sees
                     * arg1=0 and returns silently without running init,
                     * leaving DAT_04AEE900 NULL so inbox menu actions fail
                     * on the polcore side. _pcnt 1 reproduces POL's
                     * standard single-player launch. */
                    std::string polcorecmd = " /game eAZcFcB -net 3 -port " + std::to_string(globals::g_LoginViewPort) + " _pcnt 1";
                    // Cast to an LPSTR
                    LPSTR cmd = const_cast<char*>(polcorecmd.c_str());
                    polcore->SetAreaCode(globals::g_Language);
                    polcore->SetParamInit(GetModuleHandle(NULL), cmd);

                    /* Obtain the common function table.. */
                    void* (**lpCommandTable)(...);
                    polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable);

                    /* Invoke the inet mutex function.. */
                    auto findMutex = (void* (*)(...))FindINETMutex();
                    findMutex();

                    /* Locate and prepare the pol connection.. */
                    auto polConnection = (char*)FindPolConn();
                    memset(polConnection, 0x00, 0x68);
                    auto enc = (char*)malloc(0x1000);
                    memset(enc, 0x00, 0x1000);
                    memcpy(polConnection + 0x48, &enc, sizeof(char**));

                    /* Locate the character storage buffer.. */
                    globals::g_CharacterList = (char*)FindCharacters((void**)lpCommandTable);

                    /* Invoke the setup functions for polcore.. */
                    lpCommandTable[POLFUNC_REGISTRY_LANG](globals::g_Language);
                    lpCommandTable[POLFUNC_FFXI_LANG](xiloader::functions::GetRegistryPlayOnlineLanguage(globals::g_Language));
                    lpCommandTable[POLFUNC_REGISTRY_KEY](xiloader::functions::GetRegistryPlayOnlineKey(globals::g_Language));
                    lpCommandTable[POLFUNC_INSTALL_FOLDER](xiloader::functions::GetRegistryPlayOnlineInstallFolder(globals::g_Language));
                    lpCommandTable[POLFUNC_INET_MUTEX]();

                    if (!SetProfileServerPort(profileServerPort))
                    {
                        return 1;
                    }

                    /* Bootstrap friend system */
                    if (globals::g_EnableFriends)
                        friend_system::bootstrap(polcore);

                    /* Attempt to create FFXi instance..*/
                    IFFXiEntry* ffxi = NULL;
                    if (CoCreateInstance(xiloader::CLSID_FFXiEntry, NULL, 0x17, xiloader::IID_IFFXiEntry, (LPVOID*)&ffxi) != S_OK)
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of FFxi!");
                    }
                    else
                    {
                        /* Attempt to start Final Fantasy.. */
                        IUnknown* message = NULL;
                        xiloader::console::hide();
                        ffxi->GameStart(polcore, &message);
                        xiloader::console::show();
                        ffxi->Release();
                    }

                    /* Cleanup polcore object.. */
                    if (polcore != NULL)
                        polcore->Release();
                }

                /* Cleanup threads.. */
                globals::g_IsRunning = false;
                TerminateThread(hFFXiServer, 0);
                TerminateThread(hPolServer, 0);

                WaitForSingleObject(hFFXiServer, 1000);
                WaitForSingleObject(hPolServer, 1000);

                CloseHandle(hFFXiServer);
                CloseHandle(hPolServer);
            }
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
    }

    mbedtls_net_free(&sslState::server_fd);
    mbedtls_ssl_free(&sslState::ssl);
    mbedtls_ssl_config_free(&sslState::conf);
    mbedtls_ctr_drbg_free(&sslState::ctr_drbg);
    mbedtls_entropy_free(&sslState::entropy);
    mbedtls_x509_crt_free(&sslState::cacert);

    sslState::ca_chain = nullptr;

    /* Shutdown friend system */
    friend_system::shutdown();

    /* Detach detour for gethostbyname. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourDetach(&(PVOID&)Real_send, Mine_send);
    DetourDetach(&(PVOID&)Real_recv, Mine_recv);
    DetourDetach(&(PVOID&)Real_connect, Mine_connect);
    DetourDetach(&(PVOID&)Real_CreateFileA, Mine_CreateFileA);
    DetourDetach(&(PVOID&)Real_FindFirstFileA, Mine_FindFirstFileA);
    DetourDetach(&(PVOID&)Real_MoveFileA, Mine_MoveFileA);
    DetourDetach(&(PVOID&)Real_DeleteFileA, Mine_DeleteFileA);
    DetourDetach(&(PVOID&)Real_MoveFileExA, Mine_MoveFileExA);
    DetourDetach(&(PVOID&)Real_CreateDirectoryA, Mine_CreateDirectoryA);
    DetourDetach(&(PVOID&)Real_CreateDirectoryExA, Mine_CreateDirectoryExA);
    DetourDetach(&(PVOID&)Real_RemoveDirectoryA, Mine_RemoveDirectoryA);
    DetourDetach(&(PVOID&)Real_GetFileAttributesA, Mine_GetFileAttributesA);
    DetourDetach(&(PVOID&)Real_SetFileAttributesA, Mine_SetFileAttributesA);
    DetourDetach(&(PVOID&)Real_CopyFileA, Mine_CopyFileA);
    DetourDetach(&(PVOID&)Real_CreateFileW, Mine_CreateFileW);
    DetourTransactionCommit();

    /* Cleanup COM and Winsock */
    CoUninitialize();
    WSACleanup();

    xiloader::console::output(xiloader::color::error, "Closing...");
    Sleep(2000);

    return ERROR_SUCCESS;
}
