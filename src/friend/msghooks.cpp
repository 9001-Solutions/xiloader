#include <winsock2.h>
#include <windows.h>
#include "detours/detours.h"
#include <filesystem>
#include <string>
#include <cstring>
#include <intrin.h>

#include "friend.h"
#include "../console.h"

/* Message-file redirection. polcore reads and writes message bodies under
 * PlayOnlineViewer/pub/homeNN/msg/...; every path containing "msg" is redirected
 * to <ashita-root>/msg/<accid>/... so nothing touches Program Files and each
 * account keeps its own inbox. */

namespace {

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
 * inbox/outbox files live under <ashita-root>/msg/<accid>/... so multiboxed
 * xiloader instances on the same machine don't see each other's mail.
 *
 * We re-initialize if g_AccountId changes (e.g., a re-login), since the
 * same xiloader process never serves two accounts in practice but the
 * accid may be 0 on the very first call (rare; would only happen if a
 * msg-path API is hit before VerifyAccount completes). In that case we
 * stamp a `_no_accid` subdir so the bug is obvious in logs and on disk. */
static void EnsureMsgDir()
{
    uint32_t accid = friend_system::account_id();
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

            /* Retail moves a read message r\b -> r\a; polcore only issues the
             * delete. Without the copy nothing records that the message was
             * read, and the next login rewrites it into r\b as unread.
             * Must skip deletes from xiloader itself -- the startup purge of
             * r\b would otherwise mark every unread message read. */
            HMODULE selfMod = GetModuleHandleA(NULL);
            const bool from_self = selfMod != nullptr &&
                (uintptr_t)ret_ip >= (uintptr_t)selfMod &&
                (uintptr_t)ret_ip < (uintptr_t)selfMod + 0x800000;
            const char* rb = strstr(redirected.c_str(), "\\r\\b\\");
            if (rb != nullptr && !from_self)
            {
                std::string dst = redirected;
                dst.replace(rb - redirected.c_str(), 5, "\\r\\a\\");
                CopyFileA(redirected.c_str(), dst.c_str(), FALSE);
            }

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

} // namespace

namespace friend_system {

void attach_msg_hooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
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
    DetourTransactionCommit();
}

void detach_msg_hooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
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
}

} // namespace friend_system
