#include "scan.h"
#include <psapi.h>

/* Page-walking pattern scan. Upstream functions::FindPattern reads the whole
 * image linearly and faults on uncommitted section padding inside polcore and
 * FFXiMain, so the friend system carries its own copy. */
namespace friend_scan {
    bool MaskCompare(const unsigned char* lpDataPtr, const unsigned char* lpPattern, const char* pszMask)
    {
        for (; *pszMask; ++pszMask, ++lpDataPtr, ++lpPattern)
        {
            if (*pszMask == 'x' && *lpDataPtr != *lpPattern)
                return false;
        }
        return (*pszMask) == NULL;
    }

    static bool isReadableAddress(const void* p)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
            return false;
        if (mbi.State != MEM_COMMIT)
            return false;
        DWORD prot = mbi.Protect & 0xFF;
        return prot == PAGE_READONLY || prot == PAGE_READWRITE ||
               prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
               prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
    }

    DWORD FindPattern(const char* moduleName, const unsigned char* lpPattern, const char* pszMask)
    {
        MODULEINFO mod = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(moduleName), &mod, sizeof(MODULEINFO)))
            return 0;

        /* Walk page-by-page so uncommitted pages inside the reserved image
         * range (some PE images have these as section padding) don't abort
         * the scan. Within each committed page, fall back to a per-iteration
         * SEH guard so a page-boundary-straddling read into an uncommitted
         * neighbor is also survivable. */
        const DWORD imgBase = (DWORD)mod.lpBaseOfDll;
        const DWORD imgEnd  = imgBase + mod.SizeOfImage;
        const DWORD PAGE    = 0x1000;

        for (DWORD pageStart = imgBase; pageStart < imgEnd; pageStart += PAGE)
        {
            if (!isReadableAddress((const void*)pageStart))
                continue;

            const DWORD pageEnd = (pageStart + PAGE < imgEnd) ? pageStart + PAGE : imgEnd;
            for (DWORD x = pageStart; x < pageEnd; x++)
            {
                bool matched = false;
                __try
                {
                    matched = MaskCompare(reinterpret_cast<unsigned char*>(x), lpPattern, pszMask);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { matched = false; }
                if (matched)
                    return x;
            }
        }
        return 0;
    }
}
