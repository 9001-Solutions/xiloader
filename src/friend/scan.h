#pragma once
#include <winsock2.h>
#include <windows.h>

namespace friend_scan {
    bool  MaskCompare(const unsigned char* lpDataPtr, const unsigned char* lpPattern, const char* pszMask);
    DWORD FindPattern(const char* moduleName, const unsigned char* lpPattern, const char* pszMask);
}
