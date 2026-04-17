#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <string>

bool BuildPayload(
    HANDLE hBenignDll,
    std::string& payloadBuffer,
	DWORD elevateThreadId);

PVOID FindKTHREAD(DWORD dwThreadId);
bool BlessThread(DWORD dwThreadId, bool bFatal);

#define ValidHandle(_x) ((NULL != (_x)) && (INVALID_HANDLE_VALUE != (_x)))
#define InvalidHandle(_x) (!(ValidHandle(_x)))
