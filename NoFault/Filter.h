#pragma once

#include "NoFault.h"

extern PFLT_FILTER gpFilter;
extern FILE_ID_INFORMATION gProtectedFiles[1];

NTSTATUS
RegisterFilter(_In_ PDRIVER_OBJECT pDriverObject);

VOID
UnregisterFilter();

NTSTATUS
FilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS InstanceSetupCallback(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
QueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);


FLT_PREOP_CALLBACK_STATUS
PreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

// Data->RequestorMode is KernelMode in many cases where you wouldn't expect it to be, such as async I/O and network redirectors.  
// SL_FORCE_ACCESS_CHECK is a better indicator of a UserMode requestor. See this writeup by James Forshaw: 
// https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html
// This function is based on the IRP_MJ_CREATE code for Ntfs!NtfsEffectiveMode from Win10 21H2 and Win11 22H2 (they match),
// decompiled here: https://gist.github.com/gabriellandau/d5cda8b3e42547bb12c86a6d2bf243b4#file-ntfseffectivemode-win11-22h2-c-L10-L19
KPROCESSOR_MODE GetCreateIrpEffectiveMode(PFLT_CALLBACK_DATA Data);

BOOLEAN IsInterestingReparsePoint(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects);
