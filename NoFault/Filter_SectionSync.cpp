#include "Filter.h"

VOID LogSectionSyncBlock(
    _Inout_ PFLT_CALLBACK_DATA Data
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;

    // Get requested filename
    CleanUpWithStatusIfFailed(FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo));
    CleanUpWithStatusIfFailed(FltParseFileNameInformation(pNameInfo));

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "NoFault: Blocked load of image: %wZ\n", &pNameInfo->Name);

    Cleanup:
    if (pNameInfo)
    {
        FltReleaseFileNameInformation(pNameInfo);
    }

    return;
}

#define PAGE_EXECUTE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY)

FLT_PREOP_CALLBACK_STATUS
PreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS cbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    HANDLE hProcess = NULL;
    PEPROCESS pProcess = FltGetRequestorProcess(Data);;
    FILE_ATTRIBUTE_TAG_INFORMATION fileTagInfo = { 0 };

    UNREFERENCED_PARAMETER(CompletionContext);

    // We're only interested in SyncType == SyncTypeCreateSection w/ SEC_IMAGE == AllocationAttributes
    CleanUpWithStatusIf(SyncTypeCreateSection != Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType,
        STATUS_SUCCESS);
    // PAGE_EXECUTE_FLAGS and/or SEC_IMAGE could be set
    CleanUpWithStatusIf(
        !FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection, PAGE_EXECUTE_FLAGS) &&
        !FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.AllocationAttributes, SEC_IMAGE),
        STATUS_SUCCESS);

    // Ignore system worker threads, actions taken by System process, and PreviousMode == KernelMode
    CleanUpWithStatusIf(PsIsSystemThread(Data->Thread), STATUS_SUCCESS);
    CleanUpWithStatusIf(pProcess == PsInitialSystemProcess, STATUS_SUCCESS);
    CleanUpWithStatusIf(KernelMode == GetCreateIrpEffectiveMode(Data), STATUS_SUCCESS);

    // Figure out whether this is a PPL we care about.  PsGetProcessProtection is undoc.  Try to stay doc
    CleanUpWithStatusIfFailed(ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hProcess));
    CleanUpWithStatusIf(!ShouldHardenProcess(hProcess), STATUS_SUCCESS);

    // Check whether it's a CloudFilter reparse tag
    CleanUpWithStatusIf(!IsInterestingReparsePoint(Data, FltObjects), STATUS_SUCCESS);

    // At this point, we have a IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION for a SEC_IMAGE in a PPL to a CloudFilter placeholder.
    // Perform the block
    Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
    cbStatus = FLT_PREOP_COMPLETE;
    LogSectionSyncBlock(Data);

Cleanup:
    HandleDelete(hProcess);

    return cbStatus;
}
