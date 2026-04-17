#include "Filter.h"

KPROCESSOR_MODE GetCreateIrpEffectiveMode(PFLT_CALLBACK_DATA Data)
{
    if (!Data)
    {
        return ExGetPreviousMode();
    }

    NT_ASSERT(IRP_MJ_CREATE == Data->Iopb->MajorFunction);

    if (FlagOn(Data->Iopb->OperationFlags, SL_FORCE_ACCESS_CHECK))
    {
        return UserMode;
    }

    return Data->RequestorMode;
}

BOOLEAN IsInterestingReparsePoint(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BOOLEAN bResult = FALSE;
    FILE_ATTRIBUTE_TAG_INFORMATION fileTagInfo = { 0 };

    CleanUpWithStatusIf(!Data || !FltObjects->Instance || !Data->Iopb->TargetFileObject, STATUS_INVALID_PARAMETER);

    CleanUpWithStatusIfFailed(FltQueryInformationFile(FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        &fileTagInfo,
        sizeof(fileTagInfo),
        FileAttributeTagInformation,
        NULL));

    // Check whether it's a CloudFilter tag.
    // Not sure whether I can just test against IO_REPARSE_TAG_CLOUD_MASK?
    switch (fileTagInfo.ReparseTag)
    {
    case IO_REPARSE_TAG_CLOUD:
    case IO_REPARSE_TAG_CLOUD_1:
    case IO_REPARSE_TAG_CLOUD_2:
    case IO_REPARSE_TAG_CLOUD_3:
    case IO_REPARSE_TAG_CLOUD_4:
    case IO_REPARSE_TAG_CLOUD_5:
    case IO_REPARSE_TAG_CLOUD_6:
    case IO_REPARSE_TAG_CLOUD_7:
    case IO_REPARSE_TAG_CLOUD_8:
    case IO_REPARSE_TAG_CLOUD_9:
    case IO_REPARSE_TAG_CLOUD_A:
    case IO_REPARSE_TAG_CLOUD_B:
    case IO_REPARSE_TAG_CLOUD_C:
    case IO_REPARSE_TAG_CLOUD_D:
    case IO_REPARSE_TAG_CLOUD_E:
    case IO_REPARSE_TAG_CLOUD_F:
        bResult = TRUE;
        break;
    default:
        break;
    }

Cleanup:
    return bResult;
}
