#include "ProcessDisguiseKM.h"
#include <ntddk.h>
#include <ntstrsafe.h>

void* __cdecl operator new(size_t, void* ptr) {
    return ptr;
}

void __cdecl operator delete(void*, size_t) {

}

void __cdecl operator delete(void*) {

}

#define DEVICE_NAME L"\\Device\\Daku"
#define DEVICE_LINK_NAME L"\\??\\Daku"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define SystemProcessInformation 5
#define SystemExtendedProcessInformation 57

typedef NTSTATUS(NTAPI* pZwQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

pZwQuerySystemInformation g_OriginalZwQuerySystemInformation = NULL;
HANDLE g_TargetPid = NULL;
WCHAR g_SpoofName[MAX_PATH] = L"svchost.exe";

NTSTATUS FilterProcessList(PVOID SystemInformation) {
    if (!SystemInformation || !g_TargetPid) {
        return STATUS_SUCCESS;
    }

    __try {
        PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION pSvchost = NULL;
        BOOLEAN found = FALSE;

        PSYSTEM_PROCESS_INFORMATION pTemp = pCurrent;
        while (TRUE) {
            if (pTemp->UniqueProcessId == g_TargetPid) {
                found = TRUE;
            }

            if (pTemp->ImageName.Buffer && pTemp->ImageName.Length > 0) {
                if (_wcsicmp(pTemp->ImageName.Buffer, L"svchost.exe") == 0 &&
                    pTemp->UniqueProcessId != g_TargetPid) {
                    pSvchost = pTemp;
                }
            }

            if (pTemp->NextEntryOffset == 0) {
                break;
            }
            pTemp = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pTemp + pTemp->NextEntryOffset);
        }

        if (!found) {
            return STATUS_SUCCESS;
        }

        pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        while (TRUE) {
            if (pCurrent->UniqueProcessId == g_TargetPid) {
                if (pCurrent->ImageName.Buffer && pCurrent->ImageName.MaximumLength > 0) {
                    SIZE_T spoofLen = wcslen(g_SpoofName) * sizeof(WCHAR);

                    if (pCurrent->ImageName.MaximumLength >= spoofLen + sizeof(WCHAR)) {
                        RtlZeroMemory(pCurrent->ImageName.Buffer, pCurrent->ImageName.MaximumLength);
                        RtlCopyMemory(pCurrent->ImageName.Buffer, g_SpoofName, spoofLen);
                        pCurrent->ImageName.Length = (USHORT)spoofLen;

                    }

                    if (pSvchost) {
                        pCurrent->WorkingSetPrivateSize.QuadPart = pSvchost->WorkingSetPrivateSize.QuadPart + (pSvchost->WorkingSetPrivateSize.QuadPart / 20);
                        pCurrent->PeakVirtualSize = pSvchost->PeakVirtualSize + (pSvchost->PeakVirtualSize / 10);
                        pCurrent->VirtualSize = pSvchost->VirtualSize + (pSvchost->VirtualSize / 15);
                        pCurrent->PeakWorkingSetSize = pSvchost->PeakWorkingSetSize + (pSvchost->PeakWorkingSetSize / 20);
                        pCurrent->WorkingSetSize = pSvchost->WorkingSetSize + (pSvchost->WorkingSetSize / 20);
                        pCurrent->PagefileUsage = pSvchost->PagefileUsage + (pSvchost->PagefileUsage / 10);
                        pCurrent->PeakPagefileUsage = pSvchost->PeakPagefileUsage + (pSvchost->PeakPagefileUsage / 10);
                        pCurrent->PrivatePageCount = pSvchost->PrivatePageCount + (pSvchost->PrivatePageCount / 15);
                        pCurrent->BasePriority = pSvchost->BasePriority;
                        pCurrent->HandleCount = pSvchost->HandleCount + (pSvchost->HandleCount / 10);
                        pCurrent->SessionId = 0;

                    }
                }
                break;
            }

            if (pCurrent->NextEntryOffset == 0) {
                break;
            }
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI HookedZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status;

    if (!g_OriginalZwQuerySystemInformation) {
        return STATUS_UNSUCCESSFUL;
    }

    status = g_OriginalZwQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (NT_SUCCESS(status) && SystemInformation && g_TargetPid) {
        if (SystemInformationClass == SystemProcessInformation ||
            SystemInformationClass == SystemExtendedProcessInformation) {
            FilterProcessList(SystemInformation);
        }
    }

    return status;
}

NTSTATUS InstallIrpFilter() {

    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"ZwQuerySystemInformation");

    g_OriginalZwQuerySystemInformation = (pZwQuerySystemInformation)MmGetSystemRoutineAddress(&funcName);

    if (!g_OriginalZwQuerySystemInformation) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

VOID RemoveIrpFilter() {
    g_OriginalZwQuerySystemInformation = NULL;
    g_TargetPid = NULL;
}

VOID SetSpoofTarget(HANDLE Pid, PCWSTR SpoofedName) {
    g_TargetPid = Pid;

    if (SpoofedName) {
        RtlStringCbCopyW(g_SpoofName, sizeof(g_SpoofName), SpoofedName);
    } else {
        RtlStringCbCopyW(g_SpoofName, sizeof(g_SpoofName), L"svchost.exe");
    }

               (ULONG)(ULONG_PTR)Pid, g_SpoofName);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS CreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING deviceName, linkName;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&linkName, DEVICE_LINK_NAME);

    status = IoCreateDevice(
        pDriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDeviceObject
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = IoCreateSymbolicLink(&linkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDeviceObject);
        return status;
    }

    pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    pDriverObject->DriverUnload = DriverUnload;

    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = InstallIrpFilter();
    if (!NT_SUCCESS(status)) {

    }

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{

    RemoveIrpFilter();

    UNICODE_STRING linkName;
    RtlInitUnicodeString(&linkName, DEVICE_LINK_NAME);

    IoDeleteSymbolicLink(&linkName);

    if (pDriverObject->DeviceObject)
    {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }

}

NTSTATUS CreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    ULONG dwIoControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    PVOID pInputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG dwInputLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    pIrp->IoStatus.Information = 0;

    switch (dwIoControlCode)
    {
        case CTL_CODE_FAKEPROCESS_BY_PID:
        {
            if (dwInputLength != sizeof(HANDLE))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            HANDLE dwPid = *(PHANDLE)pInputBuffer;

            SetSpoofTarget(dwPid, L"svchost.exe");

            FakeProcess* pFakeProcess = (FakeProcess*)ExAllocatePoolWithTag(NonPagedPool, sizeof(FakeProcess), 'kaeF');

            if (pFakeProcess)
            {

                ::new(pFakeProcess) FakeProcess(dwPid);

                pFakeProcess->~FakeProcess();

                ExFreePoolWithTag(pFakeProcess, 'kaeF');

                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }

            break;
        }

        default:
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}