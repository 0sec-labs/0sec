/*
 * Benign, never-loaded WDM-shaped partially hardened control fixture.
 *
 * This owned fixture differs from windows_ioctl_wdm.c only by the exact
 * InputBufferLength check protecting the four-byte SystemBuffer field read.
 * It deliberately does not claim to be a fully fixed copy control: the live
 * v2 guard schema cannot yet bind both remaining-source and destination-span
 * proofs required for full suppression.
 * It is compiled solely for static PyGhidra evidence tests and never exposes a
 * device, imports kernel APIs, or executes.
 */

typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;
typedef long NTSTATUS;
typedef void *PVOID;

struct _DEVICE_OBJECT;
struct _IRP;

typedef NTSTATUS (*PDRIVER_DISPATCH)(struct _DEVICE_OBJECT *, struct _IRP *);

typedef struct _DRIVER_OBJECT {
    USHORT Type;
    USHORT Size;
    PVOID DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    PVOID DriverName[2];
    PVOID HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PDRIVER_DISPATCH MajorFunction[28];
} DRIVER_OBJECT;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG InputBufferLength;
            ULONG IoControlCode;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION;

typedef struct _IRP {
    PVOID SystemBuffer;
    IO_STACK_LOCATION *CurrentStackLocation;
    ULONG IoStatus;
    ULONG Information;
} IRP;

typedef struct _DEVICE_OBJECT {
    PVOID Reserved;
} DEVICE_OBJECT;

static volatile UCHAR KernelSink[64];

__declspec(noinline) static void *RtlCopyMemory(
    void *destination,
    const void *source,
    unsigned long long count
) {
    UCHAR *output = (UCHAR *)destination;
    const UCHAR *input = (const UCHAR *)source;
    unsigned long long index;

    for (index = 0; index < count; ++index) {
        output[index] = input[index];
    }
    return destination;
}

__declspec(noinline) NTSTATUS DispatchDeviceControl(
    DEVICE_OBJECT *device,
    IRP *irp
) {
    IO_STACK_LOCATION *stack;

    (void)device;
    stack = irp->CurrentStackLocation;
    if (stack->Parameters.DeviceIoControl.IoControlCode == 0x222004UL) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG)) {
            return 0;
        }
        ULONG attacker_length = *(ULONG *)irp->SystemBuffer;
        RtlCopyMemory(
            (void *)KernelSink,
            (UCHAR *)irp->SystemBuffer + sizeof(ULONG),
            attacker_length
        );
    }
    return 0;
}

__declspec(dllexport) NTSTATUS DriverEntry(
    DRIVER_OBJECT *driver,
    PVOID registry_path
) {
    (void)registry_path;
    driver->MajorFunction[14] = DispatchDeviceControl;
    return 0;
}
