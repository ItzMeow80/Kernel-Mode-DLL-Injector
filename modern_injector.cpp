// modern_injector.cpp — driver WDM x64: mappa manualmente una DLL in un processo
// e lancia DllMain hijackando un thread del PROCESSO TARGET.
//
// Il driver riceve dal loader (user-mode): TargetPid, TargetTid, percorso DLL.
// Tutte le API usate sono dichiarate manualmente come export di ntoskrnl x64
// (il WDK 10.0.26100 non le dichiara tutte, ma le funzioni sono nella import lib).
//
// NB: shellcode x64 → compila/build solo per x64.
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define DEVICE_NAME    L"\\Device\\ModernInjector"
#define SYMBOLIC_NAME  L"\\DosDevices\\ModernInjector"
#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define POOL_TAG       'DLLX'
#define MAX_DLL_BYTES  (64LL * 1024 * 1024)

// export ntoskrnl presenti in Lib\...\km\x64\ntoskrnl.lib ma non dichiarati nei header 26100
extern "C" {
    NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(
        PEPROCESS SourceProcess, PVOID SourceAddress,
        PEPROCESS TargetProcess, PVOID TargetAddress,
        SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
    NTSYSAPI NTSTATUS NTAPI ZwSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
    NTSYSAPI NTSTATUS NTAPI ZwResumeThread(HANDLE ThreadHandle);
    NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtection, PULONG OldProtection);
    NTSYSAPI NTSTATUS NTAPI PsGetContextThread(HANDLE ThreadHandle, PCONTEXT Context, KPROCESSOR_MODE PreviousMode);
    NTSYSAPI NTSTATUS NTAPI PsSetContextThread(HANDLE ThreadHandle, PCONTEXT Context, KPROCESSOR_MODE PreviousMode);
}

// --- strutture per enumerare processo/thread via ZwQuerySystemInformation
typedef struct _SYSTEM_THREAD_MIN_INFO {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_MIN_INFO;

typedef struct _SYSTEM_PROCESS_MIN_INFO {
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
    LONG BasePriority;
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
} SYSTEM_PROCESS_MIN_INFO;

// shellcode x64: sub rsp,0x20; movabs rax,<remoteBase>; mov rcx,rax; mov rdx,1
// (DLL_PROCESS_ATTACH); xor r8d,r8d; movabs rax,<entry>; call rax; add rsp,0x20; ret
static UCHAR g_shellcode[] = {
    0x48, 0x83, 0xEC, 0x20,
    0x48, 0xB8, 0,0,0,0,0,0,0,0,        // +6  : remoteBase
    0x48, 0x89, 0xC1,                   // mov rcx, rax
    0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1
    0x45, 0x31, 0xC0,                   // xor r8d, r8d
    0x48, 0xB8, 0,0,0,0,0,0,0,0,        // +29 : entry
    0xFF, 0xD0,                         // call rax
    0x48, 0x83, 0xC4, 0x20,
    0xC3
};
static_assert(sizeof(g_shellcode) == 44, "offset shellcode non coerente");

struct InjectionRequest {
    ULONG TargetPid;
    ULONG TargetTid;
    WCHAR DllPath[260];
};

struct HandleCloser {
    HANDLE handle;
    explicit HandleCloser(HANDLE h) : handle(h) {}
    ~HandleCloser() { if (handle) ZwClose(handle); }
};

// Alloca remoteBase/shellBase nello spazio del target; buttali via se serve.
static NTSTATUS AllocInTarget(PEPROCESS target, SIZE_T bytes, ULONG protect,
                              PVOID* base, KAPC_STATE* apcState, BOOLEAN* attached)
{
    KeStackAttachProcess(target, apcState);
    *attached = TRUE;
    PVOID va = nullptr;
    SIZE_T size = bytes;
    NTSTATUS st = ZwAllocateVirtualMemory(NtCurrentProcess(), &va, 0, &size,
        MEM_COMMIT | MEM_RESERVE, protect);
    if (!NT_SUCCESS(st)) {
        KeUnstackDetachProcess(apcState);
        *attached = FALSE;
        return st;
    }
    *base = va;
    return STATUS_SUCCESS;
}

// Copia kernel->target (cross-process, senza attach)
static NTSTATUS CopyToTarget(PEPROCESS target, PVOID kernelBuf, PVOID targetVa, SIZE_T bytes)
{
    SIZE_T copied = 0;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), kernelBuf, target, targetVa,
        bytes, KernelMode, &copied);
}

// Libera memoria allocata nel target
static VOID FreeInTarget(PEPROCESS target, PVOID* base, PSIZE_T size)
{
    if (!*base) return;
    KAPC_STATE apcState; KeStackAttachProcess(target, &apcState);
    SIZE_T dummy = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), base, &dummy, MEM_RELEASE);
    KeUnstackDetachProcess(&apcState);
    *base = nullptr;
    UNREFERENCED_PARAMETER(size);
}

// Mappa l'immagine (buffer kernel con il contenuto del file .dll x64) nel processo
// target e lancia l'entry point hijackando il thread indicato (PETHREAD già referenziato).
static NTSTATUS InjectDllInTarget(PEPROCESS targetProcess, PETHREAD thread,
                                  PUCHAR image, SIZE_T imageSize)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
    if (imageSize < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DbgPrint("[ModernInjector] DOS signature non valida\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (dos->e_lfanew <= 0 || (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > imageSize) {
        DbgPrint("[ModernInjector] header NT fuori dal file\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        DbgPrint("[ModernInjector] immagine non PE64 (serve una DLL x64)\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (nt->FileHeader.NumberOfSections > 96) {
        DbgPrint("[ModernInjector] numero sezioni anomalo\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    SIZE_T mappedSize = nt->OptionalHeader.SizeOfImage;
    mappedSize = (mappedSize + PAGE_SIZE - 1) & ~((SIZE_T)PAGE_SIZE - 1);
    if (mappedSize == 0 || mappedSize > (256 * 1024 * 1024)) {
        DbgPrint("[ModernInjector] SizeOfImage anomalo\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // immagine "virtuale" in kernel: headers+sezioni già collocate agli offset virtuali
    PUCHAR mapped = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, mappedSize, POOL_TAG);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(mapped, mappedSize);
    RtlCopyMemory(mapped, image, nt->OptionalHeader.SizeOfHeaders);

    {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (section[i].PointerToRawData >= imageSize || section[i].SizeOfRawData == 0)
                continue;
            RtlCopyMemory(mapped + section[i].VirtualAddress,
                image + section[i].PointerToRawData,
                section[i].SizeOfRawData);
        }
    }

    PVOID remoteBase = nullptr;
    PVOID shellBase = nullptr;
    NTSTATUS status;

    // allocazione IMMAGINE e SHELLCODE nello spazio del target
    KAPC_STATE apcState0, apcState1;
    BOOLEAN att0 = FALSE, att1 = FALSE;
    SIZE_T remoteSize = mappedSize, shellSize = PAGE_SIZE;

    status = AllocInTarget(targetProcess, remoteSize, PAGE_EXECUTE_READWRITE, &remoteBase, &apcState0, &att0);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(mapped, POOL_TAG);
        DbgPrint("[ModernInjector] allocazione immagine fallita: 0x%X\n", status);
        return status;
    }
    status = AllocInTarget(targetProcess, shellSize, PAGE_EXECUTE_READWRITE, &shellBase, &apcState1, &att1);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] allocazione shellcode fallita: 0x%X\n", status);
        KeUnstackDetachProcess(&apcState0);
        ExFreePoolWithTag(mapped, POOL_TAG);
        return status;
    }

    // base relocation sull'immagine kernel
    {
        ULONG_PTR delta = (ULONG_PTR)remoteBase - nt->OptionalHeader.ImageBase;
        IMAGE_DATA_DIRECTORY& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (delta != 0 && relocDir.Size) {
            PUCHAR p = mapped + relocDir.VirtualAddress;
            PUCHAR end = p + relocDir.Size;
            while (p + sizeof(IMAGE_BASE_RELOCATION) <= end) {
                auto* block = (PIMAGE_BASE_RELOCATION)p;
                if (block->SizeOfBlock == 0) break;
                ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                auto* entry16 = (PUSHORT)(p + sizeof(IMAGE_BASE_RELOCATION));
                for (ULONG i = 0; i < count; i++) {
                    PUCHAR at = mapped + block->VirtualAddress + (entry16[i] & 0xFFF);
                    switch (entry16[i] >> 12) {
                    case IMAGE_REL_BASED_DIR64:   *(PULONG64)at += delta; break;
                    case IMAGE_REL_BASED_HIGHLOW: *(PULONG)at   += (ULONG)delta; break;
                    }
                }
                p += block->SizeOfBlock;
            }
        }
    }

    // shellcode patchata ed eseguita dal thread hijackato del target
    UCHAR shell[44];
    PVOID entry = (PUCHAR)remoteBase + nt->OptionalHeader.AddressOfEntryPoint;
    RtlCopyMemory(shell, g_shellcode, sizeof(shell));
    memcpy(shell + 6,  &remoteBase, sizeof(PVOID));
    memcpy(shell + 29, &entry, sizeof(PVOID));

    status = CopyToTarget(targetProcess, mapped, remoteBase, mappedSize);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] copia immagine fallita: 0x%X\n", status);
        KeUnstackDetachProcess(&apcState0); KeUnstackDetachProcess(&apcState1);
        FreeInTarget(targetProcess, &remoteBase, &remoteSize);
        FreeInTarget(targetProcess, &shellBase, &shellSize);
        ExFreePoolWithTag(mapped, POOL_TAG);
        return status;
    }
    status = CopyToTarget(targetProcess, shell, shellBase, sizeof(shell));
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] copia shellcode fallita: 0x%X\n", status);
        KeUnstackDetachProcess(&apcState0); KeUnstackDetachProcess(&apcState1);
        FreeInTarget(targetProcess, &remoteBase, &remoteSize);
        FreeInTarget(targetProcess, &shellBase, &shellSize);
        ExFreePoolWithTag(mapped, POOL_TAG);
        return status;
    }

    ExFreePoolWithTag(mapped, POOL_TAG);

    // hijack del thread del target via HANDLE documentato
    HANDLE hThread = nullptr;
    status = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, nullptr,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        *PsThreadType, KernelMode, &hThread);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] ObOpenObjectByPointer fallito: 0x%X\n", status);
        FreeInTarget(targetProcess, &shellBase, &shellSize);
        FreeInTarget(targetProcess, &remoteBase, &remoteSize);
        return status;
    }
    HandleCloser threadCloser(hThread);

    ULONG suspendCount = 0;
    status = ZwSuspendThread(hThread, &suspendCount);
    if (NT_SUCCESS(status)) {
        UCHAR ctxBuf[sizeof(CONTEXT) + 16];
        PCONTEXT ctx = (PCONTEXT)(((ULONG_PTR)ctxBuf + 15) & ~(ULONG_PTR)15);
        RtlZeroMemory(ctx, sizeof(CONTEXT));
        ctx->ContextFlags = CONTEXT_FULL;
        status = PsGetContextThread(hThread, ctx, KernelMode);
        if (NT_SUCCESS(status)) {
            ctx->Rip = (ULONG64)shellBase;
            status = PsSetContextThread(hThread, ctx, KernelMode);
        }
        if (!NT_SUCCESS(status))
            DbgPrint("[ModernInjector] get/set context fallito: 0x%X\n", status);
        ZwResumeThread(hThread);
    } else {
        DbgPrint("[ModernInjector] suspend thread fallito: 0x%X\n", status);
    }

    DbgPrint("[ModernInjector] DLL a 0x%p, entry a 0x%p, shellcode a 0x%p\n",
        remoteBase, entry, shellBase);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleInject(InjectionRequest* req)
{
    NTSTATUS status;
    PEPROCESS targetProcess = nullptr;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->TargetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] processo %u non trovato: 0x%X\n", req->TargetPid, status);
        return status;
    }
    PETHREAD thread = nullptr;
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)req->TargetTid, &thread);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] thread %u non trovato: 0x%X\n", req->TargetTid, status);
        ObDereferenceObject(targetProcess);
        return status;
    }

    // NB: fiducia implicita che il TID appartenga al PID (il lab lo fa rispettare).
    // Un tool di ricerca dovrebbe verificare ObQueryProcesscreator? etc. — vedi nota dati client.
    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, req->DllPath);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE fileHandle = nullptr;
    IO_STATUS_BLOCK ioStatus{};
    status = ZwCreateFile(&fileHandle, GENERIC_READ, &objAttr, &ioStatus, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ModernInjector] apertura DLL fallita: 0x%X\n", status);
        ObDereferenceObject(thread);
        ObDereferenceObject(targetProcess);
        return status;
    }
    HandleCloser closer(fileHandle);

    FILE_STANDARD_INFORMATION fileInfo{};
    status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo,
        sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        ObDereferenceObject(targetProcess);
        return status;
    }
    if (fileInfo.EndOfFile.QuadPart <= 0 || fileInfo.EndOfFile.QuadPart > MAX_DLL_BYTES) {
        ObDereferenceObject(thread);
        ObDereferenceObject(targetProcess);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    SIZE_T dllSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;

    PUCHAR dllData = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, dllSize, POOL_TAG);
    if (!dllData) {
        ObDereferenceObject(thread);
        ObDereferenceObject(targetProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &ioStatus, dllData,
        (ULONG)dllSize, nullptr, nullptr);
    if (NT_SUCCESS(status))
        status = InjectDllInTarget(targetProcess, thread, dllData, dllSize);

    ExFreePoolWithTag(dllData, POOL_TAG);
    ObDereferenceObject(thread);
    ObDereferenceObject(targetProcess);
    return status;
}

extern "C" NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP irp)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    auto* stack = IoGetCurrentIrpStackLocation(irp);
    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INJECT_DLL) {
        auto* req = (InjectionRequest*)irp->AssociatedIrp.SystemBuffer;
        status = req ? HandleInject(req) : STATUS_INVALID_PARAMETER;
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

extern "C" NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP irp)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT drvObj)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(drvObj->DeviceObject);
    DbgPrint("[ModernInjector] scaricato\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    UNICODE_STRING deviceName, symLink;
    PDEVICE_OBJECT deviceObject = nullptr;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    NTSTATUS status = IoCreateDevice(driverObject, 0, &deviceName,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&symLink, SYMBOLIC_NAME);
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = DriverUnload;
    DbgPrint("[ModernInjector] caricato\n");
    return STATUS_SUCCESS;
}
