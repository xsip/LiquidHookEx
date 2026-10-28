#pragma once
#include <Windows.h>
#include <winternl.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED 0xC0000002
#endif

#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID 0x0004
#endif

#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#endif

#ifndef PCLIENT_ID
typedef CLIENT_ID* PCLIENT_ID;
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

class SyscallManager {
private:
    struct SyscallInfo {
        DWORD number;
        const char* name;
        bool initialized;
    };

    static SyscallInfo s_NtOpenProcess;
    static SyscallInfo s_NtReadVirtualMemory;
    static SyscallInfo s_NtWriteVirtualMemory;
    static SyscallInfo s_NtAllocateVirtualMemory;
    static SyscallInfo s_NtFreeVirtualMemory;
    static SyscallInfo s_NtProtectVirtualMemory;
    static SyscallInfo s_NtQueryVirtualMemory;
    static SyscallInfo s_NtCreateThreadEx;

    static DWORD ExtractSyscallNumber(const char* functionName);
    static bool InitializeSyscall(SyscallInfo& info);

public:
    static bool Initialize();

    // Syscall wrappers
    static NTSTATUS SyscallNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    static NTSTATUS SyscallNtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesRead
    );

    static NTSTATUS SyscallNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesWritten
    );

    static NTSTATUS SyscallNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    static NTSTATUS SyscallNtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    static NTSTATUS SyscallNtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T NumberOfBytesToProtect,
        ULONG NewAccessProtection,
        PULONG OldAccessProtection
    );

    static NTSTATUS SyscallNtQueryVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        ULONG MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );

    static NTSTATUS SyscallNtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );

    static HANDLE OpenProcessDirect(DWORD processId, ACCESS_MASK desiredAccess);
    static bool ReadMemoryDirect(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size);
    static bool WriteMemoryDirect(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size);
    // desiredBase: nullptr (default) lets the kernel pick anywhere, same as before. Non-null
    // is a REQUIRED base (not just a hint) - NtAllocateVirtualMemory fails if that exact
    // region isn't free, same as VirtualAllocEx with an explicit lpAddress. Used by
    // Process::AllocNear to land a trampoline within a hooked function's own +/-2GB
    // (a RIP-relative instruction carried over into it can't reach further than that).
    static PVOID AllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect, PVOID desiredBase = nullptr);
    static bool FreeMemoryDirect(HANDLE hProcess, PVOID address);
    // MemoryInformationClass 0 (MemoryBasicInformation) is the only class this is used for -
    // same information VirtualQueryEx reports, read directly so a syscall-mode target (see
    // LIQUID_HOOK_EX_SYSCALL_X64) doesn't have to go through the hooked Win32 API for this
    // either. False on failure - *info is then not meaningfully filled in.
    static bool QueryMemoryDirect(HANDLE hProcess, PVOID address, MEMORY_BASIC_INFORMATION* info);
    static HANDLE CreateRemoteThreadDirect(HANDLE hProcess, PVOID startAddress, PVOID parameter);
};

extern "C" {
    extern DWORD g_syscall_NtOpenProcess;
    extern DWORD g_syscall_NtReadVirtualMemory;
    extern DWORD g_syscall_NtWriteVirtualMemory;
    extern DWORD g_syscall_NtAllocateVirtualMemory;
    extern DWORD g_syscall_NtFreeVirtualMemory;
    extern DWORD g_syscall_NtProtectVirtualMemory;
    extern DWORD g_syscall_NtQueryVirtualMemory;
    extern DWORD g_syscall_NtCreateThreadEx;
}

extern "C" {
    NTSTATUS Syscall_NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS Syscall_NtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesRead
    );

    NTSTATUS Syscall_NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS Syscall_NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS Syscall_NtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    NTSTATUS Syscall_NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T NumberOfBytesToProtect,
        ULONG NewAccessProtection,
        PULONG OldAccessProtection
    );

    NTSTATUS Syscall_NtQueryVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        ULONG MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );

    NTSTATUS Syscall_NtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );
}