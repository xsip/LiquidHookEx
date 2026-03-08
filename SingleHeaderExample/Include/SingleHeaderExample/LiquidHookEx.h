// LiquidHookEx — single-include header (auto-generated)
// Ship alongside LiquidHookEx.lib
//
// Usage:
//   #include "LiquidHookEx.h"
//   #pragma comment(lib, "LiquidHookEx.lib")

#ifndef LIQUIDHOOKEX_AMALGAMATED_H
#define LIQUIDHOOKEX_AMALGAMATED_H

// ── System includes ─────────────────────────────────────────────────────────

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <string>
#include <map>
#include <TlHelp32.h>
#include <psapi.h>
#include <vector>
#include <algorithm>
#include <fstream>
#include <optional>

// ── Library source ──────────────────────────────────────────────────────────

// ==========================================================================
// Macros.h
// ==========================================================================

#define LH_START(seg) \
    __pragma(code_seg(seg))     \
    __pragma(optimize("", off)) \
    __pragma(runtime_checks("", off)) \
    __pragma(check_stack(off))


#define LH_END()      \
    __pragma(check_stack())     \
    __pragma(runtime_checks("", restore)) \
    __pragma(optimize("", on))  \
    __pragma(code_seg())

// ==========================================================================
// SysCallManager.h
// ==========================================================================

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
    static PVOID AllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect);
    static bool FreeMemoryDirect(HANDLE hProcess, PVOID address);
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

// ==========================================================================
// Pattern.h
// ==========================================================================

namespace LiquidHookEx {

    class Memory {
    public:
        static uint8_t* ScanMemory(uintptr_t pStart, uintptr_t pSize, const char* signature);
    };
}

// ==========================================================================
// Globals.h
// ==========================================================================

namespace LiquidHookEx {
    class Process;
    extern Process* proc;
    extern void INIT(std::string procName);
}

// ==========================================================================
// Process.h
// ==========================================================================

#define LIQUID_HOOK_EX_SYSCALL
#ifdef LIQUID_HOOK_EX_SYSCALL
#endif
#undef min



namespace LiquidHookEx {
    class Process;



    struct VTableFunctionInfo {
        int index;
        uintptr_t vTableAddr;
    };

    class RemoteModule {
    private:
        uintptr_t m_pSize{};
        uintptr_t m_pBase{};
        Process* m_pProc{};
        std::string m_szDll{};
        bool m_bIsValid{};
        bool m_bAllocated{};
    public:


        struct Section {
            std::string name;
            uintptr_t addr;
            size_t size;
        };

        RemoteModule(uintptr_t pBase, uintptr_t pSize, Process* pProc, std::string szDll = "");
        RemoteModule();
        bool Sync();
        bool IsValid() { return m_bIsValid; };
        uintptr_t GetAddr() { return m_pBase; };
        uintptr_t GetSize() { return m_pSize; };


        std::vector<Section> GetSections();
        VTableFunctionInfo FindVTableContainingFunction(uintptr_t fn);
        uint8_t* ScanMemory(const char* signature);
        uint32_t ResolveDisp32(uint8_t* instruction, uint32_t dwSkipBytes = 0);
        uintptr_t ResolveRIP(uint8_t* pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
        uintptr_t ResolveRIP(uintptr_t pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);

        inline static uintptr_t ResolveInstruction(uintptr_t addr, int byteOffset, bool isRelativeCall = false) {
            BYTE* bytes = (BYTE*)addr;

            if (isRelativeCall) {
                // For E8 call instructions
                if (bytes[0] == 0xE8) {
                    int32_t relativeOffset = *(int32_t*)(bytes + 1);
                    return addr + 5 + relativeOffset; // 5 = size of call instruction
                }
            }
            else {
                // For regular displacement extraction
                return *(int32_t*)(bytes + byteOffset);
            }

            return 0;
        }

        uintptr_t GetProcAddress(std::string szFnName);
    };

    class Process {
    public:
        HANDLE m_hProc{};
    private:
        DWORD pProcId{};
        HWND m_hWnd;
        std::string m_szProcName{};
        std::map<std::string, RemoteModule*> remoteModuleList{};
        std::vector<void*> m_remoteAllocations;

    private:
        bool InitializeSysCalls();
        void GetProcHandle();
        MODULEINFO GetModuleInfoEx(std::string m_Name);

    public:
        HWND GetHwnd();
        Process(std::string szProcName);
        PVOID Alloc(size_t size, DWORD fFLags = MEM_COMMIT | MEM_RESERVE, DWORD fAccess = PAGE_READWRITE);

        template <typename T>
        inline bool Read(uintptr_t m_Address, T* m_Buffer, SIZE_T m_Size)
        {
            SIZE_T bytesRead;
#ifdef LIQUID_HOOK_EX_SYSCALL
            auto res = SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(m_Address), m_Buffer, m_Size);
#else
            auto res = ::ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(m_Address), m_Buffer, m_Size, &bytesRead);
#endif
            return res;
        }

        DWORD GetProcId() { return pProcId; };

        void* AllocateAndWriteString(std::string str);
        VTableFunctionInfo FindVTableContainingFunction(uintptr_t fn, std::string szMod);


        template <typename T>
        inline bool Read(uintptr_t m_Address, T* m_Buffer)
        {
            return Read(m_Address, m_Buffer, sizeof(T));
        }

        template <typename T>
        inline T ReadDirect(uintptr_t m_Address)
        {
            T m_Buffer{};
            Read(m_Address, &m_Buffer, sizeof(T));
            return m_Buffer;
        }

        template <typename T>
        inline T ReadDirect(uintptr_t m_Address, int size)
        {
            T m_Buffer{};
            Read(m_Address, &m_Buffer, size);
            return m_Buffer;
        }

        template <typename T>
        std::vector<T> ReadArray(uintptr_t address, size_t count)
        {
            SIZE_T bytesRead = 0;

            if constexpr (std::is_same_v<T, bool>)
            {
                std::vector<uint8_t> temp(count);
#ifdef LIQUID_HOOK_EX_SYSCALL
                if (!SyscallManager::ReadMemoryDirect(
                    m_hProc,
                    reinterpret_cast<PVOID>(address),
                    temp.data(),
                    count * sizeof(uint8_t)))
#else
                if (!::ReadProcessMemory(
                    m_hProc,
                    reinterpret_cast<LPCVOID>(address),
                    temp.data(),
                    count * sizeof(uint8_t),
                    &bytesRead))
#endif
                {
                    return {};
                }

                std::vector<bool> result;
                result.reserve(count);
                for (auto byte : temp)
                    result.push_back(byte != 0);

                return result;
            }
            else
            {
                std::vector<T> buffer(count);
#ifdef LIQUID_HOOK_EX_SYSCALL
                if (!SyscallManager::ReadMemoryDirect(
                    m_hProc,
                    reinterpret_cast<PVOID>(address),
                    buffer.data(),
                    count * sizeof(T)))
#else
                if (!::ReadProcessMemory(
                    m_hProc,
                    reinterpret_cast<LPCVOID>(address),
                    buffer.data(),
                    count * sizeof(T),
                    &bytesRead))
#endif
                {
                    buffer.clear();
                }
                return buffer;
            }
        }

        template <typename T>
        bool WriteArray(uintptr_t address, const std::vector<T>& data)
        {
            SIZE_T bytesWritten = 0;

            if constexpr (std::is_same_v<T, bool>)
            {
                std::vector<uint8_t> temp;
                temp.reserve(data.size());
                for (bool b : data)
                    temp.push_back(b ? 1 : 0);

#ifdef LIQUID_HOOK_EX_SYSCALL
                return SyscallManager::WriteMemoryDirect(
                    m_hProc,
                    reinterpret_cast<PVOID>(address),
                    temp.data(),
                    temp.size() * sizeof(uint8_t));
#else
                return ::WriteProcessMemory(
                    m_hProc,
                    reinterpret_cast<LPVOID>(address),
                    temp.data(),
                    temp.size() * sizeof(uint8_t),
                    &bytesWritten) != 0;
#endif
            }
            else
            {
#ifdef LIQUID_HOOK_EX_SYSCALL
                return SyscallManager::WriteMemoryDirect(
                    m_hProc,
                    reinterpret_cast<PVOID>(address),
                    const_cast<T*>(data.data()),
                    data.size() * sizeof(T));
#else
                return ::WriteProcessMemory(
                    m_hProc,
                    reinterpret_cast<LPVOID>(address),
                    data.data(),
                    data.size() * sizeof(T),
                    &bytesWritten) != 0;
#endif
            }
        }

        inline std::vector<uint8_t> ReadBytes(uintptr_t address, size_t size) {
            std::vector<uint8_t> buffer(size);
            SIZE_T bytesRead{};
#ifdef LIQUID_HOOK_EX_SYSCALL
            if (!SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address),
                buffer.data(), size)) {
                buffer.clear();
            }
#else
            if (!::ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(address),
                buffer.data(), size, &bytesRead)) {
                buffer.clear();
            }
#endif
            return buffer;
        }

        template <typename T, typename T2>
        inline T2 ReadDirect(uintptr_t m_Address)
        {
            T m_Buffer{};
            Read(m_Address, &m_Buffer, sizeof(T));
            return reinterpret_cast<T2>(m_Buffer);
        }

        template <typename T>
        inline bool Write(uintptr_t m_Address, T m_Buffer)
        {
            SIZE_T bytesWritten;
#ifdef LIQUID_HOOK_EX_SYSCALL
            auto res = SyscallManager::WriteMemoryDirect(m_hProc, (PVOID)m_Address, (PVOID)&m_Buffer, sizeof(T));
#else
            auto res = ::WriteProcessMemory(m_hProc, (LPVOID)m_Address, (LPCVOID)&m_Buffer, sizeof(T), &bytesWritten);
#endif
            return res;
        }

        bool WriteString(uintptr_t address, const std::string& str, SIZE_T maxLength = 256)
        {
            SIZE_T writeLength = std::min(str.size(), maxLength - 1);
            std::vector<char> buffer(maxLength, 0);
            memcpy(buffer.data(), str.c_str(), writeLength);
            buffer[writeLength] = '\0';

            SIZE_T bytesWritten = 0;
#ifdef LIQUID_HOOK_EX_SYSCALL
            BOOL res = SyscallManager::WriteMemoryDirect(m_hProc, (PVOID)address, buffer.data(), maxLength);
            return res;
#else
            BOOL res = ::WriteProcessMemory(m_hProc, (LPVOID)address, buffer.data(), maxLength, &bytesWritten);
#endif
            return res && bytesWritten == maxLength;
        }

        std::string ReadString(uintptr_t address, SIZE_T maxLength = 256)
        {
            std::vector<char> buffer(maxLength, 0);
            if (!Read(address, buffer.data(), maxLength - 1))
                return std::string();

            buffer[maxLength - 1] = '\0';
            return std::string(buffer.data());
        }

        RemoteModule* GetRemoteModule(std::string szModuleName);

        void TrackAllocation(void* pRemote);
        bool FreeRemote(void* pRemote);
        void FreeAllRemote();
        size_t GetAllocationCount() const { return m_remoteAllocations.size(); }

        // Remote thread injection helpers
        void* AllocAndWriteShellcode(void* funcStart, void* funcEnd);
        HANDLE CreateRemoteThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
        DWORD ExecuteAndCleanup(void* shellcode, void* context, DWORD timeoutMs = 5000);

        template<typename ContextType>
        DWORD ExecuteRemoteWrapper(void* wrapperFunc, void* wrapperEnd,
            const ContextType& context, DWORD timeoutMs = 5000) {
            void* ctxRemote = Alloc(sizeof(ContextType));
            if (!ctxRemote) {
                printf("ERROR: Failed to allocate context\n");
                return (DWORD)-1;
            }

            Write(reinterpret_cast<uintptr_t>(ctxRemote), context);

            void* shellcode = AllocAndWriteShellcode(wrapperFunc, wrapperEnd);
            if (!shellcode) {
                printf("ERROR: Failed to allocate shellcode\n");
                FreeRemote(ctxRemote);
                return (DWORD)-1;
            }

            return ExecuteAndCleanup(shellcode, ctxRemote, timeoutMs);
        }

        template<typename ContextType, typename ReturnType>
        bool ExecuteRemoteWrapper(void* wrapperFunc, void* wrapperEnd,
            const ContextType& context, ReturnType& outResult,
            DWORD timeoutMs = 5000) {
            void* ctxRemote = Alloc(sizeof(ContextType));
            if (!ctxRemote) {
                printf("ERROR: Failed to allocate context\n");
                return false;
            }

            Write(reinterpret_cast<uintptr_t>(ctxRemote), context);

            void* shellcode = AllocAndWriteShellcode(wrapperFunc, wrapperEnd);
            if (!shellcode) {
                printf("ERROR: Failed to allocate shellcode\n");
                FreeRemote(ctxRemote);
                return false;
            }

            return ExecuteAndCleanup(shellcode, ctxRemote, outResult, timeoutMs);
        }

        template<typename T>
        bool ExecuteAndCleanup(void* shellcode, void* context, T& outResult, DWORD timeoutMs = 5000) {
            HANDLE hThread = CreateRemoteThreadEx(
                reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
                context
            );

            if (!hThread) {
                printf("ERROR: Failed to create remote thread\n");
                FreeRemote(context);
                FreeRemote(shellcode);
                return false;
            }

            DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);

            if (waitResult == WAIT_TIMEOUT) {
                printf("WARNING: Remote thread timed out after %dms\n", timeoutMs);
                CloseHandle(hThread);
                FreeRemote(context);
                FreeRemote(shellcode);
                return false;
            }

            DWORD exitCode = 0;
            GetExitCodeThread(hThread, &exitCode);
            CloseHandle(hThread);

            outResult = static_cast<T>(exitCode);

            FreeRemote(context);
            FreeRemote(shellcode);

            return true;
        }

        // VTable
        uintptr_t GetVTable(uintptr_t pThis) noexcept;

        template <int index>
        uintptr_t GetVTableFunction(uintptr_t pThis) noexcept {
            if (!pThis) return 0;

            uintptr_t vtablePtr = ReadDirect<uintptr_t>(pThis);
            if (!vtablePtr) return 0;

            uintptr_t funcPtr = ReadDirect<uintptr_t>(vtablePtr + (index * sizeof(void*)));
            return funcPtr;
        }

        template <int index>
        uintptr_t GetVTableFunctionFromVTable(uintptr_t vtableAddr) noexcept {
            if (!vtableAddr) return 0;

            uintptr_t funcPtr = ReadDirect<uintptr_t>(vtableAddr + (index * sizeof(void*)));
            return funcPtr;
        }

        std::vector<uintptr_t> ReadVTable(uintptr_t pThis, size_t count = 64) noexcept;
        void DumpVTable(uintptr_t pThis, size_t count = 32, const char* name = "VTable") noexcept;
    };

}

// ==========================================================================
// Config.h
// ==========================================================================

namespace LiquidHookEx {
    namespace HookConfig {

        constexpr const char* CONFIG_PATH = "hooks.json";

        // Must stay in sync with LiquidHookEx::RipSlotTarget
        enum class RipSlotTarget : uint8_t {
            HookData = 0,
            OriginalFunc = 1,
            Custom = 2,
        };

        struct RipSlotEntry {
            uintptr_t     remoteAddr = 0;   // address of the remote indirection slot
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;   // only meaningful when target == Custom
        };

        struct HookEntry {
            uint32_t                  pid = 0;
            std::string               hookName;
            uintptr_t                 dataRemote = 0;
            uintptr_t                 shellcodeRemote = 0;
            uintptr_t                 targetFunction = 0;
            uintptr_t                 callSiteAddr = 0;
            uintptr_t                 origStorage = 0;
            std::vector<RipSlotEntry> ripSlots;

            // CallSite: original instruction bytes saved for exact restore.
            // Empty for LiquidHookEx (vtable) hooks.
            std::vector<uint8_t>      origBytes;
        };

        // -----------------------------------------------------------------------
        // Internal helpers
        // -----------------------------------------------------------------------
        namespace detail {

            inline std::string uintToHex(uintptr_t v) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
                return buf;
            }

            inline uintptr_t hexToUint(const std::string& s) {
                if (s.empty()) return 0;
                return (uintptr_t)strtoull(s.c_str(), nullptr, 16);
            }

            inline std::string bytesToHex(const std::vector<uint8_t>& bytes) {
                std::string s;
                s.reserve(bytes.size() * 2);
                static const char* hex = "0123456789ABCDEF";
                for (uint8_t b : bytes) {
                    s += hex[b >> 4];
                    s += hex[b & 0xF];
                }
                return s;
            }

            inline std::vector<uint8_t> hexToBytes(const std::string& s) {
                std::vector<uint8_t> result;
                for (size_t i = 0; i + 1 < s.size(); i += 2) {
                    auto nibble = [](char c) -> uint8_t {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                        return 0;
                        };
                    result.push_back((nibble(s[i]) << 4) | nibble(s[i + 1]));
                }
                return result;
            }

            inline size_t findValueStart(const std::string& json, const std::string& key) {
                const std::string token = "\"" + key + "\":";
                size_t pos = 0;
                while (pos < json.size()) {
                    auto hit = json.find(token, pos);
                    if (hit == std::string::npos) return std::string::npos;

                    if (hit > 0) {
                        char before = json[hit - 1];
                        if (before != ' ' && before != '\t' && before != '\n' &&
                            before != '\r' && before != '{' && before != ',') {
                            pos = hit + 1;
                            continue;
                        }
                    }
                    return hit + token.size();
                }
                return std::string::npos;
            }

            inline std::string extractString(const std::string& json, const std::string& key) {
                size_t after_colon = findValueStart(json, key);
                if (after_colon == std::string::npos) return {};
                auto q1 = json.find('"', after_colon);
                if (q1 == std::string::npos) return {};
                auto q2 = json.find('"', q1 + 1);
                if (q2 == std::string::npos) return {};
                return json.substr(q1 + 1, q2 - q1 - 1);
            }

            inline uint32_t extractUint(const std::string& json, const std::string& key) {
                size_t i = findValueStart(json, key);
                if (i == std::string::npos) return 0;
                while (i < json.size() &&
                    (json[i] == ' ' || json[i] == '\t' ||
                        json[i] == '\n' || json[i] == '\r'))
                    ++i;
                return (uint32_t)strtoul(json.c_str() + i, nullptr, 10);
            }

            // Parses:
            // "ripSlots": [
            //   { "addr": "0x...", "target": 0 },
            //   { "addr": "0x...", "target": 2, "customAddr": "0x..." },
            //   ...
            // ]
            inline std::vector<RipSlotEntry> extractRipSlots(const std::string& json) {
                std::vector<RipSlotEntry> result;

                size_t after_colon = findValueStart(json, "ripSlots");
                if (after_colon == std::string::npos) return result;

                auto arrStart = json.find('[', after_colon);
                auto arrEnd = json.find(']', after_colon);
                if (arrStart == std::string::npos || arrEnd == std::string::npos) return result;

                // Walk each { ... } object inside the array
                size_t pos = arrStart + 1;
                while (pos < arrEnd) {
                    auto objStart = json.find('{', pos);
                    if (objStart == std::string::npos || objStart >= arrEnd) break;
                    auto objEnd = json.find('}', objStart);
                    if (objEnd == std::string::npos || objEnd > arrEnd) break;

                    std::string obj = json.substr(objStart, objEnd - objStart + 1);

                    RipSlotEntry e;
                    e.remoteAddr = hexToUint(extractString(obj, "addr"));
                    e.target = static_cast<RipSlotTarget>(extractUint(obj, "target"));
                    e.customAddr = hexToUint(extractString(obj, "customAddr"));

                    result.push_back(e);
                    pos = objEnd + 1;
                }
                return result;
            }

            inline HookEntry parseEntry(const std::string& block) {
                HookEntry e;
                e.pid = extractUint(block, "pid");
                e.hookName = extractString(block, "hookName");
                e.dataRemote = hexToUint(extractString(block, "dataRemote"));
                e.shellcodeRemote = hexToUint(extractString(block, "shellcodeRemote"));
                e.targetFunction = hexToUint(extractString(block, "targetFunction"));
                e.callSiteAddr = hexToUint(extractString(block, "callSiteAddr"));
                e.origStorage = hexToUint(extractString(block, "origStorage"));
                e.ripSlots = extractRipSlots(block);
                std::string origBytesHex = extractString(block, "origBytes");
                if (!origBytesHex.empty())
                    e.origBytes = hexToBytes(origBytesHex);
                return e;
            }

            inline std::string serializeEntry(const HookEntry& e) {
                std::string s = std::string("  {\n")
                    + "    \"pid\": " + std::to_string(e.pid) + ",\n"
                    + "    \"hookName\": \"" + e.hookName + "\",\n"
                    + "    \"dataRemote\": \"" + uintToHex(e.dataRemote) + "\",\n"
                    + "    \"shellcodeRemote\": \"" + uintToHex(e.shellcodeRemote) + "\",\n"
                    + "    \"targetFunction\": \"" + uintToHex(e.targetFunction) + "\"";

                if (e.callSiteAddr)
                    s += ",\n    \"callSiteAddr\": \"" + uintToHex(e.callSiteAddr) + "\"";

                if (e.origStorage)
                    s += ",\n    \"origStorage\": \"" + uintToHex(e.origStorage) + "\"";

                if (!e.origBytes.empty())
                    s += ",\n    \"origBytes\": \"" + bytesToHex(e.origBytes) + "\"";

                if (!e.ripSlots.empty()) {
                    s += ",\n    \"ripSlots\": [\n";
                    for (size_t i = 0; i < e.ripSlots.size(); ++i) {
                        const auto& slot = e.ripSlots[i];
                        s += "      { \"addr\": \"" + uintToHex(slot.remoteAddr) + "\""
                            + ", \"target\": " + std::to_string(static_cast<int>(slot.target));
                        if (slot.target == RipSlotTarget::Custom)
                            s += ", \"customAddr\": \"" + uintToHex(slot.customAddr) + "\"";
                        s += " }";
                        if (i + 1 < e.ripSlots.size()) s += ",";
                        s += "\n";
                    }
                    s += "    ]";
                }

                s += "\n  }";
                return s;
            }

        } // namespace detail

        inline std::vector<HookEntry> Load() {
            std::vector<HookEntry> entries;
            std::ifstream f(CONFIG_PATH);
            if (!f.is_open()) return entries;

            std::string json((std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());

            // Track brace depth so nested { } inside ripSlots don't confuse the parser
            size_t pos = 0;
            while (pos < json.size()) {
                auto start = json.find('{', pos);
                if (start == std::string::npos) break;

                int    depth = 0;
                size_t end = start;
                for (size_t j = start; j < json.size(); ++j) {
                    if (json[j] == '{') ++depth;
                    else if (json[j] == '}') { --depth; if (depth == 0) { end = j; break; } }
                }

                std::string block = json.substr(start, end - start + 1);
                HookEntry e = detail::parseEntry(block);
                if (!e.hookName.empty())
                    entries.push_back(e);
                pos = end + 1;
            }
            return entries;
        }

        inline bool Save(const std::vector<HookEntry>& entries) {
            std::ofstream f(CONFIG_PATH, std::ios::trunc);
            if (!f.is_open()) return false;

            f << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                f << detail::serializeEntry(entries[i]);
                if (i + 1 < entries.size()) f << ',';
                f << '\n';
            }
            f << "]\n";
            return f.good();
        }

        inline std::optional<HookEntry> Find(const std::string& hookName, uint32_t pid = 0) {
            for (auto& e : Load()) {
                if (e.hookName == hookName && (pid == 0 || e.pid == pid))
                    return e;
            }
            return std::nullopt;
        }

        inline bool Upsert(const HookEntry& entry) {
            auto entries = Load();
            for (auto& e : entries) {
                if (e.hookName == entry.hookName) {
                    e = entry;
                    return Save(entries);
                }
            }
            entries.push_back(entry);
            return Save(entries);
        }

        inline bool Remove(const std::string& hookName) {
            auto entries = Load();
            auto before = entries.size();
            entries.erase(
                std::remove_if(entries.begin(), entries.end(),
                    [&](const HookEntry& e) { return e.hookName == hookName; }),
                entries.end());
            if (entries.size() == before) return true;
            return Save(entries);
        }

    } // namespace HookConfig


}

// ==========================================================================
// VTable.h
// ==========================================================================

namespace LiquidHookEx {
    class VTable {
    public:
        struct BaseHookData {
            uint64_t pOriginalFunc;
        };

        // Must stay in sync with LiquidHookEx::HookConfig::RipSlotTarget
        enum class RipSlotTarget {
            HookData = 0,
            OriginalFunc = 1,
            Custom = 2,
        };

        struct RipSlot {
            void* pLocalVar;
            RipSlotTarget target;
            uint64_t      customAddr;

            static RipSlot Data(void* pLocalVar) {
                return { pLocalVar, RipSlotTarget::HookData, 0 };
            }
            static RipSlot Orig(void* pLocalVar) {
                return { pLocalVar, RipSlotTarget::OriginalFunc, 0 };
            }
            static RipSlot Custom(void* pLocalVar, uint64_t addr) {
                return { pLocalVar, RipSlotTarget::Custom, addr };
            }
        };

    private:
        struct RemoteSlot {
            void* remoteAddr = nullptr;  // allocated remote indirection slot
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;
            void* pLocalVar = nullptr;  // local variable this slot was matched from
        };

        Process* m_pProc;
        std::string             m_szName;

        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pOrigStorage{};   // holds originalFunc value — used by Unhook() only
        uintptr_t               m_pTargetFunction{};
        bool                    m_bIsHooked{};

        std::vector<RemoteSlot> m_RemoteSlots{};   // one per unique patched RIP variable

    public:
        VTable(std::string name, Process* proc = nullptr)
            : m_pProc(proc), m_szName(std::move(name)) {
        }

        void SetProc(Process* p) { m_pProc = p; };

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool Hook(
            std::string          pattern,
            std::string          dllName,
            HOOK_DATA            initData,
            void* fnStart,
            void* fnEnd,
            std::vector<RipSlot> ripSlots)
        {
            if (m_bIsHooked) {
                printf("[!] %s: already hooked\n", m_szName.c_str());
                return false;
            }

            if (TryRestore<HOOK_DATA>()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            // ── locate module ────────────────────────────────────────────
            auto pMod = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetRemoteModule(dllName.c_str());
            if (!pMod || !pMod->IsValid()) {
                printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str());
                return false;
            }

            // ── scan for function ────────────────────────────────────────
            uintptr_t pFnAddr = reinterpret_cast<uintptr_t>(
                pMod->ScanMemory(pattern.c_str()));
            if (!pFnAddr) {
                printf("[!] %s: pattern not found\n", m_szName.c_str());
                return false;
            }

            auto vTableInfo = pMod->FindVTableContainingFunction(pFnAddr);
            if (!vTableInfo.vTableAddr || vTableInfo.index < 0) {
                printf("[!] %s: vtable lookup failed\n", m_szName.c_str());
                return false;
            }
            m_pTargetFunction = vTableInfo.vTableAddr + (vTableInfo.index * 8);

            uint64_t originalFunc = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(m_pTargetFunction);
            printf("[+] %s: original fn @ 0x%llX\n", m_szName.c_str(), originalFunc);

            // ── allocate & write remote hook data ────────────────────────
            m_pDataRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(sizeof(HOOK_DATA));
            if (!m_pDataRemote) {
                printf("[!] %s: failed to alloc hook data\n", m_szName.c_str());
                return false;
            }

            reinterpret_cast<BaseHookData*>(&initData)->pOriginalFunc = originalFunc;
            (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<HOOK_DATA>(
                reinterpret_cast<uintptr_t>(m_pDataRemote), initData);

            // ── allocate remote orig storage (for Unhook only) ───────────
            // This is NOT what gets written into RIP slots. It exists solely so
            // Unhook() can recover the original function address to restore the vtable.
            m_pOrigStorage = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(8);
            if (!m_pOrigStorage) {
                printf("[!] %s: failed to alloc orig storage\n", m_szName.c_str());
                return false;
            }
            (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                reinterpret_cast<uintptr_t>(m_pOrigStorage), originalFunc);

            // ── copy shellcode ───────────────────────────────────────────
            size_t shellcodeSize =
                reinterpret_cast<uintptr_t>(fnEnd) -
                reinterpret_cast<uintptr_t>(fnStart);

            m_pShellcodeRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(
                shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pShellcodeRemote) {
                printf("[!] %s: failed to alloc shellcode\n", m_szName.c_str());
                return false;
            }

            std::vector<uint8_t> localCode(shellcodeSize);
            memcpy(localCode.data(), fnStart, shellcodeSize);

            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(
                reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode)) {
                printf("[!] %s: failed to write shellcode\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n",
                m_szName.c_str(), m_pShellcodeRemote, shellcodeSize);

            // ── patch RIP slots ──────────────────────────────────────────
            if (!PatchRipSlots(localCode, shellcodeSize, fnStart, originalFunc, ripSlots)) {
                printf("[!] %s: RIP patching failed\n", m_szName.c_str());
                return false;
            }

            // ── install vtable hook ──────────────────────────────────────
            if (!InstallVTableHook()) {
                printf("[!] %s: vtable install failed\n", m_szName.c_str());
                return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());

            SaveConfig();
            return true;
        }

        bool Unhook()
        {
            if (!m_bIsHooked || !m_pTargetFunction) return false;

            // Recover original function address from dedicated orig storage
            uint64_t originalFunc = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(
                reinterpret_cast<uintptr_t>(m_pOrigStorage));

            DWORD oldProtect;
            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                8, PAGE_READWRITE, &oldProtect);

            (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(m_pTargetFunction, originalFunc);

            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                8, oldProtect, &oldProtect);

            // Free remote slot allocations
            for (const auto& rs : m_RemoteSlots) {
                if (rs.remoteAddr)
                    VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, rs.remoteAddr, 0, MEM_RELEASE);
            }
            m_RemoteSlots.clear();

            if (m_pShellcodeRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, m_pShellcodeRemote, 0, MEM_RELEASE);
                m_pShellcodeRemote = nullptr;
            }
            if (m_pDataRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, m_pDataRemote, 0, MEM_RELEASE);
                m_pDataRemote = nullptr;
            }
            if (m_pOrigStorage) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, m_pOrigStorage, 0, MEM_RELEASE);
                m_pOrigStorage = nullptr;
            }

            m_bIsHooked = false;
            m_pTargetFunction = 0;
            LiquidHookEx::HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return true;
        }

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        HOOK_DATA ReadData()
        {
            HOOK_DATA out{};
            if (m_pDataRemote)
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Read(reinterpret_cast<uintptr_t>(m_pDataRemote),
                    &out, sizeof(HOOK_DATA));
            return out;
        }

        template <typename T>
        void WriteField(size_t offset, T value)
        {
            if (m_pDataRemote)
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<T>(
                    reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, value);
        }

        bool    IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool TryRestore()
        {
            uint32_t currentPid = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetProcId();
            auto entry = LiquidHookEx::HookConfig::Find(m_szName, currentPid);
            if (!entry) {
                printf("[HookConfig] %s: no saved state for pid %u\n",
                    m_szName.c_str(), currentPid);
                return false;
            }

            if (!entry->dataRemote || !entry->shellcodeRemote || !entry->targetFunction) {
                printf("[HookConfig] %s: saved state incomplete – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    reinterpret_cast<void*>(entry->dataRemote), &mbi, sizeof(mbi)) == 0 ||
                    mbi.State != MEM_COMMIT)
                {
                    printf("[HookConfig] %s: dataRemote 0x%llX no longer committed\n",
                        m_szName.c_str(), (uint64_t)entry->dataRemote);
                    LiquidHookEx::HookConfig::Remove(m_szName);
                    return false;
                }
            }

            uint64_t currentVtableEntry =
                (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(entry->targetFunction);
            if (currentVtableEntry != entry->shellcodeRemote) {
                printf("[HookConfig] %s: vtable no longer points to shellcode – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            // ── restore primary pointers ─────────────────────────────────
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_pTargetFunction = entry->targetFunction;
            m_pOrigStorage = reinterpret_cast<void*>(entry->origStorage);

            // Recover the actual original function value for slot validation below
            uint64_t origFuncValue = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(entry->origStorage);

            // ── restore remote slots with type validation ─────────────────
            m_RemoteSlots.clear();
            for (const auto& saved : entry->ripSlots) {
                RemoteSlot rs;
                rs.remoteAddr = reinterpret_cast<void*>(saved.remoteAddr);
                rs.target = static_cast<RipSlotTarget>(saved.target);
                rs.customAddr = saved.customAddr;
                rs.pLocalVar = nullptr;  // not recoverable after restart, not needed post-restore

                uint64_t storedValue = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(saved.remoteAddr);

                switch (rs.target) {
                case RipSlotTarget::HookData:
                    // Slot must contain the remote data pointer
                    if (storedValue != entry->dataRemote) {
                        printf("[HookConfig] %s: HookData slot 0x%llX value mismatch – discarding\n",
                            m_szName.c_str(), (uint64_t)saved.remoteAddr);
                        LiquidHookEx::HookConfig::Remove(m_szName);
                        return false;
                    }
                    break;
                case RipSlotTarget::OriginalFunc:
                    // Slot must contain the actual original function address (not origStorage)
                    if (storedValue != origFuncValue) {
                        printf("[HookConfig] %s: OriginalFunc slot 0x%llX value mismatch – discarding\n",
                            m_szName.c_str(), (uint64_t)saved.remoteAddr);
                        LiquidHookEx::HookConfig::Remove(m_szName);
                        return false;
                    }
                    break;
                case RipSlotTarget::Custom:
                    // Custom targets may change between runs — re-write correct value
                    if (storedValue != saved.customAddr) {
                        printf("[HookConfig] %s: Custom slot 0x%llX value changed (0x%llX → 0x%llX) – refreshing\n",
                            m_szName.c_str(), (uint64_t)saved.remoteAddr,
                            storedValue, saved.customAddr);
                        (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(saved.remoteAddr, saved.customAddr);
                    }
                    break;
                }

                m_RemoteSlots.push_back(rs);
            }

            m_bIsHooked = true;
            printf("[HookConfig] %s: restored (pid %u, %zu slots)\n",
                m_szName.c_str(), currentPid, m_RemoteSlots.size());
            return true;
        }

        bool PatchRipSlots(
            std::vector<uint8_t>& localCode,
            size_t                       shellcodeSize,
            void* fnStart,
            uint64_t                     originalFunc,
            const std::vector<RipSlot>& ripSlots)
        {
            int patched = 0;

            for (size_t i = 0; i + 7 <= shellcodeSize; ++i) {
                if (localCode[i] != 0x48) continue;
                if (localCode[i + 1] != 0x8B) continue;
                if (localCode[i + 2] != 0x05) continue;

                // ── resolve which local variable this instruction loads ───
                int32_t   localDisp = *reinterpret_cast<int32_t*>(&localCode[i + 3]);
                uintptr_t localRip = reinterpret_cast<uintptr_t>(fnStart) + i + 7;
                uintptr_t localTarget = localRip + localDisp;

                // ── find matching RipSlot by local variable address ──────
                const RipSlot* slot = nullptr;
                for (const auto& s : ripSlots) {
                    if (reinterpret_cast<uintptr_t>(s.pLocalVar) == localTarget) {
                        slot = &s;
                        break;
                    }
                }

                if (!slot) {
                    printf("[!] %s: unregistered RIP load at +0x%zX → local 0x%llX\n",
                        m_szName.c_str(), i, (uint64_t)localTarget);
                    return false;
                }

                // ── resolve the value this slot should hold ──────────────
                //
                // HookData     → pointer to remote HOOK_DATA struct
                //                shellcode: data = (HOOK_DATA*)g_pHookData
                //
                // OriginalFunc → the actual original function address
                //                shellcode: original = (Fn)g_pOriginalCreateMove
                //                NOTE: the slot holds the fn address directly,
                //                NOT the address of m_pOrigStorage.
                //                m_pOrigStorage is a separate alloc used only
                //                by Unhook() to restore the vtable.
                //
                // Custom       → caller-supplied absolute address
                //
                uint64_t remoteValue = 0;
                switch (slot->target) {
                case RipSlotTarget::HookData:
                    remoteValue = reinterpret_cast<uint64_t>(m_pDataRemote);
                    break;
                case RipSlotTarget::OriginalFunc:
                    remoteValue = originalFunc;
                    break;
                case RipSlotTarget::Custom:
                    remoteValue = slot->customAddr;
                    break;
                }

                // ── reuse existing slot if same local variable seen before ─
                void* remoteSlot = nullptr;
                for (const auto& existing : m_RemoteSlots) {
                    if (existing.pLocalVar == slot->pLocalVar) {
                        remoteSlot = existing.remoteAddr;
                        printf("[+] %s: RIP[%d] +0x%zX → reusing slot 0x%p → 0x%llX\n",
                            m_szName.c_str(), patched, i, remoteSlot, remoteValue);
                        break;
                    }
                }

                // ── allocate new slot if first time seeing this variable ──
                if (!remoteSlot) {
                    remoteSlot = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(8);
                    if (!remoteSlot) {
                        printf("[!] %s: failed to alloc remote slot at +0x%zX\n",
                            m_szName.c_str(), i);
                        return false;
                    }

                    (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                        reinterpret_cast<uintptr_t>(remoteSlot), remoteValue);

                    m_RemoteSlots.push_back({
                        remoteSlot,
                        slot->target,
                        slot->customAddr,
                        slot->pLocalVar
                        });

                    printf("[+] %s: RIP[%d] +0x%zX → slot 0x%p → 0x%llX\n",
                        m_szName.c_str(), patched, i, remoteSlot, remoteValue);
                }

                // ── patch disp32 in remote shellcode ─────────────────────
                uintptr_t remoteInstrAddr =
                    reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i;

                int32_t newOffset = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(remoteSlot) - (remoteInstrAddr + 7));

                if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->Write<int32_t>(remoteInstrAddr + 3, newOffset)) {
                    printf("[!] %s: failed to patch disp32 at +0x%zX\n",
                        m_szName.c_str(), i);
                    return false;
                }

                ++patched;
            }

            // ── verify every declared slot was matched at least once ─────
            for (const auto& s : ripSlots) {
                bool found = false;
                for (const auto& rs : m_RemoteSlots) {
                    if (rs.pLocalVar == s.pLocalVar) { found = true; break; }
                }
                if (!found) {
                    printf("[!] %s: declared RipSlot local 0x%llX was never matched in shellcode\n",
                        m_szName.c_str(), (uint64_t)s.pLocalVar);
                    return false;
                }
            }

            printf("[+] %s: patched %d RIP load(s) across %zu declared slot(s)\n",
                m_szName.c_str(), patched, ripSlots.size());
            return true;
        }

        bool InstallVTableHook()
        {
            DWORD oldProtect;
            if (!VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                8, PAGE_READWRITE, &oldProtect))
                return false;

            bool ok = (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                m_pTargetFunction,
                reinterpret_cast<uint64_t>(m_pShellcodeRemote));

            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                8, oldProtect, &oldProtect);

            return ok;
        }

        void SaveConfig()
        {
            LiquidHookEx::HookConfig::HookEntry e;
            e.pid = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = m_pTargetFunction;
            e.origStorage = reinterpret_cast<uintptr_t>(m_pOrigStorage);

            e.ripSlots.clear();
            for (const auto& rs : m_RemoteSlots) {
                LiquidHookEx::HookConfig::RipSlotEntry saved;
                saved.remoteAddr = reinterpret_cast<uintptr_t>(rs.remoteAddr);
                saved.target = static_cast<LiquidHookEx::HookConfig::RipSlotTarget>(rs.target);
                saved.customAddr = rs.customAddr;
                e.ripSlots.push_back(saved);
            }

            LiquidHookEx::HookConfig::Upsert(e);
            printf("[HookConfig] %s: state saved (%zu RIP slots)\n",
                m_szName.c_str(), m_RemoteSlots.size());
        }
    };
}

// ==========================================================================
// CallSite.h
// ==========================================================================

// ============================================================================
//  CallSite
//
//  External call-site hook: replaces a call site instruction with an
//  FF 15 (call qword ptr [rip+offset]) that dispatches into remote shellcode.
//
//  Usage is intentionally parallel to LiquidHookEx:
//
//    // 1. Static globals in the .cpp – these are the RIP slot targets
//    static void* g_pOriginalFn    = nullptr;
//    static MyHookData* g_pHookData = nullptr;
//
//    // 2. Shellcode in its own segment, optimizations off
//    #pragma code_seg(".myHook")
//    #pragma optimize("", off)
//    #pragma runtime_checks("", off)
//    #pragma check_stack(off)
//    RetType __fastcall MyClass::Hook_Shellcode(Args...) {
//        MyHookData* data   = g_pHookData;           // ← RipSlot::Data
//        typedef RetType(__fastcall* Fn)(Args...);
//        Fn original        = (Fn)g_pOriginalFn;     // ← RipSlot::Orig
//        ...
//        return original(...);
//    }
//    void MyClass::Hook_Shellcode_End() {}
//    #pragma check_stack()
//    #pragma runtime_checks("", restore)
//    #pragma optimize("", on)
//    #pragma code_seg()
//
//    // 3. Hook call
//    m_Hook.Hook<MyHookData>(
//        CALLSITE_PATTERN,   // pattern pointing at the call instruction to replace
//        "module.dll",
//        initData,
//        (void*)Hook_Shellcode,
//        (void*)Hook_Shellcode_End,
//        {
//            CallSite::RipSlot::Data(&g_pHookData),
//            CallSite::RipSlot::Orig(&g_pOriginalFn),
//        });
//
//  Supported original call instruction forms (auto-detected):
//    E8 xx xx xx xx          – direct near call              (5 bytes)
//    FF 15 xx xx xx xx       – indirect call [rip+offset]    (6 bytes)
//    FF 93 xx xx xx xx       – indirect call [rbx+offset]    (6 bytes)
//    FF D0 / FF D1 / FF D3   – indirect call rax/rcx/rbx     (2 bytes, uncommon)
//    FF 10 / FF 11 / FF 13   – indirect call [rax]/[rcx]/..  (2 bytes, uncommon)
//
//  The original instruction bytes are saved in HookConfig so Unhook() can
//  restore them exactly. If the original call could not be resolved to a
//  target address at hook time, the shellcode is still installed but
//  RipSlot::Orig will hold 0 — the shellcode must handle that case.
// ============================================================================
namespace LiquidHookEx {
    class CallSite {
    public:
        // ── RipSlot types (mirrors LiquidHookEx) ────────────────────────────────
        struct BaseHookData {
            // Mid-hook variant: no pOriginalFunc here (the original is resolved from
            // the call site, not from a vtable).  Derived structs may add their own
            // original fn pointer field and expose it via RipSlot::Orig.
        };

        enum class RipSlotTarget {
            HookData = 0,
            OriginalFunc = 1,
            Custom = 2,
        };

        struct RipSlot {
            void* pLocalVar;
            RipSlotTarget  target;
            uint64_t       customAddr;

            static RipSlot Data(void* pLocalVar) {
                return { pLocalVar, RipSlotTarget::HookData, 0 };
            }
            static RipSlot Orig(void* pLocalVar) {
                return { pLocalVar, RipSlotTarget::OriginalFunc, 0 };
            }
            static RipSlot Custom(void* pLocalVar, uint64_t addr) {
                return { pLocalVar, RipSlotTarget::Custom, addr };
            }
        };

    private:
        // ── Internal remote slot tracking ───────────────────────────────────────
        struct RemoteSlot {
            void* remoteAddr = nullptr;
            RipSlotTarget  target = RipSlotTarget::HookData;
            uint64_t       customAddr = 0;
            void* pLocalVar = nullptr;
        };

        Process* m_pProc;
        std::string             m_szName;

        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pFuncPtrStorage{};    // ±2GB alloc holding shellcodeRemote addr
        uintptr_t               m_callSiteAddr{};       // address of the patched call instruction
        uint64_t                m_originalFuncAddr{};   // resolved target of the original call (0 if unknown)

        // Original bytes snapshot for exact restore
        uint8_t                 m_originalBytes[16]{};
        uint8_t                 m_originalByteCount{};

        bool                    m_bIsHooked{};

        std::vector<RemoteSlot> m_RemoteSlots{};

    public:
        CallSite(std::string name, Process* proc = nullptr)
            : m_pProc(proc), m_szName(std::move(name)) {
        }


        void SetProc(Process* p) { m_pProc = p; };

        // ── Hook ────────────────────────────────────────────────────────────────
        //
        // overwriteSize: total bytes to snapshot and restore on Unhook().
        //   0  = auto-detect from the call instruction (default, works for most cases).
        //   >0 = caller-specified override. Use this when the original call site is
        //        followed by instruction(s) that must also be NOP'd out — i.e. when
        //        the region to atomically replace is wider than just the call itself.
        //        Must be >= 6 (the size of FF 15). Any bytes beyond 6 become NOPs.
        //
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool Hook(
            std::string          callSitePattern,
            std::string          dllName,
            HOOK_DATA            initData,
            void* fnStart,
            void* fnEnd,
            std::vector<RipSlot> ripSlots,
            uint8_t              overwriteSize = 0)
        {
            if (m_bIsHooked) {
                printf("[!] %s: already hooked\n", m_szName.c_str());
                return false;
            }

            if (TryRestore<HOOK_DATA>()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            // ── locate module ────────────────────────────────────────────────
            auto pMod = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetRemoteModule(dllName.c_str());
            if (!pMod || !pMod->IsValid()) {
                printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str());
                return false;
            }

            // ── scan for call site ───────────────────────────────────────────
            auto pCallSite = pMod->ScanMemory(callSitePattern.c_str());
            if (!pCallSite) {
                printf("[!] %s: call site pattern not found\n", m_szName.c_str());
                return false;
            }

            m_callSiteAddr = reinterpret_cast<uintptr_t>(pCallSite);
            printf("[+] %s: call site @ module+0x%llX\n",
                m_szName.c_str(), m_callSiteAddr - pMod->GetAddr());

            // ── resolve original call target & snapshot original bytes ───────
            if (!SnapshotAndResolveCallSite(pMod, overwriteSize)) {
                printf("[!] %s: failed to resolve call site\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: original bytes (%u): ", m_szName.c_str(), m_originalByteCount);
            for (int i = 0; i < m_originalByteCount; ++i)
                printf("%02X ", m_originalBytes[i]);
            printf("\n");

            if (m_originalFuncAddr)
                printf("[+] %s: original fn @ 0x%llX\n", m_szName.c_str(), m_originalFuncAddr);
            else
                printf("[~] %s: could not resolve original fn addr (indirect call form)\n", m_szName.c_str());

            // ── allocate & write remote hook data ────────────────────────────
            m_pDataRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(sizeof(HOOK_DATA));
            if (!m_pDataRemote) {
                printf("[!] %s: failed to alloc hook data\n", m_szName.c_str());
                return false;
            }

            (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<HOOK_DATA>(reinterpret_cast<uintptr_t>(m_pDataRemote), initData);
            printf("[+] %s: hook data @ 0x%p\n", m_szName.c_str(), m_pDataRemote);

            // ── copy shellcode ────────────────────────────────────────────────
            size_t shellcodeSize =
                reinterpret_cast<uintptr_t>(fnEnd) -
                reinterpret_cast<uintptr_t>(fnStart);

            m_pShellcodeRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(
                shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pShellcodeRemote) {
                printf("[!] %s: failed to alloc shellcode\n", m_szName.c_str());
                return false;
            }

            std::vector<uint8_t> localCode(shellcodeSize);
            memcpy(localCode.data(), fnStart, shellcodeSize);

            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(
                reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode)) {
                printf("[!] %s: failed to write shellcode\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n",
                m_szName.c_str(), m_pShellcodeRemote, shellcodeSize);

            // ── patch RIP slots ───────────────────────────────────────────────
            if (!PatchRipSlots(localCode, shellcodeSize, fnStart, ripSlots)) {
                printf("[!] %s: RIP patching failed\n", m_szName.c_str());
                return false;
            }

            // ── flush shellcode ───────────────────────────────────────────────
            if (!FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                m_pShellcodeRemote, shellcodeSize))
                printf("[~] %s: FlushInstructionCache failed (%lu)\n",
                    m_szName.c_str(), GetLastError());

            // ── install FF 15 call site patch ─────────────────────────────────
            if (!InstallCallSitePatch()) {
                printf("[!] %s: call site patch failed\n", m_szName.c_str());
                return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());

            SaveConfig();
            return true;
        }

        // ── Unhook ───────────────────────────────────────────────────────────────
        bool Unhook()
        {
            if (!m_bIsHooked || !m_callSiteAddr) return false;

            bool success = true;

            // Restore original bytes exactly
            DWORD oldProtect;
            if (!VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr),
                m_originalByteCount, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                success = false;
            }
            else {
                std::vector<uint8_t> origVec(
                    m_originalBytes, m_originalBytes + m_originalByteCount);
                if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(m_callSiteAddr, origVec)) {
                    printf("[!] %s: failed to restore original bytes\n",
                        m_szName.c_str());
                    success = false;
                }
                VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    reinterpret_cast<void*>(m_callSiteAddr),
                    m_originalByteCount, oldProtect, &oldProtect);
            }

            FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount);

            // Free remote allocs
            if (m_pFuncPtrStorage) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, m_pFuncPtrStorage, 0, MEM_RELEASE);
                m_pFuncPtrStorage = nullptr;
            }
            if (m_pShellcodeRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, m_pShellcodeRemote, 0, MEM_RELEASE);
                m_pShellcodeRemote = nullptr;
            }
            if (m_pDataRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc, m_pDataRemote, 0, MEM_RELEASE);
                m_pDataRemote = nullptr;
            }

            m_bIsHooked = false;
            m_callSiteAddr = 0;
            m_originalFuncAddr = 0;
            m_originalByteCount = 0;
            m_RemoteSlots.clear();

            LiquidHookEx::HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return success;
        }

        // ── Data accessors (same API as LiquidHookEx) ────────────────────────────
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        HOOK_DATA ReadData()
        {
            HOOK_DATA out{};
            if (m_pDataRemote)
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Read(reinterpret_cast<uintptr_t>(m_pDataRemote),
                    &out, sizeof(HOOK_DATA));
            return out;
        }

        template <typename T>
        void WriteField(size_t offset, T value)
        {
            if (m_pDataRemote)
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<T>(
                    reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, value);
        }

        bool    IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:

        // ── Read the original call bytes and resolve the callee address ──────────
        //
        // Detects the instruction form and resolves the callee where possible.
        //
        // IMPORTANT: FF 15 is always 6 bytes. If the original instruction is shorter
        // (e.g. E8 = 5 bytes) we must snapshot max(instrLen, 6) bytes so that
        // Unhook() restores every byte we touched, including the one byte of the
        // following instruction that we clobber.
        //
        // m_originalByteCount = max(instrLen, 6)
        // m_originalFuncAddr  = resolved callee address (0 if unknown)
        //
        bool SnapshotAndResolveCallSite(auto* pMod, uint8_t overwriteSize)
        {
            uint8_t buf[16]{};
            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->Read(m_callSiteAddr, buf, sizeof(buf))) {
                printf("[!] %s: failed to read call site bytes\n", m_szName.c_str());
                return false;
            }

            m_originalFuncAddr = 0;
            uint8_t instrLen = 0;

            // E8 xx xx xx xx  –  direct near call  (5 bytes)
            if (buf[0] == 0xE8) {
                int32_t rel32 = *reinterpret_cast<int32_t*>(&buf[1]);
                m_originalFuncAddr = static_cast<uint64_t>(
                    static_cast<int64_t>(m_callSiteAddr) + 5 + rel32);
                instrLen = 5;
            }
            // FF 15 xx xx xx xx  –  call qword ptr [rip+offset]  (6 bytes)
            else if (buf[0] == 0xFF && buf[1] == 0x15) {
                int32_t rel32 = *reinterpret_cast<int32_t*>(&buf[2]);
                uintptr_t ptrAddr = m_callSiteAddr + 6 + rel32;
                m_originalFuncAddr = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(ptrAddr);
                instrLen = 6;
            }
            // FF /2 mod=10b  –  call [reg+disp32]  e.g. FF 93 D0 0C 00 00  (6 bytes)
            else if (buf[0] == 0xFF && (buf[1] & 0x38) == 0x10 && (buf[1] & 0xC0) == 0x80) {
                instrLen = 6;
            }
            // FF D0..D7  –  call reg  (2 bytes)
            else if (buf[0] == 0xFF && (buf[1] & 0xF8) == 0xD0) {
                instrLen = 2;
            }
            // FF 10..17  –  call [reg]  (2 bytes)
            else if (buf[0] == 0xFF && (buf[1] & 0xF8) == 0x10) {
                instrLen = 2;
            }
            // 41 FF 50 xx  –  call qword ptr [r8+disp8]   (4 bytes, REX.B + FF /2 mod=01b)
            // 41 FF 90 xx xx xx xx – call qword ptr [r8+disp32] (7 bytes, REX.B + FF /2 mod=10b)
            // Covers any REX prefix (40–4F) before FF /2 — callee address not resolvable statically.
            else if (buf[0] >= 0x40 && buf[0] <= 0x4F && buf[1] == 0xFF &&
                (buf[2] & 0x38) == 0x10)
            {
                uint8_t mod = (buf[2] & 0xC0) >> 6;
                if (mod == 0x01)       instrLen = 4;  // disp8:  REX FF /2 ModRM disp8
                else if (mod == 0x02)  instrLen = 7;  // disp32: REX FF /2 ModRM disp32
                else                   instrLen = 3;  // mod=00: REX FF /2 ModRM (no disp)
            }
            else {
                printf("[!] %s: unrecognized call form at call site: %02X %02X ...\n",
                    m_szName.c_str(), buf[0], buf[1]);
                return false;
            }

            // Determine how many bytes to snapshot and restore:
            //   - overwriteSize > 0: caller explicitly says how wide the region is
            //   - otherwise: at least as wide as the instruction, but never less than
            //     6 (the size of FF 15 which we always write)
            uint8_t minBytes = (instrLen < 6) ? 6 : instrLen;
            if (overwriteSize > 0) {
                if (overwriteSize < 6) {
                    printf("[!] %s: overwriteSize %u is less than 6 (FF 15 size) – ignoring\n",
                        m_szName.c_str(), overwriteSize);
                    m_originalByteCount = minBytes;
                }
                else {
                    m_originalByteCount = overwriteSize;
                }
            }
            else {
                m_originalByteCount = minBytes;
            }
            memcpy(m_originalBytes, buf, m_originalByteCount);
            return true;
        }

        // ── Patch RIP slots (address-matched, same logic as LiquidHookEx) ────────
        bool PatchRipSlots(
            std::vector<uint8_t>& localCode,
            size_t                      shellcodeSize,
            void* fnStart,
            const std::vector<RipSlot>& ripSlots)
        {
            int patched = 0;

            for (size_t i = 0; i + 7 <= shellcodeSize; ++i) {
                if (localCode[i] != 0x48) continue;
                if (localCode[i + 1] != 0x8B) continue;
                if (localCode[i + 2] != 0x05) continue;

                int32_t   localDisp = *reinterpret_cast<int32_t*>(&localCode[i + 3]);
                uintptr_t localRip = reinterpret_cast<uintptr_t>(fnStart) + i + 7;
                uintptr_t localTarget = localRip + localDisp;

                const RipSlot* slot = nullptr;
                for (const auto& s : ripSlots) {
                    if (reinterpret_cast<uintptr_t>(s.pLocalVar) == localTarget) {
                        slot = &s;
                        break;
                    }
                }

                if (!slot) {
                    printf("[!] %s: unregistered RIP load at +0x%zX → local 0x%llX\n",
                        m_szName.c_str(), i, (uint64_t)localTarget);
                    return false;
                }

                uint64_t remoteValue = 0;
                switch (slot->target) {
                case RipSlotTarget::HookData:
                    remoteValue = reinterpret_cast<uint64_t>(m_pDataRemote);
                    break;
                case RipSlotTarget::OriginalFunc:
                    remoteValue = m_originalFuncAddr;
                    break;
                case RipSlotTarget::Custom:
                    remoteValue = slot->customAddr;
                    break;
                }

                // Reuse existing remote slot for same local variable
                void* remoteSlot = nullptr;
                for (const auto& existing : m_RemoteSlots) {
                    if (existing.pLocalVar == slot->pLocalVar) {
                        remoteSlot = existing.remoteAddr;
                        printf("[+] %s: RIP[%d] +0x%zX → reusing slot 0x%p → 0x%llX\n",
                            m_szName.c_str(), patched, i, remoteSlot, remoteValue);
                        break;
                    }
                }

                if (!remoteSlot) {
                    remoteSlot = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(8);
                    if (!remoteSlot) {
                        printf("[!] %s: failed to alloc remote slot at +0x%zX\n",
                            m_szName.c_str(), i);
                        return false;
                    }

                    (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                        reinterpret_cast<uintptr_t>(remoteSlot), remoteValue);

                    m_RemoteSlots.push_back({
                        remoteSlot,
                        slot->target,
                        slot->customAddr,
                        slot->pLocalVar
                        });

                    printf("[+] %s: RIP[%d] +0x%zX → slot 0x%p → 0x%llX\n",
                        m_szName.c_str(), patched, i, remoteSlot, remoteValue);
                }

                uintptr_t remoteInstrAddr =
                    reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i;

                int32_t newOffset = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(remoteSlot) - (remoteInstrAddr + 7));

                if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->Write<int32_t>(remoteInstrAddr + 3, newOffset)) {
                    printf("[!] %s: failed to patch disp32 at +0x%zX\n",
                        m_szName.c_str(), i);
                    return false;
                }

                ++patched;
            }

            // Verify every declared slot was matched
            for (const auto& s : ripSlots) {
                bool found = false;
                for (const auto& rs : m_RemoteSlots) {
                    if (rs.pLocalVar == s.pLocalVar) { found = true; break; }
                }
                if (!found) {
                    printf("[!] %s: declared RipSlot local 0x%llX was never matched in shellcode\n",
                        m_szName.c_str(), (uint64_t)s.pLocalVar);
                    return false;
                }
            }

            printf("[+] %s: patched %d RIP load(s) across %zu declared slot(s)\n",
                m_szName.c_str(), patched, ripSlots.size());
            return true;
        }

        // ── Allocate pFuncPtrStorage within ±2GB of the call site and write ──────
        //    FF 15 [rip+offset] patch + NOPs for any leftover bytes.
        bool InstallCallSitePatch()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);

            const uintptr_t granularity = si.dwAllocationGranularity;
            const uintptr_t ripBase = m_callSiteAddr + 6; // RIP after FF 15 instruction

            uintptr_t searchStart =
                (m_callSiteAddr > 0x7FFFFFFF)
                ? ((m_callSiteAddr - 0x7FFFFFFF) & ~(granularity - 1))
                : 0;
            uintptr_t searchEnd = m_callSiteAddr + 0x7FFFFFFF;

            for (uintptr_t addr = searchStart; addr < searchEnd; addr += granularity) {
                m_pFuncPtrStorage = VirtualAllocEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    reinterpret_cast<void*>(addr),
                    8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (m_pFuncPtrStorage) {
                    int64_t distance =
                        reinterpret_cast<uintptr_t>(m_pFuncPtrStorage) - ripBase;
                    if (distance >= INT32_MIN && distance <= INT32_MAX) {
                        printf("[+] %s: funcptr storage @ 0x%p (delta 0x%llX)\n",
                            m_szName.c_str(), m_pFuncPtrStorage, distance);
                        break;
                    }
                    VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                        m_pFuncPtrStorage, 0, MEM_RELEASE);
                    m_pFuncPtrStorage = nullptr;
                }
            }

            if (!m_pFuncPtrStorage) {
                printf("[!] %s: no ±2GB alloc for funcptr storage\n", m_szName.c_str());
                return false;
            }

            // Write shellcode address into the storage slot
            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                reinterpret_cast<uintptr_t>(m_pFuncPtrStorage),
                reinterpret_cast<uint64_t>(m_pShellcodeRemote))) {
                printf("[!] %s: failed to write funcptr storage\n", m_szName.c_str());
                return false;
            }

            int64_t  distance = reinterpret_cast<uintptr_t>(m_pFuncPtrStorage) - ripBase;
            int32_t  ripOffset = static_cast<int32_t>(distance);

            if (distance != ripOffset) {
                printf("[!] %s: RIP offset overflow\n", m_szName.c_str());
                return false;
            }

            // Build the replacement bytes: FF 15 <disp32> + NOPs for any remainder
            std::vector<uint8_t> patch;
            patch.reserve(m_originalByteCount);
            patch.push_back(0xFF);
            patch.push_back(0x15);
            patch.push_back(static_cast<uint8_t>(ripOffset & 0xFF));
            patch.push_back(static_cast<uint8_t>((ripOffset >> 8) & 0xFF));
            patch.push_back(static_cast<uint8_t>((ripOffset >> 16) & 0xFF));
            patch.push_back(static_cast<uint8_t>((ripOffset >> 24) & 0xFF));

            // Pad to original instruction length with NOPs
            while (patch.size() < m_originalByteCount)
                patch.push_back(0x90);

            DWORD oldProtect;
            if (!VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr),
                m_originalByteCount, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                return false;
            }

            bool ok = (m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(m_callSiteAddr, patch);

            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr),
                m_originalByteCount, oldProtect, &oldProtect);

            if (!ok) {
                printf("[!] %s: failed to write call site patch\n", m_szName.c_str());
                return false;
            }

            FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount);

            printf("[+] %s: call site patched (FF 15 + %d NOP(s))\n",
                m_szName.c_str(), (int)patch.size() - 6);
            return true;
        }

        // ── TryRestore ────────────────────────────────────────────────────────────
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool TryRestore()
        {
            uint32_t currentPid = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetProcId();
            auto entry = LiquidHookEx::HookConfig::Find(m_szName, currentPid);
            if (!entry) {
                printf("[HookConfig] %s: no saved state for pid %u\n",
                    m_szName.c_str(), currentPid);
                return false;
            }

            if (!entry->dataRemote || !entry->shellcodeRemote || !entry->callSiteAddr) {
                printf("[HookConfig] %s: saved state incomplete – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    reinterpret_cast<void*>(entry->dataRemote), &mbi, sizeof(mbi)) == 0 ||
                    mbi.State != MEM_COMMIT)
                {
                    printf("[HookConfig] %s: dataRemote 0x%llX no longer committed\n",
                        m_szName.c_str(), entry->dataRemote);
                    LiquidHookEx::HookConfig::Remove(m_szName);
                    return false;
                }
            }

            // Verify call site still carries FF 15
            uint8_t probe[2]{};
            (m_pProc ? m_pProc : LiquidHookEx::proc)->Read(entry->callSiteAddr, probe, 2);
            if (probe[0] != 0xFF || probe[1] != 0x15) {
                printf("[HookConfig] %s: call site 0x%llX no longer FF 15 – discarding\n",
                    m_szName.c_str(), entry->callSiteAddr);
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            // Restore origBytes from config
            if (entry->origBytes.empty()) {
                printf("[HookConfig] %s: no origBytes saved – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            if (entry->origBytes.size() > sizeof(m_originalBytes)) {
                printf("[HookConfig] %s: origBytes too large – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            m_originalByteCount = static_cast<uint8_t>(entry->origBytes.size());
            memcpy(m_originalBytes, entry->origBytes.data(), m_originalByteCount);

            // Restore primary pointers
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_callSiteAddr = entry->callSiteAddr;
            m_originalFuncAddr = entry->origStorage;   // reused field: stores the resolved fn addr

            // Restore remote slots
            m_RemoteSlots.clear();
            for (const auto& saved : entry->ripSlots) {
                RemoteSlot rs;
                rs.remoteAddr = reinterpret_cast<void*>(saved.remoteAddr);
                rs.target = static_cast<RipSlotTarget>(saved.target);
                rs.customAddr = saved.customAddr;
                rs.pLocalVar = nullptr;

                uint64_t storedValue = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(saved.remoteAddr);

                switch (rs.target) {
                case RipSlotTarget::HookData:
                    if (storedValue != entry->dataRemote) {
                        printf("[HookConfig] %s: HookData slot 0x%llX value mismatch – discarding\n",
                            m_szName.c_str(), saved.remoteAddr);
                        LiquidHookEx::HookConfig::Remove(m_szName);
                        return false;
                    }
                    break;
                case RipSlotTarget::OriginalFunc:
                    if (storedValue != m_originalFuncAddr) {
                        printf("[HookConfig] %s: OriginalFunc slot 0x%llX value mismatch – discarding\n",
                            m_szName.c_str(), saved.remoteAddr);
                        LiquidHookEx::HookConfig::Remove(m_szName);
                        return false;
                    }
                    break;
                case RipSlotTarget::Custom:
                    if (storedValue != saved.customAddr) {
                        printf("[HookConfig] %s: Custom slot refreshing (0x%llX → 0x%llX)\n",
                            m_szName.c_str(), storedValue, saved.customAddr);
                        (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(saved.remoteAddr, saved.customAddr);
                    }
                    break;
                }

                m_RemoteSlots.push_back(rs);
            }

            m_bIsHooked = true;
            printf("[HookConfig] %s: restored (pid %u, %zu slots)\n",
                m_szName.c_str(), currentPid, m_RemoteSlots.size());
            return true;
        }

        // ── SaveConfig ────────────────────────────────────────────────────────────
        void SaveConfig()
        {
            LiquidHookEx::HookConfig::HookEntry e;
            e.pid = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = 0;  // not used for mid-hooks
            e.callSiteAddr = m_callSiteAddr;
            e.origStorage = m_originalFuncAddr;  // reuse field to persist resolved fn addr

            // Persist original bytes
            e.origBytes.assign(m_originalBytes, m_originalBytes + m_originalByteCount);

            e.ripSlots.clear();
            for (const auto& rs : m_RemoteSlots) {
                LiquidHookEx::HookConfig::RipSlotEntry saved;
                saved.remoteAddr = reinterpret_cast<uintptr_t>(rs.remoteAddr);
                saved.target = static_cast<LiquidHookEx::HookConfig::RipSlotTarget>(rs.target);
                saved.customAddr = rs.customAddr;
                e.ripSlots.push_back(saved);
            }

            LiquidHookEx::HookConfig::Upsert(e);
            printf("[HookConfig] %s: state saved (%zu RIP slots, %u orig bytes)\n",
                m_szName.c_str(), m_RemoteSlots.size(), m_originalByteCount);
        }
    };
}

// ==========================================================================
// Detour.h
// ==========================================================================

// ============================================================================
//  Detour
//
//  External function prologue hook: patches the first N bytes of a target
//  function with an FF 25 (call qword ptr [rip+0]) absolute indirect jump
//  into remote shellcode. A trampoline is built from the stolen prologue
//  bytes followed by a jump back into the function past the patch, so the
//  original function can still be called from inside the shellcode.
//
//  Usage is intentionally parallel to VTable and CallSite:
//
//    // 1. Static globals in the .cpp — RIP slot targets
//    static void* g_pOriginalFn  = nullptr;   // ← points to TRAMPOLINE
//    static MyHookData* g_pHookData = nullptr;
//
//    // 2. Shellcode in its own segment, optimizations off
//    #pragma code_seg(".myHook")
//    #pragma optimize("", off)
//    #pragma runtime_checks("", off)
//    #pragma check_stack(off)
//    RetType __fastcall MyClass::Hook_Shellcode(Args...) {
//        volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(firstArg);
//        MyHookData* data   = g_pHookData;        // ← RipSlot::Data
//        typedef RetType(__fastcall* Fn)(Args...);
//        Fn original        = (Fn)g_pOriginalFn;  // ← RipSlot::Orig (trampoline)
//        ...
//        return original(...);
//    }
//    void MyClass::Hook_Shellcode_End() {}
//    #pragma check_stack()
//    #pragma runtime_checks("", restore)
//    #pragma optimize("", on)
//    #pragma code_seg()
//
//    // 3. Hook call
//    m_Hook.Hook<MyHookData>(
//        PATTERN,          // pattern pointing at the FIRST byte of the function
//        "module.dll",
//        initData,
//        (void*)Hook_Shellcode,
//        (void*)Hook_Shellcode_End,
//        {
//            Detour::RipSlot::Data(&g_pHookData),
//            Detour::RipSlot::Orig(&g_pOriginalFn),  // trampoline addr
//        },
//        14   // stolenBytes — how many prologue bytes to overwrite (>= 14)
//    );
//
//  Patch layout (always FF 25, 14 bytes total):
//    FF 25 00 00 00 00   – call qword ptr [rip+0]   (6 bytes)
//    <shellcode addr>    – absolute 64-bit address   (8 bytes)
//    90 90 ...           – NOPs padding to stolenBytes
//
//  Trampoline layout (remote alloc):
//    <stolen bytes>      – exact copy of the overwritten prologue
//    FF 25 00 00 00 00   – jmp qword ptr [rip+0]
//    <fn + stolenBytes>  – absolute address back into the original function
//
//  RipSlot::Orig points the shellcode at the TRAMPOLINE address, not the
//  raw function. Calling through the trampoline executes the stolen prologue
//  and then jumps back into the function body past the patch, giving the
//  full original behaviour.
//
//  stolenBytes rules:
//    - Minimum 14 (size of the FF 25 + addr patch). Passing 0 defaults to 14.
//    - Must cover only COMPLETE instructions — never cut mid-instruction or
//      the trampoline will execute corrupt opcodes. Use a disassembler or
//      count manually. Common prologues are 14+ bytes of complete instructions.
//    - Any bytes beyond 14 become NOPs in the target function (after the patch)
//      and are included in the trampoline so the stolen region is complete.
// ============================================================================

namespace LiquidHookEx {
    class Detour {
    public:
        // ── Hook data base (mirrors VTable / CallSite) ───────────────────────────
        struct BaseHookData {
            // No pOriginalFunc here — the trampoline address is stored in a
            // RipSlot::Orig slot and read by the shellcode directly.
            // Derived structs add their own fields.
        };

        enum class RipSlotTarget {
            HookData = 0,
            OriginalFunc = 1,   // stores TRAMPOLINE address, not raw fn addr
            Custom = 2,
        };

        struct RipSlot {
            void* pLocalVar;
            RipSlotTarget target;
            uint64_t      customAddr;

            static RipSlot Data(void* pLocalVar) {
                return { pLocalVar, RipSlotTarget::HookData, 0 };
            }
            static RipSlot Orig(void* pLocalVar) {
                return { pLocalVar, RipSlotTarget::OriginalFunc, 0 };
            }
            static RipSlot Custom(void* pLocalVar, uint64_t addr) {
                return { pLocalVar, RipSlotTarget::Custom, addr };
            }
        };

    private:
        // ── Internal remote slot tracking ───────────────────────────────────────
        struct RemoteSlot {
            void* remoteAddr = nullptr;
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;
            void* pLocalVar = nullptr;
        };

        Process* m_pProc;
        std::string m_szName;

        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pTrampolineRemote{};  // stolen bytes + jmp back into original fn
        uintptr_t m_targetFuncAddr{};     // address of the patched function prologue
        uint8_t   m_stolenBytes[32]{};    // snapshot of the overwritten prologue bytes
        uint8_t   m_stolenByteCount{};
        bool      m_bIsHooked{};

        std::vector<RemoteSlot> m_RemoteSlots{};

    public:
        Detour(std::string name, Process* proc = nullptr)
            : m_pProc(proc), m_szName(std::move(name)) {
        }

        void SetProc(Process* p) { m_pProc = p; }

        // ── Hook ────────────────────────────────────────────────────────────────
        //
        // stolenBytes: number of prologue bytes to snapshot and overwrite.
        //   0  = default to 14 (minimum for FF 25 patch).
        //   >0 = caller-specified. Must be >= 14 and must cover only complete
        //        instructions — never cut mid-instruction.
        //
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool Hook(
            std::string          pattern,
            std::string          dllName,
            HOOK_DATA            initData,
            void* fnStart,
            void* fnEnd,
            std::vector<RipSlot> ripSlots,
            uint8_t              stolenBytes = 0)
        {
            if (m_bIsHooked) {
                printf("[!] %s: already hooked\n", m_szName.c_str());
                return false;
            }

            if (TryRestore<HOOK_DATA>()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            // ── locate module ────────────────────────────────────────────────
            auto pMod = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetRemoteModule(dllName.c_str());
            if (!pMod || !pMod->IsValid()) {
                printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str());
                return false;
            }

            // ── scan for function ────────────────────────────────────────────
            auto pFn = pMod->ScanMemory(pattern.c_str());
            if (!pFn) {
                printf("[!] %s: pattern not found\n", m_szName.c_str());
                return false;
            }

            m_targetFuncAddr = reinterpret_cast<uintptr_t>(pFn);
            printf("[+] %s: target fn @ module+0x%llX\n",
                m_szName.c_str(), m_targetFuncAddr - pMod->GetAddr());

            // ── determine stolen byte count ──────────────────────────────────
            // Minimum 14: 6 (FF 25 xx xx xx xx) + 8 (absolute address).
            // The caller is responsible for ensuring this covers only complete
            // instructions — we do not embed a length disassembler.
            if (stolenBytes == 0)
                stolenBytes = 14;

            if (stolenBytes < 14) {
                printf("[!] %s: stolenBytes %u is less than 14 — clamping to 14\n",
                    m_szName.c_str(), stolenBytes);
                stolenBytes = 14;
            }

            if (stolenBytes > sizeof(m_stolenBytes)) {
                printf("[!] %s: stolenBytes %u exceeds internal limit (%zu)\n",
                    m_szName.c_str(), stolenBytes, sizeof(m_stolenBytes));
                return false;
            }

            // ── snapshot prologue bytes ──────────────────────────────────────
            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->Read(
                m_targetFuncAddr, m_stolenBytes, stolenBytes)) {
                printf("[!] %s: failed to read prologue bytes\n", m_szName.c_str());
                return false;
            }

            m_stolenByteCount = stolenBytes;

            printf("[+] %s: stolen bytes (%u): ", m_szName.c_str(), m_stolenByteCount);
            for (int i = 0; i < m_stolenByteCount; ++i)
                printf("%02X ", m_stolenBytes[i]);
            printf("\n");

            // ── allocate & write remote hook data ────────────────────────────
            m_pDataRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(sizeof(HOOK_DATA));
            if (!m_pDataRemote) {
                printf("[!] %s: failed to alloc hook data\n", m_szName.c_str());
                return false;
            }

            (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<HOOK_DATA>(
                reinterpret_cast<uintptr_t>(m_pDataRemote), initData);
            printf("[+] %s: hook data @ 0x%p\n", m_szName.c_str(), m_pDataRemote);

            // ── copy shellcode ────────────────────────────────────────────────
            size_t shellcodeSize =
                reinterpret_cast<uintptr_t>(fnEnd) -
                reinterpret_cast<uintptr_t>(fnStart);

            m_pShellcodeRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(
                shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pShellcodeRemote) {
                printf("[!] %s: failed to alloc shellcode\n", m_szName.c_str());
                return false;
            }

            std::vector<uint8_t> localCode(shellcodeSize);
            memcpy(localCode.data(), fnStart, shellcodeSize);

            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(
                reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode)) {
                printf("[!] %s: failed to write shellcode\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n",
                m_szName.c_str(), m_pShellcodeRemote, shellcodeSize);

            // ── build & write trampoline ──────────────────────────────────────
            if (!BuildTrampoline()) {
                printf("[!] %s: trampoline build failed\n", m_szName.c_str());
                return false;
            }

            // ── patch RIP slots ───────────────────────────────────────────────
            if (!PatchRipSlots(localCode, shellcodeSize, fnStart, ripSlots)) {
                printf("[!] %s: RIP patching failed\n", m_szName.c_str());
                return false;
            }

            // ── flush shellcode & trampoline ──────────────────────────────────
            FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                m_pShellcodeRemote, shellcodeSize);
            FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                m_pTrampolineRemote,
                m_stolenByteCount + 14);  // stolen bytes + FF 25 + addr

            // ── install FF 25 patch ───────────────────────────────────────────
            if (!InstallDetourPatch()) {
                printf("[!] %s: detour patch failed\n", m_szName.c_str());
                return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());

            SaveConfig();
            return true;
        }

        // ── Unhook ───────────────────────────────────────────────────────────────
        bool Unhook()
        {
            if (!m_bIsHooked || !m_targetFuncAddr) return false;

            bool success = true;

            DWORD oldProtect;
            if (!VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr),
                m_stolenByteCount, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                success = false;
            }
            else {
                std::vector<uint8_t> origVec(
                    m_stolenBytes, m_stolenBytes + m_stolenByteCount);
                if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(
                    m_targetFuncAddr, origVec)) {
                    printf("[!] %s: failed to restore prologue bytes\n", m_szName.c_str());
                    success = false;
                }
                VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    reinterpret_cast<void*>(m_targetFuncAddr),
                    m_stolenByteCount, oldProtect, &oldProtect);
            }

            FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr), m_stolenByteCount);

            // Free all remote allocations
            for (const auto& rs : m_RemoteSlots) {
                if (rs.remoteAddr)
                    VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                        rs.remoteAddr, 0, MEM_RELEASE);
            }
            m_RemoteSlots.clear();

            if (m_pTrampolineRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    m_pTrampolineRemote, 0, MEM_RELEASE);
                m_pTrampolineRemote = nullptr;
            }
            if (m_pShellcodeRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    m_pShellcodeRemote, 0, MEM_RELEASE);
                m_pShellcodeRemote = nullptr;
            }
            if (m_pDataRemote) {
                VirtualFreeEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    m_pDataRemote, 0, MEM_RELEASE);
                m_pDataRemote = nullptr;
            }

            m_bIsHooked = false;
            m_targetFuncAddr = 0;
            m_stolenByteCount = 0;

            LiquidHookEx::HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return success;
        }

        // ── Data accessors ───────────────────────────────────────────────────────
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        HOOK_DATA ReadData()
        {
            HOOK_DATA out{};
            if (m_pDataRemote)
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Read(
                    reinterpret_cast<uintptr_t>(m_pDataRemote), &out, sizeof(HOOK_DATA));
            return out;
        }

        template <typename T>
        void WriteField(size_t offset, T value)
        {
            if (m_pDataRemote)
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<T>(
                    reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, value);
        }

        bool  IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:

        // ── Build trampoline and write it into the target process ────────────────
        //
        // Layout:
        //   [stolen bytes]              – exact copy of the overwritten prologue
        //   FF 25 00 00 00 00           – jmp qword ptr [rip+0]
        //   <targetFuncAddr+stolenBytes>– absolute return address (8 bytes)
        //
        // Total size: stolenByteCount + 6 + 8 = stolenByteCount + 14
        //
        bool BuildTrampoline()
        {
            const size_t trampolineSize = m_stolenByteCount + 14;

            m_pTrampolineRemote = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(
                trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pTrampolineRemote) {
                printf("[!] %s: failed to alloc trampoline\n", m_szName.c_str());
                return false;
            }

            std::vector<uint8_t> tramp;
            tramp.reserve(trampolineSize);

            // Part 1: stolen prologue bytes
            tramp.insert(tramp.end(), m_stolenBytes, m_stolenBytes + m_stolenByteCount);

            // Part 2: FF 25 00 00 00 00 — jmp qword ptr [rip+0]
            tramp.push_back(0xFF);
            tramp.push_back(0x25);
            tramp.push_back(0x00);
            tramp.push_back(0x00);
            tramp.push_back(0x00);
            tramp.push_back(0x00);

            // Part 3: absolute address to jump to (target fn + stolen bytes)
            uint64_t returnAddr = m_targetFuncAddr + m_stolenByteCount;
            for (int i = 0; i < 8; ++i)
                tramp.push_back(static_cast<uint8_t>((returnAddr >> (i * 8)) & 0xFF));

            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(
                reinterpret_cast<uintptr_t>(m_pTrampolineRemote), tramp)) {
                printf("[!] %s: failed to write trampoline\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: trampoline @ 0x%p (%zu bytes), returns to 0x%llX\n",
                m_szName.c_str(), m_pTrampolineRemote, trampolineSize, returnAddr);
            return true;
        }

        // ── Patch RIP slots (same engine as VTable and CallSite) ─────────────────
        //
        // RipSlot::Orig resolves to the TRAMPOLINE address, not the raw fn address.
        //
        bool PatchRipSlots(
            std::vector<uint8_t>& localCode,
            size_t                      shellcodeSize,
            void* fnStart,
            const std::vector<RipSlot>& ripSlots)
        {
            int patched = 0;

            for (size_t i = 0; i + 7 <= shellcodeSize; ++i) {
                if (localCode[i] != 0x48) continue;
                if (localCode[i + 1] != 0x8B) continue;
                if (localCode[i + 2] != 0x05) continue;

                int32_t   localDisp = *reinterpret_cast<int32_t*>(&localCode[i + 3]);
                uintptr_t localRip = reinterpret_cast<uintptr_t>(fnStart) + i + 7;
                uintptr_t localTarget = localRip + localDisp;

                const RipSlot* slot = nullptr;
                for (const auto& s : ripSlots) {
                    if (reinterpret_cast<uintptr_t>(s.pLocalVar) == localTarget) {
                        slot = &s;
                        break;
                    }
                }

                if (!slot) {
                    printf("[!] %s: unregistered RIP load at +0x%zX → local 0x%llX\n",
                        m_szName.c_str(), i, (uint64_t)localTarget);
                    return false;
                }

                uint64_t remoteValue = 0;
                switch (slot->target) {
                case RipSlotTarget::HookData:
                    remoteValue = reinterpret_cast<uint64_t>(m_pDataRemote);
                    break;
                case RipSlotTarget::OriginalFunc:
                    // OriginalFunc → trampoline (not raw function address)
                    remoteValue = reinterpret_cast<uint64_t>(m_pTrampolineRemote);
                    break;
                case RipSlotTarget::Custom:
                    remoteValue = slot->customAddr;
                    break;
                }

                // Reuse existing remote slot for same local variable
                void* remoteSlot = nullptr;
                for (const auto& existing : m_RemoteSlots) {
                    if (existing.pLocalVar == slot->pLocalVar) {
                        remoteSlot = existing.remoteAddr;
                        printf("[+] %s: RIP[%d] +0x%zX → reusing slot 0x%p → 0x%llX\n",
                            m_szName.c_str(), patched, i, remoteSlot, remoteValue);
                        break;
                    }
                }

                if (!remoteSlot) {
                    remoteSlot = (m_pProc ? m_pProc : LiquidHookEx::proc)->Alloc(8);
                    if (!remoteSlot) {
                        printf("[!] %s: failed to alloc remote slot at +0x%zX\n",
                            m_szName.c_str(), i);
                        return false;
                    }

                    (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                        reinterpret_cast<uintptr_t>(remoteSlot), remoteValue);

                    m_RemoteSlots.push_back({
                        remoteSlot,
                        slot->target,
                        slot->customAddr,
                        slot->pLocalVar
                        });

                    printf("[+] %s: RIP[%d] +0x%zX → slot 0x%p → 0x%llX\n",
                        m_szName.c_str(), patched, i, remoteSlot, remoteValue);
                }

                uintptr_t remoteInstrAddr =
                    reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i;

                int32_t newOffset = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(remoteSlot) - (remoteInstrAddr + 7));

                if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->Write<int32_t>(
                    remoteInstrAddr + 3, newOffset)) {
                    printf("[!] %s: failed to patch disp32 at +0x%zX\n",
                        m_szName.c_str(), i);
                    return false;
                }

                ++patched;
            }

            // Verify every declared slot was matched
            for (const auto& s : ripSlots) {
                bool found = false;
                for (const auto& rs : m_RemoteSlots) {
                    if (rs.pLocalVar == s.pLocalVar) { found = true; break; }
                }
                if (!found) {
                    printf("[!] %s: declared RipSlot local 0x%llX was never matched in shellcode\n",
                        m_szName.c_str(), (uint64_t)s.pLocalVar);
                    return false;
                }
            }

            printf("[+] %s: patched %d RIP load(s) across %zu declared slot(s)\n",
                m_szName.c_str(), patched, ripSlots.size());
            return true;
        }

        // ── Write FF 25 patch + NOPs to the target function prologue ─────────────
        //
        // Patch layout (stolenByteCount bytes total):
        //   FF 25 00 00 00 00   – jmp qword ptr [rip+0]   (6 bytes)
        //   <shellcode addr>    – absolute 64-bit target   (8 bytes)
        //   90 90 ...           – NOPs for any extra stolen bytes
        //
        bool InstallDetourPatch()
        {
            // Build the 14-byte + NOP patch locally
            std::vector<uint8_t> patch;
            patch.reserve(m_stolenByteCount);

            // FF 25 00 00 00 00 — jmp [rip+0]
            patch.push_back(0xFF);
            patch.push_back(0x25);
            patch.push_back(0x00);
            patch.push_back(0x00);
            patch.push_back(0x00);
            patch.push_back(0x00);

            // Absolute 64-bit shellcode address
            uint64_t scAddr = reinterpret_cast<uint64_t>(m_pShellcodeRemote);
            for (int i = 0; i < 8; ++i)
                patch.push_back(static_cast<uint8_t>((scAddr >> (i * 8)) & 0xFF));

            // Pad remaining stolen bytes with NOPs
            while (patch.size() < m_stolenByteCount)
                patch.push_back(0x90);

            DWORD oldProtect;
            if (!VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr),
                m_stolenByteCount, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                return false;
            }

            bool ok = (m_pProc ? m_pProc : LiquidHookEx::proc)->WriteArray(
                m_targetFuncAddr, patch);

            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr),
                m_stolenByteCount, oldProtect, &oldProtect);

            if (!ok) {
                printf("[!] %s: failed to write detour patch\n", m_szName.c_str());
                return false;
            }

            FlushInstructionCache((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr), m_stolenByteCount);

            printf("[+] %s: function patched (FF 25 + %d NOP(s)) → shellcode 0x%p\n",
                m_szName.c_str(),
                (int)patch.size() - 14,
                m_pShellcodeRemote);
            return true;
        }

        // ── TryRestore ────────────────────────────────────────────────────────────
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool TryRestore()
        {
            uint32_t currentPid = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetProcId();
            auto entry = LiquidHookEx::HookConfig::Find(m_szName, currentPid);
            if (!entry) {
                printf("[HookConfig] %s: no saved state for pid %u\n",
                    m_szName.c_str(), currentPid);
                return false;
            }

            // For Detour hooks: dataRemote, shellcodeRemote, origStorage (trampoline),
            // callSiteAddr (target fn addr), origBytes (stolen bytes)
            if (!entry->dataRemote || !entry->shellcodeRemote || !entry->callSiteAddr) {
                printf("[HookConfig] %s: saved state incomplete – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            // Verify dataRemote is still committed
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                    reinterpret_cast<void*>(entry->dataRemote), &mbi, sizeof(mbi)) == 0 ||
                    mbi.State != MEM_COMMIT)
                {
                    printf("[HookConfig] %s: dataRemote 0x%llX no longer committed\n",
                        m_szName.c_str(), entry->dataRemote);
                    LiquidHookEx::HookConfig::Remove(m_szName);
                    return false;
                }
            }

            // Verify function prologue still carries FF 25 (our patch)
            uint8_t probe[2]{};
            (m_pProc ? m_pProc : LiquidHookEx::proc)->Read(entry->callSiteAddr, probe, 2);
            if (probe[0] != 0xFF || probe[1] != 0x25) {
                printf("[HookConfig] %s: prologue 0x%llX no longer FF 25 – discarding\n",
                    m_szName.c_str(), entry->callSiteAddr);
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            // Restore origBytes (stolen prologue)
            if (entry->origBytes.empty()) {
                printf("[HookConfig] %s: no origBytes saved – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            if (entry->origBytes.size() > sizeof(m_stolenBytes)) {
                printf("[HookConfig] %s: origBytes too large – discarding\n",
                    m_szName.c_str());
                LiquidHookEx::HookConfig::Remove(m_szName);
                return false;
            }

            m_stolenByteCount = static_cast<uint8_t>(entry->origBytes.size());
            memcpy(m_stolenBytes, entry->origBytes.data(), m_stolenByteCount);

            // Restore primary pointers
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_pTrampolineRemote = reinterpret_cast<void*>(entry->origStorage); // reused field
            m_targetFuncAddr = entry->callSiteAddr;                         // reused field

            // Restore remote slots with type validation
            m_RemoteSlots.clear();
            for (const auto& saved : entry->ripSlots) {
                RemoteSlot rs;
                rs.remoteAddr = reinterpret_cast<void*>(saved.remoteAddr);
                rs.target = static_cast<RipSlotTarget>(saved.target);
                rs.customAddr = saved.customAddr;
                rs.pLocalVar = nullptr;

                uint64_t storedValue = (m_pProc ? m_pProc : LiquidHookEx::proc)
                    ->ReadDirect<uint64_t>(saved.remoteAddr);

                switch (rs.target) {
                case RipSlotTarget::HookData:
                    if (storedValue != entry->dataRemote) {
                        printf("[HookConfig] %s: HookData slot 0x%llX value mismatch – discarding\n",
                            m_szName.c_str(), saved.remoteAddr);
                        LiquidHookEx::HookConfig::Remove(m_szName);
                        return false;
                    }
                    break;
                case RipSlotTarget::OriginalFunc:
                    // Slot holds trampoline address
                    if (storedValue != entry->origStorage) {
                        printf("[HookConfig] %s: Orig(trampoline) slot 0x%llX value mismatch – discarding\n",
                            m_szName.c_str(), saved.remoteAddr);
                        LiquidHookEx::HookConfig::Remove(m_szName);
                        return false;
                    }
                    break;
                case RipSlotTarget::Custom:
                    if (storedValue != saved.customAddr) {
                        printf("[HookConfig] %s: Custom slot refreshing (0x%llX → 0x%llX)\n",
                            m_szName.c_str(), storedValue, saved.customAddr);
                        (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                            saved.remoteAddr, saved.customAddr);
                    }
                    break;
                }

                m_RemoteSlots.push_back(rs);
            }

            m_bIsHooked = true;
            printf("[HookConfig] %s: restored (pid %u, %zu slots)\n",
                m_szName.c_str(), currentPid, m_RemoteSlots.size());
            return true;
        }

        // ── SaveConfig ────────────────────────────────────────────────────────────
        //
        // Field mapping (reusing HookConfig fields):
        //   callSiteAddr  → target function address
        //   origStorage   → trampoline remote address
        //   origBytes     → stolen prologue bytes
        //   targetFunction → 0 (unused for Detour)
        //
        void SaveConfig()
        {
            LiquidHookEx::HookConfig::HookEntry e;
            e.pid = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = 0;  // unused
            e.callSiteAddr = m_targetFuncAddr;
            e.origStorage = reinterpret_cast<uintptr_t>(m_pTrampolineRemote);
            e.origBytes.assign(m_stolenBytes, m_stolenBytes + m_stolenByteCount);

            e.ripSlots.clear();
            for (const auto& rs : m_RemoteSlots) {
                LiquidHookEx::HookConfig::RipSlotEntry saved;
                saved.remoteAddr = reinterpret_cast<uintptr_t>(rs.remoteAddr);
                saved.target = static_cast<LiquidHookEx::HookConfig::RipSlotTarget>(rs.target);
                saved.customAddr = rs.customAddr;
                e.ripSlots.push_back(saved);
            }

            LiquidHookEx::HookConfig::Upsert(e);
            printf("[HookConfig] %s: state saved (%zu RIP slots, %u stolen bytes)\n",
                m_szName.c_str(), m_RemoteSlots.size(), m_stolenByteCount);
        }
    };
}

#endif // LIQUIDHOOKEX_AMALGAMATED_H