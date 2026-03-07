// =============================================================================
//  LiquidHookEx.h  —  single-file distribution header
//
//  Usage:
//      #include "LiquidHookEx.h"
//      #pragma comment(lib, "LiquidHookEx.lib")
//
//  Requirements:
//      - x64 Release build  (no /ZI, /RTC, or incremental linking)
//      - C++20
//      - Windows SDK
//
//  What lives here vs. in the lib:
//      Header  — declarations, all templates (Process::Read/Write/etc.,
//                VTable, CallSite), HookConfig (inline JSON persistence)
//      Lib     — Process.cpp, Pattern.cpp, Globals.cpp,
//                SysCallManager.cpp, Syscalls_x64.asm
// =============================================================================

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#undef min

// ---------------------------------------------------------------------------
//  NT types not always defined by older SDK headers
// ---------------------------------------------------------------------------
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif
#ifndef PCLIENT_ID
typedef CLIENT_ID* PCLIENT_ID;
#endif
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) {  \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif


// =============================================================================
//  SyscallManager  —  SysCallManager.cpp + Syscalls_x64.asm
// =============================================================================

class SyscallManager {
private:
    struct SyscallInfo { DWORD number; const char* name; bool initialized; };

    static SyscallInfo s_NtOpenProcess;
    static SyscallInfo s_NtReadVirtualMemory;
    static SyscallInfo s_NtWriteVirtualMemory;
    static SyscallInfo s_NtAllocateVirtualMemory;
    static SyscallInfo s_NtFreeVirtualMemory;
    static SyscallInfo s_NtProtectVirtualMemory;
    static SyscallInfo s_NtQueryVirtualMemory;
    static SyscallInfo s_NtCreateThreadEx;

    static DWORD ExtractSyscallNumber(const char* functionName);
    static bool  InitializeSyscall(SyscallInfo& info);

public:
    static bool     Initialize();
    static HANDLE   OpenProcessDirect(DWORD processId, ACCESS_MASK desiredAccess);
    static bool     ReadMemoryDirect(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size);
    static bool     WriteMemoryDirect(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size);
    static PVOID    AllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect);
    static bool     FreeMemoryDirect(HANDLE hProcess, PVOID address);
    static HANDLE   CreateRemoteThreadDirect(HANDLE hProcess, PVOID startAddress, PVOID parameter);

    static NTSTATUS SyscallNtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    static NTSTATUS SyscallNtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    static NTSTATUS SyscallNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    static NTSTATUS SyscallNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    static NTSTATUS SyscallNtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
    static NTSTATUS SyscallNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    static NTSTATUS SyscallNtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
        PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
};

// ASM stubs — resolved by the lib
extern "C" {
    extern DWORD g_syscall_NtOpenProcess;
    extern DWORD g_syscall_NtReadVirtualMemory;
    extern DWORD g_syscall_NtWriteVirtualMemory;
    extern DWORD g_syscall_NtAllocateVirtualMemory;
    extern DWORD g_syscall_NtFreeVirtualMemory;
    extern DWORD g_syscall_NtProtectVirtualMemory;
    extern DWORD g_syscall_NtQueryVirtualMemory;
    extern DWORD g_syscall_NtCreateThreadEx;

    NTSTATUS Syscall_NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    NTSTATUS Syscall_NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS Syscall_NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS Syscall_NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS Syscall_NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
    NTSTATUS Syscall_NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS Syscall_NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
        PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
}


// =============================================================================
//  LiquidHookEx namespace
// =============================================================================

namespace LiquidHookEx {

    // =========================================================================
    //  Memory  —  Pattern.cpp
    // =========================================================================

    class Memory {
    public:
        static uint8_t* ScanMemory(uintptr_t pStart, uintptr_t pSize, const char* signature);
    };


    // =========================================================================
    //  Process + RemoteModule  —  Process.cpp
    //  Non-template methods: declarations only.
    //  Template methods: defined here (can't go in the lib).
    // =========================================================================

    class Process;

    struct VTableFunctionInfo {
        int       index;
        uintptr_t vTableAddr;
    };

    class RemoteModule {
    private:
        uintptr_t   m_pSize{};
        uintptr_t   m_pBase{};
        Process* m_pProc{};
        std::string m_szDll{};
        bool        m_bIsValid{};
        bool        m_bAllocated{};

    public:
        struct Section { std::string name; uintptr_t addr; size_t size; };

        RemoteModule(uintptr_t pBase, uintptr_t pSize, Process* pProc, std::string szDll = "");
        RemoteModule();

        bool      Sync();
        bool      IsValid() { return m_bIsValid; }
        uintptr_t GetAddr() { return m_pBase; }
        uintptr_t GetSize() { return m_pSize; }

        std::vector<Section> GetSections();
        VTableFunctionInfo   FindVTableContainingFunction(uintptr_t fn);
        uint8_t* ScanMemory(const char* signature);
        uint32_t             ResolveDisp32(uint8_t* instruction, uint32_t dwSkipBytes = 0);
        uintptr_t            ResolveRIP(uint8_t* pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
        uintptr_t            ResolveRIP(uintptr_t pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
        uintptr_t            GetProcAddress(std::string szFnName);

        // Inline in original header — kept here
        inline static uintptr_t ResolveInstruction(uintptr_t addr, int byteOffset, bool isRelativeCall = false) {
            BYTE* bytes = (BYTE*)addr;
            if (isRelativeCall && bytes[0] == 0xE8)
                return addr + 5 + *(int32_t*)(bytes + 1);
            return *(int32_t*)(bytes + byteOffset);
        }
    };

    class Process {
    public:
        HANDLE m_hProc{};

    private:
        DWORD       pProcId{};
        HWND        m_hWnd{};
        std::string m_szProcName{};
        std::map<std::string, RemoteModule*> remoteModuleList{};
        std::vector<void*> m_remoteAllocations;

        bool       InitializeSysCalls();
        void       GetProcHandle();
        MODULEINFO GetModuleInfoEx(std::string m_Name);

    public:
        HWND    GetHwnd();
        Process(std::string szProcName);
        PVOID   Alloc(size_t size, DWORD fFlags = MEM_COMMIT | MEM_RESERVE, DWORD fAccess = PAGE_READWRITE);
        DWORD   GetProcId() { return pProcId; }

        // ── Read — templates, must stay in header ─────────────────────────────
        template <typename T>
        inline bool Read(uintptr_t address, T* buffer, SIZE_T size) {
            return SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address), buffer, size);
        }
        template <typename T>
        inline bool Read(uintptr_t address, T* buffer) { return Read(address, buffer, sizeof(T)); }

        template <typename T>
        inline T ReadDirect(uintptr_t address) {
            T buf{}; Read(address, &buf, sizeof(T)); return buf;
        }
        template <typename T>
        inline T ReadDirect(uintptr_t address, int size) {
            T buf{}; Read(address, &buf, size); return buf;
        }
        template <typename T, typename T2>
        inline T2 ReadDirect(uintptr_t address) {
            T buf{}; Read(address, &buf, sizeof(T)); return reinterpret_cast<T2>(buf);
        }

        template <typename T>
        std::vector<T> ReadArray(uintptr_t address, size_t count) {
            if constexpr (std::is_same_v<T, bool>) {
                std::vector<uint8_t> temp(count);
                if (!SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address), temp.data(), count))
                    return {};
                std::vector<bool> result; result.reserve(count);
                for (auto b : temp) result.push_back(b != 0);
                return result;
            }
            else {
                std::vector<T> buf(count);
                if (!SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address), buf.data(), count * sizeof(T)))
                    buf.clear();
                return buf;
            }
        }

        inline std::vector<uint8_t> ReadBytes(uintptr_t address, size_t size) {
            std::vector<uint8_t> buf(size);
            if (!SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address), buf.data(), size))
                buf.clear();
            return buf;
        }

        std::string ReadString(uintptr_t address, SIZE_T maxLength = 256);

        // ── Write — templates, must stay in header ────────────────────────────
        template <typename T>
        inline bool Write(uintptr_t address, T value) {
            return SyscallManager::WriteMemoryDirect(m_hProc, (PVOID)address, (PVOID)&value, sizeof(T));
        }

        template <typename T>
        bool WriteArray(uintptr_t address, const std::vector<T>& data) {
            if constexpr (std::is_same_v<T, bool>) {
                std::vector<uint8_t> temp; temp.reserve(data.size());
                for (bool b : data) temp.push_back(b ? 1 : 0);
                return SyscallManager::WriteMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address), temp.data(), temp.size());
            }
            else {
                return SyscallManager::WriteMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address),
                    const_cast<T*>(data.data()), data.size() * sizeof(T));
            }
        }

        bool  WriteString(uintptr_t address, const std::string& str, SIZE_T maxLength = 256);
        void* AllocateAndWriteString(std::string str);

        // ── Modules ───────────────────────────────────────────────────────────
        RemoteModule* GetRemoteModule(std::string szModuleName);
        VTableFunctionInfo FindVTableContainingFunction(uintptr_t fn, std::string szMod);

        // ── VTable utilities — templates, must stay in header ─────────────────
        uintptr_t GetVTable(uintptr_t pThis) noexcept;

        template <int Index>
        uintptr_t GetVTableFunction(uintptr_t pThis) noexcept {
            if (!pThis) return 0;
            uintptr_t vt = ReadDirect<uintptr_t>(pThis);
            return vt ? ReadDirect<uintptr_t>(vt + Index * sizeof(void*)) : 0;
        }
        template <int Index>
        uintptr_t GetVTableFunctionFromVTable(uintptr_t vtableAddr) noexcept {
            return vtableAddr ? ReadDirect<uintptr_t>(vtableAddr + Index * sizeof(void*)) : 0;
        }

        std::vector<uintptr_t> ReadVTable(uintptr_t pThis, size_t count = 64) noexcept;
        void                   DumpVTable(uintptr_t pThis, size_t count = 32, const char* name = "VTable") noexcept;

        // ── Allocation tracking ───────────────────────────────────────────────
        void   TrackAllocation(void* pRemote);
        bool   FreeRemote(void* pRemote);
        void   FreeAllRemote();
        size_t GetAllocationCount() const { return m_remoteAllocations.size(); }

        // ── Remote thread helpers — templates, must stay in header ────────────
        void* AllocAndWriteShellcode(void* funcStart, void* funcEnd);
        HANDLE CreateRemoteThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
        DWORD  ExecuteAndCleanup(void* shellcode, void* context, DWORD timeoutMs = 5000);

        template<typename ContextType>
        DWORD ExecuteRemoteWrapper(void* wrapperFunc, void* wrapperEnd,
            const ContextType& context, DWORD timeoutMs = 5000) {
            void* ctx = Alloc(sizeof(ContextType)); if (!ctx) return (DWORD)-1;
            Write(reinterpret_cast<uintptr_t>(ctx), context);
            void* sc = AllocAndWriteShellcode(wrapperFunc, wrapperEnd);
            if (!sc) { FreeRemote(ctx); return (DWORD)-1; }
            return ExecuteAndCleanup(sc, ctx, timeoutMs);
        }

        template<typename ContextType, typename ReturnType>
        bool ExecuteRemoteWrapper(void* wrapperFunc, void* wrapperEnd,
            const ContextType& context, ReturnType& outResult, DWORD timeoutMs = 5000) {
            void* ctx = Alloc(sizeof(ContextType)); if (!ctx) return false;
            Write(reinterpret_cast<uintptr_t>(ctx), context);
            void* sc = AllocAndWriteShellcode(wrapperFunc, wrapperEnd);
            if (!sc) { FreeRemote(ctx); return false; }
            return ExecuteAndCleanup(sc, ctx, outResult, timeoutMs);
        }

        template<typename T>
        bool ExecuteAndCleanup(void* shellcode, void* context, T& outResult, DWORD timeoutMs = 5000) {
            HANDLE hThread = CreateRemoteThreadEx(reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode), context);
            if (!hThread) { FreeRemote(context); FreeRemote(shellcode); return false; }
            if (WaitForSingleObject(hThread, timeoutMs) == WAIT_TIMEOUT) {
                CloseHandle(hThread); FreeRemote(context); FreeRemote(shellcode); return false;
            }
            DWORD exitCode = 0; GetExitCodeThread(hThread, &exitCode); CloseHandle(hThread);
            outResult = static_cast<T>(exitCode);
            FreeRemote(context); FreeRemote(shellcode);
            return true;
        }
    };


    // =========================================================================
    //  HookConfig  —  no .cpp, inline JSON persistence
    // =========================================================================

    namespace HookConfig {

        constexpr const char* CONFIG_PATH = "hooks.json";

        enum class RipSlotTarget : uint8_t { HookData = 0, OriginalFunc = 1, Custom = 2 };

        struct RipSlotEntry {
            uintptr_t     remoteAddr = 0;
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;
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
            std::vector<uint8_t>      origBytes;
        };

        namespace detail {
            inline std::string uintToHex(uintptr_t v) {
                char b[32]; snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v); return b;
            }
            inline uintptr_t hexToUint(const std::string& s) {
                return s.empty() ? 0 : (uintptr_t)strtoull(s.c_str(), nullptr, 16);
            }
            inline std::string bytesToHex(const std::vector<uint8_t>& bytes) {
                std::string s; s.reserve(bytes.size() * 2);
                static const char* h = "0123456789ABCDEF";
                for (uint8_t b : bytes) { s += h[b >> 4]; s += h[b & 0xF]; }
                return s;
            }
            inline std::vector<uint8_t> hexToBytes(const std::string& s) {
                std::vector<uint8_t> r;
                auto nib = [](char c) -> uint8_t {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return 0;
                    };
                for (size_t i = 0; i + 1 < s.size(); i += 2)
                    r.push_back((nib(s[i]) << 4) | nib(s[i + 1]));
                return r;
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
                            before != '\r' && before != '{' && before != ',')
                        {
                            pos = hit + 1; continue;
                        }
                    }
                    return hit + token.size();
                }
                return std::string::npos;
            }
            inline std::string extractString(const std::string& json, const std::string& key) {
                size_t i = findValueStart(json, key); if (i == std::string::npos) return {};
                auto q1 = json.find('"', i);      if (q1 == std::string::npos) return {};
                auto q2 = json.find('"', q1 + 1); if (q2 == std::string::npos) return {};
                return json.substr(q1 + 1, q2 - q1 - 1);
            }
            inline uint32_t extractUint(const std::string& json, const std::string& key) {
                size_t i = findValueStart(json, key); if (i == std::string::npos) return 0;
                while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\n' || json[i] == '\r')) ++i;
                return (uint32_t)strtoul(json.c_str() + i, nullptr, 10);
            }
            inline std::vector<RipSlotEntry> extractRipSlots(const std::string& json) {
                std::vector<RipSlotEntry> result;
                size_t ac = findValueStart(json, "ripSlots"); if (ac == std::string::npos) return result;
                auto as_ = json.find('[', ac), ae = json.find(']', ac);
                if (as_ == std::string::npos || ae == std::string::npos) return result;
                size_t pos = as_ + 1;
                while (pos < ae) {
                    auto os = json.find('{', pos); if (os == std::string::npos || os >= ae) break;
                    auto oe = json.find('}', os);  if (oe == std::string::npos || oe > ae)  break;
                    std::string obj = json.substr(os, oe - os + 1);
                    RipSlotEntry e;
                    e.remoteAddr = hexToUint(extractString(obj, "addr"));
                    e.target = static_cast<RipSlotTarget>(extractUint(obj, "target"));
                    e.customAddr = hexToUint(extractString(obj, "customAddr"));
                    result.push_back(e); pos = oe + 1;
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
                std::string ob = extractString(block, "origBytes");
                if (!ob.empty()) e.origBytes = hexToBytes(ob);
                return e;
            }
            inline std::string serializeEntry(const HookEntry& e) {
                std::string s = "  {\n"
                    "    \"pid\": " + std::to_string(e.pid) + ",\n"
                    "    \"hookName\": \"" + e.hookName + "\",\n"
                    "    \"dataRemote\": \"" + uintToHex(e.dataRemote) + "\",\n"
                    "    \"shellcodeRemote\": \"" + uintToHex(e.shellcodeRemote) + "\",\n"
                    "    \"targetFunction\": \"" + uintToHex(e.targetFunction) + "\"";
                if (e.callSiteAddr) s += ",\n    \"callSiteAddr\": \"" + uintToHex(e.callSiteAddr) + "\"";
                if (e.origStorage)  s += ",\n    \"origStorage\": \"" + uintToHex(e.origStorage) + "\"";
                if (!e.origBytes.empty()) s += ",\n    \"origBytes\": \"" + bytesToHex(e.origBytes) + "\"";
                if (!e.ripSlots.empty()) {
                    s += ",\n    \"ripSlots\": [\n";
                    for (size_t i = 0; i < e.ripSlots.size(); ++i) {
                        const auto& sl = e.ripSlots[i];
                        s += "      { \"addr\": \"" + uintToHex(sl.remoteAddr) + "\", \"target\": " + std::to_string((int)sl.target);
                        if (sl.target == RipSlotTarget::Custom) s += ", \"customAddr\": \"" + uintToHex(sl.customAddr) + "\"";
                        s += " }"; if (i + 1 < e.ripSlots.size()) s += ","; s += "\n";
                    }
                    s += "    ]";
                }
                return s + "\n  }";
            }
        } // namespace detail

        inline std::vector<HookEntry> Load() {
            std::vector<HookEntry> entries;
            std::ifstream f(CONFIG_PATH); if (!f.is_open()) return entries;
            std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            size_t pos = 0;
            while (pos < json.size()) {
                auto start = json.find('{', pos); if (start == std::string::npos) break;
                int depth = 0; size_t end = start;
                for (size_t j = start; j < json.size(); ++j) {
                    if (json[j] == '{') ++depth;
                    else if (json[j] == '}' && --depth == 0) { end = j; break; }
                }
                HookEntry e = detail::parseEntry(json.substr(start, end - start + 1));
                if (!e.hookName.empty()) entries.push_back(e);
                pos = end + 1;
            }
            return entries;
        }
        inline bool Save(const std::vector<HookEntry>& entries) {
            std::ofstream f(CONFIG_PATH, std::ios::trunc); if (!f.is_open()) return false;
            f << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                f << detail::serializeEntry(entries[i]);
                if (i + 1 < entries.size()) f << ',';
                f << '\n';
            }
            f << "]\n"; return f.good();
        }
        inline std::optional<HookEntry> Find(const std::string& hookName, uint32_t pid = 0) {
            for (auto& e : Load()) if (e.hookName == hookName && (pid == 0 || e.pid == pid)) return e;
            return std::nullopt;
        }
        inline bool Upsert(const HookEntry& entry) {
            auto entries = Load();
            for (auto& e : entries) if (e.hookName == entry.hookName) { e = entry; return Save(entries); }
            entries.push_back(entry); return Save(entries);
        }
        inline bool Remove(const std::string& hookName) {
            auto entries = Load(); auto before = entries.size();
            entries.erase(std::remove_if(entries.begin(), entries.end(),
                [&](const HookEntry& e) { return e.hookName == hookName; }), entries.end());
            return entries.size() == before || Save(entries);
        }

    } // namespace HookConfig


    // =========================================================================
    //  Globals  —  Globals.cpp
    // =========================================================================

    extern Process* proc;
    extern void INIT(std::string procName);


    // =========================================================================
    //  VTable  —  fully in header (all methods touch template parameters)
    // =========================================================================

    class VTable {
    public:
        struct BaseHookData { uint64_t pOriginalFunc; };

        enum class RipSlotTarget { HookData = 0, OriginalFunc = 1, Custom = 2 };

        struct RipSlot {
            void* pLocalVar; RipSlotTarget target; uint64_t customAddr;
            static RipSlot Data(void* p) { return { p, RipSlotTarget::HookData,     0 }; }
            static RipSlot Orig(void* p) { return { p, RipSlotTarget::OriginalFunc, 0 }; }
            static RipSlot Custom(void* p, uint64_t a) { return { p, RipSlotTarget::Custom,       a }; }
        };

    private:
        struct RemoteSlot {
            void* remoteAddr = nullptr;
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;
            void* pLocalVar = nullptr;
        };

        Process* m_pProc;
        std::string             m_szName;
        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pOrigStorage{};
        uintptr_t               m_pTargetFunction{};
        bool                    m_bIsHooked{};
        std::vector<RemoteSlot> m_RemoteSlots{};

    public:
        VTable(std::string name, Process* proc = nullptr) : m_pProc(proc), m_szName(std::move(name)) {}
        void SetProc(Process* p) { m_pProc = p; }

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool Hook(std::string pattern, std::string dllName, HOOK_DATA initData,
            void* fnStart, void* fnEnd, std::vector<RipSlot> ripSlots)
        {
            if (m_bIsHooked) { printf("[!] %s: already hooked\n", m_szName.c_str()); return false; }
            if (TryRestore<HOOK_DATA>()) { printf("[+] %s: restored from saved state\n", m_szName.c_str()); return true; }

            auto* p = m_pProc ? m_pProc : proc;
            auto  pMod = p->GetRemoteModule(dllName.c_str());
            if (!pMod || !pMod->IsValid()) { printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str()); return false; }

            uintptr_t pFnAddr = reinterpret_cast<uintptr_t>(pMod->ScanMemory(pattern.c_str()));
            if (!pFnAddr) { printf("[!] %s: pattern not found\n", m_szName.c_str()); return false; }

            auto info = pMod->FindVTableContainingFunction(pFnAddr);
            if (!info.vTableAddr || info.index < 0) { printf("[!] %s: vtable lookup failed\n", m_szName.c_str()); return false; }
            m_pTargetFunction = info.vTableAddr + (info.index * 8);

            uint64_t originalFunc = p->ReadDirect<uint64_t>(m_pTargetFunction);
            printf("[+] %s: original fn @ 0x%llX\n", m_szName.c_str(), originalFunc);

            m_pDataRemote = p->Alloc(sizeof(HOOK_DATA));
            if (!m_pDataRemote) { printf("[!] %s: alloc hook data failed\n", m_szName.c_str()); return false; }
            reinterpret_cast<BaseHookData*>(&initData)->pOriginalFunc = originalFunc;
            p->Write<HOOK_DATA>(reinterpret_cast<uintptr_t>(m_pDataRemote), initData);

            m_pOrigStorage = p->Alloc(8);
            if (!m_pOrigStorage) { printf("[!] %s: alloc orig storage failed\n", m_szName.c_str()); return false; }
            p->Write<uint64_t>(reinterpret_cast<uintptr_t>(m_pOrigStorage), originalFunc);

            size_t scSize = reinterpret_cast<uintptr_t>(fnEnd) - reinterpret_cast<uintptr_t>(fnStart);
            m_pShellcodeRemote = p->Alloc(scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pShellcodeRemote) { printf("[!] %s: alloc shellcode failed\n", m_szName.c_str()); return false; }

            std::vector<uint8_t> localCode(scSize);
            memcpy(localCode.data(), fnStart, scSize);
            if (!p->WriteArray(reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode))
            {
                printf("[!] %s: write shellcode failed\n", m_szName.c_str()); return false;
            }
            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n", m_szName.c_str(), m_pShellcodeRemote, scSize);

            if (!PatchRipSlots(localCode, scSize, fnStart, originalFunc, ripSlots))
            {
                printf("[!] %s: RIP patching failed\n", m_szName.c_str()); return false;
            }
            if (!InstallVTableHook())
            {
                printf("[!] %s: vtable install failed\n", m_szName.c_str()); return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());
            SaveConfig();
            return true;
        }

        bool Unhook() {
            if (!m_bIsHooked || !m_pTargetFunction) return false;
            auto* p = m_pProc ? m_pProc : proc;
            uint64_t orig = p->ReadDirect<uint64_t>(reinterpret_cast<uintptr_t>(m_pOrigStorage));
            DWORD op;
            VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_pTargetFunction), 8, PAGE_READWRITE, &op);
            p->Write<uint64_t>(m_pTargetFunction, orig);
            VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_pTargetFunction), 8, op, &op);
            for (const auto& rs : m_RemoteSlots)
                if (rs.remoteAddr) VirtualFreeEx(p->m_hProc, rs.remoteAddr, 0, MEM_RELEASE);
            m_RemoteSlots.clear();
            if (m_pShellcodeRemote) { VirtualFreeEx(p->m_hProc, m_pShellcodeRemote, 0, MEM_RELEASE); m_pShellcodeRemote = nullptr; }
            if (m_pDataRemote) { VirtualFreeEx(p->m_hProc, m_pDataRemote, 0, MEM_RELEASE); m_pDataRemote = nullptr; }
            if (m_pOrigStorage) { VirtualFreeEx(p->m_hProc, m_pOrigStorage, 0, MEM_RELEASE); m_pOrigStorage = nullptr; }
            m_bIsHooked = false; m_pTargetFunction = 0;
            HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return true;
        }

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        HOOK_DATA ReadData() {
            HOOK_DATA out{};
            if (m_pDataRemote)
                (m_pProc ? m_pProc : proc)->Read(reinterpret_cast<uintptr_t>(m_pDataRemote), &out, sizeof(HOOK_DATA));
            return out;
        }

        template <typename T>
        void WriteField(size_t offset, T value) {
            if (m_pDataRemote)
                (m_pProc ? m_pProc : proc)->Write<T>(reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, value);
        }

        bool  IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool TryRestore() {
            auto* p = m_pProc ? m_pProc : proc;
            auto  pid = p->GetProcId();
            auto  entry = HookConfig::Find(m_szName, pid);
            if (!entry) { printf("[HookConfig] %s: no saved state for pid %u\n", m_szName.c_str(), pid); return false; }
            if (!entry->dataRemote || !entry->shellcodeRemote || !entry->targetFunction)
            {
                printf("[HookConfig] %s: incomplete – discarding\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(p->m_hProc, reinterpret_cast<void*>(entry->dataRemote), &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
            {
                printf("[HookConfig] %s: dataRemote stale – discarding\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            if (p->ReadDirect<uint64_t>(entry->targetFunction) != entry->shellcodeRemote)
            {
                printf("[HookConfig] %s: vtable stale – discarding\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_pTargetFunction = entry->targetFunction;
            m_pOrigStorage = reinterpret_cast<void*>(entry->origStorage);
            uint64_t origVal = p->ReadDirect<uint64_t>(entry->origStorage);
            m_RemoteSlots.clear();
            for (const auto& saved : entry->ripSlots) {
                RemoteSlot rs{ reinterpret_cast<void*>(saved.remoteAddr), static_cast<RipSlotTarget>(saved.target), saved.customAddr, nullptr };
                uint64_t sv = p->ReadDirect<uint64_t>(saved.remoteAddr);
                if (rs.target == RipSlotTarget::HookData && sv != entry->dataRemote)
                {
                    printf("[HookConfig] %s: HookData slot mismatch\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
                }
                else if (rs.target == RipSlotTarget::OriginalFunc && sv != origVal)
                {
                    printf("[HookConfig] %s: OriginalFunc slot mismatch\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
                }
                else if (rs.target == RipSlotTarget::Custom && sv != saved.customAddr)
                    p->Write<uint64_t>(saved.remoteAddr, saved.customAddr);
                m_RemoteSlots.push_back(rs);
            }
            m_bIsHooked = true;
            printf("[HookConfig] %s: restored (pid %u, %zu slots)\n", m_szName.c_str(), pid, m_RemoteSlots.size());
            return true;
        }

        bool PatchRipSlots(std::vector<uint8_t>& localCode, size_t scSize, void* fnStart,
            uint64_t originalFunc, const std::vector<RipSlot>& ripSlots)
        {
            auto* p = m_pProc ? m_pProc : proc;
            int patched = 0;
            for (size_t i = 0; i + 7 <= scSize; ++i) {
                if (localCode[i] != 0x48 || localCode[i + 1] != 0x8B || localCode[i + 2] != 0x05) continue;
                uintptr_t localTarget = (reinterpret_cast<uintptr_t>(fnStart) + i + 7)
                    + *reinterpret_cast<int32_t*>(&localCode[i + 3]);
                const RipSlot* slot = nullptr;
                for (const auto& s : ripSlots)
                    if (reinterpret_cast<uintptr_t>(s.pLocalVar) == localTarget) { slot = &s; break; }
                if (!slot) { printf("[!] %s: unregistered RIP load at +0x%zX\n", m_szName.c_str(), i); return false; }
                uint64_t val = (slot->target == RipSlotTarget::HookData) ? reinterpret_cast<uint64_t>(m_pDataRemote)
                    : (slot->target == RipSlotTarget::OriginalFunc) ? originalFunc
                    : slot->customAddr;
                void* remoteSlot = nullptr;
                for (const auto& ex : m_RemoteSlots)
                    if (ex.pLocalVar == slot->pLocalVar) { remoteSlot = ex.remoteAddr; break; }
                if (!remoteSlot) {
                    remoteSlot = p->Alloc(8);
                    if (!remoteSlot) { printf("[!] %s: alloc slot failed\n", m_szName.c_str()); return false; }
                    p->Write<uint64_t>(reinterpret_cast<uintptr_t>(remoteSlot), val);
                    m_RemoteSlots.push_back({ remoteSlot, slot->target, slot->customAddr, slot->pLocalVar });
                    printf("[+] %s: RIP[%d] +0x%zX → 0x%p → 0x%llX\n", m_szName.c_str(), patched, i, remoteSlot, val);
                }
                int32_t disp = static_cast<int32_t>(reinterpret_cast<uintptr_t>(remoteSlot)
                    - (reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i + 7));
                if (!p->Write<int32_t>(reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i + 3, disp))
                {
                    printf("[!] %s: disp patch failed\n", m_szName.c_str()); return false;
                }
                ++patched;
            }
            for (const auto& s : ripSlots) {
                bool found = false;
                for (const auto& rs : m_RemoteSlots) if (rs.pLocalVar == s.pLocalVar) { found = true; break; }
                if (!found) { printf("[!] %s: RipSlot never matched\n", m_szName.c_str()); return false; }
            }
            printf("[+] %s: patched %d RIP load(s)\n", m_szName.c_str(), patched);
            return true;
        }

        bool InstallVTableHook() {
            auto* p = m_pProc ? m_pProc : proc;
            DWORD op;
            if (!VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_pTargetFunction), 8, PAGE_READWRITE, &op)) return false;
            bool ok = p->Write<uint64_t>(m_pTargetFunction, reinterpret_cast<uint64_t>(m_pShellcodeRemote));
            VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_pTargetFunction), 8, op, &op);
            return ok;
        }

        void SaveConfig() {
            auto* p = m_pProc ? m_pProc : proc;
            HookConfig::HookEntry e;
            e.pid = p->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = m_pTargetFunction;
            e.origStorage = reinterpret_cast<uintptr_t>(m_pOrigStorage);
            for (const auto& rs : m_RemoteSlots)
                e.ripSlots.push_back({ reinterpret_cast<uintptr_t>(rs.remoteAddr),
                    static_cast<HookConfig::RipSlotTarget>(rs.target), rs.customAddr });
            HookConfig::Upsert(e);
            printf("[HookConfig] %s: saved (%zu slots)\n", m_szName.c_str(), m_RemoteSlots.size());
        }
    };


    // =========================================================================
    //  CallSite  —  fully in header (all methods touch template parameters)
    // =========================================================================

    class CallSite {
    public:
        struct BaseHookData {};

        enum class RipSlotTarget { HookData = 0, OriginalFunc = 1, Custom = 2 };

        struct RipSlot {
            void* pLocalVar; RipSlotTarget target; uint64_t customAddr;
            static RipSlot Data(void* p) { return { p, RipSlotTarget::HookData,     0 }; }
            static RipSlot Orig(void* p) { return { p, RipSlotTarget::OriginalFunc, 0 }; }
            static RipSlot Custom(void* p, uint64_t a) { return { p, RipSlotTarget::Custom,       a }; }
        };

    private:
        struct RemoteSlot {
            void* remoteAddr = nullptr;
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;
            void* pLocalVar = nullptr;
        };

        Process* m_pProc;
        std::string             m_szName;
        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pFuncPtrStorage{};
        uintptr_t               m_callSiteAddr{};
        uint64_t                m_originalFuncAddr{};
        uint8_t                 m_originalBytes[16]{};
        uint8_t                 m_originalByteCount{};
        bool                    m_bIsHooked{};
        std::vector<RemoteSlot> m_RemoteSlots{};

    public:
        CallSite(std::string name, Process* proc = nullptr) : m_pProc(proc), m_szName(std::move(name)) {}
        void SetProc(Process* p) { m_pProc = p; }

        // overwriteSize: 0 = auto-detect. Pass >= 6 when the instruction following
        // the call site must also be NOP'd to avoid a decoded fragment in the byte stream.
        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool Hook(std::string callSitePattern, std::string dllName, HOOK_DATA initData,
            void* fnStart, void* fnEnd, std::vector<RipSlot> ripSlots, uint8_t overwriteSize = 0)
        {
            if (m_bIsHooked) { printf("[!] %s: already hooked\n", m_szName.c_str()); return false; }
            if (TryRestore<HOOK_DATA>()) { printf("[+] %s: restored from saved state\n", m_szName.c_str()); return true; }

            auto* p = m_pProc ? m_pProc : proc;
            auto  pMod = p->GetRemoteModule(dllName.c_str());
            if (!pMod || !pMod->IsValid()) { printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str()); return false; }

            auto pCallSite = pMod->ScanMemory(callSitePattern.c_str());
            if (!pCallSite) { printf("[!] %s: call site pattern not found\n", m_szName.c_str()); return false; }
            m_callSiteAddr = reinterpret_cast<uintptr_t>(pCallSite);
            printf("[+] %s: call site @ module+0x%llX\n", m_szName.c_str(), m_callSiteAddr - pMod->GetAddr());

            if (!SnapshotAndResolveCallSite(p, overwriteSize)) { printf("[!] %s: resolve failed\n", m_szName.c_str()); return false; }

            printf("[+] %s: original bytes (%u): ", m_szName.c_str(), m_originalByteCount);
            for (int i = 0; i < m_originalByteCount; ++i) printf("%02X ", m_originalBytes[i]); printf("\n");
            if (m_originalFuncAddr) printf("[+] %s: original fn @ 0x%llX\n", m_szName.c_str(), m_originalFuncAddr);
            else printf("[~] %s: could not resolve original fn addr (indirect call form)\n", m_szName.c_str());

            m_pDataRemote = p->Alloc(sizeof(HOOK_DATA));
            if (!m_pDataRemote) { printf("[!] %s: alloc hook data failed\n", m_szName.c_str()); return false; }
            p->Write<HOOK_DATA>(reinterpret_cast<uintptr_t>(m_pDataRemote), initData);

            size_t scSize = reinterpret_cast<uintptr_t>(fnEnd) - reinterpret_cast<uintptr_t>(fnStart);
            m_pShellcodeRemote = p->Alloc(scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pShellcodeRemote) { printf("[!] %s: alloc shellcode failed\n", m_szName.c_str()); return false; }

            std::vector<uint8_t> localCode(scSize);
            memcpy(localCode.data(), fnStart, scSize);
            if (!p->WriteArray(reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode))
            {
                printf("[!] %s: write shellcode failed\n", m_szName.c_str()); return false;
            }
            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n", m_szName.c_str(), m_pShellcodeRemote, scSize);

            if (!PatchRipSlots(localCode, scSize, fnStart, ripSlots))
            {
                printf("[!] %s: RIP patching failed\n", m_szName.c_str()); return false;
            }
            FlushInstructionCache(p->m_hProc, m_pShellcodeRemote, scSize);
            if (!InstallCallSitePatch())
            {
                printf("[!] %s: call site patch failed\n", m_szName.c_str()); return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());
            SaveConfig();
            return true;
        }

        bool Unhook() {
            if (!m_bIsHooked || !m_callSiteAddr) return false;
            auto* p = m_pProc ? m_pProc : proc;
            bool ok = true; DWORD op;
            if (VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount, PAGE_EXECUTE_READWRITE, &op)) {
                std::vector<uint8_t> orig(m_originalBytes, m_originalBytes + m_originalByteCount);
                if (!p->WriteArray(m_callSiteAddr, orig)) { printf("[!] %s: restore failed\n", m_szName.c_str()); ok = false; }
                VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount, op, &op);
            }
            else ok = false;
            FlushInstructionCache(p->m_hProc, reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount);
            if (m_pFuncPtrStorage) { VirtualFreeEx(p->m_hProc, m_pFuncPtrStorage, 0, MEM_RELEASE); m_pFuncPtrStorage = nullptr; }
            if (m_pShellcodeRemote) { VirtualFreeEx(p->m_hProc, m_pShellcodeRemote, 0, MEM_RELEASE); m_pShellcodeRemote = nullptr; }
            if (m_pDataRemote) { VirtualFreeEx(p->m_hProc, m_pDataRemote, 0, MEM_RELEASE); m_pDataRemote = nullptr; }
            m_bIsHooked = false; m_callSiteAddr = 0; m_originalFuncAddr = 0; m_originalByteCount = 0;
            m_RemoteSlots.clear();
            HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return ok;
        }

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        HOOK_DATA ReadData() {
            HOOK_DATA out{};
            if (m_pDataRemote)
                (m_pProc ? m_pProc : proc)->Read(reinterpret_cast<uintptr_t>(m_pDataRemote), &out, sizeof(HOOK_DATA));
            return out;
        }

        template <typename T>
        void WriteField(size_t offset, T value) {
            if (m_pDataRemote)
                (m_pProc ? m_pProc : proc)->Write<T>(reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, value);
        }

        bool  IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:
        bool SnapshotAndResolveCallSite(Process* p, uint8_t overwriteSize) {
            uint8_t buf[16]{};
            if (!p->Read(m_callSiteAddr, buf, sizeof(buf))) return false;
            m_originalFuncAddr = 0; uint8_t instrLen = 0;
            if (buf[0] == 0xE8) {
                m_originalFuncAddr = static_cast<uint64_t>(static_cast<int64_t>(m_callSiteAddr) + 5 + *reinterpret_cast<int32_t*>(&buf[1]));
                instrLen = 5;
            }
            else if (buf[0] == 0xFF && buf[1] == 0x15) {
                m_originalFuncAddr = p->ReadDirect<uint64_t>(m_callSiteAddr + 6 + *reinterpret_cast<int32_t*>(&buf[2]));
                instrLen = 6;
            }
            else if (buf[0] == 0xFF && (buf[1] & 0x38) == 0x10 && (buf[1] & 0xC0) == 0x80) { instrLen = 6; }
            else if (buf[0] == 0xFF && (buf[1] & 0xF8) == 0xD0) { instrLen = 2; }
            else if (buf[0] == 0xFF && (buf[1] & 0xF8) == 0x10) { instrLen = 2; }
            else if (buf[0] >= 0x40 && buf[0] <= 0x4F && buf[1] == 0xFF && (buf[2] & 0x38) == 0x10) {
                uint8_t mod = (buf[2] & 0xC0) >> 6;
                instrLen = (mod == 0x01) ? 4 : (mod == 0x02) ? 7 : 3;
            }
            else { printf("[!] %s: unrecognized call form: %02X %02X\n", m_szName.c_str(), buf[0], buf[1]); return false; }

            uint8_t minBytes = instrLen < 6 ? 6 : instrLen;
            m_originalByteCount = (overwriteSize >= 6) ? overwriteSize : minBytes;
            memcpy(m_originalBytes, buf, m_originalByteCount);
            return true;
        }

        bool PatchRipSlots(std::vector<uint8_t>& localCode, size_t scSize, void* fnStart,
            const std::vector<RipSlot>& ripSlots)
        {
            auto* p = m_pProc ? m_pProc : proc;
            int patched = 0;
            for (size_t i = 0; i + 7 <= scSize; ++i) {
                if (localCode[i] != 0x48 || localCode[i + 1] != 0x8B || localCode[i + 2] != 0x05) continue;
                uintptr_t localTarget = (reinterpret_cast<uintptr_t>(fnStart) + i + 7)
                    + *reinterpret_cast<int32_t*>(&localCode[i + 3]);
                const RipSlot* slot = nullptr;
                for (const auto& s : ripSlots)
                    if (reinterpret_cast<uintptr_t>(s.pLocalVar) == localTarget) { slot = &s; break; }
                if (!slot) { printf("[!] %s: unregistered RIP load at +0x%zX\n", m_szName.c_str(), i); return false; }
                uint64_t val = (slot->target == RipSlotTarget::HookData) ? reinterpret_cast<uint64_t>(m_pDataRemote)
                    : (slot->target == RipSlotTarget::OriginalFunc) ? m_originalFuncAddr
                    : slot->customAddr;
                void* remoteSlot = nullptr;
                for (const auto& ex : m_RemoteSlots)
                    if (ex.pLocalVar == slot->pLocalVar) { remoteSlot = ex.remoteAddr; break; }
                if (!remoteSlot) {
                    remoteSlot = p->Alloc(8);
                    if (!remoteSlot) { printf("[!] %s: alloc slot failed\n", m_szName.c_str()); return false; }
                    p->Write<uint64_t>(reinterpret_cast<uintptr_t>(remoteSlot), val);
                    m_RemoteSlots.push_back({ remoteSlot, slot->target, slot->customAddr, slot->pLocalVar });
                    printf("[+] %s: RIP[%d] +0x%zX → 0x%p → 0x%llX\n", m_szName.c_str(), patched, i, remoteSlot, val);
                }
                int32_t disp = static_cast<int32_t>(reinterpret_cast<uintptr_t>(remoteSlot)
                    - (reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i + 7));
                if (!p->Write<int32_t>(reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i + 3, disp))
                {
                    printf("[!] %s: disp patch failed\n", m_szName.c_str()); return false;
                }
                ++patched;
            }
            for (const auto& s : ripSlots) {
                bool found = false;
                for (const auto& rs : m_RemoteSlots) if (rs.pLocalVar == s.pLocalVar) { found = true; break; }
                if (!found) { printf("[!] %s: RipSlot never matched\n", m_szName.c_str()); return false; }
            }
            printf("[+] %s: patched %d RIP load(s)\n", m_szName.c_str(), patched);
            return true;
        }

        bool InstallCallSitePatch() {
            auto* p = m_pProc ? m_pProc : proc;
            SYSTEM_INFO si{}; GetSystemInfo(&si);
            const uintptr_t ripBase = m_callSiteAddr + 6;
            uintptr_t searchStart = (m_callSiteAddr > 0x7FFFFFFF)
                ? ((m_callSiteAddr - 0x7FFFFFFF) & ~(uintptr_t)(si.dwAllocationGranularity - 1)) : 0;

            for (uintptr_t addr = searchStart; addr < m_callSiteAddr + 0x7FFFFFFF; addr += si.dwAllocationGranularity) {
                m_pFuncPtrStorage = VirtualAllocEx(p->m_hProc, reinterpret_cast<void*>(addr), 8,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (m_pFuncPtrStorage) {
                    int64_t dist = reinterpret_cast<uintptr_t>(m_pFuncPtrStorage) - ripBase;
                    if (dist >= INT32_MIN && dist <= INT32_MAX) break;
                    VirtualFreeEx(p->m_hProc, m_pFuncPtrStorage, 0, MEM_RELEASE); m_pFuncPtrStorage = nullptr;
                }
            }
            if (!m_pFuncPtrStorage) { printf("[!] %s: no ±2GB alloc\n", m_szName.c_str()); return false; }
            if (!p->Write<uint64_t>(reinterpret_cast<uintptr_t>(m_pFuncPtrStorage), reinterpret_cast<uint64_t>(m_pShellcodeRemote)))
            {
                printf("[!] %s: write funcptr failed\n", m_szName.c_str()); return false;
            }

            int64_t dist = reinterpret_cast<uintptr_t>(m_pFuncPtrStorage) - ripBase;
            int32_t rip = static_cast<int32_t>(dist);
            if (dist != rip) { printf("[!] %s: RIP overflow\n", m_szName.c_str()); return false; }

            std::vector<uint8_t> patch = { 0xFF, 0x15,
                uint8_t(rip & 0xFF), uint8_t((rip >> 8) & 0xFF),
                uint8_t((rip >> 16) & 0xFF), uint8_t((rip >> 24) & 0xFF) };
            while (patch.size() < m_originalByteCount) patch.push_back(0x90);

            DWORD op;
            if (!VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount, PAGE_EXECUTE_READWRITE, &op))
            {
                printf("[!] %s: VirtualProtectEx failed\n", m_szName.c_str()); return false;
            }
            bool ok = p->WriteArray(m_callSiteAddr, patch);
            VirtualProtectEx(p->m_hProc, reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount, op, &op);
            if (!ok) { printf("[!] %s: write patch failed\n", m_szName.c_str()); return false; }
            FlushInstructionCache(p->m_hProc, reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount);
            printf("[+] %s: patched (FF 15 + %d NOP(s))\n", m_szName.c_str(), (int)patch.size() - 6);
            return true;
        }

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool TryRestore() {
            auto* p = m_pProc ? m_pProc : proc;
            auto  pid = p->GetProcId();
            auto  entry = HookConfig::Find(m_szName, pid);
            if (!entry) { printf("[HookConfig] %s: no saved state\n", m_szName.c_str()); return false; }
            if (!entry->dataRemote || !entry->shellcodeRemote || !entry->callSiteAddr)
            {
                printf("[HookConfig] %s: incomplete – discarding\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(p->m_hProc, reinterpret_cast<void*>(entry->dataRemote), &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
            {
                printf("[HookConfig] %s: dataRemote stale\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            uint8_t probe[2]{}; p->Read(entry->callSiteAddr, probe, 2);
            if (probe[0] != 0xFF || probe[1] != 0x15)
            {
                printf("[HookConfig] %s: call site stale\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            if (entry->origBytes.empty() || entry->origBytes.size() > sizeof(m_originalBytes))
            {
                printf("[HookConfig] %s: origBytes invalid\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
            }
            m_originalByteCount = static_cast<uint8_t>(entry->origBytes.size());
            memcpy(m_originalBytes, entry->origBytes.data(), m_originalByteCount);
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_callSiteAddr = entry->callSiteAddr;
            m_originalFuncAddr = entry->origStorage;
            m_RemoteSlots.clear();
            for (const auto& saved : entry->ripSlots) {
                RemoteSlot rs{ reinterpret_cast<void*>(saved.remoteAddr), static_cast<RipSlotTarget>(saved.target), saved.customAddr, nullptr };
                uint64_t sv = p->ReadDirect<uint64_t>(saved.remoteAddr);
                if (rs.target == RipSlotTarget::HookData && sv != entry->dataRemote)
                {
                    printf("[HookConfig] %s: HookData mismatch\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
                }
                else if (rs.target == RipSlotTarget::OriginalFunc && sv != m_originalFuncAddr)
                {
                    printf("[HookConfig] %s: OrigFunc mismatch\n", m_szName.c_str()); HookConfig::Remove(m_szName); return false;
                }
                else if (rs.target == RipSlotTarget::Custom && sv != saved.customAddr)
                    p->Write<uint64_t>(saved.remoteAddr, saved.customAddr);
                m_RemoteSlots.push_back(rs);
            }
            m_bIsHooked = true;
            printf("[HookConfig] %s: restored (pid %u, %zu slots)\n", m_szName.c_str(), pid, m_RemoteSlots.size());
            return true;
        }

        void SaveConfig() {
            auto* p = m_pProc ? m_pProc : proc;
            HookConfig::HookEntry e;
            e.pid = p->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = 0;
            e.callSiteAddr = m_callSiteAddr;
            e.origStorage = m_originalFuncAddr;
            e.origBytes.assign(m_originalBytes, m_originalBytes + m_originalByteCount);
            for (const auto& rs : m_RemoteSlots)
                e.ripSlots.push_back({ reinterpret_cast<uintptr_t>(rs.remoteAddr),
                    static_cast<HookConfig::RipSlotTarget>(rs.target), rs.customAddr });
            HookConfig::Upsert(e);
            printf("[HookConfig] %s: saved (%zu slots, %u bytes)\n", m_szName.c_str(), m_RemoteSlots.size(), m_originalByteCount);
        }
    };

} // namespace LiquidHookEx