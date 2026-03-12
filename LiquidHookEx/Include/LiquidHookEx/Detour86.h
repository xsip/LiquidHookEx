#pragma once
#include <string>
#include <vector>
#include <cstdint>

#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Config.h>
#include <LiquidHookEx/Globals.h>
#include <LiquidHookEx/ShellCodeDll86.h>

// ============================================================================
//  Detour86
//
//  x86 (32-bit target) variant of Detour.  Prepatched-only: shellcode bytes
//  are always supplied via ShellcodeDLL86::LoadHook(), which rebases all slot
//  imm32s before they are written to the target process.  No PatchAbsSlots
//  scanner is needed.
//
//  PATCH OPCODE
//    x86: FF 25 [abs32]  — jmp dword ptr [imm32]  (6 bytes total)
//    pFuncPtrStorage holds the shellcode remote address.  Allocated anywhere
//    in the 4 GB space — no ±2 GB proximity scan needed.
//
//  TRAMPOLINE LAYOUT  (stolenByteCount + 6 bytes)
//    [stolen bytes]     — exact copy of the overwritten prologue
//    FF 25 [abs32]      — jmp dword ptr [pTrampolinePtrStorage]
//    pTrampolinePtrStorage holds targetFuncAddr + stolenByteCount.
//
//  The trampoline address is written into pOrigRemote (supplied by LoadHook)
//  so the shellcode can call the original function via the indirection slot
//  that was already rebased into the shellcode bytes.
//
//  stolenBytes rules:
//    Minimum 6 (size of the FF 25 patch).  Passing 0 defaults to 6.
//    Must cover only complete instructions — never cut mid-instruction.
//    Extra bytes beyond 6 become NOPs in the patch and are included in
//    the trampoline so the original prologue is fully preserved.
//
//  Usage:
//    ShellcodeDLL86 dll("Shellcode.dll");
//    auto h = dll.LoadHook<MyData>(".myHook",
//                                  "MyFn_Hook", "MyFn_Hook_End",
//                                  "g_hookData", "g_pOriginalFn",
//                                  initData);
//    m_Hook.HookPrepatched("55 8B EC ...", "module.dll", h, stolenBytes);
//
//  On subsequent runs against the same process (same PID), HookPrepatched
//  calls TryRestorePrepatched first and returns immediately if the saved
//  state is still valid — the pattern scan is skipped entirely.
// ============================================================================

namespace LiquidHookEx {

    class Detour86 {

        Process* m_pProc;
        std::string m_szName;

        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pTrampolineRemote{};       // stolen bytes + FF 25 back-jump
        void* m_pFuncPtrStorage{};         // 4-byte: shellcode addr (forward jump)
        void* m_pTrampolinePtrStorage{};   // 4-byte: return addr  (trampoline jump)
        uintptr_t m_targetFuncAddr{};

        uint8_t   m_stolenBytes[32]{};
        uint8_t   m_stolenByteCount{};

        bool m_bIsHooked{};

        Process* Proc() const { return m_pProc ? m_pProc : LiquidHookEx::proc; }

    public:
        Detour86(std::string name, Process* proc = nullptr)
            : m_pProc(proc), m_szName(std::move(name)) {
        }

        void SetProc(Process* p) { m_pProc = p; }

        // ── HookPrepatched (ShellcodeSection overload) ────────────────────────────
        //
        // pOrigRemote:  pre-allocated 4-byte remote slot.  On fresh hook this
        //               receives the trampoline address so the shellcode can call
        //               the original function.  On restore this is not written —
        //               the trampoline is already live from the previous session.
        //
        // pDataRemote:  address of the already-allocated remote hook data block.
        //               Stored in m_pDataRemote so WriteField() works after restart.
        //
        // stolenBytes:  prologue bytes to snapshot and overwrite.
        //   0  = default 6 (minimum for FF 25 [abs32]).
        //   >0 = caller override, must be >= 6 and cover only complete instructions.
        //
        bool HookPrepatched(
            std::string       pattern,
            std::string       dllName,
            ShellcodeSection& sc,
            void* fnStart,
            void* fnEnd,
            void* pOrigRemote,
            uint8_t           stolenBytes = 0,
            void* pDataRemote = nullptr)
        {
            if (m_bIsHooked) {
                printf("[!] %s: already hooked\n", m_szName.c_str());
                return false;
            }

            // ── architecture guard ───────────────────────────────────
            if (!Proc()->IsTarget32()) {
                printf("[!] %s::HookPrepatched => You are trying to use Detour86 on a 64-bit process. Use Detour instead.\n",
                    m_szName.c_str());
                return false;
            }

            if (TryRestorePrepatched()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            m_pDataRemote = pDataRemote;

            // ── locate module ────────────────────────────────────────────────────
            auto pMod = Proc()->GetRemoteModule(dllName.c_str(),false);
            if (!pMod || !pMod->IsValid()) {
                printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str());
                return false;
            }

            // ── scan for target function ─────────────────────────────────────────
            auto pFn = pMod->ScanMemory(pattern.c_str());
            if (!pFn) {
                printf("[!] %s: pattern not found\n", m_szName.c_str());
                return false;
            }

            m_targetFuncAddr = reinterpret_cast<uintptr_t>(pFn);
            printf("[+] %s: target fn @ module+0x%llX\n",
                m_szName.c_str(), m_targetFuncAddr - pMod->GetAddr());

            // ── validate stolenBytes ─────────────────────────────────────────────
            if (stolenBytes == 0)  stolenBytes = 6;
            if (stolenBytes < 6) {
                printf("[!] %s: stolenBytes %u < 6 — clamping to 6\n",
                    m_szName.c_str(), stolenBytes);
                stolenBytes = 6;
            }
            if (stolenBytes > sizeof(m_stolenBytes)) {
                printf("[!] %s: stolenBytes %u exceeds internal limit\n",
                    m_szName.c_str(), stolenBytes);
                return false;
            }

            // ── snapshot prologue bytes ──────────────────────────────────────────
            if (!Proc()->Read(m_targetFuncAddr, m_stolenBytes, stolenBytes)) {
                printf("[!] %s: failed to read prologue bytes\n", m_szName.c_str());
                return false;
            }
            m_stolenByteCount = stolenBytes;

            printf("[+] %s: stolen bytes (%u): ", m_szName.c_str(), m_stolenByteCount);
            for (int i = 0; i < m_stolenByteCount; ++i)
                printf("%02X ", m_stolenBytes[i]);
            printf("\n");

            // ── copy pre-rebased shellcode bytes ─────────────────────────────────
            size_t shellcodeSize =
                reinterpret_cast<uintptr_t>(fnEnd) -
                reinterpret_cast<uintptr_t>(fnStart);

            m_pShellcodeRemote = Proc()->Alloc(
                shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pShellcodeRemote) {
                printf("[!] %s: failed to alloc shellcode\n", m_szName.c_str());
                return false;
            }

            size_t fnOffset =
                reinterpret_cast<uintptr_t>(fnStart) -
                reinterpret_cast<uintptr_t>(sc.base);

            std::vector<uint8_t> localCode(
                sc.bytes.begin() + fnOffset,
                sc.bytes.begin() + fnOffset + shellcodeSize);

            if (!Proc()->WriteArray(
                reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode))
            {
                printf("[!] %s: failed to write shellcode\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n",
                m_szName.c_str(), m_pShellcodeRemote, shellcodeSize);

            // ── build trampoline ─────────────────────────────────────────────────
            if (!BuildTrampoline()) {
                printf("[!] %s: trampoline build failed\n", m_szName.c_str());
                return false;
            }

            // ── write trampoline address into the orig-fn slot ───────────────────
            if (pOrigRemote) {
                uint32_t trampolineAddr = static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(m_pTrampolineRemote));
                Proc()->Write<uint32_t>(
                    reinterpret_cast<uintptr_t>(pOrigRemote), trampolineAddr);
                printf("[+] %s: orig slot @ 0x%p → trampoline 0x%08X\n",
                    m_szName.c_str(), pOrigRemote, trampolineAddr);
            }

            FlushInstructionCache(Proc()->m_hProc, m_pShellcodeRemote, shellcodeSize);
            FlushInstructionCache(Proc()->m_hProc, m_pTrampolineRemote,
                m_stolenByteCount + 6);

            // ── install FF 25 [abs32] patch ──────────────────────────────────────
            if (!InstallDetourPatch()) {
                printf("[!] %s: detour patch failed\n", m_szName.c_str());
                return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());

            SaveConfig();
            return true;
        }

        // ── HookPrepatched (ShellcodeHook overload) ──────────────────────────────
        bool HookPrepatched(
            std::string    pattern,
            std::string    dllName,
            ShellcodeHook& h,
            uint8_t        stolenBytes = 0)
        {
            if (!h.valid) {
                printf("[!] %s: ShellcodeHook is not valid\n", m_szName.c_str());
                return false;
            }
            return HookPrepatched(
                std::move(pattern),
                std::move(dllName),
                h.sc,
                h.fnStart,
                h.fnEnd,
                h.pOrigRemote,
                stolenBytes,
                h.pDataRemote);
        }

        // ── Unhook ───────────────────────────────────────────────────────────────
        bool Unhook()
        {
            if (!m_bIsHooked || !m_targetFuncAddr) return false;

            bool success = true;

            DWORD oldProtect;
            if (!VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr),
                m_stolenByteCount, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                success = false;
            }
            else {
                std::vector<uint8_t> origVec(
                    m_stolenBytes, m_stolenBytes + m_stolenByteCount);
                if (!Proc()->WriteArray(m_targetFuncAddr, origVec)) {
                    printf("[!] %s: failed to restore prologue bytes\n", m_szName.c_str());
                    success = false;
                }
                VirtualProtectEx(Proc()->m_hProc,
                    reinterpret_cast<void*>(m_targetFuncAddr),
                    m_stolenByteCount, oldProtect, &oldProtect);
            }

            FlushInstructionCache(Proc()->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr), m_stolenByteCount);

            if (m_pFuncPtrStorage) {
                VirtualFreeEx(Proc()->m_hProc, m_pFuncPtrStorage, 0, MEM_RELEASE);
                m_pFuncPtrStorage = nullptr;
            }
            if (m_pTrampolinePtrStorage) {
                VirtualFreeEx(Proc()->m_hProc, m_pTrampolinePtrStorage, 0, MEM_RELEASE);
                m_pTrampolinePtrStorage = nullptr;
            }
            if (m_pTrampolineRemote) {
                VirtualFreeEx(Proc()->m_hProc, m_pTrampolineRemote, 0, MEM_RELEASE);
                m_pTrampolineRemote = nullptr;
            }
            if (m_pShellcodeRemote) {
                VirtualFreeEx(Proc()->m_hProc, m_pShellcodeRemote, 0, MEM_RELEASE);
                m_pShellcodeRemote = nullptr;
            }
            if (m_pDataRemote) {
                VirtualFreeEx(Proc()->m_hProc, m_pDataRemote, 0, MEM_RELEASE);
                m_pDataRemote = nullptr;
            }

            m_bIsHooked = false;
            m_targetFuncAddr = 0;
            m_stolenByteCount = 0;

            HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return success;
        }

        // ── Data accessors ───────────────────────────────────────────────────────
        template <typename T>
        void WriteField(size_t offset, T value)
        {
            if (m_pDataRemote)
                Proc()->Write<T>(
                    reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, value);
            else
                printf("[!] %s: WriteField called but m_pDataRemote is null\n",
                    m_szName.c_str());
        }

        template <typename T>
        T ReadField(size_t offset)
        {
            T out{};
            if (m_pDataRemote)
                Proc()->Read(
                    reinterpret_cast<uintptr_t>(m_pDataRemote) + offset, &out, sizeof(T));
            return out;
        }

        bool  IsHooked()           const { return m_bIsHooked; }
        void* GetDataRemote()      const { return m_pDataRemote; }
        void* GetTrampolineRemote() const { return m_pTrampolineRemote; }

    private:

        // ── BuildTrampoline ──────────────────────────────────────────────────────
        //
        // Layout: [stolen bytes] + FF 25 [abs32]  (stolenByteCount + 6 bytes)
        // pTrampolinePtrStorage holds targetFuncAddr + stolenByteCount.
        //
        bool BuildTrampoline()
        {
            size_t trampolineSize = m_stolenByteCount + 6;

            m_pTrampolineRemote = Proc()->Alloc(
                trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!m_pTrampolineRemote) {
                printf("[!] %s: failed to alloc trampoline\n", m_szName.c_str());
                return false;
            }

            m_pTrampolinePtrStorage = VirtualAllocEx(Proc()->m_hProc, nullptr,
                sizeof(uint32_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!m_pTrampolinePtrStorage) {
                printf("[!] %s: failed to alloc trampoline ptr storage\n", m_szName.c_str());
                return false;
            }

            uint32_t returnAddr = static_cast<uint32_t>(
                m_targetFuncAddr + m_stolenByteCount);

            if (!Proc()->Write<uint32_t>(
                reinterpret_cast<uintptr_t>(m_pTrampolinePtrStorage), returnAddr))
            {
                printf("[!] %s: failed to write trampoline ptr storage\n", m_szName.c_str());
                return false;
            }

            std::vector<uint8_t> tramp;
            tramp.reserve(trampolineSize);

            // Part 1: stolen prologue
            tramp.insert(tramp.end(), m_stolenBytes, m_stolenBytes + m_stolenByteCount);

            // Part 2: FF 25 [abs32] — jmp [pTrampolinePtrStorage]
            uint32_t ptrAddr = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(m_pTrampolinePtrStorage));
            tramp.push_back(0xFF);
            tramp.push_back(0x25);
            tramp.push_back(static_cast<uint8_t>(ptrAddr & 0xFF));
            tramp.push_back(static_cast<uint8_t>((ptrAddr >> 8) & 0xFF));
            tramp.push_back(static_cast<uint8_t>((ptrAddr >> 16) & 0xFF));
            tramp.push_back(static_cast<uint8_t>((ptrAddr >> 24) & 0xFF));

            if (!Proc()->WriteArray(
                reinterpret_cast<uintptr_t>(m_pTrampolineRemote), tramp))
            {
                printf("[!] %s: failed to write trampoline\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: trampoline @ 0x%p (%zu bytes), returns to 0x%08X\n",
                m_szName.c_str(), m_pTrampolineRemote, trampolineSize, returnAddr);
            return true;
        }

        // ── InstallDetourPatch ───────────────────────────────────────────────────
        //
        // x86 patch: FF 25 [abs32] + NOPs to stolenByteCount.
        //
        bool InstallDetourPatch()
        {
            m_pFuncPtrStorage = VirtualAllocEx(Proc()->m_hProc, nullptr,
                sizeof(uint32_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!m_pFuncPtrStorage) {
                printf("[!] %s: failed to alloc funcptr storage\n", m_szName.c_str());
                return false;
            }

            uint32_t scAddr = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(m_pShellcodeRemote));

            if (!Proc()->Write<uint32_t>(
                reinterpret_cast<uintptr_t>(m_pFuncPtrStorage), scAddr))
            {
                printf("[!] %s: failed to write funcptr storage\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: funcptr storage @ 0x%p → shellcode 0x%08X\n",
                m_szName.c_str(), m_pFuncPtrStorage, scAddr);

            std::vector<uint8_t> patch;
            patch.reserve(m_stolenByteCount);

            uint32_t storageAddr = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(m_pFuncPtrStorage));
            patch.push_back(0xFF);
            patch.push_back(0x25);
            patch.push_back(static_cast<uint8_t>(storageAddr & 0xFF));
            patch.push_back(static_cast<uint8_t>((storageAddr >> 8) & 0xFF));
            patch.push_back(static_cast<uint8_t>((storageAddr >> 16) & 0xFF));
            patch.push_back(static_cast<uint8_t>((storageAddr >> 24) & 0xFF));

            while (patch.size() < m_stolenByteCount)
                patch.push_back(0x90);

            DWORD oldProtect;
            if (!VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr),
                m_stolenByteCount, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                return false;
            }

            bool ok = Proc()->WriteArray(m_targetFuncAddr, patch);

            VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr),
                m_stolenByteCount, oldProtect, &oldProtect);

            if (!ok) {
                printf("[!] %s: failed to write detour patch\n", m_szName.c_str());
                return false;
            }

            FlushInstructionCache(Proc()->m_hProc,
                reinterpret_cast<void*>(m_targetFuncAddr), m_stolenByteCount);

            printf("[+] %s: fn patched (FF 25 [abs32] + %d NOP(s)) → shellcode 0x%08X\n",
                m_szName.c_str(), (int)patch.size() - 6, scAddr);
            return true;
        }

        // ── TryRestorePrepatched ─────────────────────────────────────────────────
        //
        // Validates saved state for the current PID.
        // Checks: shellcode alloc committed, prologue still FF 25, origBytes present.
        // pFuncPtrStorage and pTrampolinePtrStorage are not persisted — they will
        // be nullptr after restore, which Unhook() handles gracefully.
        //
        bool TryRestorePrepatched()
        {
            uint32_t currentPid = Proc()->GetProcId();
            auto entry = HookConfig::Find(m_szName, currentPid);
            if (!entry) {
                printf("[HookConfig] %s: no saved state for pid %u\n",
                    m_szName.c_str(), currentPid);
                return false;
            }

            if (!entry->shellcodeRemote || !entry->callSiteAddr) {
                printf("[HookConfig] %s: saved state incomplete – discarding\n",
                    m_szName.c_str());
                HookConfig::Remove(m_szName);
                return false;
            }

            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(Proc()->m_hProc,
                    reinterpret_cast<void*>(entry->shellcodeRemote),
                    &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT)
                {
                    printf("[HookConfig] %s: shellcode 0x%llX no longer committed – discarding\n",
                        m_szName.c_str(), (uint64_t)entry->shellcodeRemote);
                    HookConfig::Remove(m_szName);
                    return false;
                }
            }

            // Prologue must still carry FF 25
            uint8_t probe[2]{};
            Proc()->Read(entry->callSiteAddr, probe, 2);
            if (probe[0] != 0xFF || probe[1] != 0x25) {
                printf("[HookConfig] %s: prologue 0x%llX no longer FF 25 – discarding\n",
                    m_szName.c_str(), (uint64_t)entry->callSiteAddr);
                HookConfig::Remove(m_szName);
                return false;
            }

            if (entry->origBytes.empty() ||
                entry->origBytes.size() > sizeof(m_stolenBytes))
            {
                printf("[HookConfig] %s: origBytes invalid – discarding\n",
                    m_szName.c_str());
                HookConfig::Remove(m_szName);
                return false;
            }

            m_stolenByteCount = static_cast<uint8_t>(entry->origBytes.size());
            memcpy(m_stolenBytes, entry->origBytes.data(), m_stolenByteCount);

            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pTrampolineRemote = reinterpret_cast<void*>(entry->origStorage);
            m_targetFuncAddr = entry->callSiteAddr;
            // pFuncPtrStorage / pTrampolinePtrStorage not persisted — left nullptr

            m_bIsHooked = true;
            printf("[HookConfig] %s: prepatched restored (pid %u)\n",
                m_szName.c_str(), currentPid);
            return true;
        }

        // ── SaveConfig ───────────────────────────────────────────────────────────
        //
        // HookConfig field mapping:
        //   callSiteAddr  → target function address
        //   origStorage   → trampoline remote address
        //   origBytes     → stolen prologue bytes
        //
        void SaveConfig()
        {
            HookConfig::HookEntry e;
            e.pid = Proc()->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = 0;
            e.callSiteAddr = m_targetFuncAddr;
            e.origStorage = reinterpret_cast<uintptr_t>(m_pTrampolineRemote);
            e.origBytes.assign(m_stolenBytes, m_stolenBytes + m_stolenByteCount);
            e.ripSlots.clear(); // no slots in prepatched path

            HookConfig::Upsert(e);
            printf("[HookConfig] %s: state saved (%u stolen bytes)\n",
                m_szName.c_str(), m_stolenByteCount);
        }
    };

} // namespace LiquidHookEx