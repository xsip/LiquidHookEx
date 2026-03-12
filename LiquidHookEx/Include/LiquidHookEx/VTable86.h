#pragma once
#include <string>
#include <vector>
#include <cstdint>

#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Config.h>
#include <LiquidHookEx/Globals.h>
#include <LiquidHookEx/ShellCodeDll86.h>

// ============================================================================
//  VTable86
//
//  x86 (32-bit target) variant of VTable.  Prepatched-only: shellcode bytes
//  are always supplied via ShellcodeDLL86::LoadHook(), which rebases all slot
//  imm32s before they are written to the target process.  No PatchAbsSlots
//  scanner is needed.
//
//  VTABLE SLOT WIDTH
//    4 bytes per entry (x86 pointer size).
//
//  ORIG STORAGE
//    The pOrigRemote slot from ShellcodeHook/LoadHook doubles as the
//    orig-storage used by Unhook() to restore the vtable entry.
//    LoadHook allocates it; HookPrepatched writes the original fn address
//    into it; Unhook reads it back.
//
//  RESTORE
//    On a subsequent run against the same process, HookPrepatched calls
//    TryRestorePrepatched first.  Validates: shellcode alloc committed,
//    vtable slot still holds the shellcode address, origStorage committed.
//
//  Usage:
//    ShellcodeDLL86 dll("Shellcode.dll");
//    auto h = dll.LoadHook<MyData>(".myHook",
//                                  "MyFn_Hook", "MyFn_Hook_End",
//                                  "g_hookData", "g_pOriginalFn",
//                                  initData);
//    m_Hook.HookPrepatched("55 8B EC ...", "module.dll", h);
// ============================================================================

namespace LiquidHookEx {

    class VTable86 {

        Process* m_pProc;
        std::string m_szName;

        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pOrigStorage{};    // 4-byte remote slot — holds original fn addr for Unhook
        uintptr_t m_pTargetFunction{}; // address of the vtable slot (not the fn itself)

        bool m_bIsHooked{};

        Process* Proc() const { return m_pProc ? m_pProc : LiquidHookEx::proc; }

    public:
        VTable86(std::string name, Process* proc = nullptr)
            : m_pProc(proc), m_szName(std::move(name)) {
        }

        void SetProc(Process* p) { m_pProc = p; }

        // ── HookPrepatched (ShellcodeSection overload) ────────────────────────────
        //
        // pOrigRemote:  pre-allocated 4-byte remote slot (from LoadHook).
        //               HookPrepatched writes the original fn address into it so
        //               the shellcode can call it, and stores it as m_pOrigStorage
        //               so Unhook() can read it back to restore the vtable entry.
        //
        // pDataRemote:  address of the already-allocated remote hook data block.
        //               Stored in m_pDataRemote so WriteField() works after restart.
        //
        bool HookPrepatched(
            std::string       pattern,
            std::string       dllName,
            ShellcodeSection& sc,
            void* fnStart,
            void* fnEnd,
            void* pOrigRemote,
            void* pDataRemote = nullptr)
        {
            if (m_bIsHooked) {
                printf("[!] %s: already hooked\n", m_szName.c_str());
                return false;
            }

            // ── architecture guard ───────────────────────────────────────────────
            if (!Proc()->IsTarget32()) {
                printf("[!] %s::HookPrepatched => You are trying to use VTable86 on a 64-bit process. Use VTable instead.\n",
                    m_szName.c_str());
                return false;
            }

            if (TryRestorePrepatched()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            m_pDataRemote = pDataRemote;
            m_pOrigStorage = pOrigRemote; // reuse LoadHook's alloc as orig-storage

            // ── locate module ────────────────────────────────────────────────────
            auto pMod = Proc()->GetRemoteModule(dllName.c_str(),false);
            if (!pMod || !pMod->IsValid()) {
                printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str());
                return false;
            }

            // ── scan for function address ────────────────────────────────────────
            uintptr_t pFnAddr = reinterpret_cast<uintptr_t>(
                pMod->ScanMemory(pattern.c_str()));
            if (!pFnAddr) {
                printf("[!] %s: pattern not found\n", m_szName.c_str());
                return false;
            }

            // ── locate vtable slot ───────────────────────────────────────────────
            auto vTableInfo = pMod->FindVTableContainingFunction(pFnAddr);
            if (!vTableInfo.vTableAddr || vTableInfo.index < 0) {
                printf("[!] %s: vtable lookup failed\n", m_szName.c_str());
                return false;
            }

            // x86: vtable entries are 4 bytes wide
            m_pTargetFunction = vTableInfo.vTableAddr + (vTableInfo.index * 4u);

            uint32_t originalFunc = Proc()->ReadDirect<uint32_t>(m_pTargetFunction);
            printf("[+] %s: vtable slot @ 0x%llX  original fn @ 0x%08X\n",
                m_szName.c_str(), m_pTargetFunction, originalFunc);

            // ── write original fn address into the orig slot ─────────────────────
            if (pOrigRemote)
                Proc()->Write<uint32_t>(
                    reinterpret_cast<uintptr_t>(pOrigRemote), originalFunc);

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

            FlushInstructionCache(Proc()->m_hProc, m_pShellcodeRemote, shellcodeSize);

            // ── install vtable hook ──────────────────────────────────────────────
            if (!InstallVTableHook()) {
                printf("[!] %s: vtable install failed\n", m_szName.c_str());
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
            ShellcodeHook& h)
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
                h.pDataRemote);
        }

        // ── Unhook ───────────────────────────────────────────────────────────────
        bool Unhook()
        {
            if (!m_bIsHooked || !m_pTargetFunction) return false;

            // Read original fn addr back from the remote slot
            uint32_t originalFunc = m_pOrigStorage
                ? Proc()->ReadDirect<uint32_t>(
                    reinterpret_cast<uintptr_t>(m_pOrigStorage))
                : 0;

            if (!originalFunc) {
                printf("[!] %s: orig storage null or zero — vtable not restored\n",
                    m_szName.c_str());
            }
            else {
                DWORD oldProtect;
                VirtualProtectEx(Proc()->m_hProc,
                    reinterpret_cast<void*>(m_pTargetFunction),
                    sizeof(uint32_t), PAGE_READWRITE, &oldProtect);

                Proc()->Write<uint32_t>(m_pTargetFunction, originalFunc);

                VirtualProtectEx(Proc()->m_hProc,
                    reinterpret_cast<void*>(m_pTargetFunction),
                    sizeof(uint32_t), oldProtect, &oldProtect);

                printf("[+] %s: vtable restored to 0x%08X\n",
                    m_szName.c_str(), originalFunc);
            }

            if (m_pShellcodeRemote) {
                VirtualFreeEx(Proc()->m_hProc, m_pShellcodeRemote, 0, MEM_RELEASE);
                m_pShellcodeRemote = nullptr;
            }
            if (m_pDataRemote) {
                VirtualFreeEx(Proc()->m_hProc, m_pDataRemote, 0, MEM_RELEASE);
                m_pDataRemote = nullptr;
            }
            if (m_pOrigStorage) {
                VirtualFreeEx(Proc()->m_hProc, m_pOrigStorage, 0, MEM_RELEASE);
                m_pOrigStorage = nullptr;
            }

            m_bIsHooked = false;
            m_pTargetFunction = 0;

            HookConfig::Remove(m_szName);
            printf("[+] %s: unhooked\n", m_szName.c_str());
            return true;
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

        bool  IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:

        // ── InstallVTableHook ────────────────────────────────────────────────────
        bool InstallVTableHook()
        {
            DWORD oldProtect;
            if (!VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                sizeof(uint32_t), PAGE_READWRITE, &oldProtect))
            {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                return false;
            }

            bool ok = Proc()->Write<uint32_t>(
                m_pTargetFunction,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_pShellcodeRemote)));

            VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                sizeof(uint32_t), oldProtect, &oldProtect);

            if (!ok) {
                printf("[!] %s: failed to write vtable entry\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: vtable slot patched → shellcode 0x%p\n",
                m_szName.c_str(), m_pShellcodeRemote);
            return true;
        }

        // ── TryRestorePrepatched ─────────────────────────────────────────────────
        //
        // Validates saved state for the current PID.
        // Checks: shellcode alloc committed, vtable slot still holds shellcode
        // address, origStorage alloc committed.
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

            if (!entry->shellcodeRemote || !entry->targetFunction || !entry->origStorage) {
                printf("[HookConfig] %s: saved state incomplete – discarding\n",
                    m_szName.c_str());
                HookConfig::Remove(m_szName);
                return false;
            }

            // Shellcode alloc must still be committed
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

            // Vtable slot must still point at our shellcode
            uint32_t currentEntry = Proc()->ReadDirect<uint32_t>(entry->targetFunction);
            if (currentEntry != static_cast<uint32_t>(entry->shellcodeRemote)) {
                printf("[HookConfig] %s: vtable slot no longer points to shellcode – discarding\n",
                    m_szName.c_str());
                HookConfig::Remove(m_szName);
                return false;
            }

            // OrigStorage alloc must still be committed
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(Proc()->m_hProc,
                    reinterpret_cast<void*>(entry->origStorage),
                    &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT)
                {
                    printf("[HookConfig] %s: origStorage 0x%llX no longer committed – discarding\n",
                        m_szName.c_str(), (uint64_t)entry->origStorage);
                    HookConfig::Remove(m_szName);
                    return false;
                }
            }

            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_pOrigStorage = reinterpret_cast<void*>(entry->origStorage);
            m_pTargetFunction = entry->targetFunction;

            m_bIsHooked = true;
            printf("[HookConfig] %s: prepatched restored (pid %u)\n",
                m_szName.c_str(), currentPid);
            return true;
        }

        // ── SaveConfig ───────────────────────────────────────────────────────────
        void SaveConfig()
        {
            HookConfig::HookEntry e;
            e.pid = Proc()->GetProcId();
            e.hookName = m_szName;
            e.dataRemote = reinterpret_cast<uintptr_t>(m_pDataRemote);
            e.shellcodeRemote = reinterpret_cast<uintptr_t>(m_pShellcodeRemote);
            e.targetFunction = m_pTargetFunction;
            e.origStorage = reinterpret_cast<uintptr_t>(m_pOrigStorage);
            e.callSiteAddr = 0;
            e.ripSlots.clear(); // no slots in prepatched path

            HookConfig::Upsert(e);
            printf("[HookConfig] %s: state saved\n", m_szName.c_str());
        }
    };

} // namespace LiquidHookEx