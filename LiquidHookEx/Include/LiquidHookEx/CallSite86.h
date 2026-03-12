#pragma once
#include <string>
#include <vector>
#include <cstdint>

#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Config.h>
#include <LiquidHookEx/Globals.h>
#include <LiquidHookEx/ShellCodeDll86.h>

// ============================================================================
//  CallSite86
//
//  x86 (32-bit target) variant of CallSite.  Prepatched-only: shellcode bytes
//  are always supplied via ShellcodeDLL86::LoadHook(), which rebases all slot
//  imm32s before they are written to the target process.  No PatchAbsSlots
//  scanner is needed.
//
//  PATCH OPCODE
//    x86: FF 15 [abs32]  — call dword ptr [imm32]  (6 bytes)
//    The operand is a plain 32-bit absolute address, so pFuncPtrStorage can
//    sit anywhere in the 4 GB space — no ±2 GB proximity scan needed.
//
//  CALL SITE FORMS DECODED
//    [68 imm32]             optional push imm32 prefix (5 bytes) — pattern may
//                           be anchored here so push+call fits the 6-byte patch
//    E8 xx xx xx xx         direct near call            (5 bytes)
//    FF 15 [abs32]          indirect call [mem32]       (6 bytes)
//    FF /2 mod=10           call [reg+disp32]           (6 bytes)
//    FF /2 mod=01           call [reg+disp8]            (3 bytes)  e.g. FF 50 08
//    FF D0..D7              call reg                    (2 bytes)
//    FF 10..17              call [reg]                  (2 bytes)
//
//  Usage:
//    ShellcodeDLL86 dll("Shellcode.dll");
//    auto h = dll.LoadHook<MyData>(".myHook",
//                                  "MyFn_Hook", "MyFn_Hook_End",
//                                  "g_hookData", "g_pOriginalFn",
//                                  initData);
//    m_Hook.HookPrepatched("E8 ?? ?? ?? ?? ...", "module.dll", h, overwriteSize);
//
//  On subsequent runs against the same process (same PID), HookPrepatched
//  calls TryRestorePrepatched first and returns immediately if the saved
//  state is still valid — the pattern scan is skipped entirely.
// ============================================================================

namespace LiquidHookEx {

    class CallSite86 {

        Process* m_pProc;
        std::string m_szName;

        void* m_pShellcodeRemote{};
        void* m_pDataRemote{};
        void* m_pFuncPtrStorage{};   // 4-byte alloc holding shellcode addr for FF 15
        uintptr_t m_callSiteAddr{};
        uint32_t  m_originalFuncAddr{};  // resolved callee (0 if not statically resolvable)

        uint8_t   m_originalBytes[16]{};
        uint8_t   m_originalByteCount{};

        bool m_bIsHooked{};

        Process* Proc() const { return m_pProc ? m_pProc : LiquidHookEx::proc; }

    public:
        CallSite86(std::string name, Process* proc = nullptr)
            : m_pProc(proc), m_szName(std::move(name)) {
        }

        void SetProc(Process* p) { m_pProc = p; }

        // ── HookPrepatched (ShellcodeSection overload) ────────────────────────────
        //
        // pDataRemote: address of the already-allocated remote hook data block.
        //              Stored in m_pDataRemote so WriteField() works after restart.
        //
        // overwriteSize: bytes to snapshot / restore on Unhook().
        //   0  = auto-detected from the call instruction.
        //   >0 = caller override, must be >= 6.  Extra bytes become NOPs.
        //
        bool HookPrepatched(
            std::string       callSitePattern,
            std::string       dllName,
            ShellcodeSection& sc,
            void* fnStart,
            void* fnEnd,
            void* pOrigRemote,     // receives resolved original fn addr
            uint8_t           overwriteSize = 0,
            void* scanEnd = nullptr,
            void* pDataRemote = nullptr,
            bool              origRequired = true)
        {
            if (m_bIsHooked) {
                printf("[!] %s: already hooked\n", m_szName.c_str());
                return false;
            }

            // ── architecture guard ───────────────────────────────────────────────
            if (!Proc()->IsTarget32()) {
                printf("[!] %s::HookPrepatched => You are trying to use CallSite86 on a 64-bit process. Use CallSite instead.\n",
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

            // ── scan for call site ───────────────────────────────────────────────
            auto pCallSite = pMod->ScanMemory(callSitePattern.c_str());
            if (!pCallSite) {
                printf("[!] %s: call site pattern not found\n", m_szName.c_str());
                return false;
            }

            m_callSiteAddr = reinterpret_cast<uintptr_t>(pCallSite);
            printf("[+] %s: call site @ module+0x%llX\n",
                m_szName.c_str(), m_callSiteAddr - pMod->GetAddr());

            // ── snapshot original bytes and resolve callee ───────────────────────
            if (!SnapshotAndResolveCallSite(overwriteSize)) {
                printf("[!] %s: failed to resolve call site\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: original bytes (%u): ", m_szName.c_str(), m_originalByteCount);
            for (int i = 0; i < m_originalByteCount; ++i)
                printf("%02X ", m_originalBytes[i]);
            printf("\n");

            if (m_originalFuncAddr) {
                printf("[+] %s: original fn @ 0x%08X\n", m_szName.c_str(), m_originalFuncAddr);
                if (pOrigRemote && origRequired)
                    Proc()->Write<uint32_t>(
                        reinterpret_cast<uintptr_t>(pOrigRemote), m_originalFuncAddr);
            }
            else if (origRequired) {
                printf("[~] %s: could not resolve original fn addr\n", m_szName.c_str());
            }
            else {
                printf("[~] %s: orig fn not required (indirect call site — re-derived at runtime)\n",
                    m_szName.c_str());
            }

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

            // fnStart points into sc.bytes — compute byte offset from section base
            size_t fnOffset =
                reinterpret_cast<uintptr_t>(fnStart) -
                reinterpret_cast<uintptr_t>(sc.base);

            std::vector<uint8_t> localCode(
                sc.bytes.begin() + fnOffset,
                sc.bytes.begin() + fnOffset + shellcodeSize);

            if (!Proc()->WriteArray(reinterpret_cast<uintptr_t>(m_pShellcodeRemote), localCode)) {
                printf("[!] %s: failed to write shellcode\n", m_szName.c_str());
                return false;
            }

            printf("[+] %s: shellcode @ 0x%p (%zu bytes)\n",
                m_szName.c_str(), m_pShellcodeRemote, shellcodeSize);

            FlushInstructionCache(Proc()->m_hProc, m_pShellcodeRemote, shellcodeSize);

            // ── install FF 15 [abs32] patch ──────────────────────────────────────
            if (!InstallCallSitePatch()) {
                printf("[!] %s: call site patch failed\n", m_szName.c_str());
                return false;
            }

            m_bIsHooked = true;
            printf("[+] %s: hook installed\n\n", m_szName.c_str());

            SaveConfig();
            return true;
        }

        // ── HookPrepatched (ShellcodeHook overload) ──────────────────────────────
        bool HookPrepatched(
            std::string    callSitePattern,
            std::string    dllName,
            ShellcodeHook& h,
            uint8_t        overwriteSize = 0)
        {
            if (!h.valid) {
                printf("[!] %s: ShellcodeHook is not valid\n", m_szName.c_str());
                return false;
            }
            return HookPrepatched(
                std::move(callSitePattern),
                std::move(dllName),
                h.sc,
                h.fnStart,
                h.fnEnd,
                h.pOrigRemote,
                overwriteSize,
                h.sectionEnd,
                h.pDataRemote,
                h.origRequired);
        }

        // ── Unhook ───────────────────────────────────────────────────────────────
        bool Unhook()
        {
            if (!m_bIsHooked || !m_callSiteAddr) return false;

            bool success = true;

            DWORD oldProtect;
            if (!VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr),
                m_originalByteCount, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                success = false;
            }
            else {
                std::vector<uint8_t> origVec(
                    m_originalBytes, m_originalBytes + m_originalByteCount);
                if (!Proc()->WriteArray(m_callSiteAddr, origVec)) {
                    printf("[!] %s: failed to restore original bytes\n", m_szName.c_str());
                    success = false;
                }
                VirtualProtectEx(Proc()->m_hProc,
                    reinterpret_cast<void*>(m_callSiteAddr),
                    m_originalByteCount, oldProtect, &oldProtect);
            }

            FlushInstructionCache(Proc()->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount);

            if (m_pFuncPtrStorage) {
                VirtualFreeEx(Proc()->m_hProc, m_pFuncPtrStorage, 0, MEM_RELEASE);
                m_pFuncPtrStorage = nullptr;
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
            m_callSiteAddr = 0;
            m_originalFuncAddr = 0;
            m_originalByteCount = 0;

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

        bool  IsHooked()      const { return m_bIsHooked; }
        void* GetDataRemote() const { return m_pDataRemote; }

    private:

        // ── SnapshotAndResolveCallSite ───────────────────────────────────────────
        bool SnapshotAndResolveCallSite(uint8_t overwriteSize)
        {
            uint8_t buf[16]{};
            if (!Proc()->Read(m_callSiteAddr, buf, sizeof(buf))) {
                printf("[!] %s: failed to read call site bytes\n", m_szName.c_str());
                return false;
            }

            m_originalFuncAddr = 0;
            uint8_t instrLen = 0;

            // ── optional push imm32 prefix ───────────────────────────────────────
            // Pattern may be anchored at "push imm32" (68 xx xx xx xx, 5 bytes)
            // preceding the call so the overwrite region covers push+call without
            // spilling into the next instruction.
            // push imm8 (6A, 2 bytes) is NOT supported as prefix: 2+3 = 5 bytes
            // is less than the 6-byte minimum FF 15 patch size.
            uint8_t prefixLen = 0;
            if (buf[0] == 0x68)
                prefixLen = 5;  // push imm32

            const uint8_t* c = buf + prefixLen;

            if (c[0] == 0xE8) {
                // E8 [rel32] — direct near call (5 bytes)
                int32_t rel32 = *reinterpret_cast<const int32_t*>(&c[1]);
                m_originalFuncAddr = static_cast<uint32_t>(
                    static_cast<int32_t>(m_callSiteAddr) + prefixLen + 5 + rel32);
                instrLen = prefixLen + 5;
            }
            else if (c[0] == 0xFF && c[1] == 0x15) {
                // FF 15 [abs32] — indirect call [mem32] (6 bytes)
                uint32_t ptrAddr = *reinterpret_cast<const uint32_t*>(&c[2]);
                m_originalFuncAddr = Proc()->ReadDirect<uint32_t>(ptrAddr);
                instrLen = prefixLen + 6;
            }
            else if (c[0] == 0xFF &&
                (c[1] & 0x38) == 0x10 &&
                (c[1] & 0xC0) == 0x80)
            {
                // FF /2 mod=10 — call [reg+disp32] (6 bytes)
                instrLen = prefixLen + 6;
            }
            else if (c[0] == 0xFF &&
                (c[1] & 0x38) == 0x10 &&
                (c[1] & 0xC0) == 0x40)
            {
                // FF /2 mod=01 — call [reg+disp8] (3 bytes)
                // e.g. FF 50 08 = call dword ptr [eax+8]
                instrLen = prefixLen + 3;
            }
            else if (c[0] == 0xFF && (c[1] & 0xF8) == 0xD0) {
                // FF D0..D7 — call reg (2 bytes)
                instrLen = prefixLen + 2;
            }
            else if (c[0] == 0xFF && (c[1] & 0xF8) == 0x10) {
                // FF 10..17 — call [reg] (2 bytes)
                instrLen = prefixLen + 2;
            }
            else {
                printf("[!] %s: unrecognised x86 call form: %02X %02X ...\n",
                    m_szName.c_str(), c[0], c[1]);
                return false;
            }

            uint8_t minBytes = (instrLen < 6) ? 6 : instrLen;
            if (overwriteSize > 0) {
                m_originalByteCount = (overwriteSize < 6) ? minBytes : overwriteSize;
                if (overwriteSize < 6)
                    printf("[!] %s: overwriteSize %u < 6 — clamped to %u\n",
                        m_szName.c_str(), overwriteSize, minBytes);
            }
            else {
                m_originalByteCount = minBytes;
            }

            memcpy(m_originalBytes, buf, m_originalByteCount);
            return true;
        }

        // ── InstallCallSitePatch ─────────────────────────────────────────────────
        bool InstallCallSitePatch()
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

            // FF 15 [abs32] + NOPs to fill overwriteSize
            std::vector<uint8_t> patch;
            patch.reserve(m_originalByteCount);
            patch.push_back(0xFF);
            patch.push_back(0x15);

            uint32_t storageAddr = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(m_pFuncPtrStorage));
            patch.push_back(static_cast<uint8_t>(storageAddr & 0xFF));
            patch.push_back(static_cast<uint8_t>((storageAddr >> 8) & 0xFF));
            patch.push_back(static_cast<uint8_t>((storageAddr >> 16) & 0xFF));
            patch.push_back(static_cast<uint8_t>((storageAddr >> 24) & 0xFF));

            while (patch.size() < m_originalByteCount)
                patch.push_back(0x90);

            DWORD oldProtect;
            if (!VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr),
                m_originalByteCount, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                printf("[!] %s: VirtualProtectEx failed (%lu)\n",
                    m_szName.c_str(), GetLastError());
                return false;
            }

            bool ok = Proc()->WriteArray(m_callSiteAddr, patch);

            VirtualProtectEx(Proc()->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr),
                m_originalByteCount, oldProtect, &oldProtect);

            if (!ok) {
                printf("[!] %s: failed to write call site patch\n", m_szName.c_str());
                return false;
            }

            FlushInstructionCache(Proc()->m_hProc,
                reinterpret_cast<void*>(m_callSiteAddr), m_originalByteCount);

            printf("[+] %s: call site patched (FF 15 [abs32] + %d NOP(s))\n",
                m_szName.c_str(), (int)patch.size() - 6);
            return true;
        }

        // ── TryRestorePrepatched ─────────────────────────────────────────────────
        //
        // Checks for a saved HookConfig entry for the current PID.
        // Validates: shellcode alloc still committed, call site still FF 15,
        // origBytes present.  No slot validation — prepatched hooks have none.
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

            uint8_t probe[2]{};
            Proc()->Read(entry->callSiteAddr, probe, 2);
            if (probe[0] != 0xFF || probe[1] != 0x15) {
                printf("[HookConfig] %s: call site 0x%llX no longer FF 15 – discarding\n",
                    m_szName.c_str(), (uint64_t)entry->callSiteAddr);
                HookConfig::Remove(m_szName);
                return false;
            }

            if (entry->origBytes.empty() ||
                entry->origBytes.size() > sizeof(m_originalBytes))
            {
                printf("[HookConfig] %s: origBytes invalid – discarding\n",
                    m_szName.c_str());
                HookConfig::Remove(m_szName);
                return false;
            }

            m_originalByteCount = static_cast<uint8_t>(entry->origBytes.size());
            memcpy(m_originalBytes, entry->origBytes.data(), m_originalByteCount);

            m_pShellcodeRemote = reinterpret_cast<void*>(entry->shellcodeRemote);
            m_pDataRemote = reinterpret_cast<void*>(entry->dataRemote);
            m_callSiteAddr = entry->callSiteAddr;
            m_originalFuncAddr = static_cast<uint32_t>(entry->origStorage);

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
            e.targetFunction = 0;
            e.callSiteAddr = m_callSiteAddr;
            e.origStorage = m_originalFuncAddr;
            e.origBytes.assign(m_originalBytes, m_originalBytes + m_originalByteCount);
            e.ripSlots.clear(); // no slots in prepatched path

            HookConfig::Upsert(e);
            printf("[HookConfig] %s: state saved (%u orig bytes)\n",
                m_szName.c_str(), m_originalByteCount);
        }
    };

} // namespace LiquidHookEx