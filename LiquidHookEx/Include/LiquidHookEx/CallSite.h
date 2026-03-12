#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Config.h>
#include <LiquidHookEx/Globals.h>

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

            // ── architecture guard ───────────────────────────────────────────
            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64()) {
                printf("[!] %s::Hook => You are trying to use CallSite on a 32-bit process. Use CallSite86 instead.\n",
                    m_szName.c_str());
                return false;
            }

            if (TryRestore<HOOK_DATA>()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            // ── locate module ────────────────────────────────────────────────
            auto pMod = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetRemoteModule(dllName.c_str(),false);
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