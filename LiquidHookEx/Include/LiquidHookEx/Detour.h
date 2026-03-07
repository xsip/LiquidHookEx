#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Config.h>
#include <LiquidHookEx/Globals.h>

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