#pragma once
#include <string>
#include <vector>
#include <cstdint>

#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Config.h>
#include <LiquidHookEx/Globals.h>

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

            // ── architecture guard ───────────────────────────────────────
            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64()) {
                printf("[!] %s::Hook => You are trying to use VTable on a 32-bit process. Use VTable86 instead.\n",
                    m_szName.c_str());
                return false;
            }

            if (TryRestore<HOOK_DATA>()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            // ── locate module ────────────────────────────────────────────
            auto pMod = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetRemoteModule(dllName.c_str(),false);
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
            const size_t ptrSize = (m_pProc ? m_pProc : LiquidHookEx::proc)->TargetPtrSize();
            m_pTargetFunction = vTableInfo.vTableAddr + (vTableInfo.index * ptrSize);

            uint64_t originalFunc = 0;
            if ((m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64())
                originalFunc = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(m_pTargetFunction);
            else
                originalFunc = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint32_t>(m_pTargetFunction);
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

        template <typename HOOK_DATA>
            requires std::is_base_of_v<BaseHookData, HOOK_DATA>
        bool HookUsingAddr(
            uintptr_t pFnAddr,
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

            // ── architecture guard ───────────────────────────────────────
            if (!(m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64()) {
                printf("[!] %s::Hook => You are trying to use VTable on a 32-bit process. Use VTable86 instead.\n",
                    m_szName.c_str());
                return false;
            }

            if (TryRestore<HOOK_DATA>()) {
                printf("[+] %s: restored from saved state\n", m_szName.c_str());
                return true;
            }

            // ── locate module ────────────────────────────────────────────
            auto pMod = (m_pProc ? m_pProc : LiquidHookEx::proc)->GetRemoteModule(dllName.c_str(),false);
            if (!pMod || !pMod->IsValid()) {
                printf("[!] %s: failed to get %s\n", m_szName.c_str(), dllName.c_str());
                return false;
            }

       
            if (!pFnAddr) {
                printf("[!] %s: pattern not found\n", m_szName.c_str());
                return false;
            }

            auto vTableInfo = pMod->FindVTableContainingFunction(pFnAddr);
            if (!vTableInfo.vTableAddr || vTableInfo.index < 0) {
                printf("[!] %s: vtable lookup failed for 0x%p\n", m_szName.c_str(), pFnAddr);
                return false;
            }
            const size_t ptrSize = (m_pProc ? m_pProc : LiquidHookEx::proc)->TargetPtrSize();
            m_pTargetFunction = vTableInfo.vTableAddr + (vTableInfo.index * ptrSize);

            uint64_t originalFunc = 0;
            if ((m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64())
                originalFunc = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(m_pTargetFunction);
            else
                originalFunc = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint32_t>(m_pTargetFunction);
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

            const size_t ptrSize = (m_pProc ? m_pProc : LiquidHookEx::proc)->TargetPtrSize();

            DWORD oldProtect;
            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                ptrSize, PAGE_READWRITE, &oldProtect);

            if ((m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64())
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(m_pTargetFunction, originalFunc);
            else
                (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint32_t>(m_pTargetFunction, static_cast<uint32_t>(originalFunc));

            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                ptrSize, oldProtect, &oldProtect);

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

            uint64_t currentVtableEntry = 0;
            if ((m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64())
                currentVtableEntry = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint64_t>(entry->targetFunction);
            else
                currentVtableEntry = (m_pProc ? m_pProc : LiquidHookEx::proc)->ReadDirect<uint32_t>(entry->targetFunction);
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
            const size_t ptrSize = (m_pProc ? m_pProc : LiquidHookEx::proc)->TargetPtrSize();

            DWORD oldProtect;
            if (!VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                ptrSize, PAGE_READWRITE, &oldProtect))
                return false;

            bool ok = false;
            if ((m_pProc ? m_pProc : LiquidHookEx::proc)->IsTarget64()) {
                ok = (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint64_t>(
                    m_pTargetFunction,
                    reinterpret_cast<uint64_t>(m_pShellcodeRemote));
            }
            else {
                ok = (m_pProc ? m_pProc : LiquidHookEx::proc)->Write<uint32_t>(
                    m_pTargetFunction,
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_pShellcodeRemote)));
            }

            VirtualProtectEx((m_pProc ? m_pProc : LiquidHookEx::proc)->m_hProc,
                reinterpret_cast<void*>(m_pTargetFunction),
                ptrSize, oldProtect, &oldProtect);

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