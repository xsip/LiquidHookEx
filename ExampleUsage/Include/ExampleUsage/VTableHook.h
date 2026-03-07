#pragma once
#include <LiquidHookEx/VTable.h>

namespace VTableExample {

    class CEntity {
        const char* m_szName;
        int         m_nHealth;
    };

    // Hook data — pOriginalFunc is inherited from BaseHookData (filled by Hook())
    struct GetHealthHookData : public LiquidHookEx::VTable::BaseHookData
    {
        int forcedHealth;
    };

    static void* g_pOriginalFunction = nullptr;
    static GetHealthHookData* g_pHookData = nullptr;

#pragma code_seg(".getHealthHook")
#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma check_stack(off)

    // VTable hook for CEntity::GetHealth(void)
    // Signature matches the original: int __fastcall GetHealth(CEntity* this)
    int __fastcall hkGetHealth(CEntity* pEntity)
    {
        // Force proper stack frame so the nested call gets shadow space
        volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(pEntity);

        GetHealthHookData* data = g_pHookData;

        typedef int(__fastcall* GetHealthFn)(CEntity*);
        GetHealthFn original = (GetHealthFn)g_pOriginalFunction;

        // Call original to get the real HP value
        int realHp = original(pEntity);

        // Override: return forcedHealth instead of the real value
        return data->forcedHealth;
    }

    void hkGetHealthEnd() {}

#pragma check_stack()
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma code_seg()

} // namespace VTableExample