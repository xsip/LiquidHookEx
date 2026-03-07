#pragma once
#include <LiquidHookEx/VTable.h>

namespace CallSiteExample {
    class CEntity {
        const char* m_szName;
        int         m_nHealth;
    };

    struct SetHealthHookData : public LiquidHookEx::CallSite::BaseHookData
    {
        int health;
    };

    static void* g_pOriginalFunction = nullptr;
    static SetHealthHookData* g_pHookData = nullptr;

#pragma code_seg(".setHealthHook")
#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma check_stack(off)
    void __fastcall hkSetHealth(CEntity* pEntity, int health)
    {
        // Force the compiler to emit a proper stack frame
        // by making a volatile local — ensures sub rsp,28h is emitted
        volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(pEntity);

        SetHealthHookData* data = g_pHookData;
        typedef void(__fastcall* SetHealthFn)(CEntity*, int);
        SetHealthFn original = (SetHealthFn)g_pOriginalFunction;
        original(pEntity, data->health);
    }
    void hkSetHealthEnd() {}
#pragma check_stack()
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma code_seg()

}