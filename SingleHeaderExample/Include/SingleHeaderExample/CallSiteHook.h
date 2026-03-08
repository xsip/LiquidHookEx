#pragma once
#include <SingleHeaderExample/LiquidHookEx.h>

namespace CallSiteExample {
    class CEntity {
        const char* m_szName;
        int         m_nHealth;
    };

    struct SetHealthHookData : public LiquidHookEx::CallSite::BaseHookData
    {
        int health;
    };

    // g_pOriginalFunction unused for this hook, keep for RipSlot compat! But can be used if there is a fixed address!
    // for this example we got :  call    qword ptr [r8+10h] though.
    static void* g_pOriginalFunction = nullptr;


    static SetHealthHookData* g_pHookData = nullptr;

    LH_START(".SetHealthHook")

    void __fastcall hkSetHealth(CEntity* pEntity, int health)
    {
        volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(pEntity);

        SetHealthHookData* data = g_pHookData;

        // original fn addr is not statically resolvable (call [r8+10h] — runtime vtable dispatch)
        // reconstruct the call manually: read vtable ptr from r8, index at +0x10 (slot 2)

        // if original is resolvable by LiquidHookEx, you can do:
        // typedef void* (__fastcall* Fn)(.....);
        // Fn original = (Fn)g_pOriginalFunction;

        uintptr_t vftable = *reinterpret_cast<uintptr_t*>(pEntity);
        typedef void(__fastcall* SetHealthFn)(CEntity*, int);
        SetHealthFn original = *reinterpret_cast<SetHealthFn*>(vftable + 0x10);

        original(pEntity, data->health);
    }

    void hkSetHealthEnd() {}

    LH_END()

}