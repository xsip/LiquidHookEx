#include <ExampleUsage86/Include.h>

enum ExampleType {
    VTable,
    CallSite
};

namespace H = LiquidHookEx;
auto& proc = H::proc;

struct SetHealthHookData {
    int health;
};

int main()
{
    ExampleType ExampleToPreview = ExampleType::CallSite;

    H::INIT("ExampleProcess86.exe", H::Process::TargetArch::x86);

    H::ShellcodeDLL86 dll(
        R"(D:\cpp-projects\LiquidHookEx\Bin\Win32\Release\ExampleShellcode86.dll)");
    if (!dll.IsValid()) { printf("[-] ExampleShellcode86.dll load failed\n"); return 1; }

    if (ExampleToPreview == ExampleType::CallSite)
    {
        SetHealthHookData initData{ .health = 9000 };

        // LoadHook:
        //   - Extracts the ".hook" section bytes from the DLL on disk
        //   - Resolves SetHealthCallSite_Hook / _End symbol offsets (fnStart/fnEnd)
        //   - Allocates remote blocks for g_CallSiteHookData and g_pCallSiteOriginal
        //   - Rebases both VA slots in the section bytes to the remote addrs
        //   Returns a ShellcodeHook ready for HookPrepatched.
        //
        // Note: g_pCallSiteOriginal will be written as 0 by HookPrepatched because
        // the call site is "FF 50 08" (indirect vtable dispatch — not a direct E8
        // or FF 15 with a resolvable target).  The hook re-derives the original fn
        // at runtime by reading [thisPtr->vtable + 0x8] directly.
        auto h = dll.LoadHook<SetHealthHookData>(
            "SetHealthCallSite_Hook",
            "SetHealthCallSite_Hook_End",
            "g_CallSiteHookData",
            "g_pCallSiteOriginal",
            initData);
        if (!h.valid) { printf("[-] CallSite LoadHook failed\n"); return 1; }

        H::CallSite86 m_CallSiteHook("SetHealthExecution");

        // Hook the SECOND SetHealth call site (module+0x177F) where hp <= 0.
        // This call site uses push imm32 (5 bytes) + FF 50 08 (3 bytes) = 8 bytes,
        // which fits FF 15 [abs32] (6 bytes) + 2 NOPs cleanly — no spill into
        // the following printf push.
        //
        // The first call site (0x1762) uses push imm8 (2 bytes) + FF 50 08 (3 bytes)
        // = 5 bytes, which cannot fit a 6-byte FF 15 patch without spilling.
        //
        //   68 C8 00 00 00        — push 0C8h (health arg)        (5 bytes)
        //   FF 50 08              — call dword ptr [eax+8]         (3 bytes)
        //   68 74 6C 00 00        — push offset "..." (printf arg) (5 bytes, untouched)
        //
        // overwriteSize = 8: 5 (push imm32) + 3 (FF 50 08), patch = FF 15 + 2 NOPs.
        m_CallSiteHook.HookPrepatched(
            "68 C8 00 00 00 FF 50 08 68 ?? ?? ?? ?? E8",
            "ExampleProcess86.exe",
            h,
            8   // overwriteSize: 5 (68 C8 00 00 00) + 3 (FF 50 08)
        );

        // Update health value in the live remote data block.
        m_CallSiteHook.WriteField<int>(offsetof(SetHealthHookData, health), 10000);

        printf("Hooks active. Press DELETE to exit.\n");
        while (!GetAsyncKeyState(VK_DELETE)) { Sleep(10000); }
        m_CallSiteHook.Unhook();
    }
    else if (ExampleToPreview == ExampleType::VTable)
    {
        // VTable hook: pattern "E9 50 05 00 00" targets GetHealth.
        // TODO: implement with H::VTable86.
    }

    return 0;
}