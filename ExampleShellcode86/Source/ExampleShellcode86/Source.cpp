// =============================================================================
//  ExampleShellcode86 -- x86 shellcode DLL
//
//  Compiled as a 32-bit DLL with no CRT.  Hook functions are located by
//  exported symbol name, rebased, and injected by ShellcodeDLL86::LoadHook().
//
//  HOW TO ADD A NEW HOOK
//  ---------------------
//  1.  Define a hook-data struct below.
//  2.  Open HOOK_BEGIN.
//  3.  Declare the data global and orig-fn pointer with HOOK_EXPORT.
//  4.  Write the hook function (HOOK_EXPORT, __fastcall, correct ret N).
//  5.  Add the end sentinel immediately after -- nothing between them.
//  6.  Close with HOOK_END (after the sentinel).
//  7.  Add all four symbols to ExampleShellcode86.def EXPORTS.
// =============================================================================
#include <Windows.h>
#include <cstdint>
#include <ExampleShellcode86/Include.h>

// =============================================================================
//  Hook data structs
//
//  Fields are populated remotely by ShellcodeDLL86 before the hook fires.
//  Always hold by VALUE -- a pointer requires a second remote dereference
//  that the injected shellcode cannot perform.
// =============================================================================
struct SetHealthHookData {
    int health;
};

// =============================================================================
//  SetHealthCallSite  --  CallSite86 hook for SetHealth
//
//  Call site (module+0x1762):
//    FF 50 08              call dword ptr [eax+8]    ; vtable slot 2 dispatch
//    68 58 6C 00 00        push offset "..."         ; next instruction
//
//  [eax+8] is a vtable indirect call — eax holds the vtable pointer and
//  slot 2 (offset +8 in a 4-byte-per-entry x86 vtable) is SetHealth.
//
//  Calling convention (confirmed from CE disassembly):
//    mov eax, [esi]        ; eax = vtable
//    mov ecx, esi          ; ecx = this (CEntity*)
//    push 64h              ; health pushed as stack arg (caller-cleanup)
//    call [eax+8]          ; SetHealth(this=ecx, health=stack)
//    add esp, 4            ; caller cleans the push → callee uses ret 0
//
//  __fastcall equivalent: (void* thisPtr, int /*edx*/, int health)
//    ECX = thisPtr, EDX = unused, health = first stack arg, ret 0.
//
//  overwriteSize = 8:
//    FF 50 08              — 3 bytes, complete instruction
//    68 58 6C 00 00        — 5 bytes, complete instruction
//    Total = 8.  The FF 15 patch is 6 bytes; stopping at 6 would cut into
//    the push after 3 bytes, leaving 58 6C 00 00 as garbage in the stream.
//    8 bytes covers both complete instructions; patch = FF 15 [abs32] + 2 NOPs.
// =============================================================================
HOOK_BEGIN

HOOK_EXPORT SetHealthHookData g_CallSiteHookData = {};
HOOK_EXPORT void* g_pCallSiteOriginal = nullptr;  // unused: not resolvable

// __thiscall with callee-cleanup stack arg → ret 4:
//   ECX     = thisPtr (CEntity*)
//   stack+0 = health (int, pushed by caller)
//   The "add esp,4" at 0x176F cleans the PRINTF push that follows the call,
//   NOT the SetHealth push — callee cleans health with ret 4.
//
// __fastcall equivalent: (void* thisPtr, int /*edx*/, int health) → ret 4
extern "C" __declspec(dllexport) __declspec(noinline)
void __fastcall SetHealthCallSite_Hook(void* thisPtr, int /*edx*/, int health)
{
    uintptr_t vftable = *reinterpret_cast<uintptr_t*>(thisPtr);
    typedef void(__thiscall* SetHealthFn)(void*, int);
    SetHealthFn original = *reinterpret_cast<SetHealthFn*>(vftable + 0x8);
    original(thisPtr, g_CallSiteHookData.health);
}

HOOK_EXPORT void SetHealthCallSite_Hook_End() {}

HOOK_END

// =============================================================================
//  DllMain
// =============================================================================
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }