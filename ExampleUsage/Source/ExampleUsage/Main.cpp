#include <ExampleUsage/Include.h>
#include <ExampleUsage/CallSiteHook.h>
#include <ExampleUsage/VTableHook.h>

enum ExampleType {
    VTable,
    CallSite
};

int main() {
    ExampleType ExampleToPreview = ExampleType::CallSite;

    // Attach to ExampleProcess.exe — opens a handle and resolves the base address.
    // All subsequent Hook() calls operate on this process.
    LiquidHookEx::INIT("ExampleProcess.exe");

    if (ExampleToPreview == ExampleType::CallSite) {

        // ====================================================================
        //  CallSite hook — CEntity::SetHealth via virtual dispatch call site
        // ====================================================================
        //
        //  Target instruction in ExampleProcess.exe (module+0x172B):
        //
        //    41 FF 50 10   call qword ptr [r8+10h]   ; virtual SetHealth call
        //    48 8D 0D ...  lea  rcx, aMainHpReset...  ; next instruction
        //
        //  At this call site the registers are:
        //    rcx = CEntity*  (the object)
        //    rdx = 0x64      (hp argument, = 100)
        //    r8  = vtable ptr (already dereferenced from the object)
        //
        //  LiquidHookEx replaces the call instruction with:
        //    FF 15 <disp32>   call qword ptr [rip+offset]   (6 bytes)
        //
        //  This dispatches into our shellcode (hkSetHealth) instead of the
        //  original virtual function.
        // ====================================================================

        LiquidHookEx::CallSite m_Hook = LiquidHookEx::CallSite("SetHealthHook");

        CallSiteExample::SetHealthHookData hookData{};
        hookData.health = 3000;  // SetHealth will be called with 3000 instead of 100

        m_Hook.Hook<CallSiteExample::SetHealthHookData>(

            // ── Pattern ─────────────────────────────────────────────────────
            // Uniquely identifies the call site in the module.
            // "41 FF 50 10" = the call instruction itself (4 bytes)
            // "48 8D 0D"    = first 3 bytes of the following lea rcx — included
            //                 to make the pattern unique (the call bytes alone
            //                 could match elsewhere in the binary)
            "41 FF 50 10 48 8D 0D",

            "ExampleProcess.exe",
            hookData,
            CallSiteExample::hkSetHealth,
            CallSiteExample::hkSetHealthEnd,
            {
                // ── RipSlot::Data ────────────────────────────────────────────
                // The shellcode reads g_pHookData via a RIP-relative load:
                //   mov rax, [rip + offset]   ; 48 8B 05 xx xx xx xx
                // At hook time, LiquidHookEx scans the shellcode bytes for this
                // pattern, allocates a remote indirection slot, writes the
                // address of the remote SetHealthHookData struct into it, and
                // patches the disp32 so the shellcode reads from the correct
                // remote address after being copied into the target process.
                LiquidHookEx::CallSite::RipSlot::Data(&CallSiteExample::g_pHookData),

                // ── No RipSlot::Orig ─────────────────────────────────────────
                // Normally RipSlot::Orig would store the original function
                // address so the shellcode can call it via:
                //   mov rax, [rip + offset]   ; g_pOriginalFunction
                //   call rax
                //
                // This is not possible here because the original instruction is:
                //   call qword ptr [r8+10h]   ; indirect call through register
                //
                // The callee address is a runtime value in r8 — it cannot be
                // resolved statically at hook time. LiquidHookEx correctly sets
                // originalFuncAddr = 0 for this form and logs:
                //   "could not resolve original fn addr (indirect call form)"
                //
                // Instead, hkSetHealth reconstructs the call manually:
                //   uintptr_t vftable = *(uintptr_t*)pEntity;  // read vtable ptr
                //   original = *(SetHealthFn*)(vftable + 0x10); // slot 2 = SetHealth
                //   original(pEntity, data->health);
            },

            // ── overwriteSize = 11 ───────────────────────────────────────────
            // The FF 15 patch is always 6 bytes. The original call instruction
            // is only 4 bytes (41 FF 50 10), so FF 15 must steal 2 extra bytes
            // from the following instruction. But "stealing" only 2 bytes of a
            // 7-byte lea rcx (48 8D 0D xx xx xx xx) leaves the remaining 4
            // displacement bytes (xx xx xx xx) intact in memory — the CPU then
            // executes them as opcodes, which decoded as:
            //   FA        = cli   ← privileged instruction → crash (0xC0000096)
            //   65 00 00  = add gs:[rax], al
            //
            // The fix is to overwrite the ENTIRE following lea rcx instruction:
            //   41 FF 50 10          = 4 bytes  (original call)
            //   48 8D 0D xx xx xx xx = 7 bytes  (following lea rcx)
            //   total                = 11 bytes
            //
            // LiquidHookEx writes:
            //   FF 15 <disp32>       = 6 bytes  (the patch)
            //   90 90 90 90 90       = 5 NOPs   (padding over stolen bytes)
            //
            // When the shellcode executes 'ret', execution returns to the
            // instruction after the 11-byte region — which is intact code.
            // The 5 NOPs slide harmlessly into it.
            11
            );

        while (true) {
            Sleep(100);

            if (GetAsyncKeyState(VK_LSHIFT)) {
                // WriteField patches a single field inside the remote HookData
                // struct without re-hooking. The shellcode reads this value on
                // every call, so the change takes effect immediately on the
                // next SetHealth invocation.
                m_Hook.WriteField<int>(
                    offsetof(CallSiteExample::SetHealthHookData, health), 4000);
                printf("Set Health to 4000!!\n");
            }
        }
    }
    else {

        // ====================================================================
        //  VTable hook — CEntity::GetHealth
        // ====================================================================
        //
        //  The vtable for CEntity lives in .rdata:
        //    +0x00  j_destructor   (slot 0 — virtual ~IEntity)
        //    +0x08  j_GetHealth    (slot 1) ← hooked here
        //    +0x10  j_SetHealth    (slot 2)
        //    +0x18  j_GetName      (slot 3)
        //    +0x20  j_Update       (slot 4)
        //
        //  LiquidHookEx scans for the pattern to find the thunk address,
        //  then calls FindVTableContainingFunction() to locate which vtable
        //  slot points to it and what its index is. It then overwrites that
        //  slot with the address of our remote shellcode.
        //
        //  Unlike CallSite, no instruction bytes are patched — only an 8-byte
        //  pointer in .rdata is replaced, so there are no byte-stealing or
        //  jump-target alignment concerns.
        //
        //  IMPORTANT: this only intercepts calls made through the vtable
        //  (virtual dispatch via a base class pointer). Calls made on a
        //  concrete CEntity local variable are devirtualized by the compiler
        //  and bypass the vtable entirely — those require a CallSite hook.
        // ====================================================================

        LiquidHookEx::VTable m_vtHook("GetHealthHook");

        VTableExample::GetHealthHookData vtHookData{};
        vtHookData.forcedHealth = 999;  // every GetHealth() call returns 999

        m_vtHook.Hook<VTableExample::GetHealthHookData>(

            // ── Pattern ─────────────────────────────────────────────────────
            // Points at the j_?GetHealth thunk in .text:
            //   E9 91 04 00 00   jmp CEntity::GetHealth
            // LiquidHookEx finds this address in the vtable and replaces the
            // slot pointer with the shellcode address.
            "E9 91 04 00 00",

            "ExampleProcess.exe",
            vtHookData,
            (void*)VTableExample::hkGetHealth,
            (void*)VTableExample::hkGetHealthEnd,
            {
                // ── RipSlot::Data ────────────────────────────────────────────
                // Remote indirection slot for g_pHookData — same mechanism as
                // CallSite. The shellcode reads forcedHealth via this pointer.
                LiquidHookEx::VTable::RipSlot::Data(&VTableExample::g_pHookData),

                // ── RipSlot::Orig ────────────────────────────────────────────
                // Unlike the CallSite case above, the original function address
                // IS statically known here — it is read directly from the vtable
                // slot before it gets overwritten:
                //   originalFunc = ReadDirect<uint64_t>(vtableSlotAddr)
                // LiquidHookEx stores this in the remote slot so the shellcode
                // can call the real GetHealth and obtain the true HP value before
                // deciding what to return.
                LiquidHookEx::VTable::RipSlot::Orig(&VTableExample::g_pOriginalFunction),
            }
            );

        while (true) {
            Sleep(100);

            if (GetAsyncKeyState(VK_LSHIFT)) {
                m_vtHook.WriteField<int>(
                    offsetof(VTableExample::GetHealthHookData, forcedHealth), 4000);
                printf("Forced Health to 4000!!\n");
            }
        }
    }

    return 1;
}