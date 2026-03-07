#include <ExampleUsage/Include.h>
#include <ExampleUsage/CallSiteHook.h>
#include <ExampleUsage/VTableHook.h>

enum ExampleType {
	VTable,
	CallSite
};

int main() {


	ExampleType ExampleToPreview = ExampleType::CallSite;

	LiquidHookEx::INIT("ExampleProcess.exe");
	if (ExampleToPreview == ExampleType::CallSite) {
		LiquidHookEx::CallSite m_Hook = LiquidHookEx::CallSite("SetHealthHook");

		CallSiteExample::SetHealthHookData hookData{};
		hookData.health = 3000;

		// Hook the SetHealth call inside the RShift branch (0x169E).
		// 
		// The original instruction is a 5-byte direct call (E8 xx xx xx xx).
		// FF 15 (indirect call) requires 6 bytes, so it must steal 1 byte from
		// the following instruction: "lea rcx, aMainHpResetTo1" (48 8D 0D ...).
		// 
		// overwriteSize=7 tells the library to:
		//   - snapshot 7 bytes:  E8(5) + 48 8D(2 stolen from lea rcx)
		//   - write:             FF 15 <disp32>(6) + NOP(1) over the stolen 48
		//   - restore all 7 bytes on Unhook()
		//
		// 7 is safe here because 0x16A3 (the byte immediately after the E8) is
		// NOT a jump target — the jz at 0x1692 now jumps to loc_16AF (0x16AF),
		// so the stolen bytes are never executed as an entry point mid-patch.
		m_Hook.Hook<CallSiteExample::SetHealthHookData>(
			"41 FF 50 ?? 48 8D 0D",
			"ExampleProcess.exe",
			hookData,
			CallSiteExample::hkSetHealth,
			CallSiteExample::hkSetHealthEnd,
			{
				LiquidHookEx::CallSite::RipSlot::Data(&CallSiteExample::g_pHookData),
				LiquidHookEx::CallSite::RipSlot::Orig(&CallSiteExample::g_pOriginalFunction),
			},
			7
			);


		while (true) {
			Sleep(100);
			if (GetAsyncKeyState(VK_LSHIFT)) {
				m_Hook.WriteField<int>(offsetof(CallSiteExample::SetHealthHookData, health), 4000);
				printf("Set Health to 200!!\n");

			}
		}
	}
	else {

		LiquidHookEx::VTable m_vtHook("GetHealthHook");

		VTableExample::GetHealthHookData vtHookData{};
		vtHookData.forcedHealth = 999;  // GetHealth() will always return 999

		// Hook CEntity::GetHealth via its vtable entry.
		//
		// Pattern points at the j_?GetHealth thunk (E9 34 04 00 00) — a jmp stub
		// that IDA emits as a named entry. The VTable hooker scans for this address
		// inside the vtable, resolves the slot index, and replaces that pointer
		// with the shellcode address.
		//
		// RipSlot::Data  → remote GetHealthHookData struct (forcedHealth, pOriginalFunc)
		// RipSlot::Orig  → original GetHealth function address (for the original() call)
		m_vtHook.Hook<VTableExample::GetHealthHookData>(
			"E9 91 04 00 00",           // pattern: j_?GetHealth thunk
			"ExampleProcess.exe",
			vtHookData,
			(void*)VTableExample::hkGetHealth,
			(void*)VTableExample::hkGetHealthEnd,
			{
				LiquidHookEx::VTable::RipSlot::Data(&VTableExample::g_pHookData),
				LiquidHookEx::VTable::RipSlot::Orig(&VTableExample::g_pOriginalFunction),
			}
			);


		while (true) {
			Sleep(100);
			if (GetAsyncKeyState(VK_LSHIFT)) {
				m_vtHook.WriteField<int>(offsetof(VTableExample::GetHealthHookData, forcedHealth), 4000);
				printf("Forced Health to 4000!!\n");

			}
		}
	}

	return 1;
}