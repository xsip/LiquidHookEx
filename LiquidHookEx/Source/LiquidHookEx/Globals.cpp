#include <LiquidHookEx/Globals.h>
#include <LiquidHookEx/Process.h>
namespace LiquidHookEx {
	Process* proc = nullptr;

	void INIT(std::string procName) {
		LiquidHookEx::proc = new Process(procName);
	}
}