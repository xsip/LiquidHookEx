#include <LiquidHookEx/Globals.h>
#include <LiquidHookEx/Process.h>
namespace LiquidHookEx {
	Process* proc = nullptr;

	void INIT(std::string procName, Process::TargetArch targetArch) {
		LiquidHookEx::proc = new Process(procName, targetArch);
	}
	void INIT_BY_WND_CLASS(std::string wndClass, Process::TargetArch targetArch) {
		LiquidHookEx::proc = Process::GetFromWndClass(wndClass, targetArch);
	}
}