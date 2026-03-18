#pragma once
#include <string>
#include <LiquidHookEx/Process.h>
namespace LiquidHookEx {
	class Process;
	extern Process* proc;
	extern void INIT(std::string procName, Process::TargetArch targetArch = Process::TargetArch::x64);
	extern void INIT_BY_WND_CLASS(std::string wndClass, Process::TargetArch targetArch = Process::TargetArch::x64);
}