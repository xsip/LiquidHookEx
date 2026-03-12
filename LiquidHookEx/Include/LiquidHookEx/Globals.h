#pragma once
#include <string>
#include <LiquidHookEx/Process.h>
namespace LiquidHookEx {
	class Process;
	extern Process* proc;
	extern void INIT(std::string procName, Process::TargetArch targetArch = Process::TargetArch::x64);
}