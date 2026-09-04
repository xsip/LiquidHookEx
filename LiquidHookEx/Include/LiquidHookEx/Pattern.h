#pragma once
#include <cstdint>
#include <vector>
namespace LiquidHookEx {

	class Memory {
	public:
		static uint8_t* ScanMemory(uintptr_t pStart, uintptr_t pSize, const char* signature);
		static std::vector<uint8_t*> ScanMemoryMulti(uintptr_t pStart, uintptr_t pSize, const char* signature) noexcept;

	};
}