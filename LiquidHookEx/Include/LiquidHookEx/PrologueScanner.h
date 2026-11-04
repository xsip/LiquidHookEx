#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace LiquidHookEx {

    // Same walk as LengthToAtLeast, but also collects every RIP-relative instruction's disp32
    // byte offset (see InstructionInfo::ripDispOffset) found within the returned boundary - a
    // hook trampoline that relocates these bytes to a different address needs exactly this list
    // to patch each one's displacement (see LiquidHookEx::Detour::BuildTrampoline). totalLength
    // is 0 under the same "couldn't get there safely" conditions as LengthToAtLeast, in which
    // case ripDispOffsets is empty and must not be used.
    struct PrologueScanResult {
        size_t totalLength = 0;
        std::vector<size_t> ripDispOffsets;
    };

    PrologueScanResult ScanPrologue(const uint8_t* code, size_t maxLen, size_t minBytes);

}
