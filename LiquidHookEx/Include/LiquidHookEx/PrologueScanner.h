#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

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

    // Convenience wrappers around ScanPrologue for the two call sites that need it most:
    // LiquidHookEx::CallSite's overwriteSize (minBytes = 6, the FF 15 patch size) and
    // LiquidHookEx::Detour's stolenBytes (minBytes = 14, the FF 25 + addr patch size).
    // Resolve the target the same way Detour::Hook does - either scan `dllName` for
    // `pattern`/`callSitePattern`, or use a caller-supplied address directly - read its
    // bytes from the live process (LiquidHookEx::proc), and run ScanPrologue over them.
    // Result's ripDispOffsets is meaningful only for GetStolenBytesForDetour (Detour
    // relocates the stolen bytes into a trampoline); CallSite patches in place, so callers
    // of GetCallSiteOverwriteSize should only use .totalLength.
    // Empty result (totalLength == 0) means the module/pattern/address couldn't be
    // resolved, or ScanPrologue couldn't reach minBytes safely - never treat 0 as a usable
    // size.
    PrologueScanResult GetCallSiteOverwriteSize(std::string callSitePattern, std::string dllName);
    PrologueScanResult GetCallSiteOverwriteSize(uintptr_t pFn, std::string dllName);

    PrologueScanResult GetStolenBytesForDetour(std::string pattern, std::string dllName);
    PrologueScanResult GetStolenBytesForDetour(uintptr_t pFn, std::string dllName);

}
