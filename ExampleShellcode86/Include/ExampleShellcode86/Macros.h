#pragma once
// =============================================================================
//  ExampleShellcode86/Macros.h
//
//  Three macros covering every authoring concern for a shellcode hook:
//
//    HOOK_BEGIN   open a hook block  (set segments + disable compiler helpers)
//    HOOK_END     close a hook block (restore all settings)
//    HOOK_EXPORT  extern "C" __declspec(dllexport)
//
//  See README.md for the rationale behind each pragma.
// =============================================================================

// -----------------------------------------------------------------------------
//  HOOK_BEGIN
//
//  1. Routes code / data / BSS into the .hook section family so the linker
//     merges them into one contiguous byte range via /MERGE:.hookd=.hook etc.
//  2. Disables the three compiler features that emit CRT helper calls:
//       optimize       off  -- no inlining / reordering across the boundary
//       runtime_checks off  -- suppresses /RTC helpers (__RTC_CheckEsp etc.)
//       check_stack    off  -- suppresses __chkstk stack probes
//
//  _Pragma() is used because #pragma is not permitted inside a #define.
//  MSVC supports _Pragma since VS 2019 16.6.
// -----------------------------------------------------------------------------
#define HOOK_BEGIN                                    \
    _Pragma("code_seg(\".hook\")")                    \
    _Pragma("data_seg(\".hookd\")")                   \
    _Pragma("bss_seg(\".hookb\")")                    \
    _Pragma("optimize(\"\", off)")                    \
    _Pragma("runtime_checks(\"\", off)")              \
    _Pragma("check_stack(off)")

// -----------------------------------------------------------------------------
//  HOOK_END
//
//  Restores everything changed by HOOK_BEGIN.
//  Place AFTER the end sentinel, not before it.
// -----------------------------------------------------------------------------
#define HOOK_END                                      \
    _Pragma("check_stack()")                          \
    _Pragma("runtime_checks(\"\", restore)")          \
    _Pragma("optimize(\"\", on)")                     \
    _Pragma("code_seg()")                             \
    _Pragma("data_seg()")                             \
    _Pragma("bss_seg()")

// -----------------------------------------------------------------------------
//  HOOK_EXPORT
//
//  extern "C" __declspec(dllexport)
//
//  Apply to every global and function that LoadHook must locate via
//  GetProcAddress.  Each symbol must also appear in the .def EXPORTS.
// -----------------------------------------------------------------------------
#define HOOK_EXPORT extern "C" __declspec(dllexport)

