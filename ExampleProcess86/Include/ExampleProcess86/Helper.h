#pragma once
#include <cstdio>

// ============================================================================
//  Helper free functions
//
//  ComputeDamage()  calls  ApplyDamage() – the *call site* inside
//  ComputeDamage is the hook target for ExampleUsage's CallSite test.
//
//  Pattern to scan for in ExampleUsage:
//    Find the E8 call to ApplyDamage inside ComputeDamage.
// ============================================================================

// Forward declaration so ComputeDamage can call it
void ApplyDamage(int baseDamage, float multiplier);

// Inner function – this is what ExampleUsage hooks via CallSite
inline void ApplyDamage(int baseDamage, float multiplier) {
    int  total = static_cast<int>(baseDamage * multiplier);
    printf("[ApplyDamage] base=%d  mult=%.2f  total=%d\n",
        baseDamage, multiplier, total);
}

// Outer function – ExampleUsage scans for the call instruction to ApplyDamage
// that lives inside this function body
inline void ComputeDamage(int baseDamage, float multiplier) {
    printf("[ComputeDamage] calculating...\n");
    ApplyDamage(baseDamage, multiplier);   // <-- call site hooked by ExampleUsage
}
