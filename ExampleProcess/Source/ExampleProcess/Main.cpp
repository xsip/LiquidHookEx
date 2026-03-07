#include <ExampleProcess/Include.h>
#include <ExampleProcess/IEntity.h>
#include <ExampleProcess/Helper.h>

#include <Windows.h>
#include <cstdio>

// ============================================================================
//  ExampleProcess entry point
//
//  Three things ExampleUsage can test against:
//
//  1. VTable hook  –  CEntity::Update() is called every loop iteration.
//                     ExampleUsage can hook IEntity::Update (vtable index 3)
//                     to intercept / replace the call.
//
//  2. CallSite hook – ComputeDamage() calls ApplyDamage() on every iteration.
//                     ExampleUsage can hook the E8 call site inside
//                     ComputeDamage to intercept ApplyDamage.
//
//  3. General loop  – The while(true) keeps the process alive and repeating
//                     so ExampleUsage has time to attach, hook, and observe.
// ============================================================================

int main() {
    printf("[ExampleProcess] started (pid=%lu)\n\n", GetCurrentProcessId());

    // Entity used for VTable hook tests
    CEntity entity("TestEntity", 10);

    int tick = 0;
    while (true) {
        printf("--- tick %d ---\n", tick);

        // ── VTable hook target ───────────────────────────────────────────────
        // ExampleUsage hooks IEntity::Update (vtable slot 3) and / or
        // IEntity::GetHealth (vtable slot 0).
        entity.Update();

        int hp = entity.GetHealth();
        printf("[main] entity hp = %d\n", hp);

        if (GetAsyncKeyState(VK_RSHIFT)) {
            entity.SetHealth(100);
            printf("[main] hp reset to 100\n");

        }

        // Reset HP so the process runs indefinitely for testing
        if (hp <= 0) {
            entity.SetHealth(200);
            printf("[main] hp reset to 200\n");
        }

        // ── CallSite hook target ─────────────────────────────────────────────
        // ExampleUsage hooks the call to ApplyDamage inside ComputeDamage.
        ComputeDamage(25, 1.5f);

        printf("\n");
        ++tick;
        Sleep(1000);
    }

    return 0;
}