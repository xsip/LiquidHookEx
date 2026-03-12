# LiquidHookEx - External Hooking Library [Preview Video here](https://www.youtube.com/watch?v=XncMj_yiuTc)
![Header](https://raw.githubusercontent.com/xsip/LiquidHookEx/refs/heads/main/header.png)
**LiquidHookEx** is an external x64 process hooking library for Windows. It operates entirely from outside the target process — no injected DLL, no in-process threads. Hooks are installed by writing shellcode and hook data directly into the target process's virtual memory via `WriteProcessMemory`, then redirecting execution either by patching a vtable slot pointer or by overwriting a specific call instruction at a known call site.

The library supports two independent hook mechanisms, each exposed through its own class:

| Class | Mechanism | What gets patched |
|---|---|---|
| `VTable` | Vtable slot overwrite | 8-byte function pointer in `.rdata` |
| `CallSite` | Call site instruction overwrite | `call` instruction bytes in `.text` |

Both classes share the same RIP-slot patching engine, the same `HookConfig` JSON persistence layer, and the same `TryRestore()` logic for surviving tool restarts across a live session.

---

## Table of Contents

- [Architecture overview](#architecture-overview)
- [VTable.h — vtable slot hook](#vtableh--vtable-slot-hook)
    - [How it works](#how-it-works)
    - [API](#api)
    - [Hook data](#hook-data)
- [CallSite.h — call site instruction hook](#callsiteh--call-site-instruction-hook)
    - [How it works](#how-it-works-1)
    - [API](#api-1)
- [RIP slots](#rip-slots)
- [Shellcode authoring rules](#shellcode-authoring-rules)
- [Hook state persistence (HookConfig)](#hook-state-persistence-hookconfig)
- [Example — VTableHook.h: intercept CEntity::GetHealth](#example--vtablehookh-intercept-centitygethealth)
- [Example — CallSiteHook.h: intercept a virtual dispatch call site](#example--callsitehookh-intercept-a-virtual-dispatch-call-site)
- [HookConfig — hooks.json format](#hookconfig--hooksjson-format)
- [Project structure](#project-structure)
- [x86 target support](#x86-target-support)
    - [Architecture overview (x86 path)](#architecture-overview-x86-path)
    - [LiquidHookEx::INIT — target architecture parameter](#liquidhookexinit--target-architecture-parameter)
    - [ShellcodeDLL86 — reading the x86 shellcode DLL](#shellcodedll86--reading-the-x86-shellcode-dll)
    - [VTable86 — x86 vtable slot hook](#vtable86--x86-vtable-slot-hook)
    - [CallSite86 — x86 call site hook](#callsite86--x86-call-site-hook)
    - [Detour86 — x86 function prologue hook](#detour86--x86-function-prologue-hook)
    - [Setting up an x86 shellcode DLL project](#setting-up-an-x86-shellcode-dll-project)
    - [Writing hooks for the x86 shellcode DLL](#writing-hooks-for-the-x86-shellcode-dll)
    - [Complete x86 hook example — CallSite86: intercept SetHealth](#complete-x86-hook-example--callsite86-intercept-sethealth)
    - [x86 hook persistence](#x86-hook-persistence-hookconfig--same-json-format)
- [Updated project structure](#updated-project-structure)

---

## Architecture overview

```
Your process                          Target process
─────────────────────────────         ──────────────────────────────────────────
Hook()
  │
  ├─ ScanMemory(pattern)         →    find call site / vtable thunk in .text
  │
  ├─ Alloc + WriteArray          →    remote shellcode  (PAGE_EXECUTE_READWRITE)
  │
  ├─ PatchRipSlots               →    scan shellcode bytes for `48 8B 05` (mov rax, [rip+x])
  │    ├─ alloc remote slot[0]   →    8-byte slot → &HookData struct
  │    └─ alloc remote slot[1]   →    8-byte slot → original fn address
  │         patch disp32 in shellcode so mov reads from remote slot
  │
  ├─ Alloc + Write<HOOK_DATA>    →    remote HookData struct
  │
  └─ Install patch
       VTable:    Write<uint64_t> to vtable slot   →  shellcode addr
       CallSite:  WriteArray FF 15 <disp32> + NOPs →  funcptr storage → shellcode addr
```

When the target process calls the hooked function, it executes the shellcode. The shellcode accesses `HookData` and the original function pointer via RIP-relative loads that — after patching — point to the remote slots inside the target process.

---

## `VTable.h` — vtable slot hook

### How it works

`VTable::Hook()` intercepts a virtual function by overwriting the function pointer stored inside the target class's vtable in `.rdata`. The original pointer is saved before the overwrite so `Unhook()` can restore it exactly.

**Step by step:**

1. `ScanMemory(pattern)` finds the thunk address matching your byte pattern in the target module.
2. `FindVTableContainingFunction(addr)` walks the module's `.rdata` section to find which vtable slot points to that address, and at which index.
3. `ReadDirect<uint64_t>(slotAddr)` reads and saves the original function pointer.
4. The `HOOK_DATA` struct is written into a remote allocation. `pOriginalFunc` (inherited from `BaseHookData`) is automatically populated with the original function address before writing.
5. Shellcode is copied to a remote `PAGE_EXECUTE_READWRITE` allocation.
6. `PatchRipSlots()` scans the shellcode bytes for `48 8B 05 xx xx xx xx` (`mov rax, [rip+offset]`) patterns, allocates a remote 8-byte indirection slot per matched local variable, and patches the `disp32` so the RIP-relative load resolves correctly in the target process's address space.
7. The vtable slot is overwritten with the shellcode address via `VirtualProtectEx` + `Write<uint64_t>`.

**Unhooking** reads the original function address back from a dedicated `origStorage` remote allocation (not from the data struct, which the shellcode may still be reading), then restores the vtable slot and frees all remote memory.

### API

```cpp
// Initialise the global process handle (used as fallback by all hooks)
LiquidHookEx::INIT("target.exe");

// Construct — name is used for logging and HookConfig persistence.
// A Process* can optionally be passed as the second argument; if omitted,
// the process initialised by INIT() is used automatically.
LiquidHookEx::VTable m_hook("MyHookName");            // uses INIT() process
LiquidHookEx::VTable m_hook("MyHookName", pMyProc);   // uses explicit instance

// Install the hook
m_hook.Hook<MyHookData>(
    "E9 91 04 00 00",     // byte pattern identifying the function in the module
    "target.exe",         // module name (GetModuleHandle key)
    initData,             // initial value of the remote HookData struct
    (void*)hkMyFunc,      // shellcode start
    (void*)hkMyFuncEnd,   // shellcode end (address used to compute size)
    {
        LiquidHookEx::VTable::RipSlot::Data(&g_pHookData),        // HookData pointer
        LiquidHookEx::VTable::RipSlot::Orig(&g_pOriginalFunc),     // original fn address
        LiquidHookEx::VTable::RipSlot::Custom(&g_pCustom, addr),   // arbitrary address
    }
);

// Read the entire HookData struct back from the target process
MyHookData d = m_hook.ReadData<MyHookData>();

// Patch a single field in-place (takes effect on the next call)
m_hook.WriteField<int>(offsetof(MyHookData, someField), newValue);

// Remove the hook and restore the vtable slot
m_hook.Unhook();
```

### Hook data

Every `HOOK_DATA` struct must derive from `VTable::BaseHookData`:

```cpp
struct VTable::BaseHookData {
    uint64_t pOriginalFunc;   // filled automatically by Hook() — do not set manually
};

struct MyHookData : LiquidHookEx::VTable::BaseHookData {
    int   someValue;
    float someOtherValue;
    // ...
};
```

`pOriginalFunc` is populated by `Hook()` before writing the struct to the target. The shellcode reads it through the `RipSlot::Orig` slot.

> **Limitation:** vtable hooks only intercept calls made through virtual dispatch (via a base-class pointer). Calls on a concrete local variable are devirtualized by the compiler at compile time and bypass the vtable entirely — use `CallSite` for those.

---

## `CallSite.h` — call site instruction hook

### How it works

`CallSite::Hook()` intercepts a specific call invocation by overwriting the call instruction at a pattern-identified address in `.text`. The original instruction bytes are snapshotted before patching so `Unhook()` can restore them exactly.

The patch always writes a 6-byte `FF 15 <disp32>` (`call qword ptr [rip+offset]`) instruction. A helper allocation (`funcPtrStorage`) is placed within ±2 GB of the call site (required for the 32-bit RIP-relative displacement to reach it), and it holds the shellcode address. When the CPU executes the patched `FF 15`, it reads `funcPtrStorage`, gets the shellcode address, and calls it.

**Step by step:**

1. `ScanMemory(pattern)` locates the call instruction in the target module.
2. `SnapshotAndResolveCallSite()` reads up to 16 bytes at the call site, auto-detects the instruction form, snapshots the bytes to restore, and — where statically possible — resolves the original callee address.
3. Hook data is written to a remote allocation; shellcode is copied to a remote `PAGE_EXECUTE_READWRITE` allocation.
4. `PatchRipSlots()` rewires each `48 8B 05` load in the shellcode (same engine as `VTable`).
5. `InstallCallSitePatch()` scans from `callSiteAddr - 2GB` upward for a free 8-byte allocation within ±2 GB of the call site. It writes the shellcode address there, then overwrites the call site with `FF 15 <disp32>` followed by `0x90` NOPs to cover any bytes beyond 6.

**Supported original call forms (auto-detected):**

| Bytes | Form | Size | Callee resolved? |
|---|---|---|---|
| `E8 xx xx xx xx` | direct near call | 5 | ✅ |
| `FF 15 xx xx xx xx` | call `[rip+offset]` | 6 | ✅ (dereferences the pointer) |
| `FF 93 xx xx xx xx` | call `[rbx+offset]` | 6 | ❌ |
| `FF D0` / `FF D1` / `FF D3` | call reg | 2 | ❌ |
| `FF 10`..`FF 13` | call `[reg]` | 2 | ❌ |
| `REX FF /2 mod=01` | call `[reg+disp8]` | 4 | ❌ |
| `REX FF /2 mod=10` | call `[reg+disp32]` | 7 | ❌ |

When the callee cannot be resolved statically (e.g. `call [r8+10h]`), `originalFuncAddr` is set to `0` and logged. The shellcode must handle this manually by reconstructing the virtual call from the object's vtable at runtime.

**`overwriteSize` parameter:**

The `FF 15` patch is always 6 bytes. If the original instruction is shorter (e.g. `E8` = 5 bytes, `41 FF 50 10` = 4 bytes), the patch must steal bytes from the following instruction. If those stolen bytes leave a fragment that decodes as a privileged or corrupt instruction, the CPU will fault. Pass `overwriteSize` to explicitly specify how many bytes to snapshot and overwrite (minimum 6). Bytes beyond 6 become `0x90` NOPs.

### API

```cpp
// A Process* can optionally be passed as the second argument; if omitted,
// the process initialised by INIT() is used automatically.
LiquidHookEx::CallSite m_hook("MyCallSiteHook");           // uses INIT() process
LiquidHookEx::CallSite m_hook("MyCallSiteHook", pMyProc);  // uses explicit instance

m_hook.Hook<MyHookData>(
    "41 FF 50 10 48 8D 0D",  // pattern matching the call instruction (+ context bytes for uniqueness)
    "target.exe",
    initData,
    (void*)hkMyFunc,
    (void*)hkMyFuncEnd,
    {
        LiquidHookEx::CallSite::RipSlot::Data(&g_pHookData),
        LiquidHookEx::CallSite::RipSlot::Orig(&g_pOriginalFunc),  // only if callee is statically resolvable
    },
    11   // optional overwriteSize — omit or pass 0 for auto
);

MyHookData d = m_hook.ReadData<MyHookData>();
m_hook.WriteField<int>(offsetof(MyHookData, health), 999);
m_hook.Unhook();
```

`CallSite::BaseHookData` has no fields (unlike `VTable::BaseHookData` which carries `pOriginalFunc`). The original function address is stored separately in `originalFuncAddr` and is only useful when the call form allows static resolution.

---

## RIP slots

Both `VTable` and `CallSite` use the same RIP-slot patching engine to connect the shellcode — which runs inside the target process — to data that lives at addresses only known at hook time.

The mechanism exploits the fact that x64 compilers emit `mov rax, [rip+offset]` (`48 8B 05 xx xx xx xx`) to load static/global variables. When the shellcode is copied into the target, the original `disp32` values still point into your local process. The engine:

1. Scans the copied shellcode bytes for `48 8B 05` sequences.
2. Computes the local target address: `localRip + disp32`.
3. Looks up the matching `RipSlot` by comparing the local target against `pLocalVar` for each declared slot.
4. Allocates a remote 8-byte indirection cell and writes the intended value into it (the `HookData` pointer, the original function address, or a custom address).
5. Patches the `disp32` in the remote shellcode copy so the load resolves to the remote cell.

Every `RipSlot` declared in the `Hook()` call must be matched at least once in the shellcode; unmatched slots are an error.

**Slot types:**

```cpp
RipSlot::Data(&g_pHookData)           // remote cell → address of remote HookData struct
RipSlot::Orig(&g_pOriginalFunc)        // remote cell → original function address
RipSlot::Custom(&g_pSomething, addr)   // remote cell → caller-supplied absolute address
```

---

## Shellcode authoring rules

Shellcode must be isolated in its own code segment and compiled with all runtime helpers disabled, so the byte range `[fnStart, fnEnd)` contains only your logic. Use the `LH_START(<segname>)` / `LH_END()` macros to wrap the shellcode — they expand to the required `__pragma` directives for `code_seg`, `optimize`, `runtime_checks`, and `check_stack`:

```cpp
static void* g_pOriginalFunc = nullptr;
static MyHookData* g_pHookData = nullptr;

LH_START(".myHook")

RetType __fastcall MyClass::hkMyFunc(Args...) {
    volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(firstArg); // force stack frame

    MyHookData* data = g_pHookData;           // → RipSlot::Data
    typedef RetType(__fastcall* Fn)(Args...);
    Fn original = (Fn)g_pOriginalFunc;         // → RipSlot::Orig

    // ... hook logic ...

    return original(...);
}

void MyClass::hkMyFuncEnd() {}

LH_END()
```

Key rules:
- `hkMyFuncEnd` is a sentinel — its address minus `hkMyFunc`'s address gives the shellcode size. It must immediately follow in the same segment.
- The `volatile _dummy` line forces MSVC to emit a proper stack frame prologue/epilogue. Without it, calls from inside the shellcode may corrupt the shadow space.
- All globals accessed from the shellcode must be registered as `RipSlot`s. Any unregistered `48 8B 05` load will cause `PatchRipSlots` to fail with an error.
- Do not call CRT functions, use SEH, or reference any symbol that generates a runtime library call — those addresses are invalid in the target process.

---

## Hook state persistence (`HookConfig`)

After every successful `Hook()`, the library serialises all remote addresses to `hooks.json` next to the executable. On the next `Hook()` call, `TryRestore()` runs first and attempts to reconnect to the live hook:

- Verifies the target process PID matches.
- Checks that `dataRemote` is still committed memory (`VirtualQueryEx`).
- Verifies the hook is still active (vtable slot still points to shellcode / call site still has `FF 15`).
- Validates each remote slot's stored value against the expected type (`HookData`, `OriginalFunc`, or `Custom`). Custom slots whose value has changed are refreshed.

If any check fails the stale entry is removed and a fresh `Hook()` proceeds.

`Unhook()` always removes the entry from `hooks.json`.

---

## Example — `VTableHook.h`: intercept `CEntity::GetHealth`

**Goal:** force every `GetHealth()` call through the vtable to return a fixed value instead of the real one, while still having access to the real value.

### 1. Define hook data and shellcode

```cpp
// VTableHook.h
namespace VTableExample {

    struct GetHealthHookData : LiquidHookEx::VTable::BaseHookData {
        int forcedHealth;   // overriding return value, set from the external process
    };

    static void* g_pOriginalFunction = nullptr;
    static GetHealthHookData* g_pHookData = nullptr;

LH_START(".getHealthHook")

    int __fastcall hkGetHealth(CEntity* pEntity)
    {
        volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(pEntity);

        GetHealthHookData* data = g_pHookData;          // RipSlot::Data

        typedef int(__fastcall* GetHealthFn)(CEntity*);
        GetHealthFn original = (GetHealthFn)g_pOriginalFunction;  // RipSlot::Orig

        int realHp = original(pEntity);   // call the real GetHealth (ignored here)
        return data->forcedHealth;        // return our value instead
    }

    void hkGetHealthEnd() {}

LH_END()
}
```

`pOriginalFunc` in `BaseHookData` is populated automatically by `Hook()` — it reads the vtable slot value before overwriting it. The `RipSlot::Orig` call wires `g_pOriginalFunction` to the remote slot that holds this address.

### 2. Install the hook

```cpp
// Main.cpp
LiquidHookEx::INIT("ExampleProcess.exe");

LiquidHookEx::VTable m_vtHook("GetHealthHook");

VTableExample::GetHealthHookData vtHookData{};
vtHookData.forcedHealth = 999;

m_vtHook.Hook<VTableExample::GetHealthHookData>(
    "E9 91 04 00 00",         // byte pattern of the j_?GetHealth thunk in .text
    "ExampleProcess.exe",
    vtHookData,
    (void*)VTableExample::hkGetHealth,
    (void*)VTableExample::hkGetHealthEnd,
    {
        LiquidHookEx::VTable::RipSlot::Data(&VTableExample::g_pHookData),
        LiquidHookEx::VTable::RipSlot::Orig(&VTableExample::g_pOriginalFunction),
    }
);
```

The library finds the vtable slot for `GetHealth` by scanning `.rdata` for a pointer matching the thunk address, overwrites it with the shellcode address, and stores the original pointer so `Unhook()` can restore it.

### 3. Update the hook data live

```cpp
// Change the forced return value without re-hooking
m_vtHook.WriteField<int>(offsetof(VTableExample::GetHealthHookData, forcedHealth), 4000);
```

`WriteField` writes directly into the remote `HookData` struct. The shellcode reads this value on every invocation, so the change takes effect immediately on the next `GetHealth()` call.

---

## Example — `CallSiteHook.h`: intercept a virtual dispatch call site

**Goal:** intercept the specific call site in `ExampleProcess.exe` that calls `SetHealth(entity, 100)` and make it call `SetHealth(entity, 3000)` instead.

The target instruction is:

```asm
; module+0x172B
41 FF 50 10           call qword ptr [r8+10h]   ; virtual SetHealth — r8 = vtable ptr
48 8D 0D xx xx xx xx  lea  rcx, [rip + ...]      ; next instruction
```

This is a `call [r8+10h]` form — the callee address lives in a register at runtime. LiquidHookEx cannot resolve `originalFuncAddr` statically for this form and will log _"could not resolve original fn addr (indirect call form)"_. The shellcode reconstructs the call manually.

### 1. Define hook data and shellcode

```cpp
// CallSiteHook.h
namespace CallSiteExample {

    struct SetHealthHookData : LiquidHookEx::CallSite::BaseHookData {
        int health;   // the hp value we inject instead of 100
    };

    static void* g_pOriginalFunction = nullptr;  // unused here — call form not statically resolvable
    static SetHealthHookData* g_pHookData = nullptr;

LH_START(".setHealthHook")

    void __fastcall hkSetHealth(CEntity* pEntity, int health)
    {
        volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(pEntity);

        SetHealthHookData* data = g_pHookData;   // RipSlot::Data

        // The original call was `call [r8+10h]`.
        // r8 held the vtable pointer. We reconstruct it by reading the
        // vtable pointer from pEntity and indexing slot 2 (offset 0x10).
        uintptr_t vftable = *reinterpret_cast<uintptr_t*>(pEntity);
        typedef void(__fastcall* SetHealthFn)(CEntity*, int);
        SetHealthFn original = *reinterpret_cast<SetHealthFn*>(vftable + 0x10);

        original(pEntity, data->health);   // call real SetHealth with our value
    }

    void hkSetHealthEnd() {}

LH_END()
}
```

Note that `g_pOriginalFunction` is declared but not used as a `RipSlot` — it is kept as a placeholder comment for cases where the original _is_ statically resolvable, and its presence documents the intent.

### 2. Install the hook

```cpp
LiquidHookEx::INIT("ExampleProcess.exe");

LiquidHookEx::CallSite m_Hook("SetHealthHook");

CallSiteExample::SetHealthHookData hookData{};
hookData.health = 3000;

m_Hook.Hook<CallSiteExample::SetHealthHookData>(
    // Pattern: the 4-byte call + first 3 bytes of the following lea rcx
    // The extra bytes make the pattern unique in the binary.
    "41 FF 50 10 48 8D 0D",

    "ExampleProcess.exe",
    hookData,
    CallSiteExample::hkSetHealth,
    CallSiteExample::hkSetHealthEnd,
    {
        LiquidHookEx::CallSite::RipSlot::Data(&CallSiteExample::g_pHookData),
        // No RipSlot::Orig — original address is not statically resolvable
    },

    // overwriteSize = 11
    //
    // The original call is 4 bytes. FF 15 is 6 bytes — 2 bytes must come from
    // the following lea rcx (7 bytes). If we only took 2 bytes, the remaining
    // 4 displacement bytes of the lea would execute as opcodes and crash.
    // Taking the full 11 bytes (4 + 7) covers both instructions; the 5 bytes
    // beyond the 6-byte FF 15 become NOPs.
    11
);
```

### 3. Update the injected health value live

```cpp
m_Hook.WriteField<int>(offsetof(CallSiteExample::SetHealthHookData, health), 4000);
```

---

## `HookConfig` — `hooks.json` format

```json
[
  {
    "pid": 12345,
    "hookName": "GetHealthHook",
    "dataRemote": "0x1A2B3C4D",
    "shellcodeRemote": "0x5E6F7A8B",
    "targetFunction": "0x9C0D1E2F",
    "origStorage": "0x3A4B5C6D",
    "ripSlots": [
      { "addr": "0x7E8F9A0B", "target": 0 },
      { "addr": "0x1C2D3E4F", "target": 1 }
    ]
  }
]
```

For `CallSite` hooks, `callSiteAddr` and `origBytes` are additionally present; `origStorage` holds the resolved callee address (reusing the field). `targetFunction` is `0x0` for call site hooks.

`target` values: `0` = HookData, `1` = OriginalFunc, `2` = Custom (includes `customAddr`).

---

## Project structure

```
LiquidHookEx/
├── LiquidHookEx/
│   └── Include/LiquidHookEx/
│       ├── VTable.h          ← vtable slot hook
│       ├── CallSite.h        ← call site instruction hook
│       ├── Config.h          ← HookConfig JSON persistence
│       ├── Process.h         ← remote process abstraction (read/write/alloc/scan)
│       ├── Pattern.h         ← byte pattern scanner
│       ├── Globals.h         ← global Process* (LiquidHookEx::proc)
│       └── SysCallManager.h  ← direct syscall layer
│
└── ExampleUsage/
    ├── Include/ExampleUsage/
    │   ├── VTableHook.h      ← GetHealth vtable hook example
    │   └── CallSiteHook.h    ← SetHealth call site hook example
    └── Source/ExampleUsage/
        └── Main.cpp          ← wiring and live WriteField loop
```

---

## x86 target support

LiquidHookEx can hook 32-bit (x86) processes from a 64-bit external tool. Because the tool itself is a 64-bit process, it cannot compile shellcode inline and copy it into a 32-bit target the same way it does for 64-bit targets. The RIP-relative `mov rax, [rip+X]` mechanism that powers the 64-bit RIP slot engine does not exist in x86 — global variables are loaded via absolute 32-bit `MOV reg, [imm32]` instructions instead.

The solution is a **shellcode DLL**: a separate 32-bit DLL project that is compiled in x86 mode, never loaded into any process at runtime, and instead read off disk as raw bytes by `ShellcodeDLL86`. The DLL's export table is used to locate hook functions and their associated globals by name, and `RebaseBytes` replaces the compiler-burned absolute VAs with the actual remote addresses before the bytes are written into the target.

### Architecture overview (x86 path)

```
Your 64-bit tool                        32-bit target process
────────────────────────────────        ──────────────────────────────────────
INIT("target.exe", TargetArch::x86)
  │
  ├─ ShellcodeDLL86("MyHooks.dll")  ←   reads DLL from disk (never LoadLibrary'd)
  │    ├─ GetSection(".hook")            extract raw bytes of .hook section
  │    ├─ GetSymbolVA("g_hookData")      resolve imm32 the compiler burned in
  │    ├─ GetSymbolVA("g_pOrigFn")
  │    └─ LoadHook<MyData>(...)
  │         ├─ Alloc(sizeof(MyData))  →  remote hook data block
  │         ├─ Alloc(4)              →  remote orig-fn slot (4-byte pointer)
  │         └─ RebaseBytes(...)          patch old VA → remote addr in section bytes
  │
  ├─ VTable86 / CallSite86 / Detour86
  │    └─ HookPrepatched(pattern, dll, hook)
  │         ├─ ScanMemory(pattern)   →  find call site / vtable thunk in .text
  │         ├─ Alloc(shellcodeSize)  →  remote PAGE_EXECUTE_READWRITE
  │         ├─ WriteArray(bytes)     →  copy pre-rebased shellcode bytes
  │         ├─ Alloc(4)             →  pFuncPtrStorage  (FF 15 [abs32] operand)
  │         └─ Install patch
  │              VTable86:   Write<uint32_t> to vtable slot → shellcode addr
  │              CallSite86: Write FF 15 [abs32] → pFuncPtrStorage → shellcode
  │              Detour86:   Write FF 25 [abs32] + trampoline
  │
  └─ Hook active
       WriteField<T>(offset, value)  →  patching live remote hook data
       Unhook()                      →  restore bytes + free all remote allocs
```

---

### `LiquidHookEx::INIT` — target architecture parameter

```cpp
// x64 target (default — identical to previous behaviour)
LiquidHookEx::INIT("target64.exe");
LiquidHookEx::INIT("target64.exe", LiquidHookEx::Process::TargetArch::x64);

// x86 target — 32-bit process hooked from the 64-bit tool
LiquidHookEx::INIT("target32.exe", LiquidHookEx::Process::TargetArch::x86);
```

`INIT` opens the target process and stores the resulting `Process*` in `LiquidHookEx::proc`. Passing `TargetArch::x86` sets `Process::m_targetArch`, which controls:

- `TargetPtrSize()` — returns 4 instead of 8; used by vtable slot stride and read/write widths throughout the hooking layer.
- `IsTarget32()` / `IsTarget64()` — queried by each hook class constructor to emit the correct architecture guard error if the wrong class is used.
- All x86 hook classes (`VTable86`, `CallSite86`, `Detour86`) check `IsTarget32()` at the top of `HookPrepatched` and refuse if the target is 64-bit.
- `Read` / `Write` path selection — x86 targets use plain `ReadProcessMemory` / `WriteProcessMemory`; x64 targets go through the direct-syscall layer (`SyscallManager`).

---

### `ShellcodeDLL86` — reading the x86 shellcode DLL

`ShellcodeDLL86` reads a 32-bit DLL from disk (via `fopen`, not `LoadLibrary`) and exposes three operations: section extraction, symbol resolution, and VA rebasing.

```cpp
#include <LiquidHookEx/ShellCodeDll86.h>

LiquidHookEx::ShellcodeDLL86 dll("path/to/MyHooks.dll");

if (!dll.IsValid()) {
    // DLL file not found, bad DOS/NT magic, or not IMAGE_FILE_MACHINE_I386
    printf("failed to load shellcode DLL\n");
    return;
}
```

#### `GetSection` — extract raw section bytes

```cpp
LiquidHookEx::ShellcodeSection sc = dll.GetSection(".hook");
// sc.bytes     — raw file bytes of that PE section
// sc.base      — == sc.bytes.data(), convenience pointer
// sc.sectionRVA — VA offset of section start in the DLL image
// sc.imageBase — DLL preferred load address (from OptionalHeader.ImageBase)
```

#### `GetSymbolInSection` — locate a function inside the section buffer

```cpp
// Returns a pointer into sc.bytes — use as fnStart / fnEnd for HookPrepatched
void* fnStart = dll.GetSymbolInSection("MyHook",     sc);
void* fnEnd   = dll.GetSymbolInSection("MyHook_End", sc);
```

#### `GetSymbolVA` — get the imm32 the compiler burned into the shellcode

```cpp
// Returns imageBase + RVA — the exact 4-byte value the x86 compiler emitted
// into MOV reg, [abs32] instructions inside the hook function body.
uint32_t oldDataVA = dll.GetSymbolVA("g_myHookData");
uint32_t oldOrigVA = dll.GetSymbolVA("g_pMyHookOrigFn");
```

#### `RebaseBytes` — replace old VAs with remote addresses

```cpp
// Scans sc.bytes for every 4-byte occurrence of oldVA and replaces with newVA.
// Call once per global slot before writing bytes to the target process.
dll.RebaseBytes(sc, oldDataVA, (uint32_t)(uintptr_t)pRemoteDataBlock);
dll.RebaseBytes(sc, oldOrigVA, (uint32_t)(uintptr_t)pRemoteOrigSlot);
```

#### `LoadHook` — all-in-one helper

`LoadHook` combines `GetSection`, `GetSymbolInSection`, `GetSymbolVA`, `Alloc`, `Write<HOOK_DATA>`, and `RebaseBytes` into a single call. It is the recommended entry point for the x86 path.

```cpp
MyHookData initData{ .health = 9000 };

LiquidHookEx::ShellcodeHook h = dll.LoadHook<MyHookData>(
    "MyHook",          // exported name of the hook function
    "MyHook_End",      // exported name of the end sentinel
    "g_myHookData",    // exported name of the hook-data global
    "g_pMyHookOrigFn", // exported name of the orig-fn pointer global
    initData           // initial value written into remote hook data
    // optional: pass an explicit Process* as last arg; defaults to LiquidHookEx::proc
);

if (!h.valid) { /* LoadHook printed the failure reason */ return; }

// h.sc          — ShellcodeSection with rebased bytes
// h.fnStart     — pointer into h.sc.bytes at the hook function
// h.fnEnd       — pointer into h.sc.bytes at the end sentinel
// h.pDataRemote — remote address of the allocated hook data block
// h.pOrigRemote — remote address of the allocated orig-fn slot (4-byte)
// h.origRequired — false if the orig-fn VA was not found in the section bytes
//                  (indirect call site: orig fn re-derived at runtime)
```

> **Note:** `LoadHook` always looks for a section named `.hook`. Ensure the shellcode DLL linker merges `.hookd` and `.hookb` into `.hook` (see project setup below).

---

### `VTable86` — x86 vtable slot hook

`VTable86` is the x86 counterpart of `VTable`. It uses a prepatched shellcode path: bytes are rebased by `ShellcodeDLL86` before being written, so no RIP-slot scanner is needed.

The vtable slot is 4 bytes wide (x86 pointer). `HookPrepatched` locates the slot via the same `.rdata` walk as `VTable`, overwrites it with the shellcode address, and saves the original function address into `pOrigRemote` so `Unhook` can restore it.

```cpp
LiquidHookEx::VTable86 m_hook("GetHealthHook");

// Using the ShellcodeHook overload (recommended):
m_hook.HookPrepatched(
    "E9 50 05 00 00",      // pattern identifying the vtable thunk in .text
    "ExampleProcess86.exe",
    h                      // ShellcodeHook from dll.LoadHook<>()
);

// Using the explicit overload:
m_hook.HookPrepatched(
    "E9 50 05 00 00",
    "ExampleProcess86.exe",
    h.sc,                  // ShellcodeSection
    h.fnStart,
    h.fnEnd,
    h.pOrigRemote,         // 4-byte slot — receives original fn address
    h.pDataRemote          // hook data remote address (for WriteField)
);

// Live update
m_hook.WriteField<int>(offsetof(MyHookData, health), 999);

// Remove
m_hook.Unhook();
```

---

### `CallSite86` — x86 call site hook

`CallSite86` patches a specific call instruction in the 32-bit target's `.text` with `FF 15 [abs32]` (`call dword ptr [imm32]`). Because x86 uses absolute 32-bit addressing, `pFuncPtrStorage` can be allocated anywhere in the 4 GB address space — no ±2 GB proximity scan is needed.

**Supported original call forms (x86, auto-detected):**

| Bytes | Form | Size | Callee resolved? |
|---|---|---|---|
| `68 xx xx xx xx` | optional `push imm32` prefix | 5 | prefix only |
| `E8 xx xx xx xx` | direct near call | 5 | ✅ |
| `FF 15 [abs32]` | indirect call `[mem32]` | 6 | ✅ (dereferences ptr) |
| `FF /2 mod=10` | call `[reg+disp32]` | 6 | ❌ |
| `FF /2 mod=01` | call `[reg+disp8]` | 3 | ❌ |
| `FF D0`..`FF D7` | call reg | 2 | ❌ |
| `FF 10`..`FF 17` | call `[reg]` | 2 | ❌ |

The optional `push imm32` prefix (`68 xx xx xx xx`, 5 bytes) is handled specially: patterns may be anchored at the `push` so the combined `push` + `call` region (≥ 8 bytes) fits the 6-byte `FF 15` patch without spilling into the following instruction.

```cpp
LiquidHookEx::CallSite86 m_hook("SetHealthHook");

m_hook.HookPrepatched(
    "68 C8 00 00 00 FF 50 08 68 ?? ?? ?? ?? E8",  // push + call + next bytes for uniqueness
    "ExampleProcess86.exe",
    h,          // ShellcodeHook from dll.LoadHook<>()
    8           // overwriteSize: 5 (push imm32) + 3 (FF 50 08)
);

m_hook.WriteField<int>(offsetof(MyHookData, health), 10000);
m_hook.Unhook();
```

**`overwriteSize` in x86:** same semantics as the x64 `CallSite`. Minimum 6 (size of `FF 15 [abs32]`). Must cover only complete instructions. Bytes beyond 6 become `0x90` NOPs. Use it whenever the original call instruction is shorter than 6 bytes (e.g. `FF 50 08` = 3 bytes) and the following instruction must also be consumed to avoid a corrupt decode.

---

### `Detour86` — x86 function prologue hook

`Detour86` patches the first N bytes of a target function with `FF 25 [abs32]` (`jmp dword ptr [imm32]`), building a trampoline from the stolen prologue bytes so the original function can still be called from inside the shellcode.

**Patch layout** (always `FF 25 [abs32]`, 6 bytes + NOPs):
```
FF 25 [abs32]   — jmp dword ptr [pFuncPtrStorage]    (6 bytes)
90 90 ...       — NOPs padding to stolenBytes
```

**Trampoline layout** (remote alloc, `stolenBytes + 6` bytes):
```
[stolen bytes]  — exact copy of the overwritten prologue
FF 25 [abs32]   — jmp dword ptr [pTrampolinePtrStorage]
                  → jumps back to targetFuncAddr + stolenBytes
```

`RipSlot::Orig` in x64 detours stores the trampoline address. In x86, the trampoline address is written into `pOrigRemote` (the slot allocated by `LoadHook`) so the shellcode can call the original function through the already-rebased `g_pOrigFn` pointer.

```cpp
LiquidHookEx::Detour86 m_hook("GetCoinsDetour");

m_hook.HookPrepatched(
    "55 8B EC 83 EC 08",   // pattern matching the FIRST byte of the function
    "ExampleProcess86.exe",
    h,                     // ShellcodeHook from dll.LoadHook<>()
    10                     // stolenBytes: must cover complete instructions, >= 6
);

m_hook.WriteField<int>(offsetof(MyHookData, coins), 9999);
m_hook.Unhook();
```

**`stolenBytes` rules (x86):** minimum 6. Must not cut mid-instruction. Common function prologues (`push ebp; mov ebp, esp; sub esp, N`) are typically 6–10 bytes of complete instructions.

---

### Setting up an x86 shellcode DLL project

#### Option A — scaffold with `CreateShellCodeProject86`

`CreateShellCodeProject86` is a standalone generator that produces a ready-to-compile Visual Studio project with all required settings:

```
CreateShellCodeProject86.exe MyHooks [OutputDir]
```

This creates:

```
MyHooks/
├── MyHooks.vcxproj      ← Win32 DLL, all compiler/linker settings pre-configured
├── MyHooks.def          ← module definition file — add your exported symbols here
├── Include/MyHooks/
│   ├── Include.h        ← master include
│   └── Macros.h         ← HOOK_BEGIN / HOOK_END / HOOK_EXPORT macros
└── Source/MyHooks/
    └── Source.cpp       ← scaffold with one example hook to rename
```

Add the generated `.vcxproj` to your solution, set the platform to **Win32**, and build **Release | Win32**.

#### Option B — configure an existing project manually

The following settings are mandatory for the shellcode DLL to work correctly. All are for the **Win32** configuration only:

**Compiler (`ClCompile`):**

| Setting | Value | Why |
|---|---|---|
| `RuntimeLibrary` | `MultiThreaded` (`/MT`) | Prevents CRT import table references |
| `BufferSecurityCheck` | `false` | Suppresses `__security_check_cookie` calls |
| `BasicRuntimeChecks` | `Default` | Suppresses `/RTC` helper calls |

**Linker (`Link`):**

| Setting | Value | Why |
|---|---|---|
| `ModuleDefinitionFile` | `$(ProjectName).def` | Enables named exports for `GetSymbolVA` |
| `AdditionalOptions` | `/MERGE:.hookd=.hook /MERGE:.hookb=.hook /OPT:NOICF` | Merges data/BSS into `.hook`; disables identical COMDAT folding |
| `EnableCOMDATFolding` | `false` | Prevents the linker from merging hook functions that share identical bytes |

> **`/OPT:NOICF` is critical.** Without it, MSVC's identical COMDAT folding may merge two end-sentinel functions (e.g. `MyHook_End` and `MyHook2_End`) into a single address, making the shellcode size calculation for one of them wrong.

---

### Writing hooks for the x86 shellcode DLL

#### Macros

```cpp
// Open a hook block — place before globals and hook function
HOOK_BEGIN

// Close a hook block — place after the end sentinel
HOOK_END

// Mark every global and function that LoadHook must locate by name
HOOK_EXPORT  // expands to: extern "C" __declspec(dllexport)
```

`HOOK_BEGIN` does three things:
1. Routes code into `.hook`, initialised data into `.hookd`, BSS into `.hookb` — the linker `/MERGE` flags collapse all three into one contiguous `.hook` section.
2. Disables `optimize` to prevent inlining or reordering across the hook boundary.
3. Disables `runtime_checks` and `check_stack` to suppress `/RTC` helper calls and `__chkstk` stack probes, neither of which exists in the target process.

#### Hook function structure

```cpp
// Hook data struct — defined OUTSIDE HOOK_BEGIN (normal .data segment)
struct MyHookData {
    int someValue;
    float anotherValue;
    // Note: hold data by VALUE — a pointer requires a second remote deref
    // that the injected shellcode cannot perform.
};

// ── Hook block ──────────────────────────────────────────────────────────────
HOOK_BEGIN

// All four symbols must appear in the .def EXPORTS section.
HOOK_EXPORT MyHookData g_myHookData    = {};   // hook data — rebased by LoadHook
HOOK_EXPORT void*      g_pMyHookOrigFn = nullptr; // orig fn — written by HookPrepatched

// Hook function.
// Use __fastcall as a drop-in for __thiscall:
//   ECX = thisPtr (first arg), EDX = ignored second arg, stack args follow.
// Declare ALL original stack args so MSVC emits the correct ret N.
HOOK_EXPORT
int __fastcall MyHook(void* thisPtr, int /*edx*/, int arg1)
{
    // Call original via the rebased slot.
    typedef int(__thiscall* OrigFn)(void*, int);
    const auto original = reinterpret_cast<OrigFn>(g_pMyHookOrigFn);
    return original(thisPtr, g_myHookData.someValue);
}

// End sentinel — must be the VERY NEXT symbol after MyHook.
// Nothing at all between the hook function and this line.
HOOK_EXPORT void MyHook_End() {}

HOOK_END
// ── End of hook block ───────────────────────────────────────────────────────
```

#### `.def` file

Every symbol accessed by `LoadHook` must be exported by name:

```
LIBRARY MyHooks

EXPORTS
    MyHook
    MyHook_End
    g_myHookData
    g_pMyHookOrigFn
```

Without an entry in the `.def` file, `GetSymbolVA` / `GetSymbolInSection` will fail to find the symbol and `LoadHook` will return `h.valid == false`.

#### Calling convention notes

x86 calling conventions require care:

- **`__thiscall`** (MSVC default for member functions): `ECX` = `this`, stack args pushed right-to-left, **callee** cleans the stack (`ret N`). Use `__fastcall` in the hook DLL as a drop-in — both pass arg0 in `ECX`. Declare all stack args that the original function takes so MSVC emits the correct `ret N` and keeps `ESP` balanced in the caller.
- **`__cdecl`**: `ECX` unused, stack args pushed right-to-left, **caller** cleans stack (`ret 0` in callee). No stack cleanup in the hook.
- **`__stdcall`**: like `__cdecl` in layout but callee cleans (`ret N`).

If you get the return convention wrong, `ESP` will be misaligned in the caller after the hook returns, typically causing a crash at the next stack-sensitive operation.

#### Indirect call sites (vtable dispatch)

When the original call site is a vtable indirect dispatch (e.g. `FF 50 08` = `call dword ptr [eax+8]`), the callee address is not statically resolvable. `HookPrepatched` will log `"orig fn not required"` and leave `pOrigRemote` null. The shellcode must re-derive the original function at runtime:

```cpp
HOOK_EXPORT
void __fastcall MyVtableHook(void* thisPtr, int /*edx*/, int health)
{
    // thisPtr→vtable→slot[N] (here slot 2, offset +8 in a 4-byte-per-entry table)
    uintptr_t vftable = *reinterpret_cast<uintptr_t*>(thisPtr);
    typedef void(__thiscall* SetHealthFn)(void*, int);
    SetHealthFn original = *reinterpret_cast<SetHealthFn*>(vftable + 0x8);
    original(thisPtr, g_myHookData.someValue);
}
```

`g_pMyHookOrigFn` should still be declared and exported (so the `.def` and `LoadHook` call stay consistent) but its value at hook time will be zero.

---

### Complete x86 hook example — `CallSite86`: intercept `SetHealth`

#### Target disassembly (from Cheat Engine / IDA)

```asm
; module+0x177F
68 C8 00 00 00        push 0C8h            ; health arg (200)    (5 bytes)
FF 50 08              call [eax+8]         ; virtual SetHealth   (3 bytes)
68 74 6C 00 00        push offset "..."    ; printf arg          (5 bytes, untouched)
```

The call is `FF 50 08` (3 bytes). The `FF 15` patch is 6 bytes — we must consume 3 more. Taking the preceding `push imm32` (5 bytes) gives us 8 bytes total: `FF 15 [abs32]` + 2 NOPs.

#### 1. Shellcode DLL (Win32 Release)

```cpp
// MyHooks/Source/MyHooks/Source.cpp
#include <Windows.h>
#include <cstdint>
#include <MyHooks/Include.h>

struct SetHealthData {
    int health;    // value to inject
};

HOOK_BEGIN

HOOK_EXPORT SetHealthData g_setHealthData   = {};
HOOK_EXPORT void*         g_pSetHealthOrig  = nullptr;  // unused: indirect call site

HOOK_EXPORT
void __fastcall SetHealth_Hook(void* thisPtr, int /*edx*/, int /*health*/)
{
    // Re-derive original from vtable slot 2 (offset +8)
    uintptr_t vftable = *reinterpret_cast<uintptr_t*>(thisPtr);
    typedef void(__thiscall* SetHealthFn)(void*, int);
    SetHealthFn original = *reinterpret_cast<SetHealthFn*>(vftable + 0x8);
    original(thisPtr, g_setHealthData.health);
}

HOOK_EXPORT void SetHealth_Hook_End() {}

HOOK_END

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
```

```
; MyHooks/MyHooks.def
LIBRARY MyHooks
EXPORTS
    SetHealth_Hook
    SetHealth_Hook_End
    g_setHealthData
    g_pSetHealthOrig
```

#### 2. x64 tool (loads and installs the hook)

```cpp
#include <LiquidHookEx/Include.h>

namespace H = LiquidHookEx;

struct SetHealthData {
    int health;
};

int main()
{
    // Tell LiquidHookEx the target is a 32-bit process
    H::INIT("TargetGame.exe", H::Process::TargetArch::x86);

    // Load the shellcode DLL from disk — never injected
    H::ShellcodeDLL86 dll(R"(.\Bin\Win32\Release\MyHooks.dll)");
    if (!dll.IsValid()) { printf("DLL load failed\n"); return 1; }

    SetHealthData initData{ .health = 9999 };

    // LoadHook:
    //  - extracts .hook section bytes
    //  - allocates remote blocks for g_setHealthData and g_pSetHealthOrig
    //  - rebases both VAs in section bytes to remote addresses
    auto h = dll.LoadHook<SetHealthData>(
        "SetHealth_Hook",
        "SetHealth_Hook_End",
        "g_setHealthData",
        "g_pSetHealthOrig",
        initData
    );
    if (!h.valid) { printf("LoadHook failed\n"); return 1; }

    H::CallSite86 m_hook("SetHealthHook");

    m_hook.HookPrepatched(
        "68 C8 00 00 00 FF 50 08 68 ?? ?? ?? ?? E8",
        "TargetGame.exe",
        h,
        8   // overwriteSize: 5 (push imm32) + 3 (FF 50 08)
    );

    // Update the injected health value live without re-hooking
    m_hook.WriteField<int>(offsetof(SetHealthData, health), 5000);

    printf("Hook active. DELETE to exit.\n");
    while (!GetAsyncKeyState(VK_DELETE)) Sleep(100);

    m_hook.Unhook();
    return 0;
}
```

---

### x86 hook persistence (`HookConfig` — same JSON format)

x86 hooks use the same `hooks.json` persistence layer as x64 hooks. `TryRestorePrepatched` runs at the top of every `HookPrepatched` call and reconnects to a live hook if the PID matches and the patch is still in place:

- Verifies `shellcodeRemote` is still committed (`VirtualQueryEx`).
- Verifies the call site / vtable slot / function prologue still carries the expected patch bytes (`FF 15` / vtable addr / `FF 25`).
- Restores `origBytes` from JSON for exact `Unhook()` restoration.

If any check fails the stale entry is removed and a full `HookPrepatched` proceeds. `pFuncPtrStorage` and `pTrampolinePtrStorage` are not persisted for `Detour86` — `Unhook()` guards against their being null, but they will be leaked in the target on a restored session (see known limitations).

---

## Updated project structure

```
LiquidHookEx/
├── LiquidHookEx/
│   └── Include/LiquidHookEx/
│       ├── VTable.h          ← x64 vtable slot hook
│       ├── VTable86.h        ← x86 vtable slot hook (prepatched)
│       ├── CallSite.h        ← x64 call site hook
│       ├── CallSite86.h      ← x86 call site hook (prepatched)
│       ├── Detour.h          ← x64 function prologue detour
│       ├── Detour86.h        ← x86 function prologue detour (prepatched)
│       ├── ShellCodeDll86.h  ← x86 shellcode DLL reader / rebaser
│       ├── Config.h          ← HookConfig JSON persistence (shared)
│       ├── Process.h         ← remote process abstraction + TargetArch
│       ├── Pattern.h         ← byte pattern scanner
│       ├── Globals.h         ← global Process* + INIT()
│       ├── Macros.h          ← LH_START / LH_END (x64 shellcode macros)
│       └── SysCallManager.h  ← direct syscall layer (x64 path only)
│
├── ExampleUsage/             ← x64 hook example (GetHealth / SetHealth)
├── ExampleUsage86/           ← x86 hook example (SetHealth CallSite86)
├── ExampleProcess/           ← 64-bit target process
├── ExampleProcess86/         ← 32-bit target process
├── ExampleShellcode86/       ← x86 shellcode DLL (HOOK_BEGIN/HOOK_END)
└── CreateShellCodeProject86/ ← project scaffolding tool
```

### x86 class comparison

| Class | Mechanism | Target | Shellcode path |
|---|---|---|---|
| `VTable` | vtable slot overwrite | x64 | inline RIP-slot patching |
| `VTable86` | vtable slot overwrite | x86 | `ShellcodeDLL86` prepatched |
| `CallSite` | `FF 15 [rip+X]` call site | x64 | inline RIP-slot patching |
| `CallSite86` | `FF 15 [abs32]` call site | x86 | `ShellcodeDLL86` prepatched |
| `Detour` | `FF 25` prologue + trampoline | x64 | inline RIP-slot patching |
| `Detour86` | `FF 25 [abs32]` prologue + trampoline | x86 | `ShellcodeDLL86` prepatched |