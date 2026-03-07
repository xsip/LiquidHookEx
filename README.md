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

Shellcode must be isolated in its own code segment and compiled with all runtime helpers disabled, so the byte range `[fnStart, fnEnd)` contains only your logic:

```cpp
static void* g_pOriginalFunc = nullptr;
static MyHookData* g_pHookData = nullptr;

#pragma code_seg(".myHook")
#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma check_stack(off)

RetType __fastcall MyClass::hkMyFunc(Args...) {
    volatile uintptr_t _dummy = reinterpret_cast<uintptr_t>(firstArg); // force stack frame

    MyHookData* data = g_pHookData;           // → RipSlot::Data
    typedef RetType(__fastcall* Fn)(Args...);
    Fn original = (Fn)g_pOriginalFunc;         // → RipSlot::Orig

    // ... hook logic ...

    return original(...);
}

void MyClass::hkMyFuncEnd() {}

#pragma check_stack()
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma code_seg()
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

#pragma code_seg(".getHealthHook")
#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma check_stack(off)

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

#pragma check_stack()
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma code_seg()
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

#pragma code_seg(".setHealthHook")
#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma check_stack(off)

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

#pragma check_stack()
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma code_seg()
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

