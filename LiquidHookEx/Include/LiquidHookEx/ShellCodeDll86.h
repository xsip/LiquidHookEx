#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <LiquidHookEx/Process.h>
#include <LiquidHookEx/Globals.h>

// ============================================================================
//  ShellcodeDLL86
//
//  Reads an x86 DLL file on disk (never LoadLibrary'd) and:
//    - Extracts raw bytes of a named PE section
//    - Resolves export symbol buffer pointers (for fnStart/fnEnd)
//    - Resolves export symbol VAs (imageBase+RVA, what the x86 compiler
//      burned into MOV reg,[abs32] imm32 operands)
//    - Rebases those VAs in the section bytes to point at remote allocs
//
//  Workflow:
//    ShellcodeDLL86 dll("Shellcode.dll");
//    auto sc     = dll.GetSection(".coins");
//    void* start = dll.GetSymbolInSection("GetCoins_Hook",     sc);
//    void* end   = dll.GetSymbolInSection("GetCoins_Hook_End", sc);
//
//    // For each slot global: rebase the old DLL VA → new remote slot addr
//    uint32_t oldData = dll.GetSymbolVA("g_pHookData");
//    uint32_t oldOrig = dll.GetSymbolVA("g_pOriginalFn");
//    // ... allocate remote slots, then:
//    dll.RebaseBytes(sc, oldData, remoteDataSlot);
//    dll.RebaseBytes(sc, oldOrig, remoteOrigSlot);
//
//    // Pass sc.bytes directly — slots are already patched
//    m_Hook.Hook(..., start, end, {}, 6, sectionEnd);
// ============================================================================

namespace LiquidHookEx {

    struct ShellcodeSection {
        std::vector<uint8_t> bytes;
        void* base = nullptr; // == bytes.data(), convenience pointer
        uint32_t sectionRVA = 0;      // VA offset of section start in the DLL
        uint32_t imageBase = 0;      // DLL preferred load address
    };

    // ── ShellcodeHook ─────────────────────────────────────────────────────────────
    // Returned by ShellcodeDLL86::LoadHook(). Contains everything CallSite86::
    // HookPrepatched() needs, plus the pre-allocated remote orig-fn slot.
    //
    // Usage:
    //   auto h = dll.LoadHook<MyData>(".coins", "MyFn_Hook", "MyFn_Hook_End",
    //                                 "g_myData", "g_pOriginalFn",
    //                                 initData);          // proc defaults to LiquidHookEx::proc
    //   // or pass an explicit Process* as the last argument:
    //   auto h = dll.LoadHook<MyData>(".coins", "MyFn_Hook", "MyFn_Hook_End",
    //                                 "g_myData", "g_pOriginalFn",
    //                                 initData, myProc);
    //   m_Hook.HookPrepatched(pattern, dll, h, overwriteSize);
    struct ShellcodeHook {
        ShellcodeSection sc;
        void* fnStart = nullptr;
        void* fnEnd = nullptr;
        void* sectionEnd = nullptr;
        void* pOrigRemote = nullptr; // pre-allocated, HookPrepatched writes origFn here
        void* pDataRemote = nullptr; // pre-allocated, stored in m_pDataRemote for WriteField
        bool     valid = false;
        bool     origRequired = true;
    };

    class ShellcodeDLL86 {
    public:
        explicit ShellcodeDLL86(const std::string& path) { Load(path); }

        bool IsValid() const { return !m_image.empty(); }

        // ── GetSection ───────────────────────────────────────────────────────────
        ShellcodeSection GetSection(const std::string& sectionName) const
        {
            if (!IsValid()) return {};
            auto* nth = NtHeaders();
            if (!nth) return {};

            auto* secs = IMAGE_FIRST_SECTION(nth);
            for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
                char name[9]{};
                memcpy(name, secs[i].Name, 8);
                if (sectionName != name) continue;

                uint32_t off = secs[i].PointerToRawData;
                uint32_t size = secs[i].SizeOfRawData;
                if (off + size > m_image.size()) {
                    printf("[ShellcodeDLL86] %s: raw data out of bounds\n", sectionName.c_str());
                    return {};
                }

                ShellcodeSection sc;
                sc.bytes.assign(m_image.data() + off, m_image.data() + off + size);
                sc.base = sc.bytes.data();
                sc.sectionRVA = secs[i].VirtualAddress;
                sc.imageBase = nth->OptionalHeader.ImageBase;
                printf("[ShellcodeDLL86] section %s: %zu bytes at file offset 0x%X  sectionRVA=0x%X  imageBase=0x%X\n",
                    sectionName.c_str(), sc.bytes.size(), off, sc.sectionRVA, sc.imageBase);
                return sc;
            }

            printf("[ShellcodeDLL86] section %s: not found\n", sectionName.c_str());
            return {};
        }

        // ── GetSymbolInSection ───────────────────────────────────────────────────
        // Returns a pointer into the local section buffer.
        // Use for fnStart / fnEnd passed to Hook().
        void* GetSymbolInSection(
            const std::string& exportName,
            const ShellcodeSection& section) const
        {
            if (!IsValid() || section.bytes.empty()) return nullptr;
            uint32_t rva = ResolveRVA(exportName);
            if (rva == 0) return nullptr;

            if (rva < section.sectionRVA) {
                printf("[ShellcodeDLL86] %s: RVA 0x%X before section RVA 0x%X\n",
                    exportName.c_str(), rva, section.sectionRVA);
                return nullptr;
            }
            uint32_t offset = rva - section.sectionRVA;
            if (offset >= (uint32_t)section.bytes.size()) {
                printf("[ShellcodeDLL86] %s: offset 0x%X outside section\n",
                    exportName.c_str(), offset);
                return nullptr;
            }
            void* ptr = static_cast<uint8_t*>(section.base) + offset;
            printf("[ShellcodeDLL86] symbol %s: buffer+0x%X @ %p\n",
                exportName.c_str(), offset, ptr);
            return ptr;
        }

        // ── GetSymbolVA ──────────────────────────────────────────────────────────
        // Returns imageBase + RVA — the value the x86 compiler burned into the
        // shellcode bytes as the imm32 operand of MOV reg, [abs32].
        uint32_t GetSymbolVA(const std::string& exportName) const
        {
            if (!IsValid()) return 0;
            uint32_t rva = ResolveRVA(exportName);
            if (rva == 0) return 0;
            uint32_t va = NtHeaders()->OptionalHeader.ImageBase + rva;
            printf("[ShellcodeDLL86] symbol %s: VA 0x%08X (imageBase=0x%08X + RVA=0x%X)\n",
                exportName.c_str(), va, NtHeaders()->OptionalHeader.ImageBase, rva);
            return va;
        }

        // ── RebaseBytes ──────────────────────────────────────────────────────────
        // Replaces all occurrences of oldVA (4-byte LE) in the section bytes with
        // newVA.  Call once per global slot before Hook() so the shellcode already
        // contains the correct remote addresses — no PatchAbsSlots needed.
        int RebaseBytes(ShellcodeSection& section, uint32_t oldVA, uint32_t newVA) const
        {
            int count = 0;
            auto& b = section.bytes;
            for (size_t i = 0; i + 4 <= b.size(); ++i) {
                uint32_t v;
                memcpy(&v, &b[i], 4);
                if (v == oldVA) {
                    memcpy(&b[i], &newVA, 4);
                    printf("[ShellcodeDLL86] rebase +0x%zX: 0x%08X -> 0x%08X\n",
                        i, oldVA, newVA);
                    ++count;
                    i += 3; // skip past replaced bytes (loop adds 1 more)
                }
            }
            if (count == 0)
                printf("[ShellcodeDLL86] rebase: 0x%08X not found in section bytes\n", oldVA);
            return count;
        }


        // ── LoadHook ─────────────────────────────────────────────────────────────
        // Combines GetSection + GetSymbolInSection + GetSymbolVA + Alloc +
        // Write<HOOK_DATA> + RebaseBytes into a single call.
        //
        // hookDataSymbol:   name of the global that holds the hook data struct
        // origFnSymbol:     name of the global that holds the original fn pointer
        // initData:         initial value written into the remote hook data alloc
        //
        // On success, returns a ShellcodeHook ready to pass to HookPrepatched().
        // On failure, ShellcodeHook::valid == false and error is printed.
        template <typename HOOK_DATA>
        ShellcodeHook LoadHook(
            const std::string& fnStartSymbol,
            const std::string& fnEndSymbol,
            const std::string& hookDataSymbol,
            const std::string& origFnSymbol,
            HOOK_DATA              initData,
            Process* proc = nullptr)
        {
            ShellcodeHook h;
            std::string sectionName = ".hook";
            h.sc = GetSection(sectionName);
            if (h.sc.bytes.empty()) {
                printf("[ShellcodeDLL86] LoadHook: section %s not found\n", sectionName.c_str());
                return h;
            }

            h.fnStart = GetSymbolInSection(fnStartSymbol, h.sc);
            h.fnEnd = GetSymbolInSection(fnEndSymbol, h.sc);
            if (!h.fnStart || !h.fnEnd) {
                printf("[ShellcodeDLL86] LoadHook: missing fn symbols\n");
                return h;
            }

            h.sectionEnd = static_cast<uint8_t*>(h.sc.base) + h.sc.bytes.size();

            // ── hook data ────────────────────────────────────────────────────────
            uint32_t oldDataVA = GetSymbolVA(hookDataSymbol);
            if (!oldDataVA) {
                printf("[ShellcodeDLL86] LoadHook: missing data VA\n");
                return h;
            }

            void* pDataRemote = (proc ? proc : LiquidHookEx::proc)->Alloc(sizeof(HOOK_DATA));
            if (!pDataRemote) {
                printf("[ShellcodeDLL86] LoadHook: alloc hook data failed\n");
                return h;
            }
            (proc ? proc : LiquidHookEx::proc)->Write<HOOK_DATA>(reinterpret_cast<uintptr_t>(pDataRemote), initData);
            h.pDataRemote = pDataRemote;
            RebaseBytes(h.sc, oldDataVA,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pDataRemote)));

            // ── original fn slot ─────────────────────────────────────────────────
            uint32_t oldOrigVA = GetSymbolVA(origFnSymbol);
            if (!oldOrigVA) {
                printf("[ShellcodeDLL86] LoadHook: missing origFn VA\n");
                return h;
            }

            h.pOrigRemote = (proc ? proc : LiquidHookEx::proc)->Alloc(sizeof(uint32_t));
            if (!h.pOrigRemote) {
                printf("[ShellcodeDLL86] LoadHook: alloc orig slot failed\n");
                return h;
            }
            if (RebaseBytes(h.sc, oldOrigVA,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(h.pOrigRemote))) == 0)
            {
                // Symbol exists in exports but its VA doesn't appear in the section
                // bytes — the shellcode never references it (indirect call site, orig
                // fn is re-derived at runtime via vtable).  Free the unused alloc and
                // mark origRequired=false so HookPrepatched skips the orig-fn write.
                printf("[ShellcodeDLL86] LoadHook: orig slot VA not found in section bytes — indirect call site, origRequired=false\n");
                VirtualFreeEx((proc ? proc : LiquidHookEx::proc)->m_hProc,
                    h.pOrigRemote, 0, MEM_RELEASE);
                h.pOrigRemote = nullptr;
                h.origRequired = false;
            }

            printf("[+] ShellcodeDLL86::LoadHook: pDataRemote=0x%p  pOrigRemote=0x%p\n",
                pDataRemote, h.pOrigRemote);

            h.valid = true;
            return h;
        }

    private:
        std::vector<uint8_t> m_image;

        void Load(const std::string& path)
        {
            FILE* f = nullptr;
            fopen_s(&f, path.c_str(), "rb");
            if (!f) { printf("[ShellcodeDLL86] cannot open %s\n", path.c_str()); return; }

            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz <= 0) { fclose(f); return; }

            m_image.resize((size_t)sz);
            fread(m_image.data(), 1, m_image.size(), f);
            fclose(f);

            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_image.data());
            if (m_image.size() < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
                printf("[ShellcodeDLL86] bad DOS magic\n"); m_image.clear(); return;
            }
            auto* nth = NtHeaders();
            if (!nth || nth->Signature != IMAGE_NT_SIGNATURE) {
                printf("[ShellcodeDLL86] bad NT signature\n"); m_image.clear(); return;
            }
            if (nth->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
                printf("[ShellcodeDLL86] not x86 (machine=0x%X)\n",
                    nth->FileHeader.Machine);
                m_image.clear(); return;
            }

            // Dump sections
            auto* secs = IMAGE_FIRST_SECTION(nth);
            printf("[ShellcodeDLL86] loaded %s (%zu bytes, %u sections)\n",
                path.c_str(), m_image.size(), nth->FileHeader.NumberOfSections);
            for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
                char name[9]{};
                memcpy(name, secs[i].Name, 8);
                printf("[ShellcodeDLL86]   [%u] %-8s  RVA=0x%X  size=0x%X\n",
                    i, name, secs[i].VirtualAddress, secs[i].SizeOfRawData);
            }
        }

        IMAGE_NT_HEADERS32* NtHeaders() const
        {
            if (m_image.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_image.data());
            size_t off = dos->e_lfanew;
            if (off + sizeof(IMAGE_NT_HEADERS32) > m_image.size()) return nullptr;
            return reinterpret_cast<IMAGE_NT_HEADERS32*>(
                const_cast<uint8_t*>(m_image.data()) + off);
        }

        uint32_t ResolveRVA(const std::string& name) const
        {
            uint32_t rva = GetExportRVA(name);
            if (rva == 0) rva = GetExportRVA("_" + name);
            if (rva == 0)
                printf("[ShellcodeDLL86] symbol %s: not found in exports\n", name.c_str());
            return rva;
        }

        uint32_t GetExportRVA(const std::string& name) const
        {
            auto* nth = NtHeaders();
            if (!nth) return 0;
            auto& dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress) return 0;

            uint32_t off = RVAToFileOffset(dir.VirtualAddress);
            if (!off) return 0;

            IMAGE_EXPORT_DIRECTORY* exp =
                reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                    const_cast<uint8_t*>(m_image.data()) + off);

            uint32_t* names = reinterpret_cast<uint32_t*>(
                const_cast<uint8_t*>(m_image.data()) + RVAToFileOffset(exp->AddressOfNames));
            uint16_t* ords = reinterpret_cast<uint16_t*>(
                const_cast<uint8_t*>(m_image.data()) + RVAToFileOffset(exp->AddressOfNameOrdinals));
            uint32_t* funcs = reinterpret_cast<uint32_t*>(
                const_cast<uint8_t*>(m_image.data()) + RVAToFileOffset(exp->AddressOfFunctions));

            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                const char* ename = reinterpret_cast<const char*>(
                    m_image.data() + RVAToFileOffset(names[i]));
                if (name == ename)
                    return funcs[ords[i]];
            }
            return 0;
        }

        uint32_t RVAToFileOffset(uint32_t rva) const
        {
            auto* nth = NtHeaders();
            auto* secs = IMAGE_FIRST_SECTION(nth);
            for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
                uint32_t secRVA = secs[i].VirtualAddress;
                uint32_t secSize = secs[i].Misc.VirtualSize;
                if (rva >= secRVA && rva < secRVA + secSize)
                    return secs[i].PointerToRawData + (rva - secRVA);
            }
            return 0;
        }
    };

} // namespace LiquidHookEx