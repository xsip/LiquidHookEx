
#include <LiquidHookEx/PrologueScanner.h>
#include <LiquidHookEx/Globals.h>
#include <LiquidHookEx/Process.h>






namespace LiquidHookEx {

    namespace {
        struct InstructionInfo {
            bool ok = false;
            size_t length = 0;
            // True for the one ModRM form that's actually RIP-relative on x64 (mod=00, no SIB,
            // rm=101 - "[RIP + disp32]"). NOT set for SIB.base=101/mod=00 with no index - that's
            // a plain absolute disp32, no RIP involved, despite the superficially similar encoding.
            bool ripRelative = false;
            // Byte offset of the 4-byte disp32 field, relative to the START of this instruction
            // (i.e. relative to `code`) - valid only when ripRelative. Where a caller relocating
            // these bytes elsewhere (a hook trampoline) needs to rewrite the displacement so the
            // instruction still reaches the same absolute address from its new location.
            size_t ripDispOffset = 0;
        };
        // Everything this opcode needs besides its own byte, resolved against the prefixes/REX
        // already seen by the time the opcode is looked up. `immSize` may still need adjusting
        // after ModRM is read (F6/F7 - their reg field decides it), which DecodeOneX64 does inline.
        struct OpcodeInfo {
            bool recognized = false;
            bool hasModRM = false;
            size_t immSize = 0;
            bool isGroup3 = false; // F6/F7: immSize depends on ModRM.reg, patched in after ModRM
        };

        OpcodeInfo LookupOneByteOpcode(uint8_t op, bool has66, bool hasRexW)
        {
            OpcodeInfo info;
            info.recognized = true;

            if ((op >= 0x50 && op <= 0x57) || (op >= 0x58 && op <= 0x5F))
            {
                // push/pop r64
                return info;
            }
            switch (op)
            {
            case 0x68: info.immSize = 4; return info; // push imm32
            case 0x6A: info.immSize = 1; return info; // push imm8
            case 0x63: info.hasModRM = true; return info; // movsxd r64, r/m32 (no immediate)
            case 0x69: info.hasModRM = true; info.immSize = has66 ? 2 : 4; return info; // imul r, r/m, imm32/16
            case 0x6B: info.hasModRM = true; info.immSize = 1; return info; // imul r, r/m, imm8
            default: break;
            }
            if (op >= 0x70 && op <= 0x7F) { info.immSize = 1; return info; } // Jcc rel8 (short conditional jump)
            // ModRM arithmetic families: add/or/adc/sbb/and/sub/xor/cmp (/r forms)
            switch (op)
            {
            case 0x00: case 0x01: case 0x02: case 0x03: // add
            case 0x08: case 0x09: case 0x0A: case 0x0B: // or
            case 0x10: case 0x11: case 0x12: case 0x13: // adc
            case 0x18: case 0x19: case 0x1A: case 0x1B: // sbb
            case 0x20: case 0x21: case 0x22: case 0x23: // and
            case 0x28: case 0x29: case 0x2A: case 0x2B: // sub
            case 0x30: case 0x31: case 0x32: case 0x33: // xor
            case 0x38: case 0x39: case 0x3A: case 0x3B: // cmp
                info.hasModRM = true;
                return info;
            default: break;
            }
            switch (op)
            {
            case 0x04: case 0x0C: case 0x14: case 0x1C: // AL, imm8 (same families)
            case 0x24: case 0x2C: case 0x34: case 0x3C:
                info.immSize = 1;
                return info;
            case 0x05: case 0x0D: case 0x15: case 0x1D: // eAX, imm32/16
            case 0x25: case 0x2D: case 0x35: case 0x3D:
                info.immSize = has66 ? 2 : 4;
                return info;
            default: break;
            }
            switch (op)
            {
            case 0x80: info.hasModRM = true; info.immSize = 1; return info; // group1 Eb,Ib
            case 0x81: info.hasModRM = true; info.immSize = has66 ? 2 : 4; return info; // group1 Ev,Iz
            case 0x83: info.hasModRM = true; info.immSize = 1; return info; // group1 Ev,Ib
            case 0x84: case 0x85: info.hasModRM = true; return info; // test r/m,r
            case 0x88: case 0x89: case 0x8A: case 0x8B: info.hasModRM = true; return info; // mov
            case 0x8D: info.hasModRM = true; return info; // lea
            case 0x8F: info.hasModRM = true; return info; // pop r/m (group1A)
            case 0x90: return info; // nop
            case 0x98: return info; // cwde/cdqe
            case 0x99: return info; // cdq/cqo
            case 0xA8: info.immSize = 1; return info; // test AL,imm8
            case 0xA9: info.immSize = has66 ? 2 : 4; return info; // test eAX,imm32/16
            default: break;
            }
            if (op >= 0xB0 && op <= 0xB7) { info.immSize = 1; return info; } // mov r8,imm8
            if (op >= 0xB8 && op <= 0xBF) { info.immSize = hasRexW ? 8 : 4; return info; } // mov r32/r64,imm32/imm64
            switch (op)
            {
            case 0xC0: case 0xC1: info.hasModRM = true; info.immSize = 1; return info; // shift group2 ,Ib
            case 0xC2: info.immSize = 2; return info; // ret imm16
            case 0xC3: return info; // ret
            case 0xC6: info.hasModRM = true; info.immSize = 1; return info; // group11 mov Eb,Ib
            case 0xC7: info.hasModRM = true; info.immSize = has66 ? 2 : 4; return info; // group11 mov Ev,Iz
            case 0xCC: return info; // int3
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: info.hasModRM = true; return info; // shift group2 ,1/CL
            case 0xE8: info.immSize = 4; return info; // call rel32
            case 0xE9: info.immSize = 4; return info; // jmp rel32
            case 0xEB: info.immSize = 1; return info; // jmp rel8
            case 0xF6: info.hasModRM = true; info.isGroup3 = true; return info; // group3 Eb (reg-dependent)
            case 0xF7: info.hasModRM = true; info.isGroup3 = true; return info; // group3 Ev (reg-dependent)
            case 0xFE: info.hasModRM = true; return info; // group4 Eb (inc/dec)
            case 0xFF: info.hasModRM = true; return info; // group5 Ev (every reg variant same length)
            default: break;
            }

            info.recognized = false;
            return info;
        }

        OpcodeInfo LookupTwoByteOpcode(uint8_t op2)
        {
            OpcodeInfo info;
            info.recognized = true;

            if (op2 == 0x1F) { info.hasModRM = true; return info; } // multi-byte nop Ev
            if (op2 >= 0x80 && op2 <= 0x8F) { info.immSize = 4; return info; } // Jcc rel32
            if (op2 >= 0x40 && op2 <= 0x4F) { info.hasModRM = true; return info; } // CMOVcc Gv,Ev
            if (op2 == 0xA2) { return info; } // cpuid
            if (op2 == 0xAF) { info.hasModRM = true; return info; } // imul r,r/m
            if (op2 == 0xB6 || op2 == 0xB7) { info.hasModRM = true; return info; } // movzx
            if (op2 == 0xBE || op2 == 0xBF) { info.hasModRM = true; return info; } // movsx
            if (op2 == 0x10 || op2 == 0x11) { info.hasModRM = true; return info; } // movups/movss/movsd
            if (op2 == 0x28 || op2 == 0x29) { info.hasModRM = true; return info; } // movaps
            if (op2 == 0x6E || op2 == 0x7E) { info.hasModRM = true; return info; } // movd/movq

            info.recognized = false;
            return info;
        }

    }


    // Decodes exactly ONE x86-64 instruction starting at `code`. `ok` is false if it isn't one
    // of the supported forms (see LengthDisasm.cpp's opcode tables), or if decoding it would
    // need to read past `code + maxLen` - in either case `length` is meaningless, never treat
    // it as a fallback value. Never reads past `code + maxLen`. Never throws.
    //
    // Deliberately narrow in scope: this only ever needs to decode the first ~20-30 bytes of a
    // function compiled by a real x64 toolchain (used against Unity/IL2CPP-compiled game
    // binaries - MSVC-style codegen, no hand-written assembly, no obfuscation/packing to defend
    // against) - not a general-purpose disassembler. When something outside that set shows up,
    // the right behavior is to say so (ok=false), never guess - a caller patches live process
    // memory with the answer (see Core::ExternalSdkGenerator's use for LiquidHookEx::Detour's
    // stolenBytes - a generated hook stub must steal only complete instructions from the
    // target's prologue, or the trampoline it rebuilds executes corrupt opcodes).

    InstructionInfo DecodeOneX64(const uint8_t* code, size_t maxLen)
    {
        InstructionInfo result;
        size_t pos = 0;
        auto HasBytes = [&](size_t n) { return pos + n <= maxLen; };

        // 1. Legacy prefixes.
        bool has66 = false;
        for (;;)
        {
            if (!HasBytes(1)) return result;
            uint8_t b = code[pos];
            if (b == 0x66) { has66 = true; pos += 1; continue; }
            if (b == 0xF2 || b == 0xF3) { pos += 1; continue; }
            if (b == 0xF0 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                b == 0x64 || b == 0x65 || b == 0x67)
            {
                return result; // lock / segment override / address-size override: unsupported
            }
            break;
        }

        // 2. REX prefix.
        bool hasRexW = false;
        if (!HasBytes(1)) return result;
        if (code[pos] >= 0x40 && code[pos] <= 0x4F)
        {
            hasRexW = (code[pos] & 0x08) != 0;
            pos += 1;
        }

        // 3. Opcode.
        if (!HasBytes(1)) return result;
        uint8_t op = code[pos];
        pos += 1;

        OpcodeInfo opInfo;
        if (op == 0x0F)
        {
            if (!HasBytes(1)) return result;
            uint8_t op2 = code[pos];
            if (op2 == 0x38 || op2 == 0x3A) return result; // three-byte opcode: unsupported
            pos += 1;
            opInfo = LookupTwoByteOpcode(op2);
        }
        else
        {
            opInfo = LookupOneByteOpcode(op, has66, hasRexW);
        }
        if (!opInfo.recognized) return result;

        // 4. ModRM.
        size_t immSize = opInfo.immSize;
        if (opInfo.hasModRM)
        {
            if (!HasBytes(1)) return result;
            uint8_t modrm = code[pos];
            pos += 1;
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;

            if (opInfo.isGroup3)
            {
                bool isTestForm = (reg == 0 || reg == 1);
                if (isTestForm)
                    immSize = (op == 0xF7) ? (has66 ? 2 : 4) : 1;
                else
                    immSize = 0;
            }

            // 5. SIB.
            bool hasSib = (mod != 0x03 && rm == 0x04);
            uint8_t sibBase = 0;
            if (hasSib)
            {
                if (!HasBytes(1)) return result;
                sibBase = code[pos] & 0x07;
                pos += 1;
            }

            // 6. Displacement.
            size_t dispSize = 0;
            if (mod == 0x01) dispSize = 1;
            else if (mod == 0x02) dispSize = 4;
            else if (mod == 0x00)
            {
                if (!hasSib && rm == 0x05) dispSize = 4; // RIP-relative
                else if (hasSib && sibBase == 0x05) dispSize = 4; // [index*scale + disp32]
            }
            const bool isRipRelative = (mod == 0x00 && !hasSib && rm == 0x05);
            if (dispSize > 0)
            {
                if (!HasBytes(dispSize)) return result;
                if (isRipRelative)
                {
                    result.ripRelative = true;
                    result.ripDispOffset = pos;
                }
                pos += dispSize;
            }
        }

        // 7. Immediate.
        if (immSize > 0)
        {
            if (!HasBytes(immSize)) return result;
            pos += immSize;
        }

        // 8. Defensive invariant: never claim a longer-than-architecturally-possible instruction.
        if (pos > 15) return result;

        result.ok = true;
        result.length = pos;
        return result;
    }

    // Convenience wrapper for the actual use case: walks forward decoding whole instructions
    // until the running total is >= minBytes, returning that boundary-aligned total (the first
    // instruction boundary at or past minBytes) - or 0 if it couldn't get there (hit an
    // unsupported form, or ran out of maxLen first). 0 is never a valid answer here either -
    // same "don't guess" contract as DecodeOneX64.ok.

    size_t LengthToAtLeast(const uint8_t* code, size_t maxLen, size_t minBytes)
    {
        return ScanPrologue(code, maxLen, minBytes).totalLength;
    }

    PrologueScanResult ScanPrologue(const uint8_t* code, size_t maxLen, size_t minBytes)
    {
        PrologueScanResult scan;
        size_t total = 0;
        while (total < minBytes)
        {
            if (total >= maxLen)
                return {}; // ran out of buffer before reaching minBytes

            InstructionInfo info = DecodeOneX64(code + total, maxLen - total);
            if (!info.ok || info.length == 0)
                return {}; // unsupported form - never guess

            if (info.ripRelative)
                scan.ripDispOffsets.push_back(total + info.ripDispOffset);
            total += info.length;
        }
        scan.totalLength = total;
        return scan;
    }

    namespace {
        // Reads up to 32 bytes at `addr` from the live process and scans them for a
        // complete-instruction boundary at or past minBytes. Same "never guess" contract
        // as ScanPrologue: an empty result means the read failed or no safe boundary was
        // found within the 32 bytes read.
        PrologueScanResult ScanAt(uintptr_t addr, size_t minBytes)
        {
            if (!addr)
                return {};

            uint8_t buf[32]{};
            if (!LiquidHookEx::proc->Read(addr, buf, sizeof(buf)))
                return {};

            return ScanPrologue(buf, sizeof(buf), minBytes);
        }
    }

    // See Detour::Hook's pattern-form overload: resolves the module, scans it for
    // `callSitePattern`, then reads/scans the bytes at the match.
    PrologueScanResult GetCallSiteOverwriteSize(std::string callSitePattern, std::string dllName)
    {
        auto pMod = LiquidHookEx::proc->GetRemoteModule(dllName, false);
        if (!pMod || !pMod->IsValid())
            return {};

        auto pCallSite = pMod->ScanMemory(callSitePattern.c_str());
        if (!pCallSite)
            return {};

        return ScanAt(reinterpret_cast<uintptr_t>(pCallSite), 6);
    }

    // See Detour::Hook's address-form overload: dllName is only used to validate the
    // module is present, same as Detour does for its module+offset logging.
    PrologueScanResult GetCallSiteOverwriteSize(uintptr_t pFn, std::string dllName)
    {
        auto pMod = LiquidHookEx::proc->GetRemoteModule(dllName, false);
        if (!pMod || !pMod->IsValid())
            return {};

        if (!pFn)
            return {};

        return ScanAt(pFn, 6);
    }

    PrologueScanResult GetStolenBytesForDetour(std::string pattern, std::string dllName)
    {
        auto pMod = LiquidHookEx::proc->GetRemoteModule(dllName, false);
        if (!pMod || !pMod->IsValid())
            return {};

        auto pFn = pMod->ScanMemory(pattern.c_str());
        if (!pFn)
            return {};

        return ScanAt(reinterpret_cast<uintptr_t>(pFn), 14);
    }

    PrologueScanResult GetStolenBytesForDetour(uintptr_t pFn, std::string dllName)
    {
        auto pMod = LiquidHookEx::proc->GetRemoteModule(dllName, false);
        if (!pMod || !pMod->IsValid())
            return {};

        if (!pFn)
            return {};

        return ScanAt(pFn, 14);
    }

}
