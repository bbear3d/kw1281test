using System;
using System.Collections.Generic;

namespace BitFab.KW1281Test.EDC15;

/// <summary>One decoded C166 instruction. <see cref="Operands"/> uses Keil assembler syntax
/// (e.g. <c>DPP2, #24H</c>, <c>R1, 0F8C0H</c>, <c>R3.14</c>).</summary>
internal readonly record struct C166Instruction(int Offset, int Length, string Mnemonic, string Operands);

/// <summary>
/// A small C166/C167 instruction decoder, just enough for <see cref="Edc15Checksum"/> to walk an
/// EDC15 image's own checksum-verify driver instruction by instruction. Every opcode decodes to
/// its correct length (so a walk never desynchronises), and operands are rendered in the same
/// text form the Keil assembler uses, which is what the checksum model matches against.
/// </summary>
internal static class C166Decoder
{
    private static readonly string[] ByteRegs =
    [
        "RL0", "RH0", "RL1", "RH1", "RL2", "RH2", "RL3", "RH3",
        "RL4", "RH4", "RL5", "RH5", "RL6", "RH6", "RL7", "RH7",
    ];

    private static readonly string[] Cc =
    [
        "cc_UC", "cc_NET", "cc_Z", "cc_NZ", "cc_V", "cc_NV", "cc_N", "cc_NN",
        "cc_C", "cc_NC", "cc_SGT", "cc_SLE", "cc_SLT", "cc_SGE", "cc_UGT", "cc_ULE",
    ];

    // byte-bit-offset -> SFR name (bit-addressable region)
    private static readonly Dictionary<int, string> BitoffNames = new()
    {
        [0x88] = "PSW", [0xD8] = "S0CON", [0xB7] = "S0RIC", [0xB6] = "S0TIC", [0xE0] = "P2", [0xE1] = "DP2",
    };

    private static readonly Dictionary<(int, int), string> NamedBits = new()
    {
        [(0x88, 11)] = "IEN", [(0x88, 1)] = "C", [(0xD8, 4)] = "S0REN", [(0xB7, 7)] = "S0RIR",
        [(0xB6, 7)] = "S0TIR",
    };

    // 16-bit mem operand -> SFR name
    private static readonly Dictionary<int, string> MemNames = new()
    {
        [0xFEB0] = "S0TBUF", [0xFEB2] = "S0RBUF", [0xFEB4] = "S0BG",
        [0xFE00] = "DPP0", [0xFE02] = "DPP1", [0xFE04] = "DPP2", [0xFE06] = "DPP3", [0xFE10] = "CP",
        [0xFF6C] = "S0TIC", [0xFF6E] = "S0RIC",
        [0xFF10] = "PSW", [0xFFB0] = "S0CON", [0xFFC0] = "P2", [0xFFC2] = "DP2",
    };

    private static readonly Dictionary<int, string> Protected = new()
    {
        [0xA5] = "DISWDT", [0xA7] = "SRVWDT", [0xB5] = "EINIT", [0xB7] = "SRST",
        [0x87] = "IDLE", [0x97] = "PWRDN",
    };

    private enum F
    {
        RR, RRB, REGMEM, REGMEMB, MEMREG, MEMREGB, REGD16, REGD16B, RNM8, RNM8B, BFLD, SHREG, SHIMM,
        BITBIT, CMPI, CMPMEM, MEMPTR_ST, MEMPTR_LD, CMPD16, PUSH, PUSHB, BITJMP, RN_PINC, RN_PINCB,
        TRAP, CALLI, RN_IND, RN_INDB, R1, R1B, PCALL, ST_IND, ST_INDB, CALLR, MOVBZS, DISP_ST,
        SCXT, IND_IND, IND_INDB, CALLA, R0, N0, DISP_LD, EXT, PINC_IND, PINC_INDB, CALLS, MOVI4,
        MOVI4B, DISP_STB, IND_PINC, IND_PINCB, JMPA, RETP, PSHPOP, DISP_LDB, JMPS, RETI0,
    }

    // opcode -> (mnemonic, format)
    private static readonly Dictionary<int, (string Mn, F Fmt)> Spec = new()
    {
        [0x00] = ("ADD", F.RR), [0x01] = ("ADDB", F.RRB), [0x02] = ("ADD", F.REGMEM), [0x03] = ("ADDB", F.REGMEMB),
        [0x04] = ("ADD", F.MEMREG), [0x05] = ("ADDB", F.MEMREGB), [0x06] = ("ADD", F.REGD16), [0x07] = ("ADDB", F.REGD16B),
        [0x08] = ("ADD", F.RNM8), [0x09] = ("ADDB", F.RNM8B), [0x0A] = ("BFLDL", F.BFLD), [0x0C] = ("ROL", F.SHREG),
        [0x10] = ("ADDC", F.RR), [0x11] = ("ADDCB", F.RRB), [0x12] = ("ADDC", F.REGMEM), [0x13] = ("ADDCB", F.REGMEMB),
        [0x14] = ("ADDC", F.MEMREG), [0x15] = ("ADDCB", F.MEMREGB), [0x16] = ("ADDC", F.REGD16), [0x17] = ("ADDCB", F.REGD16B),
        [0x18] = ("ADDC", F.RNM8), [0x19] = ("ADDCB", F.RNM8B), [0x1A] = ("BFLDH", F.BFLD), [0x1C] = ("ROL", F.SHIMM),
        [0x20] = ("SUB", F.RR), [0x21] = ("SUBB", F.RRB), [0x22] = ("SUB", F.REGMEM), [0x23] = ("SUBB", F.REGMEMB),
        [0x24] = ("SUB", F.MEMREG), [0x25] = ("SUBB", F.MEMREGB), [0x26] = ("SUB", F.REGD16), [0x27] = ("SUBB", F.REGD16B),
        [0x28] = ("SUB", F.RNM8), [0x29] = ("SUBB", F.RNM8B), [0x2A] = ("BCMP", F.BITBIT), [0x2C] = ("ROR", F.SHREG),
        [0x30] = ("SUBC", F.RR), [0x31] = ("SUBCB", F.RRB), [0x32] = ("SUBC", F.REGMEM), [0x33] = ("SUBCB", F.REGMEMB),
        [0x34] = ("SUBC", F.MEMREG), [0x35] = ("SUBCB", F.MEMREGB), [0x36] = ("SUBC", F.REGD16), [0x37] = ("SUBCB", F.REGD16B),
        [0x38] = ("SUBC", F.RNM8), [0x39] = ("SUBCB", F.RNM8B), [0x3A] = ("BMOVN", F.BITBIT), [0x3C] = ("ROR", F.SHIMM),
        [0x40] = ("CMP", F.RR), [0x41] = ("CMPB", F.RRB), [0x42] = ("CMP", F.REGMEM), [0x43] = ("CMPB", F.REGMEMB),
        [0x46] = ("CMP", F.REGD16), [0x47] = ("CMPB", F.REGD16B), [0x48] = ("CMP", F.RNM8), [0x49] = ("CMPB", F.RNM8B),
        [0x4A] = ("BMOV", F.BITBIT), [0x4C] = ("SHL", F.SHREG),
        [0x50] = ("XOR", F.RR), [0x51] = ("XORB", F.RRB), [0x52] = ("XOR", F.REGMEM), [0x53] = ("XORB", F.REGMEMB),
        [0x54] = ("XOR", F.MEMREG), [0x55] = ("XORB", F.MEMREGB), [0x56] = ("XOR", F.REGD16), [0x57] = ("XORB", F.REGD16B),
        [0x58] = ("XOR", F.RNM8), [0x59] = ("XORB", F.RNM8B), [0x5A] = ("BOR", F.BITBIT), [0x5C] = ("SHL", F.SHIMM),
        [0x60] = ("AND", F.RR), [0x61] = ("ANDB", F.RRB), [0x62] = ("AND", F.REGMEM), [0x63] = ("ANDB", F.REGMEMB),
        [0x64] = ("AND", F.MEMREG), [0x65] = ("ANDB", F.MEMREGB), [0x66] = ("AND", F.REGD16), [0x67] = ("ANDB", F.REGD16B),
        [0x68] = ("AND", F.RNM8), [0x69] = ("ANDB", F.RNM8B), [0x6A] = ("BAND", F.BITBIT), [0x6C] = ("SHR", F.SHREG),
        [0x70] = ("OR", F.RR), [0x71] = ("ORB", F.RRB), [0x72] = ("OR", F.REGMEM), [0x73] = ("ORB", F.REGMEMB),
        [0x74] = ("OR", F.MEMREG), [0x75] = ("ORB", F.MEMREGB), [0x76] = ("OR", F.REGD16), [0x77] = ("ORB", F.REGD16B),
        [0x78] = ("OR", F.RNM8), [0x79] = ("ORB", F.RNM8B), [0x7A] = ("BXOR", F.BITBIT), [0x7C] = ("SHR", F.SHIMM),
        [0x80] = ("CMPI1", F.CMPI), [0x82] = ("CMPI1", F.CMPMEM), [0x84] = ("MOV", F.MEMPTR_ST), [0x86] = ("CMPI1", F.CMPD16),
        [0x88] = ("MOV", F.PUSH), [0x89] = ("MOVB", F.PUSHB), [0x8A] = ("JB", F.BITJMP),
        [0x90] = ("CMPI2", F.CMPI), [0x92] = ("CMPI2", F.CMPMEM), [0x94] = ("MOV", F.MEMPTR_LD), [0x96] = ("CMPI2", F.CMPD16),
        [0x98] = ("MOV", F.RN_PINC), [0x99] = ("MOVB", F.RN_PINCB), [0x9A] = ("JNB", F.BITJMP), [0x9B] = ("TRAP", F.TRAP),
        [0x9C] = ("JMPI", F.CALLI),
        [0xA0] = ("CMPD1", F.CMPI), [0xA2] = ("CMPD1", F.CMPMEM), [0xA4] = ("MOVB", F.MEMPTR_ST), [0xA6] = ("CMPD1", F.CMPD16),
        [0xA8] = ("MOV", F.RN_IND), [0xA9] = ("MOVB", F.RN_INDB), [0xAA] = ("JBC", F.BITJMP), [0xAB] = ("CALLI", F.CALLI),
        [0xAC] = ("ASHR", F.SHREG),
        [0xB0] = ("CMPD2", F.CMPI), [0xB2] = ("CMPD2", F.CMPMEM), [0xB4] = ("MOVB", F.MEMPTR_LD), [0xB6] = ("CMPD2", F.CMPD16),
        [0x0B] = ("MUL", F.RR), [0x1B] = ("MULU", F.RR), [0x2B] = ("PRIOR", F.RR), [0x4B] = ("DIV", F.R1),
        [0x5B] = ("DIVU", F.R1), [0x6B] = ("DIVL", F.R1), [0x7B] = ("DIVLU", F.R1), [0x81] = ("NEG", F.R1),
        [0x91] = ("CPL", F.R1), [0xA1] = ("NEGB", F.R1B), [0xB1] = ("CPLB", F.R1B), [0xC2] = ("MOVBZ", F.REGMEM),
        [0xD2] = ("MOVBS", F.REGMEM), [0xD6] = ("SCXT", F.REGMEM), [0xE2] = ("PCALL", F.PCALL),
        [0xB8] = ("MOV", F.ST_IND), [0xB9] = ("MOVB", F.ST_INDB), [0xBA] = ("JNBS", F.BITJMP), [0xBB] = ("CALLR", F.CALLR),
        [0xBC] = ("ASHR", F.SHIMM),
        [0xC0] = ("MOVBZ", F.MOVBZS), [0xC4] = ("MOV", F.DISP_ST), [0xC5] = ("MOVBZ", F.REGMEM), [0xC6] = ("SCXT", F.SCXT),
        [0xC8] = ("MOV", F.IND_IND), [0xC9] = ("MOVB", F.IND_INDB), [0xCA] = ("CALLA", F.CALLA), [0xCB] = ("RET", F.R0),
        [0xCC] = ("NOP", F.N0),
        [0xD0] = ("MOVBS", F.MOVBZS), [0xD4] = ("MOV", F.DISP_LD), [0xD5] = ("MOVBS", F.REGMEM), [0xD7] = ("EXTP", F.EXT),
        [0xD8] = ("MOV", F.PINC_IND), [0xD9] = ("MOVB", F.PINC_INDB), [0xDA] = ("CALLS", F.CALLS), [0xDB] = ("RETS", F.R0),
        [0xE0] = ("MOV", F.MOVI4), [0xE1] = ("MOVB", F.MOVI4B), [0xE4] = ("MOVB", F.DISP_STB), [0xE6] = ("MOV", F.REGD16),
        [0xE7] = ("MOVB", F.REGD16B), [0xE8] = ("MOV", F.IND_PINC), [0xE9] = ("MOVB", F.IND_PINCB), [0xEA] = ("JMPA", F.JMPA),
        [0xEB] = ("RETP", F.RETP), [0xEC] = ("PUSH", F.PSHPOP),
        [0xF0] = ("MOV", F.RR), [0xF1] = ("MOVB", F.RRB), [0xF2] = ("MOV", F.REGMEM), [0xF3] = ("MOVB", F.REGMEMB),
        [0xF4] = ("MOVB", F.DISP_LDB), [0xF6] = ("MOV", F.MEMREG), [0xF7] = ("MOVB", F.MEMREGB), [0xFA] = ("JMPS", F.JMPS),
        [0xFB] = ("RETI", F.RETI0), [0xFC] = ("POP", F.PSHPOP),
    };

    /// <summary>Decodes consecutive instructions from <paramref name="start"/> while the
    /// instruction start is below <paramref name="end"/> (file offsets into
    /// <paramref name="data"/>; <paramref name="baseAddress"/> is the CPU address of offset 0,
    /// used for branch targets).</summary>
    public static List<C166Instruction> DecodeAll(byte[] data, int baseAddress, int start, int end)
    {
        var output = new List<C166Instruction>();
        var pos = start;
        while (pos < end)
        {
            var ins = DecodeOne(data, pos, baseAddress);
            output.Add(ins);
            pos += ins.Length;
        }
        return output;
    }

    public static C166Instruction DecodeOne(byte[] data, int pos, int baseAddress)
    {
        int B(int i) => pos + i < data.Length ? data[pos + i] : 0;

        int op = data[pos];
        int addr = baseAddress + pos;
        int hi = op >> 4, lo = op & 0xF;

        C166Instruction Mk(string mn, int length, string ops = "") =>
            new(pos, Math.Min(length, data.Length - pos), mn, ops);

        // protected 4-byte instructions
        if (Protected.TryGetValue(op, out var prot) && pos + 3 < data.Length
            && data[pos + 1] is 0x58 or 0x48 or 0x5A or 0x4A or 0x78 or 0x68
            && data[pos + 2] == op && data[pos + 3] == op)
        {
            return Mk(prot, 4);
        }

        // uniform low-nibble families
        if (lo == 0xD)
        {
            var tgt = (addr + 2 + 2 * S8(B(1))) & 0xFFFF;
            return Mk("JMPR", 2, $"{Cc[hi]}, {FmtHex(tgt, 4)}");
        }
        if (lo == 0xE)
        {
            return Mk("BCLR", 2, BitName(B(1), hi));
        }
        if (lo == 0xF)
        {
            return Mk("BSET", 2, BitName(B(1), hi));
        }

        // segment/page extension prefixes
        if (op == 0xD1)
        {
            int b = B(1), irang = ((b >> 4) & 3) + 1;
            return Mk((b & 0x80) != 0 ? "EXTR" : "ATOMIC", 2, $"#{irang}");
        }
        if (op == 0xDC)
        {
            int b = B(1), irang = ((b >> 4) & 3) + 1;
            string mn = ExtMnemonic((b >> 6) & 3);
            return Mk(mn, 2, $"{Rw(b & 0xF)}, #{irang}");
        }
        if (op == 0xD7)
        {
            int b = B(1), irang = ((b >> 4) & 3) + 1;
            string mn = ExtMnemonic((b >> 6) & 3);
            int val = B(2) | (B(3) << 8);
            int arg = mn is "EXTS" or "EXTSR" ? B(2) : val;
            return Mk(mn, 4, $"#{FmtHex(arg)}, #{irang}");
        }

        if (!Spec.TryGetValue(op, out var spec))
        {
            return Mk("DB", 1, FmtHex(op, 2));
        }
        var (m, fmt) = spec;
        int b1 = B(1), n = b1 >> 4, mm = b1 & 0xF;
        int d16 = pos + 3 < data.Length ? data[pos + 2] | (data[pos + 3] << 8) : 0;

        switch (fmt)
        {
            case F.RR: return Mk(m, 2, $"{Rw(n)}, {Rw(mm)}");
            case F.RRB: return Mk(m, 2, $"{Rb(n)}, {Rb(mm)}");
            case F.MOVBZS: return Mk(m, 2, $"{Rw(n)}, {Rb(mm)}");
            case F.RNM8: return Mk(m, 2, $"{Rw(n)}, {M8(mm)}");
            case F.RNM8B: return Mk(m, 2, $"{Rb(n)}, {M8(mm)}");
            case F.MOVI4:
            case F.CMPI:
            case F.SHIMM: return Mk(m, 2, $"{Rw(mm)}, {Imm(n)}");
            case F.MOVI4B: return Mk(m, 2, $"{Rb(mm)}, {Imm(n)}");
            case F.SHREG: return Mk(m, 2, $"{Rw(n)}, {Rw(mm)}");
            case F.PUSH: return Mk(m, 2, $"[-{Rw(mm)}], {Rw(n)}");
            case F.PUSHB: return Mk(m, 2, $"[-{Rw(mm)}], {Rb(n)}");
            case F.RN_PINC: return Mk(m, 2, $"{Rw(n)}, [{Rw(mm)}+]");
            case F.RN_PINCB: return Mk(m, 2, $"{Rb(n)}, [{Rw(mm)}+]");
            case F.RN_IND: return Mk(m, 2, $"{Rw(n)}, [{Rw(mm)}]");
            case F.RN_INDB: return Mk(m, 2, $"{Rb(n)}, [{Rw(mm)}]");
            case F.ST_IND: return Mk(m, 2, $"[{Rw(mm)}], {Rw(n)}");
            case F.ST_INDB: return Mk(m, 2, $"[{Rw(mm)}], {Rb(n)}");
            case F.IND_IND:
            case F.IND_INDB: return Mk(m, 2, $"[{Rw(n)}], [{Rw(mm)}]");
            case F.PINC_IND:
            case F.PINC_INDB: return Mk(m, 2, $"[{Rw(n)}+], [{Rw(mm)}]");
            case F.IND_PINC:
            case F.IND_PINCB: return Mk(m, 2, $"[{Rw(n)}], [{Rw(mm)}+]");
            case F.REGMEM: return Mk(m, 4, $"{Reg8(b1)}, {MemName(d16)}");
            case F.REGMEMB: return Mk(m, 4, $"{Reg8(b1, true)}, {MemName(d16)}");
            case F.MEMREG: return Mk(m, 4, $"{MemName(d16)}, {Reg8(b1)}");
            case F.MEMREGB: return Mk(m, 4, $"{MemName(d16)}, {Reg8(b1, true)}");
            case F.REGD16: return Mk(m, 4, $"{Reg8(b1)}, {Imm(d16)}");
            case F.REGD16B: return Mk(m, 4, $"{Reg8(b1, true)}, {Imm(d16)}");
            case F.DISP_ST: return Mk(m, 4, $"[{Rw(mm)}+{Imm(d16)}], {Rw(n)}");
            case F.DISP_LD: return Mk(m, 4, $"{Rw(n)}, [{Rw(mm)}+{Imm(d16)}]");
            case F.DISP_STB: return Mk(m, 4, $"[{Rw(mm)}+{Imm(d16)}], {Rb(n)}");
            case F.DISP_LDB: return Mk(m, 4, $"{Rb(n)}, [{Rw(mm)}+{Imm(d16)}]");
            case F.MEMPTR_ST: return Mk(m, 4, $"[{Rw(mm)}], {MemName(d16)}");
            case F.MEMPTR_LD: return Mk(m, 4, $"{MemName(d16)}, [{Rw(mm)}]");
            case F.CMPMEM: return Mk(m, 4, $"{Rw(mm)}, {MemName(d16)}");
            case F.CMPD16: return Mk(m, 4, $"{Rw(mm)}, {Imm(d16)}");
            case F.SCXT: return Mk(m, 4, $"{Reg8(b1)}, {Imm(d16)}");
            case F.BITBIT:
            {
                int x = B(1), y = B(2), z = B(3);
                return Mk(m, 4, $"{BitName(y, z & 0xF)}, {BitName(x, z >> 4)}");
            }
            case F.BITJMP:
            {
                var tgt = (addr + 4 + 2 * S8(B(2))) & 0xFFFF;
                return Mk(m, 4, $"{BitName(B(1), B(3) >> 4)}, {FmtHex(tgt, 4)}");
            }
            case F.BFLD: return Mk(m, 4, $"{BitName(B(1), 0)}, {Imm(B(2))}, {Imm(B(3))}");
            case F.CALLA:
            case F.JMPA:
            {
                var cc = (b1 & 0xF) == 0 ? b1 >> 4 : b1 & 0xF;
                return Mk(m, 4, $"{Cc[cc]}, {FmtHex(d16, 4)}");
            }
            case F.CALLS:
            case F.JMPS: return Mk(m, 4, $"{FmtHex(b1, 2)}, {FmtHex(d16, 4)}");
            case F.CALLR: return Mk(m, 2, FmtHex((addr + 2 + 2 * S8(B(1))) & 0xFFFF, 4));
            case F.CALLI: return Mk(m, 2, $"{Cc[b1 >> 4]}, [{Rw(mm)}]");
            case F.R1: return Mk(m, 2, Rw(n));
            case F.R1B: return Mk(m, 2, Rb(n));
            case F.PCALL: return Mk(m, 4, $"{Reg8(b1)}, {FmtHex(d16, 4)}");
            case F.RETP:
            case F.PSHPOP: return Mk(m, 2, Reg8(b1));
            case F.TRAP: return Mk(m, 2, Imm(b1 >> 1));
            case F.R0:
            case F.N0:
            case F.RETI0: return Mk(m, 2);
            case F.EXT: return Mk(m, 2, "(prefix)");
            default: return Mk("DB", 1, FmtHex(op, 2));
        }
    }

    private static string ExtMnemonic(int xx) => xx switch
    {
        0 => "EXTS",
        1 => "EXTP",
        2 => "EXTSR",
        _ => "EXTPR",
    };

    /// <summary>Keil-style hex: upper case, a leading 0 when the first digit is a letter, and an
    /// H suffix (<c>0F8C0H</c>, <c>24H</c>).</summary>
    internal static string FmtHex(int v, int width = 0)
    {
        var h = width > 0 ? v.ToString("X" + width) : v.ToString("X");
        if (h[0] >= 'A' && h[0] <= 'F')
        {
            h = "0" + h;
        }
        return h + "H";
    }

    private static string Imm(int v) => "#" + FmtHex(v);

    private static string MemName(int addr) => MemNames.TryGetValue(addr, out var name) ? name : FmtHex(addr, 4);

    private static string BitName(int bitoff, int bit)
    {
        if (NamedBits.TryGetValue((bitoff, bit), out var named))
        {
            return named;
        }
        if (bitoff >= 0xF0)
        {
            return $"R{bitoff - 0xF0}.{bit}";
        }
        if (BitoffNames.TryGetValue(bitoff, out var sfr))
        {
            return $"{sfr}.{bit}";
        }
        var addr = bitoff >= 0x80 ? 0xFF00 + 2 * (bitoff - 0x80) : 0xFD00 + 2 * bitoff;
        return $"{FmtHex(addr, 4)}.{bit}";
    }

    private static string Rw(int n) => $"R{n}";

    private static string Rb(int n) => ByteRegs[n];

    /// <summary>8-bit reg field: 0xF0-0xFF is a GPR, anything else a short SFR address.</summary>
    private static string Reg8(int r, bool isByte = false)
    {
        if (r >= 0xF0)
        {
            return isByte ? Rb(r - 0xF0) : Rw(r - 0xF0);
        }
        return MemName(r < 0x80 ? 0xFE00 + 2 * r : 0xFF00 + 2 * (r - 0x80));
    }

    private static int S8(int v) => v >= 128 ? v - 256 : v;

    // short "reg,[Rwi]/[Rwi+]/#data3" second-nibble operand
    private static string M8(int m4)
    {
        if (m4 <= 7)
        {
            return Imm(m4);
        }
        return m4 <= 0xB ? $"[R{m4 & 3}]" : $"[R{m4 & 3}+]";
    }
}
