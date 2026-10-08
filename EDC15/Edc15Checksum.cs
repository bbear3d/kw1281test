using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace BitFab.KW1281Test.EDC15;

/// <summary>
/// EDC15 "V4.1" external-flash checksums (EDC15P/V/VM+, 512 KB), verified and corrected the way
/// the ECU itself verifies them: the scheme is read out of each image's own verify driver rather
/// than taken from a fixed table of regions.
///
/// <para><b>What the ECU does.</b> There is no per-region stored checksum. The driver seeds a
/// 32-bit state once (<c>R1 = 0x8631</c>, <c>R6 = 0xEFCD</c>), runs the checksum worker
/// (<c>CALLS 00H,1584H</c>) over a sequence of ranges, and then requires the state to equal
/// <see cref="Target"/> (<c>SUB R1,#8631H ; SUBC R6,#0EFCDH ; JMPR cc_Z</c>). The last four bytes
/// of each check's final range are <i>correction words</i>, solved so the state lands on that
/// constant. One driver run can contain several checks, each reseeded with its own correction
/// words.</para>
///
/// <para>Details the model depends on (each one cost a wrong answer when simplified away):</para>
/// <list type="bullet">
/// <item>DPP is a stack: the driver uses <c>SCXT DPPn,#page</c> / <c>POP DPPn</c>, so after a POP
/// the register holds what the routine was entered with.</item>
/// <item>The ranges depend on the dataset selected at runtime -- the driver is entered with DPP0
/// pointing at the active dataset -- so every dataset in the image is checked, since any of them
/// may be the selected one.</item>
/// <item>R3 carries over between ranges: the worker leaves R3 where it stopped, and the driver
/// relies on it (after the 0..0xB80 header range, a call with only R0 set covers the body).</item>
/// <item>R0 is the END offset, and the worker's termination test is <c>&gt;=</c> on a 4-byte
/// stride, so a range whose length is not a multiple of 4 consumes up to 2 bytes past R0. The
/// correction pair is the last one consumed.</item>
/// <item>The classic driver also sweeps DPP2 over a run of 16 KB code pages (bounds read from the
/// driver's own <c>CMP DPP2,#imm</c> / <c>MOV DPP2,#imm</c>); that sweep returns the state to the
/// seed and has its own correction word.</item>
/// </list>
///
/// <para><b>Two generations.</b> The late PD software (038906019 BH/KG/LB/NF/NJ/PJ) carries a more
/// elaborate driver: a page-walking sweep with its state crossed through RAM, a 64-bit compare,
/// and ranges that must return the state to where they started. Both are modelled; the image's
/// own driver decides which applies.</para>
///
/// <para><b>Refusal over guessing.</b> If the driver cannot be read, <see cref="Verify"/> reports
/// <see cref="Result.Supported"/> = false with a reason, never "valid". <see cref="VerifyAndCorrect"/>
/// additionally refuses (and leaves the buffer untouched) when any call to the checksum worker
/// in the image is not accounted for by the model, when a dataset is missing its header or body
/// check, when two checks want different bytes at one address, or when the correction does not
/// converge -- each of those means there is a condition the model would not be satisfying, and a
/// checksum that looks right here but not to the ECU is a no-start.</para>
///
/// <para><b>Safety:</b> <see cref="Verify"/> never modifies its input. <see cref="VerifyAndCorrect"/>
/// only writes into the caller's own in-memory buffer, and only once a fully converged correction
/// exists; the caller decides whether to persist it.</para>
/// </summary>
public static class Edc15Checksum
{
    private const int ExpectedLength = 0x80000;

    /// <summary>Where the flash is mapped in the CPU/DPP address space
    /// (file offset = absolute - FlashBase).</summary>
    private const int FlashBase = 0x80000;

    /// <summary>DPP pages are 16 KB; a 16-bit data address's top two bits pick the DPP.</summary>
    private const int PageSize = 0x4000;

    private const int Mask = 0xFFFF;

    /// <summary>The state every classic check requires, as <c>(R6 &lt;&lt; 16) | R1</c>.</summary>
    public const uint Target = 0xEFCD8631;

    private const int SeedR1 = 0x8631;
    private const int SeedR6 = 0xEFCD;

    // Correction-word constants for a range that must land on (SeedR6, SeedR1).
    private const int PadLBias = 0xAB85;
    private const int PadHXor = 0xDF9B;

    /// <summary>How far the classic driver body can run.</summary>
    private const int DriverSpan = 0x200;

    /// <summary><c>MOV R1,#8631H ; MOV R6,#0EFCDH</c> -- the driver seeding the state.</summary>
    private static readonly byte[] SeedPattern = [0xE6, 0xF1, 0x31, 0x86, 0xE6, 0xF6, 0xCD, 0xEF];

    /// <summary>The start of every V4.1 dataset.</summary>
    private static readonly byte[] DatasetSignature =
        [0xF9, 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, (byte)'V', (byte)'4', (byte)'.', (byte)'1'];

    /// <summary>Which verify driver the image carries.</summary>
    public enum Algorithm
    {
        /// <summary>The classic driver: page sweep plus per-dataset checks against
        /// <see cref="Target"/>.</summary>
        V41,

        /// <summary>The late PD driver (038906019 BH/KG/LB/NF/NJ/PJ): RAM-crossed sweep, 64-bit
        /// compare, code halves and dataset ranges that return the state to their seed.</summary>
        V41LatePd,
    }

    /// <summary>One range the worker runs over, as file offsets.</summary>
    /// <param name="Start">Where the range starts.</param>
    /// <param name="End">The stated end (R0 resolved).</param>
    /// <param name="Stop">Where the worker actually stopped (up to 2 bytes past End).</param>
    public readonly record struct Range(int Start, int End, int Stop);

    /// <summary>One condition the ECU checks, and the correction word that satisfies it.</summary>
    public sealed class Check
    {
        public IReadOnlyList<Range> Ranges { get; init; } = [];

        /// <summary>The state the driver compares, as <c>(R6 &lt;&lt; 16) | R1</c>.</summary>
        public uint State { get; init; }

        /// <summary>File offset of the 4 correction bytes, if this check has them.</summary>
        public int? FixAt { get; init; }

        /// <summary>What those 4 bytes must be for the check to pass.</summary>
        public byte[]? Want { get; init; }

        /// <summary>What those 4 bytes currently are.</summary>
        public byte[]? Have { get; init; }

        /// <summary>Set for checks that do not compare against <see cref="Target"/> (they must
        /// return the state to where it started instead).</summary>
        public bool? Satisfied { get; init; }

        public string Label { get; init; } = "";

        internal int? HeaderOf { get; init; }
        internal int? BodyOf { get; init; }

        public bool Ok => Satisfied ?? State == Target;
    }

    /// <summary>Result of a <see cref="Verify"/> or <see cref="VerifyAndCorrect"/> call.</summary>
    public sealed class Result
    {
        /// <summary>False when this image's verify driver could not be read (or it isn't a 512 KB
        /// EDC15 V4.1 image at all). <see cref="Reason"/> says why; nothing else is meaningful and
        /// the buffer was not touched.</summary>
        public bool Supported { get; init; }

        /// <summary>Why the image could not be verified, when <see cref="Supported"/> is false.</summary>
        public string Reason { get; init; } = "";

        public Algorithm Algorithm { get; init; }

        /// <summary>Every condition checked, as found BEFORE any correction.</summary>
        public IReadOnlyList<Check> Checks { get; init; } = [];

        /// <summary>File offsets of the V4.1 datasets (each one is checked).</summary>
        public IReadOnlyList<int> Datasets { get; init; } = [];

        public int ChecksTotal => Checks.Count;

        /// <summary>How many checks failed before any correction. 0 means the image verified.</summary>
        public int ChecksFailed => Checks.Count(c => !c.Ok);

        /// <summary>True only when the driver was read AND every check passed.</summary>
        public bool Valid => Supported && Checks.Count > 0 && ChecksFailed == 0;

        /// <summary><see cref="VerifyAndCorrect"/> only: true when correction words were written
        /// into the buffer and the result verifies.</summary>
        public bool Corrected { get; init; }

        /// <summary><see cref="VerifyAndCorrect"/> only: how many 4-byte correction words changed.</summary>
        public int WordsCorrected { get; init; }

        /// <summary><see cref="VerifyAndCorrect"/> only: why correction was refused (the buffer was
        /// not modified). Empty when it was not needed or it succeeded.</summary>
        public string RefusedReason { get; init; } = "";

        public string Describe()
        {
            if (!Supported)
            {
                return "EDC15 V4.1 checksums: CANNOT VERIFY\n" + Reason;
            }
            var sb = new StringBuilder();
            sb.Append("EDC15 V4.1 checksums (from the image's own verify driver, ")
              .Append(Algorithm == Algorithm.V41LatePd ? "late PD" : "classic")
              .Append("): ").Append(Valid ? "OK" : "MISMATCH");
            foreach (var c in Checks)
            {
                var spans = string.Join(", ", c.Ranges.Select(r => $"0x{r.Start:X5}-0x{r.Stop:X5}"));
                sb.Append($"\n  state {c.State:X8} {(c.Ok ? "ok " : "BAD")}  {spans}");
                if (c.Label.Length > 0)
                {
                    sb.Append("   ").Append(c.Label);
                }
                if (c.FixAt is { } at && c.Have is { } have && c.Want is { } want
                    && !have.AsSpan().SequenceEqual(want))
                {
                    sb.Append($"\n      correction at 0x{at:X5}: have {Hex(have)}, needs {Hex(want)}");
                }
            }
            if (RefusedReason.Length > 0)
            {
                sb.Append("\nCorrection refused: ").Append(RefusedReason);
            }
            return sb.ToString();
        }

        private static string Hex(byte[] b) => string.Join(" ", b.Select(x => x.ToString("x2")));
    }

    private const string Unreadable =
        "This EDC15 image's V4.1 verify driver could not be read, so its real checksum ranges are " +
        "unknown. The image is NOT reported as valid and will not be corrected.";

    /// <summary>Checks every condition the image's verify driver applies. Never modifies
    /// <paramref name="image"/>.</summary>
    public static Result Verify(byte[] image)
    {
        var (result, _) = Analyse(image);
        return result;
    }

    /// <summary>Same as <see cref="Verify"/>, and if a check fails, writes the correction words
    /// into <paramref name="image"/> so every check passes. Refuses -- leaving
    /// <paramref name="image"/> untouched and setting <see cref="Result.RefusedReason"/> -- rather
    /// than write a correction the model cannot fully account for.</summary>
    public static Result VerifyAndCorrect(byte[] image)
    {
        var (result, report) = Analyse(image);
        if (!result.Supported || result.Valid || report == null)
        {
            return result;
        }

        byte[] fixedImage;
        try
        {
            fixedImage = Correct(image, report);
        }
        catch (Refused ex)
        {
            return WithCorrection(result, false, 0, ex.Message);
        }
        catch (Exception ex)
        {
            return WithCorrection(result, false, 0,
                $"the checksum model failed while correcting ({ex.Message}). The image was NOT modified.");
        }

        var words = report.Checks
            .Where(c => c.FixAt is { } at && !image.AsSpan(at, 4).SequenceEqual(fixedImage.AsSpan(at, 4)))
            .Select(c => c.FixAt!.Value)
            .Distinct()
            .Count();
        Array.Copy(fixedImage, image, image.Length);
        return WithCorrection(result, true, words, "");
    }

    private static Result WithCorrection(Result r, bool corrected, int words, string refused) => new()
    {
        Supported = r.Supported,
        Reason = r.Reason,
        Algorithm = r.Algorithm,
        Checks = r.Checks,
        Datasets = r.Datasets,
        Corrected = corrected,
        WordsCorrected = words,
        RefusedReason = refused,
    };

    private static (Result, Report?) Analyse(byte[] image)
    {
        if (image == null || image.Length != ExpectedLength)
        {
            return (new Result
            {
                Reason = $"Not a 512 KB EDC15 flash image ({image?.Length ?? 0} bytes).",
            }, null);
        }
        if (DatasetBases(image).Count == 0)
        {
            return (new Result { Reason = "No V4.1 dataset found -- not an EDC15 V4.1 flash image." }, null);
        }
        Report report;
        try
        {
            if (DriverOffsets(image).Count == 0)
            {
                return (new Result { Reason = Unreadable }, null);
            }
            report = AllChecks(image);
        }
        catch (Exception)
        {
            return (new Result { Reason = Unreadable }, null);
        }
        if (report.Checks.Count == 0)
        {
            return (new Result { Reason = Unreadable }, null);
        }
        return (new Result
        {
            Supported = true,
            Algorithm = report.LatePd != null ? Algorithm.V41LatePd : Algorithm.V41,
            Checks = report.Checks,
            Datasets = report.Datasets,
        }, report);
    }

    // ------------------------------------------------------------------ the worker

    private static int Ror(int v, int n)
    {
        n &= 0xF;
        return ((v >> n) | (v << (16 - n))) & Mask;
    }

    private static (int Value, int Carry) Rol(int v, int n)
    {
        n &= 0xF;
        v = ((v << n) | (v >> (16 - n))) & Mask;
        return (v, (v & 1) == 0 || n == 0 ? 0 : 1);
    }

    /// <summary>The ECU's checksum worker (<c>CALLS 00H,1584H</c>) over 16-bit data addresses
    /// <c>[start, end)</c>, resolved through <paramref name="mem"/>'s DPP pages. Returns the new
    /// state and where it stopped; the <c>&gt;=</c> termination can read one word past
    /// <paramref name="end"/>.</summary>
    private static (int R6, int R1, int Stop) Run(Memory mem, int start, int end, int r6, int r1)
    {
        var a = start;
        while (true)
        {
            r1 ^= mem.Word(a); a += 2;
            int c;
            (r1, c) = Rol(r1, r6);
            r6 = (r6 - mem.Word(a) - c) & Mask; a += 2;
            r6 ^= r1;
            if (a >= end)
            {
                break;
            }
            r1 = (r1 - mem.Word(a) - 1) & Mask; a += 2;
            r1 = (r1 + 0xDAAD) & Mask;
            r6 ^= mem.Word(a); a += 2;
            r6 = Ror(r6, r1);
            if (a >= end)
            {
                break;
            }
        }
        return (r6, r1, a);
    }

    /// <summary>The 4 correction bytes ending a range so the chain lands on
    /// (<paramref name="r6t"/>, <paramref name="r1t"/>). The final pair sits at stop-4/stop-2
    /// and is consumed in the worker's third/fourth slot, where both steps invert:
    /// <c>w2 = r1_before - 1 + 0xDAAD - r1_target</c>,
    /// <c>w3 = r6_before ^ rol(r6_target, r1_target)</c>.</summary>
    private static byte[] SolveTail(Memory mem, int start, int stop, int r6s, int r1s, int r6t, int r1t)
    {
        var (r6b, r1b, _) = Run(mem, start, stop - 4, r6s, r1s);
        return Pack((r1b - 1 + 0xDAAD - r1t) & Mask, r6b ^ Rol(r6t, r1t).Value);
    }

    private static byte[] Pack(int lo, int hi) =>
        [(byte)lo, (byte)(lo >> 8), (byte)hi, (byte)(hi >> 8)];

    /// <summary>A word fetch hit an address outside the image: the range is not a flash range.</summary>
    private sealed class OutOfImage : Exception
    {
    }

    /// <summary>The model met something it cannot interpret (an unset DPP, a slot outside the
    /// image). Always means "cannot verify", never "valid".</summary>
    private sealed class ModelFault(string message) : Exception(message);

    /// <summary>Correction refused; the message is shown to the user.</summary>
    private sealed class Refused(string message) : Exception(message);

    /// <summary>The image seen through a set of DPP pages (null = unknown).</summary>
    private sealed class Memory(byte[] data, int?[] pages)
    {
        private readonly int?[] _pages = (int?[])pages.Clone();

        /// <summary>CPU address of a 16-bit data address, or null if its DPP is unknown.</summary>
        public int? Absolute(int a16)
        {
            var p = _pages[(a16 >> 14) & 3];
            return p == null ? null : p.Value * PageSize + (a16 & 0x3FFF);
        }

        /// <summary>File offset of a 16-bit data address.</summary>
        public int FileOffset(int a16) =>
            (Absolute(a16) ?? throw new ModelFault($"DPP{(a16 >> 14) & 3} unknown")) - FlashBase;

        public int Word(int a16)
        {
            var o = FileOffset(a16);
            if (o < 0 || o >= data.Length - 1)
            {
                throw new OutOfImage();
            }
            return data[o] | (data[o + 1] << 8);
        }
    }

    private static int?[] AllPages(int page) => [page, page, page, page];

    private static int?[] Consecutive(int page) => [page, page + 1, page + 2, page + 3];

    private static byte[] Slice4(byte[] data, int at)
    {
        if (at < 0 || at + 4 > data.Length)
        {
            throw new ModelFault($"correction word at 0x{at:X} is outside the image");
        }
        return data[at..(at + 4)];
    }

    private static int U16(byte[] data, int at)
    {
        if (at < 0 || at + 2 > data.Length)
        {
            throw new ModelFault($"0x{at:X} is outside the image");
        }
        return data[at] | (data[at + 1] << 8);
    }

    // ------------------------------------------------------------------ byte search helpers

    private static int Find(byte[] data, byte[] needle, int from = 0)
    {
        if (from > data.Length)
        {
            return -1;
        }
        var i = data.AsSpan(from).IndexOf(needle);
        return i < 0 ? -1 : i + from;
    }

    private static List<int> FindAll(byte[] data, byte[] needle)
    {
        var output = new List<int>();
        for (var i = Find(data, needle); i >= 0; i = Find(data, needle, i + 1))
        {
            output.Add(i);
        }
        return output;
    }

    /// <summary>Non-overlapping matches of a byte pattern where -1 matches any byte.</summary>
    private static List<int> FindPattern(byte[] data, int[] pattern)
    {
        var output = new List<int>();
        var i = 0;
        while (i + pattern.Length <= data.Length)
        {
            var ok = true;
            for (var k = 0; k < pattern.Length; k++)
            {
                if (pattern[k] >= 0 && data[i + k] != pattern[k])
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
            {
                output.Add(i);
                i += pattern.Length;
            }
            else
            {
                i++;
            }
        }
        return output;
    }

    // ------------------------------------------------------------------ image structure

    /// <summary>File offsets of the verify-driver seed sites (usually one, sometimes two).</summary>
    private static List<int> DriverOffsets(byte[] data) => FindAll(data, SeedPattern);

    /// <summary>The seed sites that are real entry points. The driver reseeds mid-chain; walking
    /// again from a later site inside an earlier site's span would lose the R3 carry-over and
    /// produce a truncated, spurious check.</summary>
    private static List<int> DriverEntries(byte[] data)
    {
        var output = new List<int>();
        foreach (var off in DriverOffsets(data))
        {
            if (output.Count > 0 && off - output[^1] < DriverSpan)
            {
                continue;
            }
            output.Add(off);
        }
        return output;
    }

    private static List<int> DatasetBases(byte[] data)
    {
        var output = new List<int>();
        var n = DatasetSignature.Length;
        for (var i = 0; i < data.Length - n; i += 0x1000)
        {
            if (data.AsSpan(i, n).SequenceEqual(DatasetSignature))
            {
                output.Add(i);
            }
        }
        return output;
    }

    // ------------------------------------------------------------------ the classic driver

    private static readonly Regex DppImm = new(@"^DPP(\d), #([0-9A-F]+)H$", RegexOptions.CultureInvariant);
    private static readonly Regex DppOnly = new(@"^DPP(\d)$", RegexOptions.CultureInvariant);
    private static readonly Regex R16Imm = new(@"^R([16]), #([0-9A-F]+)H$", RegexOptions.CultureInvariant);
    private static readonly Regex R1ImmPrefix = new(@"^R1, #([0-9A-F]+)H", RegexOptions.CultureInvariant);

    private static int Hex(string s) => Convert.ToInt32(s, 16);

    /// <summary>The 16-bit immediate of <c>&lt;mn&gt; reg, #imm</c>, or null.</summary>
    private static int? Imm(C166Instruction ins, string reg)
    {
        var ops = ins.Operands;
        var prefix = reg + ", #";
        if (!ops.StartsWith(prefix, StringComparison.Ordinal) || !ops.EndsWith('H'))
        {
            return null;
        }
        var digits = ops.Substring(prefix.Length, ops.Length - prefix.Length - 1);
        if (digits.Length == 0 || !digits.All(Uri.IsHexDigit) || digits.Any(char.IsLower))
        {
            return null;
        }
        return Hex(digits);
    }

    /// <summary>Walks one classic driver with <paramref name="datasetBase"/> as the active
    /// dataset, emitting a check at every comparison against the seed constant and one identity
    /// check per dataset header block.</summary>
    private static List<Check> ChecksFor(byte[] data, int driver, int datasetBase, HashSet<int> bases)
    {
        var page = (FlashBase + datasetBase) >> 14;
        var dpp = Consecutive(page);
        var stack = new[] { new List<int?>(), new List<int?>(), new List<int?>(), new List<int?>() };
        int? src = null, dst = null;
        int r1 = SeedR1, r6 = SeedR6;
        int? r3 = null, r0 = null;
        var pending = new List<Range>();
        (int FixAt, int R6, int R1)? lastPre = null;
        // Adjustments applied AFTER the last range and before the comparison: the correction word
        // is solved against adjust^-1(target).
        var post = new List<(string M, char G, int V)>();
        var output = new List<Check>();

        foreach (var ins in C166Decoder.DecodeAll(data, FlashBase, driver, Math.Min(driver + DriverSpan, data.Length)))
        {
            var m = ins.Mnemonic;
            var ops = ins.Operands;

            var mm = DppImm.Match(ops);
            if (mm.Success)
            {
                int n = int.Parse(mm.Groups[1].Value), v = Hex(mm.Groups[2].Value);
                if (m == "SCXT")
                {
                    stack[n].Add(dpp[n]);
                    dpp[n] = v;
                    continue;
                }
                if (m == "MOV")
                {
                    dpp[n] = v;
                    continue;
                }
                if (m is "ADD" or "SUB" && dpp[n] != null)
                {
                    dpp[n] = m == "ADD" ? dpp[n] + v : dpp[n] - v;
                    continue;
                }
            }
            if (m == "POP" && DppOnly.IsMatch(ops))
            {
                var n = ops[3] - '0';
                dpp[n] = Pop(stack[n]);
                continue;
            }
            if (m == "MOV" && ops == "R1, DPP0")
            {
                src = dpp[0];
                continue;
            }
            if (m == "ADD" && ops.StartsWith("R1, #", StringComparison.Ordinal) && src != null)
            {
                dst = src + Hex(R1ImmPrefix.Match(ops).Groups[1].Value);
                continue;
            }
            if (m == "MOV" && ops == "DPP2, R1" && dst != null)
            {
                dpp[2] = dst;
                continue;
            }
            if (m == "MOV" && Imm(ins, "R3") is { } r3v)
            {
                r3 = r3v;
                continue;
            }
            if (m == "MOV" && Imm(ins, "R0") is { } r0v)
            {
                r0 = r0v;
                continue;
            }

            mm = R16Imm.Match(ops);
            if (mm.Success)
            {
                char g = mm.Groups[1].Value[0];
                var v = Hex(mm.Groups[2].Value);
                if (m == "MOV")
                {
                    // reseed: a new, independent check
                    if (g == '1')
                    {
                        r1 = v;
                    }
                    else
                    {
                        r6 = v;
                    }
                    continue;
                }
                if (m == "SUB" && g == '1' && v == SeedR1)
                {
                    if (pending.Count == 0)
                    {
                        // every range of this chain was a header block, emitted on its own
                        lastPre = null;
                        continue;
                    }
                    int? fixAt = null;
                    byte[]? want = null, have = null;
                    if (lastPre is var (preAt, r6b, r1b))
                    {
                        // undo the post-range adjustments to get the state the final range
                        // itself has to produce
                        int t1 = SeedR1, t6 = SeedR6;
                        for (var k = post.Count - 1; k >= 0; k--)
                        {
                            var (am, ag, av) = post[k];
                            if (ag == '1')
                            {
                                t1 = am == "XOR" ? t1 ^ av : am == "ADD" ? (t1 - av) & Mask : (t1 + av) & Mask;
                            }
                            else
                            {
                                t6 = am == "XOR" ? t6 ^ av : am == "ADD" ? (t6 - av) & Mask : (t6 + av) & Mask;
                            }
                        }
                        fixAt = preAt;
                        want = Pack((r1b - 1 + 0xDAAD - t1) & Mask, r6b ^ Rol(t6, t1).Value);
                        have = Slice4(data, preAt);
                    }
                    output.Add(new Check
                    {
                        Ranges = pending.ToArray(),
                        State = ((uint)r6 << 16) | (uint)r1,
                        FixAt = fixAt,
                        Want = want,
                        Have = have,
                    });
                    pending.Clear();
                    lastPre = null;
                    post.Clear();
                    continue;
                }
                if (m is "XOR" or "ADD" or "SUB" or "SUBC")
                {
                    if (g == '1')
                    {
                        r1 = m == "XOR" ? r1 ^ v : m == "ADD" ? (r1 + v) & Mask : (r1 - v) & Mask;
                    }
                    else
                    {
                        r6 = m == "XOR" ? r6 ^ v : m == "ADD" ? (r6 + v) & Mask : (r6 - v) & Mask;
                    }
                    post.Add((m, g, v));
                    continue;
                }
            }

            if (m == "CALLS" && ops.StartsWith("00H", StringComparison.Ordinal) && r0 != null)
            {
                var start = r3 ?? 0;
                var mem = new Memory(data, dpp);
                int? lo = mem.Absolute(start), hi = mem.Absolute(r0.Value);
                if (lo == null || hi == null || hi <= lo)
                {
                    r3 = r0 = null;
                    continue;
                }
                int r6In = r6, r1In = r1, stop, r6Before, r1Before;
                try
                {
                    (r6, r1, stop) = Run(mem, start, r0.Value, r6, r1);
                    // The correction pair is the last one CONSUMED, at stop-4 -- not r0-4, which
                    // differs whenever the >= termination overshoots r0.
                    if (stop - 4 > start)
                    {
                        (r6Before, r1Before, _) = Run(mem, start, stop - 4, r6In, r1In);
                    }
                    else
                    {
                        (r6Before, r1Before) = (r6In, r1In);
                    }
                }
                catch (OutOfImage)
                {
                    r3 = r0 = null;
                    continue;
                }
                var stopAbs = stop > start
                    ? (mem.Absolute(stop - 2) ?? throw new ModelFault("range end has no DPP")) + 2
                    : lo.Value;
                int fLo = lo.Value - FlashBase, fStop = stopAbs - FlashBase;

                if (bases.Contains(fLo))
                {
                    // A dataset header block. Each one is identity on the seed (which is what
                    // makes the composed chain work when the fixed header page IS the active
                    // dataset and gets hashed twice), so it is emitted as its own identity check
                    // and left out of the chain -- every solve stays single-consumption.
                    var (sr6, sr1, sstop) = Run(mem, start, r0.Value, SeedR6, SeedR1);
                    var (pr6, pr1, _) = Run(mem, start, sstop - 4, SeedR6, SeedR1);
                    var fix = (mem.Absolute(sstop - 2) ?? throw new ModelFault("header end has no DPP"))
                              + 2 - FlashBase - 4;
                    output.Add(new Check
                    {
                        Ranges = [new Range(fLo, hi.Value - FlashBase, fStop)],
                        State = ((uint)sr6 << 16) | (uint)sr1,
                        Satisfied = sr1 == SeedR1 && sr6 == SeedR6,
                        Label = $"dataset header @0x{fLo:X5}",
                        HeaderOf = fLo,
                        FixAt = fix,
                        Want = Pack((pr1 - PadLBias) & Mask, (PadHXor ^ pr6) & Mask),
                        Have = Slice4(data, fix),
                    });
                    // identity, so the carried state is unchanged -- but R3 still advances
                    r3 = stop;
                    r0 = null;
                    continue;
                }

                pending.Add(new Range(fLo, hi.Value - FlashBase, fStop));
                lastPre = (fStop - 4, r6Before, r1Before);
                post.Clear();
                r3 = stop;
                r0 = null;
            }
        }
        return output;
    }

    private static int? Pop(List<int?> stack)
    {
        if (stack.Count == 0)
        {
            return null;
        }
        var v = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        return v;
    }

    // The classic driver's page sweep:
    //
    //   MOV   R3, #0C000H
    //   SCXT  R0, #0C000H
    //   BMOV  C, R3.14        ; first entry only; the loop re-enters at ADDC
    //   ADDC  DPP2, #0H       ; advance the page on the carry out of R3.14
    //   BCLR  R3.14           ; R3 -> 0x8000, the bottom of the DPP2 window
    //   CALLS 00H, 1584H      ; hash [0x8000, 0xC000) in that page
    //   CMP   DPP2, #limit
    //   JMPR  cc_C, <ADDC>    ; loop while DPP2 < limit
    //   MOV   DPP2, #init     ; re-arm -- so THIS is the entry value
    //
    // A linear walk reads R3 = R0 = 0xC000 as an empty range, so the sweep is modelled on its
    // own: hashing every swept page from the seed must return the state to the seed.

    /// <summary><c>ADDC DPP2,#0H ; BCLR R3.14 ; CALLS 00H,1584H</c> then
    /// <c>CMP DPP2,#limit ; JMPR ; MOV DPP2,#init</c>.</summary>
    private static readonly int[] ClassicSweep =
    [
        0x16, 0x02, 0x00, 0x00, 0xEE, 0xF3, 0xDA, 0x00, 0x84, 0x15,
        0x46, 0x02, -1, -1, 0x8D, -1, 0xE6, 0x02, -1, -1,
    ];

    private const int SweepLo = 0x8000;
    private const int SweepHi = 0xC000;

    private static (int Init, int Limit)? ClassicSweepBounds(byte[] data)
    {
        var ms = FindPattern(data, ClassicSweep);
        if (ms.Count != 1)
        {
            return null;
        }
        int limit = U16(data, ms[0] + 12), init = U16(data, ms[0] + 18);
        if (!(0 < init && init < limit))
        {
            return null;
        }
        return (init, limit);
    }

    private static Check? ClassicSweepCheck(byte[] data)
    {
        if (ClassicSweepBounds(data) is not var (init, limit))
        {
            return null;
        }
        int r1 = SeedR1, r6 = SeedR6;
        int? first = null;
        (Memory Mem, int R6, int R1, int Stop)? last = null;
        for (var page = init + 1; page <= limit; page++)
        {
            var mem = new Memory(data, AllPages(page));
            int r6b = r6, r1b = r1, stop;
            try
            {
                (r6, r1, stop) = Run(mem, SweepLo, SweepHi, r6, r1);
            }
            catch (OutOfImage)
            {
                return null;
            }
            first ??= mem.FileOffset(SweepLo);
            last = (mem, r6b, r1b, stop);
        }
        if (last is not var (lastMem, lr6, lr1, lstop) || first == null)
        {
            return null;
        }
        var fixAt = lastMem.FileOffset(lstop - 4);
        var end = lastMem.FileOffset(lstop - 2) + 2;
        return new Check
        {
            Ranges = [new Range(first.Value, end, end)],
            State = ((uint)r6 << 16) | (uint)r1,
            Satisfied = r1 == SeedR1 && r6 == SeedR6,
            Label = $"code sweep, pages 0x{init + 1:X2}-0x{limit:X2}",
            FixAt = fixAt,
            Want = SolveTail(lastMem, SweepLo, lstop, lr6, lr1, SeedR6, SeedR1),
            Have = Slice4(data, fixAt),
        };
    }

    // ------------------------------------------------------------------ the report

    private sealed class Report
    {
        public List<Check> Checks { get; } = [];
        public List<int> Datasets { get; init; } = [];
        public LatePd? LatePd { get; init; }
        public bool Ok => Checks.Count > 0 && Checks.All(c => c.Ok);
    }

    private static Report AllChecks(byte[] data)
    {
        var datasets = DatasetBases(data);
        var late = LatePdModel(data);
        var rep = new Report { Datasets = datasets, LatePd = late };
        if (late != null)
        {
            // the code halves do not depend on the dataset, so they are checked once
            rep.Checks.AddRange(LatePdCodeChecks(data, late));
            rep.Checks.AddRange(LatePdHeaderChecks(data, late, datasets));
            foreach (var b in datasets)
            {
                rep.Checks.Add(LatePdDatasetCheck(data, late, b));
            }
            return rep;
        }
        if (ClassicSweepCheck(data) is { } sweep)
        {
            rep.Checks.Add(sweep);
        }
        var bases = new HashSet<int>(datasets);
        var seen = new HashSet<string>();
        foreach (var driver in DriverEntries(data))
        {
            foreach (var b in datasets)
            {
                foreach (var c in ChecksFor(data, driver, b, bases))
                {
                    var key = $"{c.Label}|{c.FixAt}|{string.Join(",", c.Ranges.Select(r => $"{r.Start}-{r.Stop}"))}";
                    if (seen.Add(key))
                    {
                        rep.Checks.Add(c);   // dataset-independent ones are collected once
                    }
                }
            }
        }
        return rep;
    }

    // ------------------------------------------------------------------ the worker-call audit
    //
    // A passing verify means the conditions the model LOOKED AT hold; it says nothing about a
    // condition the model never found. So every use of the checksum worker in the image must be
    // either modelled or shown not to constrain flash, and correction refuses otherwise. That can
    // refuse an image it should not; it never writes correction bytes the ECU rejects.

    /// <summary><c>CALLS 00H, 1584H</c> -- a call to the checksum worker.</summary>
    private static readonly byte[] WorkerCall = [0xDA, 0x00, 0x84, 0x15];

    /// <summary>The internal-ROM self-test: <c>MOV DPP2,#imm ; MOV R3,#0 ; MOV R0,#len ;
    /// MOV R1,#0 ; MOV R6,#0 ; CALLS 00H,1584H ; SUB R1,mem ; SUBC R6,mem</c>. It hashes CPU
    /// 0x0000..0x8000 (the C167's internal boot ROM, not flash) against a dword stored in flash,
    /// so correction must never touch it.</summary>
    private static readonly int[] IromCheck =
    [
        0xE6, 0x02, -1, -1, 0xE0, 0x03, 0xE6, 0xF0, -1, -1, 0xE0, 0x01, 0xE0, 0x06,
        0xDA, 0x00, 0x84, 0x15, 0x22, 0xF1, -1, -1, 0x32, 0xF6, -1, -1,
    ];

    private static int? IromCheckCallSite(byte[] data)
    {
        var ms = FindPattern(data, IromCheck);
        if (ms.Count != 1)
        {
            return null;
        }
        var at = ms[0];
        int dpp2 = U16(data, at + 2), r0 = U16(data, at + 8), a16 = U16(data, at + 20), b16 = U16(data, at + 24);
        if (b16 != a16 + 2)
        {
            return null;
        }
        var off = new Memory(data, AllPages(dpp2)).FileOffset(a16);
        if (!(0 <= off + 4 && off + 4 <= data.Length) || !(0 < r0 && r0 <= 0x8000))
        {
            return null;
        }
        return at + 14;
    }

    /// <summary>The latest <c>&lt;opcode&gt; #imm16</c> in <c>data[from..to)</c>, from raw bytes
    /// (decoding from an arbitrary offset could land mid-instruction).</summary>
    private static int? LastImm(byte[] data, int from, int to, params byte[][] opcodes)
    {
        (int At, int Value)? best = null;
        var window = data.AsSpan(from, to - from);
        foreach (var opc in opcodes)
        {
            var at = window.LastIndexOf(opc);
            if (at >= 0 && at + 4 <= window.Length && (best == null || at > best.Value.At))
            {
                best = (at, window[at + 2] | (window[at + 3] << 8));
            }
        }
        return best?.Value;
    }

    private static readonly byte[] MovR3 = [0xE6, 0xF3], ScxtR3 = [0xC6, 0xF3];
    private static readonly byte[] MovR0 = [0xE6, 0xF0], ScxtR0 = [0xC6, 0xF0];
    private static readonly byte[] MovDpp0 = [0xE6, 0x00], ScxtDpp0 = [0xC6, 0x00];

    /// <summary>Worker calls the model cannot account for, as file offsets.</summary>
    private static List<int> UnexplainedWorkerCalls(byte[] data, Report rep)
    {
        var output = new List<int>();
        var irom = IromCheckCallSite(data);
        var late = rep.LatePd;
        foreach (var site in FindAll(data, WorkerCall))
        {
            if (!Explained(data, site, irom, late, rep))
            {
                output.Add(site);
            }
        }
        return output;
    }

    private static bool Explained(byte[] data, int site, int? irom, LatePd? late, Report rep)
    {
        if (site == irom)
        {
            return true;   // internal ROM self-test -- segment 0, not flash
        }
        if (site + 6 <= data.Length && data[site + 4] == 0xDB && data[site + 5] == 0x00)
        {
            return true;   // delay routine -- RETS straight after, the result is discarded
        }

        var from = Math.Max(0, site - 0x40);
        var lo = LastImm(data, from, site, MovR3, ScxtR3);   // R3, the start
        var hi = LastImm(data, from, site, MovR0, ScxtR0);   // R0, the end
        if (lo >= 0xC000 && hi >= 0xC000)
        {
            return true;   // internal RAM (DPP3 window) -- an uploaded routine, not flash
        }

        if (late != null)
        {
            if (Math.Abs(site - late.CompareAt) <= 0xC0 || Math.Abs(site - late.IdentityAt) <= 0x60)
            {
                return true;   // the late-PD driver
            }
            var seed = Find(data, SeedPattern);
            if (seed - 0x20 <= site && site <= seed + 0x60)
            {
                return true;   // the late-PD sweep
            }
            return site > late.IdentityAt;   // the late-PD boot-path code half
        }

        foreach (var d0 in DriverOffsets(data))
        {
            if (d0 - 0x40 <= site && site <= d0 + DriverSpan)
            {
                return true;   // the classic driver
            }
        }
        var sweep = FindPattern(data, ClassicSweep);
        if (sweep.Count > 0 && sweep[0] - 0x20 <= site && site <= sweep[0] + ClassicSweep.Length)
        {
            return true;   // the classic sweep
        }

        // A check elsewhere that hashes a range the model already covers adds no constraint (the
        // boot path duplicates the driver's code-half check this way). Proved, not assumed: the
        // range is resolved through the DPP0 page set just before the call.
        var page = LastImm(data, from, site, ScxtDpp0, MovDpp0);
        if (page != null && lo != null && hi != null)
        {
            var fLo = page.Value * PageSize + lo.Value - FlashBase;
            var fHi = page.Value * PageSize + hi.Value - FlashBase;
            if (rep.Checks.SelectMany(c => c.Ranges).Any(r => r.Start <= fLo && fHi <= r.Stop))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Datasets missing a header or body check. The driver checks every dataset in both
    /// stages, so a missing one means a degraded parse that could otherwise report OK with ranges
    /// of the wrong length.</summary>
    private static List<(int Base, string Missing)> UncheckedDatasets(Report rep)
    {
        var bases = rep.Datasets.OrderBy(b => b).ToList();
        var haveHeader = new HashSet<int>();
        var haveBody = new HashSet<int>();
        foreach (var c in rep.Checks)
        {
            if (c.HeaderOf is { } h)
            {
                haveHeader.Add(h);
                continue;
            }
            if (c.BodyOf is { } b)
            {
                haveBody.Add(b);
                continue;
            }
            if (c.Label.Length > 0 || c.Ranges.Count == 0)
            {
                continue;
            }
            var start = c.Ranges[0].Start;
            var below = bases.Where(x => x <= start).ToList();
            if (below.Count > 0 && start > below[^1])
            {
                haveBody.Add(below[^1]);   // starts strictly inside a dataset
            }
        }
        var output = new List<(int, string)>();
        foreach (var b in bases)
        {
            var missing = new List<string>();
            if (!haveHeader.Contains(b))
            {
                missing.Add("header");
            }
            if (!haveBody.Contains(b))
            {
                missing.Add("body");
            }
            if (missing.Count > 0)
            {
                output.Add((b, string.Join(" and ", missing)));
            }
        }
        return output;
    }

    private static byte[] Correct(byte[] image, Report first)
    {
        var buf = (byte[])image.Clone();

        var loose = UnexplainedWorkerCalls(buf, first);
        if (loose.Count > 0)
        {
            throw new Refused(
                $"this image uses the checksum worker at {string.Join(", ", loose.Select(a => $"0x{a:X5}"))}, " +
                $"and the model cannot account for {(loose.Count == 1 ? "it" : "them")}. That means there " +
                "is a check it would not be satisfying, so the image was NOT modified.");
        }
        var missing = UncheckedDatasets(first);
        if (missing.Count > 0)
        {
            throw new Refused(
                "the driver checks every dataset in both stages, but the model found no " +
                string.Join(", ", missing.Select(x => $"{x.Missing} check for the dataset at 0x{x.Base:X5}")) +
                ". The parse is incomplete, so the image was NOT modified.");
        }
        // Two checks wanting different bytes at one address is always a model fault.
        var want = new Dictionary<int, byte[]>();
        foreach (var c in first.Checks)
        {
            if (c.FixAt is { } at && c.Want is { } w)
            {
                if (want.TryGetValue(at, out var other) && !other.AsSpan().SequenceEqual(w))
                {
                    throw new Refused(
                        $"two checks want different bytes at 0x{at:X5}, so this image cannot be corrected " +
                        "safely. The image was NOT modified.");
                }
                want[at] = w;
            }
        }

        // Iterate: on some images a correction word lies inside an earlier check's ranges, so
        // fixing one can disturb another. Normally converges in one or two passes.
        for (var pass = 0; pass < 8; pass++)
        {
            var rep = AllChecks(buf);
            if (rep.Ok)
            {
                return buf;
            }
            var changed = false;
            foreach (var c in rep.Checks)
            {
                if (c.FixAt is { } at && c.Want is { } w && !buf.AsSpan(at, 4).SequenceEqual(w))
                {
                    w.CopyTo(buf, at);
                    changed = true;
                }
            }
            if (!changed)
            {
                break;
            }
        }
        if (!AllChecks(buf).Ok)
        {
            throw new Refused("the correction did not converge; the image was NOT modified.");
        }
        return buf;
    }

    // ------------------------------------------------------------------ the late PD generation
    //
    // A different, more elaborate verify driver:
    //
    //  * a page-walking loop sweeps DPP2 from sweep_init + 1 to sweep_limit inclusive, one 16 KB
    //    page per pass through the 16-bit window 0x8000..0xC000;
    //  * the swept state lives in RAM at 0xF8C0..0xF8C7, two passes deep, and is CROSSED each
    //    pass ([F8C2],[F8C0] <- old [F8C4],[F8C6]; [F8C4],[F8C6] <- R1,R6); two per-software
    //    constants are folded in afterwards. The result, S0, seeds the dataset ranges. S0 is never
    //    compared against anything, so the swept region is pinned through the words solved
    //    against it;
    //  * the comparison is 64-bit: SUB R0,[F8C4] ; SUBC R3,[F8C6] ; SUBC R1,[F8C0] ; SUBC R6,[F8C2].
    //
    // The conditions, and the correction word that satisfies each:
    //
    //   low code half    zero-seeded, must land where the folds map the stored seed back to
    //   high code half   seeded from the dword stored at its start, must reach the R0/R3
    //                    immediates loaded before the compare
    //   dataset headers  each header block must return S0 to S0
    //   dataset body     body, then the 16 KB page below the dataset, S0 -> S0
    //
    // Everything is read out of the driver by walking its instructions, not from fixed offsets,
    // and an image whose driver does not present the expected seven ranges is not modelled.

    /// <summary><c>SUB R0,0F8C4H ; SUBC R3,0F8C6H ; SUBC R1,0F8C0H ; SUBC R6,0F8C2H</c>.</summary>
    private static readonly byte[] LatePdCompare =
        [0x22, 0xF0, 0xC4, 0xF8, 0x32, 0xF3, 0xC6, 0xF8, 0x32, 0xF1, 0xC0, 0xF8, 0x32, 0xF6, 0xC2, 0xF8];

    /// <summary><c>SUB R1,0F8C0H ; SUBC R6,0F8C2H</c> -- the second stage's identity compare.</summary>
    private static readonly byte[] LatePdIdentity = [0x22, 0xF1, 0xC0, 0xF8, 0x32, 0xF6, 0xC2, 0xF8];

    /// <summary>Instructions whose presence, in this order, says this really is the late-PD
    /// driver.</summary>
    private static readonly (string Mn, string Ops)[] LatePdShape =
    [
        ("ADDC", "DPP2, #0H"),      // the page-walking loop's advance
        ("MOV", "R1, #0H"),         // the low code half is zero-seeded
        ("MOV", "R6, #0H"),
        ("MOV", "R1, 0F8C0H"),      // the header ranges are seeded from S0
        ("MOV", "R6, 0F8C2H"),
        ("SUB", "R0, 0F8C4H"),      // the 64-bit compare itself
    ];

    /// <summary>How far past the compare the second stage reaches.</summary>
    private const int LateSpanForward = 0xD0;

    private sealed class RangeCall
    {
        public int At;
        public Dictionary<int, int?> Dpp = [];
        public int? Start;
        public int? End;
        public bool Looped;
        public int? Limit;
        public int? Rearm;
        public List<(string Mn, string Reg, int V)> Adj = [];
    }

    private sealed class LatePd
    {
        public int CompareAt, IdentityAt, SweepInit, SweepLimit;
        public int? FoldLo, FoldHi;
        public int LoPage0, LoPage1, LoEnd, LoSubR1, LoSubR6;
        public int HiPage0, HiPage1, HiEnd, HiXorR1, HiAddR6;
        public int HdrPage, HdrEnd, WantR1, WantR6;
        public int BodyDelta, BodyEnd, PreDelta, PreStart;
    }

    /// <summary>Collects the driver's <c>CALLS</c> sites in order, with the DPP pages, start/end
    /// offsets and register adjustments in force at each.</summary>
    private static List<RangeCall> WalkLatePd(List<C166Instruction> ins)
    {
        var dpp = new Dictionary<int, int?>();
        var stack = new[] { new List<int?>(), new List<int?>(), new List<int?>(), new List<int?>() };
        int? r3 = null, r0 = null;
        var r3Stack = new List<int?>();   // SCXT R3 / POP R3 -- the driver parks R3 there
        var adj = new List<(string, string, int)>();
        var calls = new List<RangeCall>();
        for (var k = 0; k < ins.Count; k++)
        {
            var i = ins[k];
            string mn = i.Mnemonic, ops = i.Operands;
            var m = DppImm.Match(ops);
            if (m.Success)
            {
                int n = int.Parse(m.Groups[1].Value), v = Hex(m.Groups[2].Value);
                if (mn == "SCXT")
                {
                    stack[n].Add(dpp.GetValueOrDefault(n));
                    dpp[n] = v;
                }
                else if (mn == "MOV")
                {
                    dpp[n] = v;
                }
                else if (mn is "ADD" or "SUB" && dpp.GetValueOrDefault(n) is { } cur)
                {
                    dpp[n] = mn == "ADD" ? cur + v : cur - v;
                }
                continue;
            }
            if (mn == "POP" && DppOnly.IsMatch(ops))
            {
                var n = ops[3] - '0';
                dpp[n] = Pop(stack[n]);
                continue;
            }
            if (mn == "MOV" && ops == "DPP2, R1")
            {
                // DPP2 = active dataset + delta; the delta is recovered separately
                dpp[2] = null;
                continue;
            }
            if (mn is "MOV" or "SCXT" && Imm(i, "R3") is { } r3v)
            {
                if (mn == "SCXT")
                {
                    r3Stack.Add(r3);
                }
                r3 = r3v;
                continue;
            }
            if (mn == "POP" && ops == "R3")
            {
                r3 = Pop(r3Stack);
                continue;
            }
            if (mn is "BCLR" or "BSET" && BitOfR3(ops) is { } bit && r3 != null)
            {
                r3 = mn == "BCLR" ? r3 & ~(1 << bit) & Mask : r3 | (1 << bit);
                continue;
            }
            if (mn == "AND" && Imm(i, "R3") is { } andV && r3 != null)
            {
                r3 &= andV;
                continue;
            }
            if (mn is "MOV" or "SCXT" && Imm(i, "R0") is { } r0v)
            {
                r0 = r0v;
                continue;
            }
            foreach (var reg in new[] { "R1", "R6" })
            {
                if (mn is "SUB" or "ADD" or "XOR" or "MOV" && Imm(i, reg) is { } av)
                {
                    adj.Add((mn, reg, av));
                }
            }
            if (mn == "CALLS" && ops.StartsWith("00H", StringComparison.Ordinal) && ops.Contains("1584"))
            {
                var c = new RangeCall
                {
                    At = i.Offset, Dpp = new Dictionary<int, int?>(dpp), Start = r3, End = r0, Adj = [.. adj],
                };
                // A looped call is followed by CMP DPP2,#imm and a backward JMPR; scan to the NEXT
                // call (the late-PD sweep crosses its state into RAM in between).
                for (var j = k + 1; j < ins.Count; j++)
                {
                    var x = ins[j];
                    if (x.Mnemonic == "CALLS" && x.Operands.Contains("1584"))
                    {
                        break;
                    }
                    var lim = Imm(x, "DPP2");
                    if (x.Mnemonic == "CMP" && lim != null)
                    {
                        c.Looped = true;
                        c.Limit = lim;
                    }
                    else if (c.Looped && x.Mnemonic == "MOV" && lim != null)
                    {
                        c.Rearm = lim;
                        break;
                    }
                }
                calls.Add(c);
                // the worker leaves R3 where it stopped, and the driver relies on it
                r3 = c.End;
                adj.Clear();
            }
        }
        return calls;
    }

    private static int? BitOfR3(string ops)
    {
        if (!ops.StartsWith("R3.", StringComparison.Ordinal) || ops.Length < 4 || !ops[3..].All(ch => ch >= '0' && ch <= '9'))
        {
            return null;
        }
        return int.Parse(ops[3..]);
    }

    private static (int R1, int R6)? LatePdExpected(byte[] data)
    {
        var at = Find(data, LatePdCompare);
        if (at < 8)
        {
            return null;
        }
        int r0At = at - 8, r3At = at - 4;
        if (data[r0At] != 0xE6 || data[r0At + 1] != 0xF0 || data[r3At] != 0xC6 || data[r3At + 1] != 0xF3)
        {
            return null;
        }
        return (U16(data, r0At + 2), U16(data, r3At + 2));
    }

    private static LatePd? LatePdModel(byte[] data)
    {
        var at = Find(data, LatePdCompare);
        if (at < 0 || Find(data, LatePdCompare, at + 1) != -1)
        {
            return null;
        }
        var ident = Find(data, LatePdIdentity);
        if (ident < 0 || Find(data, LatePdIdentity, ident + 1) != -1)
        {
            return null;
        }
        if (LatePdExpected(data) is not var (wantR1, wantR6))
        {
            return null;
        }
        var seed = data.AsSpan(0, at).LastIndexOf(SeedPattern);
        if (seed < 0 || at + LateSpanForward > data.Length)
        {
            return null;
        }
        var ins = C166Decoder.DecodeAll(data, FlashBase, seed, at + LateSpanForward);
        if (!ins.Any(i => i.Offset == at && i.Mnemonic == "SUB" && i.Operands == "R0, 0F8C4H"))
        {
            return null;   // the window did not decode onto the compare
        }

        var shape = 0;
        foreach (var i in ins)
        {
            if (shape < LatePdShape.Length && i.Mnemonic == LatePdShape[shape].Mn && i.Operands == LatePdShape[shape].Ops)
            {
                shape++;
            }
        }
        if (shape != LatePdShape.Length)
        {
            return null;
        }

        var calls = WalkLatePd(ins);
        if (calls.Count != 7)
        {
            return null;
        }
        RangeCall sweep = calls[0], lo = calls[1], hi = calls[2], hdrf = calls[3], hdra = calls[4],
            body = calls[5], pre = calls[6];
        if (!(sweep.Looped && sweep.Limit != null && sweep.Rearm != null))
        {
            return null;
        }
        if (lo.Looped || hi.Looped || body.Looped || pre.Looped)
        {
            return null;
        }
        if (body.At <= at || pre.At <= at)
        {
            return null;   // the second stage is past the compare
        }

        static int? AdjOf(RangeCall c, string mn, string reg)
        {
            foreach (var (m, r, v) in c.Adj)
            {
                if (m == mn && r == reg)
                {
                    return v;
                }
            }
            return null;
        }

        // The body range's start is NOT read from the walk: R3 carries over from the header
        // range, and the failure path between the compare and the second stage contains its own
        // POP R3, which a linear walk would wrongly apply.
        var folds = LatePdFolds(ins, sweep);
        var delta = LatePdDelta(ins, body);
        var back = LatePdBack(ins, pre);
        if (folds == null || delta == null || back == null)
        {
            return null;
        }
        int? Page(RangeCall c, int n) => c.Dpp.TryGetValue(n, out var p) ? p : throw new KeyNotFoundException();
        int? loPage0, loPage1, hiPage0, hiPage1, hdrPage;
        try
        {
            loPage0 = Page(lo, 0);
            loPage1 = Page(lo, 1);
            hiPage0 = Page(hi, 0);
            hiPage1 = Page(hi, 1);
            hdrPage = Page(hdrf, 0);
        }
        catch (KeyNotFoundException)
        {
            return null;
        }
        // the two header ranges share a length; the body and pre ranges share an end
        if (hdra.End != hdrf.End || pre.End != body.End)
        {
            return null;
        }
        int? loSubR1 = AdjOf(hi, "SUB", "R1"), loSubR6 = AdjOf(hi, "SUB", "R6");
        int? hiXorR1 = AdjOf(hi, "XOR", "R1"), hiAddR6 = AdjOf(hi, "ADD", "R6");
        if (loSubR1 is not { } a1 || loSubR6 is not { } a2 || hiXorR1 is not { } a3 || hiAddR6 is not { } a4
            || lo.End is not { } loEnd || hi.End is not { } hiEnd || hdrf.End is not { } hdrEnd
            || body.End is not { } bodyEnd || pre.Start is not { } preStart
            || hdrPage is not { } hp || loPage0 is not { } l0 || loPage1 is not { } l1
            || hiPage0 is not { } h0 || hiPage1 is not { } h1)
        {
            return null;
        }
        var model = new LatePd
        {
            CompareAt = at, IdentityAt = ident,
            SweepInit = sweep.Rearm.Value, SweepLimit = sweep.Limit.Value,
            FoldLo = folds.Value.Lo, FoldHi = folds.Value.Hi,
            LoPage0 = l0, LoPage1 = l1, LoEnd = loEnd,
            // the low half's POST-adjust sits between the two calls, so it is in the high call's
            // block alongside the high half's PRE-adjust; told apart by mnemonic
            LoSubR1 = a1, LoSubR6 = a2,
            HiPage0 = h0, HiPage1 = h1, HiEnd = hiEnd, HiXorR1 = a3, HiAddR6 = a4,
            HdrPage = hp, HdrEnd = hdrEnd, WantR1 = wantR1, WantR6 = wantR6,
            BodyDelta = delta.Value, BodyEnd = bodyEnd,
            PreDelta = delta.Value - back.Value, PreStart = preStart,
        };
        if (!(0 < model.SweepInit && model.SweepInit < model.SweepLimit))
        {
            return null;
        }
        return model;
    }

    /// <summary><c>ADD 0F8C0H,R3</c> / <c>ADD 0F8C2H,R3</c> after the sweep, each with the
    /// <c>MOV R3,#imm</c> that loads it.</summary>
    private static (int? Lo, int? Hi)? LatePdFolds(List<C166Instruction> ins, RangeCall sweep)
    {
        int? last = null;
        bool haveLo = false, haveHi = false;
        int? foldLo = null, foldHi = null;
        foreach (var i in ins)
        {
            if (i.Offset <= sweep.At)
            {
                continue;
            }
            if (i.Mnemonic == "MOV" && Imm(i, "R3") is { } v)
            {
                last = v;
            }
            else if (i.Mnemonic == "ADD" && i.Operands == "0F8C0H, R3")
            {
                foldLo = last;
                haveLo = true;
            }
            else if (i.Mnemonic == "ADD" && i.Operands == "0F8C2H, R3")
            {
                foldHi = last;
                haveHi = true;
            }
        }
        return haveLo && haveHi ? (foldLo, foldHi) : null;
    }

    /// <summary><c>ADD R1,#imm</c> before <c>MOV DPP2,R1</c> -- the body range's page offset
    /// from the active dataset.</summary>
    private static int? LatePdDelta(List<C166Instruction> ins, RangeCall body)
    {
        int? last = null;
        foreach (var i in ins)
        {
            if (i.Offset >= body.At)
            {
                break;
            }
            if (i.Mnemonic == "ADD" && Imm(i, "R1") is { } v)
            {
                last = v;
            }
            else if (i.Mnemonic == "MOV" && i.Operands == "DPP2, R1" && last != null)
            {
                return last;
            }
        }
        return null;
    }

    /// <summary><c>SUB DPP2,#imm</c> between the body and pre ranges.</summary>
    private static int? LatePdBack(List<C166Instruction> ins, RangeCall pre)
    {
        int? last = null;
        foreach (var i in ins)
        {
            if (i.Offset >= pre.At)
            {
                break;
            }
            if (i.Mnemonic == "SUB" && Imm(i, "DPP2") is { } v)
            {
                last = v;
            }
        }
        return last;
    }

    /// <summary>S0 -- the swept, crossed and folded accumulator the dataset ranges are seeded
    /// from, as (R1, R6).</summary>
    private static (int R1, int R6) LatePdSeed(byte[] data, LatePd m)
    {
        if (m.FoldLo is not { } foldLo || m.FoldHi is not { } foldHi)
        {
            throw new ModelFault("late-PD fold constant not loaded from an immediate");
        }
        int f0 = 0, f2 = 0, f4 = 0, f6 = 0;
        int r1 = SeedR1, r6 = SeedR6;
        for (var page = m.SweepInit + 1; page <= m.SweepLimit; page++)
        {
            (r6, r1, _) = Run(new Memory(data, AllPages(page)), SweepLo, SweepHi, r6, r1);
            (f2, f0) = (f4, f6);   // the cross: [F8C2],[F8C0] <- [F8C4],[F8C6]
            (f4, f6) = (r1, r6);
        }
        return ((f0 + foldLo) & Mask, (f2 + foldHi) & Mask);
    }

    /// <summary>One condition: run <paramref name="bounds"/> through the matching DPP page sets
    /// from <paramref name="seed"/>, require <paramref name="target"/>, and solve the last
    /// range's final pair.</summary>
    private static Check LateCheck(
        byte[] data, int?[][] dpps, (int Start, int End)[] bounds, (int R1, int R6) seed,
        (int R1, int R6) target, string label, int? headerOf = null, int? bodyOf = null)
    {
        int r6 = seed.R6, r1 = seed.R1;
        var ranges = new List<Range>();
        Memory? lastMem = null;
        int lastStart = 0, lastStop = 0, r6b = 0, r1b = 0;
        for (var k = 0; k < bounds.Length; k++)
        {
            var mem = new Memory(data, dpps[k]);
            var (start, end) = bounds[k];
            (r6b, r1b) = (r6, r1);
            int stop;
            (r6, r1, stop) = Run(mem, start, end, r6, r1);
            ranges.Add(new Range(mem.FileOffset(start), mem.FileOffset(end), mem.FileOffset(stop - 2) + 2));
            (lastMem, lastStart, lastStop) = (mem, start, stop);
        }
        var fixAt = lastMem!.FileOffset(lastStop - 4);
        return new Check
        {
            Ranges = ranges,
            State = ((uint)r6 << 16) | (uint)r1,
            Satisfied = r1 == target.R1 && r6 == target.R6,
            Label = label,
            HeaderOf = headerOf,
            BodyOf = bodyOf,
            FixAt = fixAt,
            Want = SolveTail(lastMem, lastStart, lastStop, r6b, r1b, target.R6, target.R1),
            Have = Slice4(data, fixAt),
        };
    }

    /// <summary>The two code-half conditions. The driver runs them as one chain (low half, fold,
    /// high half, compare), but the boot path runs the same high range from the dword stored at
    /// its start, so the chain splits losslessly into two independent conditions.</summary>
    private static Check[] LatePdCodeChecks(byte[] data, LatePd m)
    {
        int?[] loDpp = [m.LoPage0, m.LoPage1, m.LoPage1, m.LoPage1];
        int?[] hiDpp = [m.HiPage0, m.HiPage1, m.HiPage1, m.HiPage1];
        var seedAt = new Memory(data, hiDpp).FileOffset(0);
        (int R1, int R6) seed = (U16(data, seedAt), U16(data, seedAt + 2));
        // undo  r1' = (r1 - loSubR1) ^ hiXorR1 ;  r6' = (r6 - loSubR6) + hiAddR6
        (int, int) loTarget = (((seed.R1 ^ m.HiXorR1) + m.LoSubR1) & Mask, (seed.R6 - m.HiAddR6 + m.LoSubR6) & Mask);
        return
        [
            LateCheck(data, [loDpp], [(0, m.LoEnd)], (0, 0), loTarget, "code low half"),
            LateCheck(data, [hiDpp], [(0, m.HiEnd)], seed, (m.WantR1, m.WantR6), "code high half"),
        ];
    }

    /// <summary>One condition per dataset header block (including the fixed header page): the
    /// block must leave the state exactly where it found it.</summary>
    private static List<Check> LatePdHeaderChecks(byte[] data, LatePd m, List<int> bases)
    {
        var s0 = LatePdSeed(data, m);
        var blocks = new SortedSet<int>(bases) { new Memory(data, Consecutive(m.HdrPage)).FileOffset(0) };
        var output = new List<Check>();
        foreach (var b in blocks)
        {
            var page = (FlashBase + b) >> 14;
            output.Add(LateCheck(data, [Consecutive(page)], [(0, m.HdrEnd)], s0, s0,
                $"dataset header @0x{b:X5}", headerOf: b));
        }
        return output;
    }

    /// <summary>The dataset-body condition for one selected dataset.</summary>
    private static Check LatePdDatasetCheck(byte[] data, LatePd m, int datasetBase)
    {
        var s0 = LatePdSeed(data, m);
        var page = (FlashBase + datasetBase) >> 14;
        var body = Consecutive(page);
        body[2] = page + m.BodyDelta;
        var pre = Consecutive(page);
        pre[2] = page + m.PreDelta;
        return LateCheck(data, [body, pre], [(m.HdrEnd, m.BodyEnd), (m.PreStart, m.BodyEnd)], s0, s0,
            $"dataset body @0x{datasetBase:X5}", bodyOf: datasetBase);
    }
}
