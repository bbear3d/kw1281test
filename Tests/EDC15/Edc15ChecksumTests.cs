using BitFab.KW1281Test.EDC15;
using Shouldly;

namespace BitFab.KW1281Test.Tests.EDC15;

/// <summary>
/// <see cref="Edc15Checksum"/> against synthetic images. Real EDC15 flash images can't be checked
/// in, so these build a minimal image the same way the ECU's is laid out -- a V4.1 dataset plus a
/// verify driver that seeds the state, hashes the dataset header and body with the checksum
/// worker, and compares against 0xEFCD8631 -- and exercise the model through the public API.
/// </summary>
[TestClass]
public class Edc15ChecksumTests
{
    private const int Size = 0x80000;
    private const int Driver = 0x10000;

    private static readonly byte[] DatasetSignature =
        [0xF9, 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, (byte)'V', (byte)'4', (byte)'.', (byte)'1'];

    // MOV R1,#8631H ; MOV R6,#0EFCDH ; MOV R3,#0H ; MOV R0,#0B80H ; CALLS 00H,1584H
    // MOV R0,#0BFFEH ; CALLS 00H,1584H ; SUB R1,#8631H ; SUBC R6,#0EFCDH ; RETS
    private static readonly byte[] ClassicDriver =
    [
        0xE6, 0xF1, 0x31, 0x86, 0xE6, 0xF6, 0xCD, 0xEF, 0xE0, 0x03, 0xE6, 0xF0, 0x80, 0x0B,
        0xDA, 0x00, 0x84, 0x15, 0xE6, 0xF0, 0xFE, 0xBF, 0xDA, 0x00, 0x84, 0x15,
        0x26, 0xF1, 0x31, 0x86, 0x36, 0xF6, 0xCD, 0xEF, 0xDB, 0x00,
    ];

    /// <summary>Random content, one driver, and a dataset at each of <paramref name="datasets"/>.
    /// The checksums are NOT valid until corrected.</summary>
    private static byte[] SyntheticImage(params int[] datasets)
    {
        var rnd = new Random(1234);
        var image = new byte[Size];
        rnd.NextBytes(image);
        // the driver, then NOPs for the rest of the window the model decodes
        for (var i = Driver; i < Driver + 0x200; i += 2)
        {
            image[i] = 0xCC;
            image[i + 1] = 0x00;
        }
        ClassicDriver.CopyTo(image, Driver);
        foreach (var b in datasets)
        {
            DatasetSignature.CopyTo(image, b);
        }
        return image;
    }

    private static byte[] CorrectedImage(params int[] datasets)
    {
        var image = SyntheticImage(datasets);
        Edc15Checksum.VerifyAndCorrect(image).Corrected.ShouldBeTrue();
        return image;
    }

    [TestMethod]
    public void HeaderAndBodyAreCheckedForEveryDataset()
    {
        var result = Edc15Checksum.Verify(SyntheticImage(0x50000, 0x60000));

        result.Supported.ShouldBeTrue();
        result.Algorithm.ShouldBe(Edc15Checksum.Algorithm.V41);
        result.Datasets.ShouldBe(new[] { 0x50000, 0x60000 });
        result.ChecksTotal.ShouldBe(4);
        result.Valid.ShouldBeFalse();
    }

    [TestMethod]
    public void CorrectionWordsAreWhereTheWorkerLastConsumes()
    {
        var result = Edc15Checksum.Verify(SyntheticImage(0x50000));

        // header 0..0xB80 is a multiple of 4; the body 0xB80..0xBFFE is not, so the worker's >=
        // termination runs 2 bytes past R0 and the correction pair ends at 0xC000, not 0xBFFE.
        result.Checks.Select(c => c.FixAt).ShouldBe(new int?[] { 0x50B7C, 0x5BFFC }, ignoreOrder: true);
        var body = result.Checks.Single(c => c.FixAt == 0x5BFFC);
        body.Ranges.ShouldBe(new[] { new Edc15Checksum.Range(0x50B80, 0x5BFFE, 0x5C000) });
    }

    [TestMethod]
    public void CorrectWritesOnlyTheCorrectionWordsAndVerifies()
    {
        var original = SyntheticImage(0x50000, 0x60000);
        var image = (byte[])original.Clone();

        var result = Edc15Checksum.VerifyAndCorrect(image);

        result.Corrected.ShouldBeTrue();
        result.WordsCorrected.ShouldBe(4);
        Edc15Checksum.Verify(image).Valid.ShouldBeTrue();
        int[] words = [0x50B7C, 0x5BFFC, 0x60B7C, 0x6BFFC];
        for (var i = 0; i < Size; i++)
        {
            if (image[i] != original[i])
            {
                words.ShouldContain(w => w <= i && i < w + 4, $"changed 0x{i:X5}");
            }
        }
    }

    [TestMethod]
    public void AnEditIsDetectedAndOnlyItsCheckIsRepaired()
    {
        var good = CorrectedImage(0x50000, 0x60000);
        var image = (byte[])good.Clone();
        image[0x62345] ^= 0x5A;

        var before = Edc15Checksum.Verify(image);
        before.Valid.ShouldBeFalse();
        before.ChecksFailed.ShouldBe(1);

        var result = Edc15Checksum.VerifyAndCorrect(image);
        result.Corrected.ShouldBeTrue();
        result.WordsCorrected.ShouldBe(1);
        Edc15Checksum.Verify(image).Valid.ShouldBeTrue();
        // nothing changed but the edit itself and the body's correction word
        for (var i = 0; i < Size; i++)
        {
            if (image[i] != good[i])
            {
                (i == 0x62345 || (0x6BFFC <= i && i < 0x6C000)).ShouldBeTrue($"changed 0x{i:X5}");
            }
        }
    }

    [TestMethod]
    public void AValidImageIsLeftAlone()
    {
        var good = CorrectedImage(0x50000);
        var image = (byte[])good.Clone();

        var result = Edc15Checksum.VerifyAndCorrect(image);

        result.Valid.ShouldBeTrue();
        result.Corrected.ShouldBeFalse();
        image.ShouldBe(good);
    }

    [TestMethod]
    public void AnUnexplainedWorkerCallRefusesCorrection()
    {
        var image = SyntheticImage(0x50000);
        // a call to the checksum worker that nothing in the model accounts for
        byte[] call = [0xDA, 0x00, 0x84, 0x15];
        call.CopyTo(image, 0x30000);
        var before = (byte[])image.Clone();

        var result = Edc15Checksum.VerifyAndCorrect(image);

        result.Supported.ShouldBeTrue();
        result.Corrected.ShouldBeFalse();
        result.RefusedReason.ShouldContain("0x30000");
        image.ShouldBe(before);
    }

    [TestMethod]
    public void AnImageWithoutADriverIsNotSupportedAndNotTouched()
    {
        var image = SyntheticImage(0x50000);
        image[Driver] ^= 0xFF;   // no seed sequence -> no driver to read
        var before = (byte[])image.Clone();

        var result = Edc15Checksum.VerifyAndCorrect(image);

        result.Supported.ShouldBeFalse();
        result.Valid.ShouldBeFalse();
        result.Reason.ShouldNotBeNullOrEmpty();
        image.ShouldBe(before);
    }

    [TestMethod]
    public void NonEdc15BuffersAreNotSupported()
    {
        Edc15Checksum.Verify(new byte[0x40000]).Supported.ShouldBeFalse();

        var blank = Enumerable.Repeat((byte)0xFF, Size).ToArray();
        Edc15Checksum.VerifyAndCorrect(blank).Supported.ShouldBeFalse();
        blank.ShouldAllBe(b => b == 0xFF);
    }

    [TestMethod]
    [DataRow(new byte[] { 0xC6, 0x02, 0x24, 0x00 }, "SCXT", "DPP2, #24H")]
    [DataRow(new byte[] { 0xFC, 0x02 }, "POP", "DPP2")]
    [DataRow(new byte[] { 0xF2, 0xF1, 0x00, 0xFE }, "MOV", "R1, DPP0")]
    [DataRow(new byte[] { 0xF6, 0xF1, 0x04, 0xFE }, "MOV", "DPP2, R1")]
    [DataRow(new byte[] { 0x16, 0x02, 0x00, 0x00 }, "ADDC", "DPP2, #0H")]
    [DataRow(new byte[] { 0xEE, 0xF3 }, "BCLR", "R3.14")]
    [DataRow(new byte[] { 0xDA, 0x00, 0x84, 0x15 }, "CALLS", "00H, 1584H")]
    [DataRow(new byte[] { 0xE6, 0xF1, 0x31, 0x86 }, "MOV", "R1, #8631H")]
    [DataRow(new byte[] { 0x36, 0xF6, 0xCD, 0xEF }, "SUBC", "R6, #0EFCDH")]
    [DataRow(new byte[] { 0x22, 0xF0, 0xC4, 0xF8 }, "SUB", "R0, 0F8C4H")]
    [DataRow(new byte[] { 0x04, 0xF3, 0xC0, 0xF8 }, "ADD", "0F8C0H, R3")]
    [DataRow(new byte[] { 0xE0, 0x03 }, "MOV", "R3, #0H")]
    public void TheDecoderRendersTheDriverIdioms(byte[] code, string mnemonic, string operands)
    {
        var ins = C166Decoder.DecodeOne(code, 0, 0x80000);

        ins.Length.ShouldBe(code.Length);
        ins.Mnemonic.ShouldBe(mnemonic);
        ins.Operands.ShouldBe(operands);
    }
}
