using BitFab.KW1281Test.Kwp2000;
using BitFab.KW1281Test.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace BitFab.KW1281Test.EDC15
{
    public class Edc15VM
    {
        public byte[] ReadWriteEeprom(
            string? filename,
            List<KeyValuePair<ushort, byte>>? addressValuePairs = null,
            Action<byte[]>? onPostWriteReadback = null)
        {
            addressValuePairs ??= [];

            var kwp2000 = new KW2000Dialog(_kwpCommon, (byte)_controllerAddress);

            _ = kwp2000.SendReceive(DiagnosticService.startDiagnosticSession, [0x89]);

            _ = kwp2000.SendReceive(DiagnosticService.startDiagnosticSession, [0x85]);

            const byte accMod = 0x41;
            var resp = kwp2000.SendReceive(DiagnosticService.securityAccess, [accMod]);

            // ECU normally doesn't require seed/key authentication the first time it wakes up in
            // KWP2000 mode so sending an empty key is sufficient.
            var buf = new List<byte> { accMod + 1 };

            if (!resp.Body.SequenceEqual(new byte[] { accMod, 0x00, 0x00 }))
            {
                // Normally we'll only get here if we wake up the ECU and it's already in KWP2000 mode,
                // which can happen if a previous download attempt did not complete. In that case we
                // need to calculate and send back a real key.
                var seedBuf = resp.Body.Skip(1).Take(4).ToArray();
                var keyBuf = Edc15KeyAlgorithms.ComputeLvl41Key(0x508DA647, 0x3800000, seedBuf);

                buf.AddRange(keyBuf);
            }
            _ = kwp2000.SendReceive(DiagnosticService.securityAccess, buf.ToArray());

            var loader = Edc15VM.GetEepromLoader();
            var len = loader.Length;

            // Ask the ECU to accept our loader and store it in RAM
            _ = kwp2000.SendReceive(DiagnosticService.requestDownload, [
                0x40, 0xE0, 0x00, // Load address 0x40E000
                0x00, // Not compressed, not encrypted
                (byte)(len >> 16), (byte)(len >> 8), (byte)(len & 0xFF) // Length
                ],
            excludeAddresses: true);

            // Break the loader into blocks and send each one
            var maxBlockLen = resp.Body[0];
            var s = new MemoryStream(loader);
            while (true)
            {
                Thread.Sleep(5);

                var blockBytes = new byte[maxBlockLen];
                var readCount = s.Read(blockBytes, 0, maxBlockLen - 1);
                if (readCount == 0)
                {
                    break;
                }

                SendTransferDataWithRetry(kwp2000, blockBytes.Take(readCount).ToArray());
            }

            // Ask the ECU to execute our loader
            kwp2000.SendMessage(
                DiagnosticService.startRoutineByLocalIdentifier, [0x02],
                excludeAddresses: true);
            _ = kwp2000.ReceiveMessage();

            // Initial 0xA6 "Dump EEPROM": on a pure read this IS the operation; on a write it is NOT
            // needed anymore. Historically a write depended on the dump because the loader set up its
            // EEPROM-bus GPIO directions (DP2.8 data, DP2.9 clock) only inside the dump routine E1C6,
            // so a write with no dump in front of it never drove the clock line and hung. The loader
            // now initialises those directions itself at the start of every write command (the EInit
            // routine added to CmdA7/CmdA8/CmdA9/CmdAA in Loader-EEPROM.a66 /
            // Loader-EEPROM.bin, mirroring E1C6's exact preamble), so a write drives the bus on its
            // own. We therefore dump ONLY on a read, or on a write where the caller explicitly asked
            // for a pre-write backup (a non-null filename); a plain write (clone, Write Full, immo
            // change) does no dump at all.
            var isWrite = addressValuePairs.Count > 0;
            var eeprom = Array.Empty<byte>();
            if (!isWrite || !string.IsNullOrEmpty(filename))
            {
                eeprom = DumpEepromInSession(kwp2000);
                var saveTo = filename ?? "EDC15_EEPROM.bin";
                File.WriteAllBytes(saveTo, eeprom);
                Log.WriteLine($"Saved EEPROM to {saveTo}");
            }

            // Now write any supplied values, via the batched 0xA9/0xAA "write N bytes" commands
            // (WriteEepromBatched, grouped by EEPROM page and chunked to <=255 pairs). This is the
            // only write path now -- the stock loader's one-byte-per-command 0xA7/0xA8 path (and the
            // stock Loader.bin itself) were removed once the batched loader became the single EEPROM
            // loader for both reads and writes. VerboseLog=false routes SendMessage/ReceiveMessage's
            // routine per-field trace lines to the log file instead of the screen (see VerboseLog's
            // own doc comment) so a large write doesn't cause the spinner/log choppiness the flash
            // path had before its own equivalent fix.
            kwp2000.VerboseLog = false;
            if (addressValuePairs.Count > 0)
            {
                WriteEepromBatched(kwp2000, addressValuePairs);
            }

            // In-session verification read-back: if the caller asked for it and we actually wrote
            // something, dump the EEPROM one more time -- while the loader is still resident and
            // BEFORE the 0xA2 reboot below. This is the whole point of doing it here: the main ECU
            // firmware hasn't run yet, so nothing has revalidated the immobilizer records and
            // rewritten their status/checksum bytes (the "self-correcting" offsets a post-reboot
            // read-back sees). What comes back is exactly what we just wrote, so the caller can do a
            // plain byte-for-byte compare with no special-offset allowance. We only capture the image
            // and hand it back -- the caller runs the actual comparison/notification later (it can
            // happen after the reboot; only the read itself has to be pre-reboot).
            if (onPostWriteReadback != null && addressValuePairs.Count > 0)
            {
                Log.WriteLine("Reading EEPROM back for verification (in loader session, before reboot)...");
                eeprom = DumpEepromInSession(kwp2000);
                onPostWriteReadback(eeprom);
            }

            // Custom loader command to reboot the ECU to return it to normal operation.
            kwp2000.SendMessage(
                    (DiagnosticService)0xA2, [],
                excludeAddresses: true);
            _ = kwp2000.ReceiveMessage();

            var b = _kwpCommon.Interface.ReadByte();
            if (b == 0x55)
            {
                Log.WriteLine($"Reboot successful!");
            }

            return eeprom;
        }

        /// <summary>
        /// The K-line can drop a byte mid-transfer during the (slow, multi-chunk) loader upload.
        /// Retry the individual chunk rather than aborting the whole read/write. Used for every
        /// loader upload in this class (EEPROM loader and the sector-erase loader). Incorporates
        /// gmenounos/kw1281test#185.
        /// </summary>
        private static void SendTransferDataWithRetry(
            KW2000Dialog kwp2000, byte[] data, int maxAttempts = 3)
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    _ = kwp2000.SendReceive(
                        DiagnosticService.transferData, data, excludeAddresses: true);
                    return;
                }
                catch (TimeoutException) when (attempt < maxAttempts)
                {
                    Log.WriteLine(
                        $"Timed out sending loader block (attempt {attempt}/{maxAttempts})." +
                        " Retrying...");
                    Thread.Sleep(200);
                }
            }
        }

        /// <summary>Issues the loader's 0xA6 "Dump EEPROM" command once, on an already-running loader
        /// session, and returns all 512 bytes it clocks back. Factored out of
        /// <see cref="ReadWriteEeprom"/> so the same wire dance (first ACK, 512 raw bytes, trailing
        /// ACK -- see the loader's CmdA6 -> E1C6 -> Cmd36x path) can be used both for the pre-write
        /// dump and for the optional post-write verification read-back, without duplicating it.
        /// Assumes the loader is already uploaded and started (as it is by the time
        /// <see cref="ReadWriteEeprom"/> calls this).</summary>
        private byte[] DumpEepromInSession(KW2000Dialog kwp2000)
        {
            kwp2000.SendMessage((DiagnosticService)0xA6, [], excludeAddresses: true);
            var resp = kwp2000.ReceiveMessage();
            if (!resp.IsPositiveResponse(DiagnosticService.transferData))
            {
                throw new InvalidOperationException("Dump EEPROM failed.");
            }

            var eeprom = new byte[512];
            for (var i = 0; i < 512; i++)
            {
                eeprom[i] = _kwpCommon.Interface.ReadByte();
            }

            _ = kwp2000.ReceiveMessage(); // trailing ACK the loader sends after the 512-byte dump
            return eeprom;
        }


        /// <summary>
        /// Writes addressValuePairs to EEPROM using the loader's 0xA9/0xAA batched "write N bytes"
        /// commands (Loader-EEPROM.bin). Pairs are grouped into maximal runs of the same EEPROM page (address &lt;=
        /// 0xFF =&gt; page 0, else page 1), preserving the caller's original order across runs,
        /// and each run is further chunked to at most 255 pairs -- the loader's count parameter
        /// (E3W0/E3W1's R4, moved in from a single byte in the command buffer) can't represent
        /// more than that in one command.
        /// </summary>
        private void WriteEepromBatched(
            KW2000Dialog kwp2000, List<KeyValuePair<ushort, byte>> addressValuePairs)
        {
            const int maxPairsPerChunk = 255;

            var i = 0;
            while (i < addressValuePairs.Count)
            {
                var page1 = addressValuePairs[i].Key > 0xFF;

                var runEnd = i + 1;
                while (runEnd < addressValuePairs.Count &&
                       (addressValuePairs[runEnd].Key > 0xFF) == page1 &&
                       runEnd - i < maxPairsPerChunk)
                {
                    runEnd++;
                }

                var count = runEnd - i;
                var service = (DiagnosticService)(page1 ? 0xAA : 0xA9);

                kwp2000.SendMessage(service, [(byte)count], excludeAddresses: true);
                var resp = kwp2000.ReceiveMessage();
                if (!resp.IsPositiveResponse(DiagnosticService.transferData))
                {
                    throw new InvalidOperationException($"Write EEPROM (batched) failed.");
                }

                var raw = new byte[count * 2];
                for (var j = 0; j < count; j++)
                {
                    var pair = addressValuePairs[i + j];
                    raw[j * 2] = (byte)(pair.Key & 0xFF);
                    raw[j * 2 + 1] = pair.Value;
                }

                _kwpCommon.WriteBytes(raw);
                Log.WriteLine(
                    $"Sent {count} pairs to page {(page1 ? 1 : 0)}: {Utils.DumpBytes(raw)}",
                    LogDest.File);

                resp = kwp2000.ReceiveMessage();
                if (!resp.IsPositiveResponse(DiagnosticService.transferData))
                {
                    throw new InvalidOperationException($"Write EEPROM (batched) failed.");
                }

                i = runEnd;
            }
        }

        /// <summary>
        /// The values DisplayEepromInfo computes from an EDC15 EEPROM image and displays it.
        /// </summary>
        public readonly record struct Edc15EepromInfo(
            ushort Skc,
            double OdometerKm,
            string Vin,
            string ImmoNumber,
            string ImmoId,
            bool ImmoIsOn);

        public static Edc15EepromInfo GetEepromInfo(ReadOnlySpan<byte> eeprom)
        {
            var skc = Utils.GetShort(eeprom, 0x12E);

            double odometerKm =
                eeprom[0x1BF] +
                (eeprom[0x1C0] << 8) +
                (eeprom[0x1C1] << 16) +
                ((eeprom[0x1C2] & 0x3F) << 24);
            odometerKm /= 100.0;

            var vin = Utils.DumpAscii(eeprom.Slice(0x140, 17).ToArray());
            var immoNumber = Utils.DumpAscii(eeprom.Slice(0x131, 14).ToArray());
            var immoId = Utils.DumpBytes(eeprom.Slice(0x126, 7).ToArray());

            const ushort immo1Addr = 0x1B0;
            var immo1 = eeprom[immo1Addr];
            const ushort immo2Addr = 0x1DE;
            var immo2 = eeprom[immo2Addr];
            var immoIsOn = !(immo1 == 0x60 && immo2 == 0x60);

            return new Edc15EepromInfo(skc, odometerKm, vin, immoNumber, immoId, immoIsOn);
        }

        public static void DisplayEepromInfo(ReadOnlySpan<byte> eeprom)
        {
            var info = GetEepromInfo(eeprom);
            Log.WriteLine($"SKC: {info.Skc:D5}");
            Log.WriteLine($"Odometer: {info.OdometerKm} km");
            Log.WriteLine($"VIN: {info.Vin}");
            Log.WriteLine($"Immo Number: {info.ImmoNumber}");
            Log.WriteLine($"Immo Id: {info.ImmoId}");
            const ushort immo1Addr = 0x1B0;
            const ushort immo2Addr = 0x1DE;
            var immoStatus = info.ImmoIsOn ? "On" : "Off";
            Log.WriteLine(
                $"Immo is {immoStatus} (${immo1Addr:X3}=${eeprom[immo1Addr]:X2}, " +
                $"${immo2Addr:X3}=${eeprom[immo2Addr]:X2})");
        }

        /// <summary>
        /// The single EEPROM loader used for both reads and writes: reads/writes the serial EEPROM,
        /// exposes the 0xA9/0xAA "write N bytes" batched-write commands, and sets up its own
        /// EEPROM-bus GPIO directions at the start of every write (the EInit routine) so a write
        /// needs no dump in front of it. See Loader-EEPROM.a66 (assembled to
        /// Loader-EEPROM.bin with Tools/c166/reasm.py, verified byte-identical to Keil, and
        /// validated on hardware). Replaced the stock single-byte-write Loader.bin, which is
        /// gone -- this loader is a strict superset of it.
        /// </summary>
        private static byte[] GetEepromLoader() =>
            GetLoaderFromResource("BitFab.KW1281Test.EDC15.Loader-EEPROM.bin");


        /// <summary>
        /// Shared by GetEepromLoader()/GetSectorEraseLoader(): loads the named embedded resource and
        /// patches it exactly the way the ECU's boot ROM requires -- see the "must be EFCD8631"
        /// comment below. This patching is entirely a function of the resource's own bytes and
        /// length, so it applies unchanged to any loader binary of any size/content, including a
        /// larger one with new commands appended (no manual checksum work needed when swapping in
        /// a different compiled loader).
        /// </summary>
        private static byte[] GetLoaderFromResource(string resourceName)
        {
            // Use the assembly that actually contains the embedded resource. On Android
            // Assembly.GetEntryAssembly() can return null, so GetEntryAssembly() is not safe here.
            var assembly = typeof(Edc15VM).Assembly;
            var resourceStream = assembly.GetManifestResourceStream(resourceName);
            if (resourceStream == null)
            {
                throw new InvalidOperationException(
                    $"Unable to load {resourceName} embedded resource.");
            }

            var loaderLength = resourceStream.Length + 4; // Add 4 bytes for checksum correction
            loaderLength = (loaderLength + 7) / 8 * 8; // Round up to a multiple of 8 bytes
            var buf = new byte[loaderLength];

            resourceStream.ReadExactly(buf, 0, (int)resourceStream.Length);

            // In order for this loader to be executed by the ECU, the checksum of all the bytes
            // must be EFCD8631.

            // Patch the loader with the location of the end (actually 1 byte past the end)
            ushort loaderEnd = (ushort)(0xE000 + loaderLength);
            buf[0x0E] = (byte)(loaderEnd & 0xFF);
            buf[0x0F] = (byte)(loaderEnd >> 8);

            // Take the checksum of the loader up to but not including the checksum correction
            ushort r6 = 0xEFCD;
            ushort r1 = 0x8631;
            Checksum(ref r6, ref r1, buf.Take(buf.Length - 4).ToArray());

            // Calculate the checksum correction bytes and insert them at the end of the loader
            var padding = CalcPadding(r6, r1);
            Array.Copy(padding, 0, buf, buf.Length - 4, 4);

            return buf;
        }

        /// <summary>
        /// Calculate the checksum correction padding needed to result in a checksum of EFCD8631
        /// </summary>
        /// <param name="r6"></param>
        /// <param name="r1"></param>
        /// <returns></returns>
        private static byte[] CalcPadding(ushort r6, ushort r1)
        {
            var paddingH = (ushort)(0xDF9B ^ r6);
            var paddingL = (ushort)(r1 - 0xAB85);

            return
            [
                (byte)(paddingL & 0xFF),
                (byte)(paddingL >> 8),
                (byte)(paddingH & 0xFF),
                (byte)(paddingH >> 8)
            ];
        }

        /// <summary>
        /// EDC15 checksum algorithm (sub_1584).
        /// Calculates a 32-bit checksum of an array of bytes based on an initial 32-bit seed.
        /// Based on https://www.ecuconnections.com/forum/viewtopic.php?f=211&t=49704&sid=5cf324c44d2c74d372984f428ffea5ed
        /// </summary>
        /// <param name="r6">Input: High word of seed, Output: High word of checksum</param>
        /// <param name="r1">Input: Low word of seed, Output: Low word of checksum</param>
        /// <param name="buf">Buffer to calculate checksum for</param>
        static void Checksum(ref ushort r6, ref ushort r1, byte[] buf)
        {
            int r3 = 0; // Buffer index
            int r0 = buf.Length;
            while (true)
            {
                r1 ^= GetBuf(buf, r3); r3 += 2;
                r1 = Rol(r1, r6, out ushort c);
                r6 = (ushort)(r6 - GetBuf(buf, r3) - c); r3 += 2;
                r6 ^= r1;
                if (r3 >= r0)
                {
                    break;
                }

                r1 = (ushort)(r1 - GetBuf(buf, r3) - 1); r3 += 2;
                r1 += 0xDAAD;
                r6 ^= GetBuf(buf, r3); r3 += 2;
                r6 = Ror(r6, r1);
                if (r3 >= r0)
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Rotates a 16-bit value right by count bits.
        /// </summary>
        private static ushort Ror(ushort value, ushort count)
        {
            count &= 0xF;
            value = (ushort)((value >> count) | (value << (16 - count)));
            return value;
        }

        /// <summary>
        /// Rotates a 16-bit value left by count bits. Carry will be equal to the last bit rotated
        /// or 0 if the low 4 bits of count are 0;
        /// </summary>
        private static ushort Rol(ushort value, ushort count, out ushort carry)
        {
            count &= 0xF;
            value = (ushort)((value << count) | (value >> (16 - count)));
            carry = ((value & 1) == 0 || (count == 0)) ? (ushort)0 : (ushort)1;
            return value;
        }

        private static ushort GetBuf(byte[] buf, int ix)
        {
            return (ushort)(buf[ix] + (buf[ix + 1] << 8));
        }

        private readonly IKwpCommon _kwpCommon;
        private readonly int _controllerAddress;

        public Edc15VM(IKwpCommon kwpCommon, int controllerAddress)
        {
            _kwpCommon = kwpCommon;
            _controllerAddress = controllerAddress;
        }
    }
}
