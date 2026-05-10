using System.IO;
using System.Security.Cryptography;

namespace Cyber_Cripter
{
    /// <summary>
    /// Crypto primitives used by the builder. The byte layout and parameters
    /// here MUST stay in sync with what the native stub re-implements via
    /// Windows CNG (BCrypt) on the decrypt side.
    /// </summary>
    internal static class Encryption
    {
        /// <summary>
        /// AES-256-CBC encrypt with PKCS#7 padding. Matches BCryptEncrypt with
        /// BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC, BCRYPT_BLOCK_PADDING.
        /// </summary>
        public static byte[] EncryptAes256Cbc(byte[] plaintext, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (var enc = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        /// <summary>
        /// SHA-256 over a single buffer. Returns the full 32-byte digest.
        /// </summary>
        public static byte[] Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        /// <summary>
        /// Re-implements the stub's key derivation:
        ///     SHA256( heap_marker(8) || stubBytes[0..hashRegion] || timestamp(8 LE) )
        /// The stub bytes inside the hash give anti-tamper: any modification of
        /// the hashed prefix invalidates the resulting key.
        /// </summary>
        public static byte[] DeriveKey(byte[] heapMarker, byte[] stubBytes, int hashRegion, ulong timestamp)
        {
            byte[] buf = new byte[8 + hashRegion + 8];
            System.Buffer.BlockCopy(heapMarker, 0, buf, 0, 8);
            System.Buffer.BlockCopy(stubBytes,  0, buf, 8, hashRegion);
            // little-endian uint64 timestamp (matches MSVC x64 layout of g_meta.timestamp)
            for (int i = 0; i < 8; i++) buf[8 + hashRegion + i] = (byte)(timestamp >> (8 * i));
            return Sha256(buf);
        }
    }
}
