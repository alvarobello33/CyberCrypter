namespace Cyber_Cripter
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Código generado por el Diseñador de Windows Forms

        private void InitializeComponent()
        {
            this.fileRoute = new System.Windows.Forms.Label();
            this.browseFile = new System.Windows.Forms.Button();
            this.encryptBtn = new System.Windows.Forms.Button();
            this.title = new System.Windows.Forms.Label();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.statusTextBox = new System.Windows.Forms.TextBox();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // fileRoute
            // 
            this.fileRoute.BackColor = System.Drawing.SystemColors.ButtonHighlight;
            this.fileRoute.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F);
            this.fileRoute.Location = new System.Drawing.Point(24, 110);
            this.fileRoute.Name = "fileRoute";
            this.fileRoute.Size = new System.Drawing.Size(454, 32);
            this.fileRoute.TabIndex = 1;
            this.fileRoute.Text = "File to encrypt path";
            this.fileRoute.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // browseFile
            // 
            this.browseFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 11.25F);
            this.browseFile.Location = new System.Drawing.Point(490, 110);
            this.browseFile.Name = "browseFile";
            this.browseFile.Size = new System.Drawing.Size(82, 32);
            this.browseFile.TabIndex = 2;
            this.browseFile.Text = "Browse";
            this.browseFile.UseVisualStyleBackColor = true;
            this.browseFile.Click += new System.EventHandler(this.browseFile_Click);
            // 
            // encryptBtn
            // 
            this.encryptBtn.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(60)))), ((int)(((byte)(110)))), ((int)(((byte)(180)))));
            this.encryptBtn.Cursor = System.Windows.Forms.Cursors.Hand;
            this.encryptBtn.FlatAppearance.BorderSize = 0;
            this.encryptBtn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.encryptBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Bold);
            this.encryptBtn.ForeColor = System.Drawing.Color.White;
            this.encryptBtn.Location = new System.Drawing.Point(170, 168);
            this.encryptBtn.Name = "encryptBtn";
            this.encryptBtn.Size = new System.Drawing.Size(260, 56);
            this.encryptBtn.TabIndex = 3;
            this.encryptBtn.Text = "ENCRYPT";
            this.encryptBtn.UseVisualStyleBackColor = false;
            this.encryptBtn.Click += new System.EventHandler(this.encryptBtn_Click);
            // 
            // title
            // 
            this.title.BackColor = System.Drawing.Color.Transparent;
            this.title.Font = new System.Drawing.Font("Microsoft Sans Serif", 18F, System.Drawing.FontStyle.Bold);
            this.title.ForeColor = System.Drawing.Color.White;
            this.title.Image = global::Cyber_Cripter.Properties.Resources.titleCrypter;
            this.title.Location = new System.Drawing.Point(24, 23);
            this.title.Name = "title";
            this.title.Size = new System.Drawing.Size(540, 50);
            this.title.TabIndex = 0;
            this.title.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // pictureBox1
            // 
            this.pictureBox1.Location = new System.Drawing.Point(0, 0);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(0, 0);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.pictureBox1.TabIndex = 4;
            this.pictureBox1.TabStop = false;
            this.pictureBox1.Visible = false;
            // 
            // statusTextBox
            // 
            this.statusTextBox.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(20)))), ((int)(((byte)(23)))), ((int)(((byte)(28)))));
            this.statusTextBox.ForeColor = System.Drawing.SystemColors.WindowText;
            this.statusTextBox.Location = new System.Drawing.Point(29, 267);
            this.statusTextBox.Multiline = true;
            this.statusTextBox.Name = "statusTextBox";
            this.statusTextBox.ReadOnly = true;
            this.statusTextBox.Size = new System.Drawing.Size(535, 175);
            this.statusTextBox.TabIndex = 5;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(35)))), ((int)(((byte)(39)))), ((int)(((byte)(42)))));
            this.ClientSize = new System.Drawing.Size(596, 470);
            this.Controls.Add(this.statusTextBox);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.encryptBtn);
            this.Controls.Add(this.browseFile);
            this.Controls.Add(this.fileRoute);
            this.Controls.Add(this.title);
            this.Name = "Form1";
            this.Text = "CYBER CRIPTER";
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label title;
        private System.Windows.Forms.Button encryptBtn;
        private System.Windows.Forms.Label fileRoute;
        private System.Windows.Forms.Button browseFile;
        private System.Windows.Forms.PictureBox pictureBox1;
        private System.Windows.Forms.TextBox statusTextBox;
    }
}
