# Cyber Crypter

An educational crypter developed for my Computer Engineering Bachelor's Thesis.

The project takes an `.exe` flagged as a threat by antivirus engines, converts it into position-independent shellcode with [Donut](https://github.com/TheWover/donut), encrypts it with a unique AES-256 key for each build, and generates a self-contained native loader from the compiled stub. When executed, the loader decrypts the payload and executes it in memory using the technique implemented by the stub selected at build time, evading a large number of modern antivirus engines.

> **Project for academic use only**: Its purpose is to study modern techniques found in malware analysis (semi-bound payloads, dynamic key derivation, EarlyBird APC injection, anti-tamper through hashing of the binary itself, ...) by building a complete crypter from start to finish.

## Implemented techniques

- **Hybrid semi-bound payload**: the encrypted code is split into two parts:
  - `half1` (up to 1 MiB) embedded in a custom `.cdata` section within the stub.
  - `half2` (unlimited size) appended as a PE overlay after the last section.
  - The stub reassembles `half1 || half2` before decryption.
- **Dynamic AES key**:
  `key = SHA256( heap_marker || stub_file[0..4096] || timestamp )`.
  - `heap_marker` and `timestamp` are generated for each build and stored in the embedded metadata.
  - The first 4 KiB of the file itself are included in the hash calculation → any patching of the PE headers or `.text` invalidates the key (anti-tamper).
- **AES-256-CBC encryption with PKCS#7** using `System.Security.Cryptography` in the builder and Windows CNG (`bcrypt.dll`) in the stub. The IV is random for each build and stored in the embedded metadata.
- **EarlyBird APC injection** as the in-memory injection technique:
  ```
  CreateProcessA(notepad, CREATE_SUSPENDED)
  VirtualAllocEx(RWX) -> WriteProcessMemory(shellcode)
  QueueUserAPC((PAPCFUNC)mem, hThread, 0)
  ResumeThread
  ```

## Repository structure

```
Cyber-Crypter-main/
├── Cyber Cripter.sln
├── Cyber Cripter/                # Builder (C# WinForms, .NET Framework 4.8)
│   ├── Form1.cs / Form1.Designer.cs
│   ├── Encryption.cs             # AES-256-CBC + SHA-256 + DeriveKey()
│   ├── Donut.cs                  # invokes donut.exe as a subprocess
│   ├── StubBuilder.cs            # binary patching of stub_template.exe
│   └── Resources/
│       └── stub_template.exe     # produced by stub/build.bat
├── stub/                         # Native stub (C, MSVC x64)
│   ├── stub_EarlyBirdAPC.c
│   ├── stub_IndirectSC.c
│   ├── stub_Test.c
│   ├── build.bat
│   └── README.md
└── outputs/                      # destination for encrypted binaries
```

## Prerequisites

- **Visual Studio 2019 / 2022** with the **Desktop development with C++** workload (required for `cl.exe`, `link.exe`, Windows SDK headers, and `bcrypt.lib`).
- **.NET Framework 4.8 SDK** (required to compile the C# builder).
- **donut.exe** from https://github.com/TheWover/donut/releases.

## Build

### 1) Native stub

These steps only need to be performed once, or whenever `stub.c` is modified.

#### 1.1) Install the C++ build tools

1. Open `Visual Studio Installer`.
2. Click **Modify** on your Visual Studio 2022 installation.
3. On the **Workloads** tab, select **"Desktop development with C++"**.
4. Click **Modify** to install it.

> If the checkbox was already selected, you do not need to perform this step.

#### 1.2) Build the stub

1. Open the Start menu, type `x64 Native Tools`, and click **"x64 Native Tools Command Prompt for VS 2022"**.
2. In the terminal that opens, navigate to the `stub` folder:

```cmd
cd "\CyberCrypter\stub"
```

3. Run the build script:

```cmd
build.bat
```

After it completes, `build.bat` compiles the `stub_EarlyBirdAPC.c` variant, producing `stub/build/stub_template.exe` and automatically copying it to `CyberCrypter\Resources\stub_template.exe` (the location from which the builder looks up the stub at runtime).

4. Quick layout check (optional):

```cmd
dumpbin /headers build\stub_template.exe | findstr /I /C:"SECTION HEADER" /C:"name" /C:"size of raw data"
```

`.cdata` (SECTION HEADER #5) must have `size of raw data` ≥ `100040`. If it is `0`, MSVC truncated the buffer due to BSS optimization. See `stub/README.md` for error mitigation.

### 2) C# builder

Open `CyberCrypter.sln` in Visual Studio and build the project.

The executable program will be saved to `CyberCrypter\bin\Debug\CyberCrypter.exe`.

### 3) Place `donut.exe`

Download `donut.exe` and copy it to `CyberCrypter\bin\Debug\`, alongside the builder executable (it can also be placed in the `PATH`).

> You will very likely need to disable antivirus protection to download donut.exe, or add the project directory to Windows Defender exclusions.

## Usage

1. Run `Cyber Cripter.exe`.
2. **Browse** → select the `.exe` executable you want to encrypt so it evades antivirus.
3. **ENCRYPT**.
4. The status panel shows:
   - the size of the shellcode generated by Donut,
   - the size of the ciphertext after AES,
   - the split between `half1` (embedded) and `half2` (overlay),
   - the build timestamp,
   - the derived key in hexadecimal (for educational verification only).
5. The encrypted binary appears in `outputs\<name>_crypted.exe`.

When it is executed, that binary:

- Reads its own bytes from disk.
- Re-derives the AES key using the same formula used by the builder.
- Reassembles and decrypts the encrypted code split between `half1 || half2`.
- Starts `notepad.exe` suspended and injects the shellcode through EarlyBird APC.
- Runs the original payload inside the `notepad.exe` process.

## Technical considerations

- **Donut produces shellcode, not a PE.** This is necessary because EarlyBird APC executes a memory address as if it were a function. That requires position-independent code, not a PE with headers, IAT, relocations, etc.
- **The stub does not store the key.** It only stores `heap_marker`, `timestamp`, and the `IV`. The AES key is reconstructed at runtime from these values and the first 4 KiB of the file itself.
- **`CyberCripter.exe` and the binaries in `outputs/` use the x64 architecture.** The stub is compiled with `/MACHINE:X64` and Donut is invoked with `-a 2` to generate shellcode for the same architecture.

## Notice

This code is maintained solely for educational and research purposes. Its use outside an authorized academic environment or an isolated lab is the responsibility of the person running it.
