# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`Cyber Cripter` is a coursework crypter for a Computer Security course. It takes
an arbitrary `.exe`, converts it to position-independent shellcode (Donut),
encrypts the shellcode with a per-build AES-256 key, and emits a self-contained
native loader that decrypts and runs the payload via EarlyBird APC injection
into a suspended `notepad.exe`.

The project ships as **two binaries that must agree on a wire format**:

- **`Cyber Cripter/`** — the C# WinForms builder (.NET Framework 4.8). User-facing.
- **`stub/`** — a native C stub (MSVC x64, no CRT init) compiled once into a
  template. The builder patches this template per build; it does not recompile
  the stub.

## Build & run

The two halves are built separately.

**Native stub (one-time, then on any C-source change):**
```cmd
:: from a "x64 Native Tools Command Prompt for VS"
cd stub
build.bat
```
This produces `stub/build/stub_template.exe` and auto-copies it to
`Cyber Cripter/Resources/stub_template.exe` (where the C# builder loads it
from at runtime via `AppDomain.CurrentDomain.BaseDirectory`).

**C# builder:**
```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" `
  ".\Cyber Cripter\Cyber Cripter.csproj" /t:Rebuild /p:Configuration=Debug /v:minimal
```
Output goes to `Cyber Cripter/bin/Debug/Cyber Cripter.exe`.

**Runtime extra dependency:** `donut.exe` from
https://github.com/TheWover/donut/releases must sit either next to the built
`Cyber Cripter.exe` or somewhere on `PATH`. Without it the encrypt button fails.

There are no tests. There is no linter configured. The project is .NET Framework
4.8, not .NET (Core/5+).

## Architecture: how the two halves stay in sync

The whole system rests on **byte-for-byte agreement** between the C# builder
(`StubBuilder.cs` + `Encryption.cs`) and the C stub (`stub/stub.c`). Every
constant duplicated below has to match across both files.

### Layout the builder patches into the stub

The compiled stub binary contains, in its custom `.cdata` section:

- `g_meta` — `StubMetadata` struct (60 bytes, `#pragma pack(1)`), located by
  the 16-byte `METADATA_MAGIC`.
- `g_half1_buf` — 16-byte `HALF1_MAGIC` followed by a 1 MiB capacity buffer.

After patching, the file also has a **PE overlay** appended after the last
section: the raw bytes of `half2`. The PE loader ignores overlays.

The `StubMetadata` field order (immediately after the 16-byte magic) is:
`heap_marker[8]`, `timestamp` (LE u64), `iv[16]`, `half1_size` (LE u32),
`half2_size` (LE u32), `hash_region_size` (LE u32). The constants
`OFF_HEAP_MARKER..OFF_HASH_REGION` in `StubBuilder.cs` mirror this layout.

### Dynamic key derivation (the anti-tamper hook)

```
key = SHA256( heap_marker(8) || stub_file[0..STABLE_REGION] || timestamp(8 LE) )
```

- `heap_marker` is 8 random bytes generated per build by the builder. It is
  stored in the metadata. Despite the name, it is **not** the runtime
  `GetProcessHeap()` — that value can't be reproduced between build and runtime.
- `stub_file[0..STABLE_REGION]` is the first `STABLE_REGION = 4096` bytes of
  the on-disk file. The builder hashes them from the unpatched template, the
  stub hashes them from its own file via `GetModuleFileNameA` + `ReadFile`.
  This is the anti-tamper hook: any modification of those 4 KiB invalidates
  the key. The builder enforces both magic offsets be `>= STABLE_REGION`, so
  patching never disturbs the hashed prefix.
- `timestamp` is `DateTimeOffset.UtcNow.ToUnixTimeSeconds()` at build, written
  little-endian to match the MSVC x64 `unsigned long long` layout.

The IV is a separate random 16 bytes, stored in metadata — not derived.

### Constants that must stay in sync

| Constant            | C stub (`stub.c`)        | C# builder (`StubBuilder.cs`) |
|---------------------|--------------------------|-------------------------------|
| `HALF1_MAX`         | `#define HALF1_MAX 0x100000` | `public const int HALF1_MAX = 0x100000` |
| `STABLE_REGION`     | implicit (uses `g_meta.hash_region_size`) | `public const int STABLE_REGION = 4096` |
| `METADATA_MAGIC`    | `g_meta.magic` initializer | `METADATA_MAGIC` byte array |
| `HALF1_MAGIC`       | `g_half1_buf` first 16 bytes | `HALF1_MAGIC` byte array |
| Metadata field order | `StubMetadata` struct order | `OFF_*` constants |

If you change any of the above on one side, change it on the other and rebuild
**the stub template first**, then the C# builder. The C# builder will refuse
to patch a template whose magics don't match or whose `.cdata` is too small.

## Common pitfalls

- **`.cdata` BSS truncation.** `g_half1_buf` is 1 MiB of mostly zero. MSVC
  must keep the whole array on disk (initialized data) — if it puts the tail
  in BSS, `dumpbin /headers stub_template.exe` will show `.cdata` `size of raw
  data` < `0x100040` and the builder fails with "stub template too small".
  Mitigation: add a few non-zero bytes near the end of `g_half1_buf`'s
  initializer and rebuild.
- **Donut output is shellcode, not PE.** EarlyBird APC executes a memory
  address as a `PAPCFUNC`. That works only on PIC shellcode. Donut's `-f 1`
  flag is correct here; do not change to a PE output format.
- **EarlyBird semantics.** The APC is queued on the *primary thread* of a
  `CREATE_SUSPENDED` `notepad.exe`. It fires during the loader's alertable
  wait early in process startup. Do not call `WaitForSingleObject(thread)`
  before `ResumeThread` and do not queue the APC after the thread is resumed.
- **Stub stores no key.** Only `heap_marker`, `timestamp` and `IV` are stored.
  The actual AES key is derived at runtime; do not try to read it from the
  binary.

## Output flow

User clicks ENCRYPT in `Form1` →
`Donut.Convert(inputExe)` (subprocess) →
`StubBuilder.Build(template, shellcode, outputs/<name>_crypted.exe)` →
status panel reports shellcode/ciphertext sizes, half1/half2 split, build
timestamp, and the derived key (hex, for educational verification).
