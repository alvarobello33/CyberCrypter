;
; syscall.asm — Trampolín de indirect syscall para x64 (MASM, ml64.exe).
;
; MSVC no soporta ensamblador inline en x64, así que el trampolín vive en este
; fichero externo. El stub C lo enlaza como un símbolo `do_syscall`.
;
; Flujo de una llamada do_syscall(arg1, arg2, ...):
;
;   1. El compilador C coloca arg1..arg4 en rcx/rdx/r8/r9 y el resto en pila,
;      tal y como exige la ABI x64 de Windows.
;   2. El stub C escribe el SSN (System Service Number) en g_current_ssn
;      y la dirección del gadget `syscall; ret` (situado en ntdll) en
;      g_syscall_gadget, ANTES de llamar a do_syscall.
;   3. do_syscall:
;        - Mueve rcx a r10 (la convención del syscall espera el 1er arg en r10).
;        - Carga el SSN en EAX.
;        - JMP al gadget dentro de ntdll. El gadget es `syscall; ret`, así que
;          la instrucción syscall se ejecuta desde memoria de ntdll (no desde
;          nuestro propio .text), evadiendo los hooks de userland que comprueban
;          "¿la llamada proviene de fuera de ntdll?".
;        - El `ret` del gadget devuelve el control al llamante original de do_syscall.
;
; Limitación: g_current_ssn/g_syscall_gadget son globales, por tanto este
; trampolín NO es thread-safe. El stub es single-threaded, así que basta.
;

.code

EXTRN g_current_ssn:DWORD
EXTRN g_syscall_gadget:QWORD

do_syscall PROC
    mov r10, rcx                            ; convención syscall: 1er arg en r10
    mov eax, dword ptr [g_current_ssn]      ; SSN del Nt* objetivo
    jmp qword ptr [g_syscall_gadget]        ; salto a 'syscall; ret' dentro de ntdll
do_syscall ENDP

END
