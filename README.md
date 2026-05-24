# Cyber Cripter

Crypter educativo para una asignatura de Computer Security. Toma un `.exe`
arbitrario, lo convierte a shellcode posicional-independiente con
[Donut](https://github.com/TheWover/donut), lo encripta con una clave AES-256
única por build, y genera un loader nativo autosuficiente que al ejecutarse
desencripta el payload e inyecta el shellcode en una instancia suspendida de
`notepad.exe` mediante **EarlyBird APC injection**.

> Proyecto de uso académico. La idea es estudiar las técnicas que aparecen en
> análisis de malware (semi-binded payload, derivación dinámica de clave,
> inyección APC temprana, anti-tamper por hash del propio binario) construyendo
> un crypter completo de principio a fin.

## Técnicas implementadas

- **Payload semi-binded híbrido**: el ciphertext se parte en dos.
  - `half1` (hasta 1 MiB) va embebido en una sección custom `.cdata` del stub.
  - `half2` (sin límite) se appendea como overlay PE detrás de la última sección.
  - El stub reensambla `half1 || half2` antes de descifrar.
- **Clave AES dinámica**:
  `key = SHA256( heap_marker || stub_file[0..4096] || timestamp )`.
  - `heap_marker` y `timestamp` se generan en cada build y se almacenan en el
    metadata embebido.
  - Los primeros 4 KiB del propio fichero entran en el hash → cualquier
    parcheo de cabeceras PE o `.text` invalida la clave (anti-tamper).
- **AES-256-CBC con PKCS#7** vía `System.Security.Cryptography` en el builder
  y Windows CNG (`bcrypt.dll`) en el stub. El IV es aleatorio por build y se
  guarda en el metadata.
- **EarlyBird APC injection** en `notepad.exe` suspendido:
  ```
  CreateProcessA(notepad, CREATE_SUSPENDED)
  VirtualAllocEx(RWX) -> WriteProcessMemory(shellcode)
  QueueUserAPC((PAPCFUNC)mem, hThread, 0)
  ResumeThread
  ```

## Estructura del repositorio

```
Cyber-Crypter-main/
├── Cyber Cripter.sln
├── Cyber Cripter/                # Builder (C# WinForms, .NET Framework 4.8)
│   ├── Form1.cs / Form1.Designer.cs
│   ├── Encryption.cs             # AES-256-CBC + SHA-256 + DeriveKey()
│   ├── Donut.cs                  # invoca donut.exe como subproceso
│   ├── StubBuilder.cs            # parcheo binario del stub_template.exe
│   └── Resources/
│       └── stub_template.exe     # producido por stub/build.bat
├── stub/                         # Stub nativo (C, MSVC x64)
│   ├── stub.c
│   ├── build.bat
│   └── README.md
├── outputs/                      # destino de los binarios crypteados
└── CLAUDE.md                     # notas de arquitectura para Claude Code
```

## Requisitos

- **Visual Studio 2019 / 2022** con la workload **Desarrollo de escritorio con C++**
  (necesario para `cl.exe`, `link.exe`, las cabeceras del Windows SDK y `bcrypt.lib`).
- **.NET Framework 4.8 SDK** (para compilar el builder C#).
- **donut.exe** de https://github.com/TheWover/donut/releases.

## Compilación

### 1) Stub nativo (una sola vez, o cuando se modifique `stub.c`)

#### 1.1) Instalar las herramientas de compilación de C++

1. Abre `Visual Studio Installer`.
2. Haz clic en **Modificar** sobre tu instalación de Visual Studio 2022.
3. En la pestaña **Cargas de trabajo**, marca **"Desarrollo de escritorio con C++"**.
4. Pulsa **Modificar** para instalar.

> Si el recuadro ya estaba marcado, no necesitas hacer este paso.

#### 1.2) Compilar el stub

1. Abre el menú Inicio, escribe `x64 Native Tools` y haz clic en
   **"x64 Native Tools Command Prompt for VS 2022"**.
2. En el terminal que se abre, navega a la carpeta `stub`:

```cmd
cd "\Cyber-Crypter-main\stub"
```

3. Ejecuta el script de compilación:

```cmd
build.bat
```

Al finalizar, `build.bat` compila `stub.c`, produciendo `stub/build/stub_template.exe` y lo
copia automáticamente a `Cyber Cripter\Resources\stub_template.exe` (que es
donde el builder lo buscará en runtime).

Verificación rápida del layout (opcional):

```cmd
dumpbin /headers build\stub_template.exe | findstr /B /C:"  SECTION HEADER" /C:"   .cdata" /C:"  size of raw data"
```

`.cdata` debe tener `size of raw data` ≥ `0x100040`. Si sale `0` significa que
MSVC truncó el buffer por optimización BSS; ver `stub/README.md` para la
mitigación.

### 2) Builder C#

Abre `Cyber Cripter.sln` en Visual Studio y compila el proyecto.

El programa ejecutable se guardará en `Cyber Cripter\bin\Debug\Cyber Cripter.exe`.

### 3) Colocar `donut.exe`

Descarga `donut.exe` y copialo a `Cyber Cripter\bin\Debug\` (junto al
ejecutable del builder). También lo encuentra si está en el `PATH`.

> Es muy probable que se deba desactivar el antivirus para la descarga de donut.exe, o agregar el directorio del proyecto a exclusiones de windows defender.

## Uso

1. Ejecuta `Cyber Cripter.exe`.
2. **Browse** → selecciona el `.exe` que quieres crypter.
3. **ENCRYPT**.
4. El status panel muestra:
   - tamaño del shellcode generado por Donut,
   - tamaño del ciphertext tras AES,
   - reparto entre `half1` (embebido) y `half2` (overlay),
   - timestamp del build,
   - clave derivada en hex (sólo para verificación educativa).
5. El binario crypteado aparece en `outputs\<nombre>_crypted.exe`.

Al ejecutarlo, ese binario:
- Lee sus propios bytes desde disco.
- Re-deriva la clave AES con la misma fórmula que usó el builder.
- Reensambla `half1 || half2` y desencripta.
- Lanza `notepad.exe` suspendido y le inyecta el shellcode mediante APC.
- El payload original corre dentro del proceso `notepad.exe`.

## Consideraciones técnicas

- **Donut produce shellcode, no PE.** Es necesario porque EarlyBird APC
  ejecuta una dirección de memoria como si fuera una función — eso requiere
  código posicional-independiente, no un PE con cabeceras / IAT / relocations.
- **El stub no almacena la clave.** Sólo guarda `heap_marker`, `timestamp` e
  `IV`. La clave AES se reconstruye en runtime a partir de estos valores y de
  los primeros 4 KiB del propio fichero.
- **`Cyber Cripter.exe` y los binarios en `outputs/` son x64.** El stub está
  compilado con `/MACHINE:X64` y Donut se invoca con `-a 2`.

## Aviso

Este código se mantiene únicamente con fines docentes y de investigación.
Su uso fuera de un entorno académico autorizado o de un laboratorio aislado
es responsabilidad de quien lo ejecute.
