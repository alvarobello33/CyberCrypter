# Cyber Crypter

Crypter educativo desarrollado para mi Trabajo de Fin de Grado de Ingeniería Informática. 

El proyecto toma un `.exe` marcado como amenaza por los motores antivirus, lo convierte a shellcode posicional-independiente con [Donut](https://github.com/TheWover/donut), lo encripta con una clave AES-256
única para cada compilación y genera un loader nativo autosuficiente a partir del stub compilado. Al ejecutarse, el loader descifra el payload y lo ejecuta en memoria mediante la técnica implementada por el stub seleccionado en la compilación, evadiendo un gran número de los motores antivirus modernos. 

> **Proyecto de uso exclusivamente académico**: Su objetivo es estudiar las técnicas modernas 
> que aparecen en análisis de malware (semi-binded payload, derivación dinámica de clave,
> inyección APC temprana, anti-tamper por hash del propio binario, ...) construyendo
> un crypter completo de principio a fin.

## Técnicas implementadas

- **Payload semi-binded híbrido**: el código cifrado se divide en dos partes:
  - `half1` (hasta 1 MiB) embebido en una sección personalizada `.cdata` dentro del stub.
  - `half2` (sin límite de tamaño) se agrega como overlay PE detrás de la última sección.
  - El stub reensambla `half1 || half2` antes de realizar el descifrado.
- **Clave AES dinámica**:
  `key = SHA256( heap_marker || stub_file[0..4096] || timestamp )`.
  - `heap_marker` y `timestamp` se generan en cada compilación y se almacenan en los metadatos embebidos.
  - Los primeros 4 KiB del propio archivo se incluyen en el cálculo del hash → cualquier
    parcheo de cabeceras PE o `.text` invalida la clave (anti-tamper).
- **Encriptación AES-256-CBC con PKCS#7** mediante `System.Security.Cryptography` en el builder
  y Windows CNG (`bcrypt.dll`) en el stub. El IV es aleatorio por build y se
  guarda en los metadatos embebidos.
- **EarlyBird APC injection** como técnica de inyección en memoria:
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
│   ├── stub_EarlyBirdAPC.c
│   ├── stub_IndirectSC.c
│   ├── stub_Test.c
│   ├── build.bat
│   └── README.md
└── outputs/                      # destino de los binarios crypteados
```

## Requisitos

- **Visual Studio 2019 / 2022** con la carga de trabajo **Desarrollo de escritorio con C++**
  (necesario para `cl.exe`, `link.exe`, las cabeceras del Windows SDK y `bcrypt.lib`).
- **.NET Framework 4.8 SDK** (necesario para compilar el builder en C#).
- **donut.exe** de https://github.com/TheWover/donut/releases.

## Compilación

### 1) Stub nativo 
Estos pasos solo es necesario realizarlos una vez o cada vez que se modifique `stub.c`.

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
cd "\CyberCrypter\stub"
```

3. Ejecuta el script de compilación:

```cmd
build.bat
```

Al finalizar, `build.bat` compila la variante `stub_EarlyBirdAPC.c`, produciendo `stub/build/stub_template.exe` y lo
copia automáticamente a `CyberCrypter\Resources\stub_template.exe` (ubicación en la cual el builder buscará el stub
durante la ejecución).

4. Verificación rápida del layout (opcional):

```cmd
dumpbin /headers build\stub_template.exe | findstr /I /C:"SECTION HEADER" /C:"name" /C:"size of raw data"
```

`.cdata` (SECTION HEADER #5) debe tener `size of raw data` ≥ `100040`. Si sale `0` significa que
MSVC truncó el buffer por optimización BSS. Ver `stub/README.md` para la mitigación del error.

### 2) Builder C#

Abre `CyberCrypter.sln` en Visual Studio y compila el proyecto.

El programa ejecutable se guardará en `CyberCrypter\bin\Debug\CyberCrypter.exe`.

### 3) Colocar `donut.exe`

Descarga `donut.exe` y copialo en `CyberCrypter\bin\Debug\`, junto al
ejecutable del builder (también se puede colocar en el `PATH`).

> Es muy probable que se deba desactivar el antivirus para la descarga de donut.exe, o agregar el directorio del proyecto a exclusiones de windows defender.

## Uso

1. Ejecuta `Cyber Cripter.exe`.
2. **Browse** → selecciona el ejecutable `.exe` que quieres cryptear para que evada al antivirus.
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
- Reensambla y desencripta el código encriptado repartido entre `half1 || half2`.
- Lanza `notepad.exe` suspendido y le inyecta el shellcode mediante Early Bird APC.
- El payload original corre dentro del proceso `notepad.exe`.

## Consideraciones técnicas

- **Donut produce shellcode, no PE.** Es necesario porque EarlyBird APC
  ejecuta una dirección de memoria como si fuera una función. Eso requiere
  código posicional-independiente, no un PE con cabeceras, IAT, relocations, ...
- **El stub no almacena la clave.** Sólo guarda `heap_marker`, `timestamp` e
  `IV`. La clave AES se reconstruye en runtime a partir de estos valores y de
  los primeros 4 KiB del propio fichero.
- **`CyberCripter.exe` y los binarios en `outputs/` son de arquitectura x64.** El stub está
  compilado con `/MACHINE:X64` y Donut se invoca con `-a 2` para generar shellcode con esta 
  misma arquitectura.

## Aviso

Este código se mantiene únicamente con fines docentes y de investigación.
Su uso fuera de un entorno académico autorizado o de un laboratorio aislado
es responsabilidad de quien lo ejecute.
