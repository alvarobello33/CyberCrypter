# Stub Template

El Stub es el loader nativo encargado de reconstruir y desencriptar el shellcode, y finalmente, ejecutarlo en memoria mediante la técnica utilizada por la plantilla seleccionada en la compilación.

La plantilla seleccionada es compilada una sola vez y utilizada por el constructor en C# como una plantilla de ejecutable final. El constructor lo parchea (modificando las secciones personalizadas) en cada operación de cifrado; nunca vuelve a compilar el stub.

## Requisitos de compilación

- Visual Studio 2019 o 2022 con la carga de trabajo **C++ Build Tools** (para `cl.exe`, `link.exe`, las cabeceras del SDK de Windows y `bcrypt.lib`).
- Herramienta `x64 Native Tools Command Prompt for VS`, viene instalada junto a VS y se puede ejucutar desde el menú de inicio (o ejecutar `vcvars64.bat` manualmente para configurar el entorno).

## Compilación
Abriendo la aplicación `x64 Native Tools Command Prompt for VS`nos moveremos al directorio actual:
```
cd CyberCrypter/stub
```
Y compilaremos el template predeterminado (`EarlyBirdAPC`) ejecutando:

```cmd
build.bat
```

También es posible compilar otros templates indicando su nombre como argumento:

```cmd
build.bat TEST
build.bat EarlyBirdAPC
build.bat IndirectSC
```

Esto genera `build\stub_template.exe` y lo copia automáticamente a
`..\Cyber Cripter\Resources\stub_template.exe`, desde donde el constructor de C# lo cargará durante la ejecución.

> En caso de querer diseñar plantillas personalizadas se deberá modificar build.bat para que permita compilar las nuevas plantillas.

## Verificar que la plantilla se puede parchear

Después de compilar, es recomendable realizar una comprobación rápida de la distribución de secciones:

```cmd
dumpbin /headers build\stub_template.exe | findstr /I /C:"SECTION HEADER" /C:"name" /C:"size of raw data"
```

El objetivo para `.cdata` (SECTION HEADER #5) es:
1. Existir como una sección.
2. Tener **size of raw data ≥ 0x100040** (1 MiB más la estructura de metadatos).
   Si `size of raw data` es `0`, MSVC colocó los datos en BSS y los marcadores mágicos no estarán en disco para que el constructor los encuentre. En ese caso, aumenta los inicializadores no nulos en `g_half1_buf` (por ejemplo, añade unos cuantos bytes `0xCC` cerca del final) y vuelve a compilar.
3. Comenzar en un desplazamiento de archivo > `0x1000` para que `STABLE_REGION` (los primeros 4 KiB calculados con hash tanto por el constructor como por el stub) no se solape con ningún byte parcheado.
   Las distribuciones estándar de MSVC sitúan `.cdata` después de `.text` y `.rdata`, por lo que normalmente queda bastante posterior a `0x1000`.

## Distribución parcheada por el constructor

La sección `.cdata` contiene, localizados mediante prefijos mágicos de 16 bytes:

| Campo            | Marcador mágico de origen                  | Tamaño              |
|------------------|--------------------------------------------|---------------------|
| `g_meta`         | `M E T A ! C R Y p T e R ! AA BB CC`       | 60 bytes            |
| `g_half1_buf`    | `H A L F ! O N E ! D A T A DD EE FF`       | 16 + capacidad de 1 MiB |

Superposición PE (después de la última sección): bytes sin procesar de la segunda mitad del shellcode cifrado `half2`.

## Comportamiento en tiempo de ejecución

1. `GetModuleFileNameA` + `ReadFile`: lee su propio archivo desde el disco.
2. SHA-256 sobre `heap_marker || self_bytes[0..hash_region_size] || timestamp`para obtener la clave AES-256.
3. Vuelve a ensamblar el shellcode cifrado uniendo `half1` con `half2`.
4. Descifra el shellcode cifrado con AES-256-CBC y relleno PKCS#7 usando la clave derivada y el IV almacenado en `g_meta.iv`.
5. Inyección del shellcode desencriptado mediante APC EarlyBird en un proceso `notepad.exe` iniciado 
con `CREATE_SUSPENDED`:

   `VirtualAllocEx` RW → `WriteProcessMemory` shellcode → `VirtualAllocEx` RX →
   `QueueUserAPC((PAPCFUNC)mem, hThread, 0)` → `ResumeThread`.

Se espera que la carga útil en texto plano sea **shellcode independiente de posición**
(generado por Donut a partir del `.exe` original); la técnica APC EarlyBird no puede ejecutar un PE sin procesar.
