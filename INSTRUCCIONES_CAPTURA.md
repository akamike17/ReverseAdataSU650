# CAPTURA DE DownloadMPISP - Procedimiento Exacto
# Para el usuario que usa x32dbg por primera vez
# Este procedimiento es 100% manual but extremadamente simple

## PRERREQUISITO
1. Abre x32dbg.exe como Administrador (click derecho -> Ejecutar como administrador)
   Ruta: C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe

2. File -> Open -> selecciona: C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe
   Click "Abrir"

## PASO A PASO (4 comandos en el Command Bar)

### PASO 1: Ignorar system breakpoint inicial
Cuando x32dbg se abre, está pausado en el system breakpoint (EIP en ntdll).
En el **Command bar** (parte inferior de la ventana), escribe:

```
run
```

Presiona Enter. Verás que el proceso empieza a correr.

### PASO 2: Poner breakpoint en SWPtest.dll
Cuando el proceso corra y SWPtest.dll se cargue (verás en el Log "DLL Loaded: SWPtest.dll"),
escribe en el **Command bar**:

```
bpdll SWPtest.dll
```

Presiona Enter. Esto hace que cada vez que SWPtest.dll se cargue, el debugger pare.

### PASO 3: Continuar hasta que SWPtest se cargue

```
run
```

Presiona Enter. Espera unos segundos. Cuando veas en el Log:
"DLL breakpoint reached: C:\SM2258XT_MPTool\Dll\SWPtest.dll"
significa que SWPtest está CARGADO.

### PASO 4: Poner breakpoint en DownloadMPISP
Ahora que SWPtest está cargado, escribe:

```
bp _SMIPtestDownloadMPISP
```

Presiona Enter. Si este comando funciona, verás "Breakpoint set" en el log.
Si no funciona, prueba:
```
bp SWPtest._SMIPtestDownloadMPISP
```

### PASO 5: Continuar y hacer click en MPTool

```
run
```

Presiona Enter. Ahora el proceso está corriendo libremente.

**AHORA DEBES HACER LO SIGUIENTE:**

1. Ve a la ventana de MPTool (la que tiene el Flash Type, Channel, etc.)
2. En MPTool, haz click en **Scan Drive**
   (El boton que parece una lupa o dice "Scan")
3. Esto activará la detección del SSD
4. Si el SSD es detectado, aparecerá información del Flash en MPTool
5. Cuando MPTool haya listo y quieras ver el comando DownloadMPISP,
   por ahora NO continues con Start (que hace el flash real)
6. Regresa a x32dbg y verás que está PAUSADO en DownloadMPISP
   (El status bar dirá "Paused" y EIP estará en SWPtest.dll)

### QUÉ CAPTURAR (screenshots):

Cuando x32dbg esté pausado en DownloadMPISP:

A) **Registers panel** (left side): Captura los valores de:
   - EAX, EBX, ECX, EDX (estos son los 4 primeros argumentos)
   - EDI, ESI (punteros)
   - ESP (stack pointer - para ver el stack)

B) **Stack panel** (right side, bottom): Muestra los primeros 16 bytes
   que contienen los argumentos y local variables de DownloadMPISP

C) **Stack dump**: Presiona **Ctrl+F6** o selecciona View -> Stack
   para ver un dump del stack

D) **Memory dump**: Selecciona el segundo argumento (ECX normalmente)
   haz click derecho en el valor en el panel de Registers
   selecciona "Dump at this address" para ver los datos en memoria

E) **Log**: En el panel de Log (debajo del CPU), busca lineas que mencionen
   [UNICODE] o datos del context

## ARCHIVOS A GENERAR

Mientras x32dbg esté pausado en DownloadMPISP:

1. **Screenshot completo** de la ventana de x32dbg
2. **Lista de breakpoints**: View -> Breakpoints (o Ctrl+B) - muestra todos los breakpoints activos
3. **El Log completo**: File -> Save Log As -> guarda como:
   C:\SM2258XT_MPTool\capture\downloadmpisp_breakpoint.log

4. **Memory dump**: En Memory Map (Ctrl+M), haz click derecho en SWPtest
   -> "Dump module to file" -> guarda como:
   C:\SM2258XT_MPTool\capture\swptest_dump.bin

## DESPUÉS DE CAPTURAR

Una vez tengas los 4 archivos/screenshots arriba, di:
"Ahora puedo escribir los próximos pasos de automatización"

## Si NO funciona el comando "bp _SMIPtestDownloadMPISP"

1. Ve a Symbols tab (tab superior "Symbols")
2. Expande SWPtest.dll
3. Busca en la lista la función _SMIPtestDownloadMPISP
4. Haz click derecho sobre ella
5. Selecciona "Follow in Disassembler" (esto carga la función)
6. Una vez en Disassembler, presiona F2 para poner breakpoint en esa dirección exacta

## RESUMEN VISUAL DEL FLUJO EN x32dbg:

```
1. run                    {Proceso empieza a correr}
2. bpdll SWPtest.dll     {Breakpoint en carga de SWPtest.dll}
3. run                    {Continúa hasta que SWPtest cargue}

   [MPTool.exe corre y muestra su GUI]
   [MPTool detecta el SSD]
   [MPTool prepara el contexto]

4. bp _SMIPtestDownloadMPISP    {Breakpoint en la función objetivo}
5. run                          {Continúa - cuando MPTool llame a DownloadMPISP, x32dbg se pausará}

   [x32dbg se detiene en DownloadMPISP]
   [Capturas registros, stack, memoria]
```

## LO QUE NO DEBES HACER

- NO hagas click en Start/Go/Erase en MPTool todavía
- NO hagas click en Format
- Solo queremos ver QUÉ PARAMETROS pasa MPTool a DownloadMPISP
- NO flashees nada todavía
