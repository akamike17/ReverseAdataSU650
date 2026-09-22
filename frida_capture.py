#!/usr/bin/env python3
"""
Frida script para capturar _SMIPtestDownloadMPISP cuando MPTool lo llama
Uso: python frida_capture.py
Luego ir a MPTool GUI y hacer click en Scan/Start
"""

import frida
import sys
import time

# Código JavaScript para inyectar en el proceso MPTool
JS_CODE = """
// Hook exports de SWPtest.dll
var SWP = null;
var interval = null;

function tryHook() {
    SWP = Module.findBaseAddress('SWPtest.dll');
    if (!SWP) {
        console.log('[*] SWPtest.dll no cargada aun, reintentando...');
        return false;
    }
    console.log('[+] SWPtest.dll encontrada en: ' + SWP);

    var downloadMpisp = Module.getExportByName('SWPtest.dll', '_SMIPtestDownloadMPISP');
    console.log('[+] _SMIPtestDownloadMPISP: ' + downloadMpisp);

    Interceptor.attach(downloadMpisp, {
        onEnter: function(args) {
            console.log('');
            console.log('========================================');
            console.log('CAPTURA DownloadMPISP');
            console.log('========================================');

            // Argumentos segun firma: (driveIdx, data, word, context)
            console.log('Arg0 (driveIdx):  0x' + args[0].toString(16));
            console.log('Arg1 (data ptr):  0x' + args[1].toString(16));
            console.log('Arg2 (word):      0x' + args[2].toString(16));
            console.log('Arg3 (context):   0x' + args[3].toString(16));

            // Dump de los primeros 64 bytes del buffer data
            try {
                var buf = new Uint8Array(Memory.readByteArray(args[1], 64));
                console.log('Data buffer (primeros 64 bytes):');
                var hex = '';
                for (var i = 0; i < buf.length; i++) {
                    hex += ('0' + buf[i].toString(16)).slice(-2) + ' ';
                    if ((i+1) % 16 == 0) hex += '\\n';
                }
                console.log(hex);
            } catch(e) {
                console.log('No se pudo leer data buffer: ' + e);
            }

            // Dump del contexto (primeros 256 bytes)
            try {
                var ctx = new Uint8Array(Memory.readByteArray(args[3], 256));
                console.log('Context buffer (primeros 256 bytes):');
                var hexCtx = '';
                for (var i = 0; i < ctx.length; i++) {
                    hexCtx += ('0' + ctx[i].toString(16)).slice(-2) + ' ';
                    if ((i+1) % 16 == 0) hexCtx += '\\n';
                }
                console.log(hexCtx);
            } catch(e) {
                console.log('No se pudo leer context: ' + e);
            }

            console.log('========================================');
            console.log('');

            // Guardar en archivo
            var f = new File('C:/SM2258XT_MPTool/capture/mpisp_capture.txt', 'ab');
            f.write('=== DownloadMPISP Capture ===\\n');
            f.write('driveIdx: 0x' + args[0].toString(16) + '\\n');
            f.write('dataPtr: 0x' + args[1].toString(16) + '\\n');
            f.write('word: 0x' + args[2].toString(16) + '\\n');
            f.write('context: 0x' + args[3].toString(16) + '\\n');
            f.close();
        },
        onLeave: function(retval) {
            console.log('DownloadMPISP retorno: ' + retval);
        }
    });

    console.log('[+] Hook instalado. Esperando llamada...');
    console.log('');
    console.log('Ahora ve a MPTool GUI y haz click en:');
    console.log('  1. SCAN DRIVE (o el boton de detectar)');
    console.log('  2. Cuando detecte el SSD, haz lo que haria normalmente');
    console.log('  3. Cuando vayas a hacer flash, PASA POR AQUI PRIMERO');
    console.log('');
    return true;
}

// Intentar hook inmediatamente
if (!tryHook()) {
    // Si no esta cargada, intentar cada 2 segundos
    interval = setInterval(function() {
        if (tryHook()) {
            clearInterval(interval);
        }
    }, 2000);
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[FRIDA] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    print("")
    print("==========================================")
    print("FRIDA CAPTURE - DownloadMPISP")
    print("==========================================")
    print("")
    print("Buscando proceso MPTool...")

    # Esperar a que el proceso exista
    max_attempts = 30
    session = None
    for i in range(max_attempts):
        try:
            session = frida.attach("SM2258XTMPToolQ0816A.exe")
            if session:
                print(f"[+] Attach exitoso (intento {i+1})")
                break
        except Exception as e:
            if i < max_attempts - 1:
                time.sleep(1)
            else:
                print(f"[-] No se pudo attach: {e}")
                sys.exit(1)

    # Inyectar el script
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()

    print("")
    print("[+] Frida listo. Esperando que MPTool llame a DownloadMPISP...")
    print("[+] Presiona Ctrl+C para terminar")
    print("")

    # Mantener el script corriendo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("")
        print("[*] Desconectando...")
        session.detach()

if __name__ == '__main__':
    main()
