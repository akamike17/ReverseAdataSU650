#!/usr/bin/env python3
"""
Frida script to capture DownloadMPISP calls from SWPtest.dll
Run: python frida_capture_mpisp.py
Then: In MPTool GUI, click "Scan Drive"
"""

import frida
import sys
import time

# JavaScript code to inject into MPTool process
JS_CODE = """
// Hook SWPtest.dll exports
var swptest = Module.findBaseAddress('SWPtest.dll');
if (swptest) {
    console.log('[+] SWPtest.dll found at: ' + swptest);

    // Get address of _SMIPtestDownloadMPISP
    var downloadMpisp = Module.getExportByName('SWPtest.dll', '_SMIPtestDownloadMPISP');
    console.log('[+] _SMIPtestDownloadMPISP at: ' + downloadMpisp);

    if (downloadMpisp) {
        // Hook the function
        Interceptor.attach(downloadMpisp, {
            onEnter: function(args) {
                console.log('');
                console.log('[!!!] DOWNLOAD_MPISP CALLED [!!!]');
                console.log('');
                console.log('Arguments (stdcall, 4 params):');

                // arg0: drive handle (usually index or handle reference)
                var driveHandle = args[0];
                console.log('  arg0 (drive): ' + driveHandle);
                console.log('  arg0 (hex): 0x' + driveHandle.toString(16));

                // arg1: data buffer pointer (BootISP content)
                var dataPtr = args[1];
                console.log('  arg1 (data ptr): ' + dataPtr);

                // Read first 64 bytes of the data buffer
                try {
                    var data = Memory.readByteArray(dataPtr, 64);
                    var hex = Array.prototype.map.call(
                        new Uint8Array(data),
                        function(x) { return ('00' + x.toString(16)).slice(-2); }
                    ).join(' ');
                    console.log('  arg1 data (first 64 bytes): ' + hex);
                } catch(e) {
                    console.log('  arg1 data: [could not read: ' + e + ']');
                }

                // arg2: checksum/word value
                var checksum = args[2];
                console.log('  arg2 (checksum): 0x' + checksum.toString(16));

                // arg3: context pointer
                var context = args[3];
                console.log('  arg3 (context ptr): ' + context);

                if (!context.isNull()) {
                    try {
                        // Read context structure (0x100 bytes to inspect)
                        var ctxData = Memory.readByteArray(context, 256);
                        var ctxHex = Array.prototype.map.call(
                            new Uint8Array(ctxData),
                            function(x) { return ('00' + x.toString(16)).slice(-2); }
                        ).join(' ');
                        console.log('  context (first 256 bytes): ' + ctxHex);

                        // Try to read possible handle at +0x0
                        var possibleHandle = Memory.readU32(context);
                        console.log('  context[0x0] as handle: 0x' + possibleHandle.toString(16));

                    } catch(e) {
                        console.log('  context: [could not read: ' + e + ']');
                    }
                }

                // Also dump registers at this point
                console.log('');
                console.log('Thread context:');
                console.log('  ESP: ' + this.context.esp);
                console.log('  EBP: ' + this.context.ebp);
                console.log('  ESI: ' + this.context.esi);
                console.log('  EDI: ' + this.context.edi);

                // Read return address from stack (at [ESP])
                var retAddr = this.context.esp.readPointer();
                console.log('  Return address (from ESP): ' + retAddr);

                // Try to resolve return address to a module+function
                try {
                    var module = Process.findModuleByAddress(retAddr);
                    if (module) {
                        console.log('  Return module: ' + module.name);
                    }
                } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('');
                console.log('[DownloadMPISP returned: ' + retval + ']');
            }
        });

        console.log('');
        console.log('[+] Hook installed. Waiting for MPTool to call DownloadMPISP...');
        console.log('[+] Now go to MPTool and click "SCAN DRIVE"');
        console.log('');
    } else {
        console.log('[!] Could not find _SMIPtestDownloadMPISP export');
    }
} else {
    console.log('[!] SWPtest.dll not loaded in process');
    console.log('[!] Will retry every 2 seconds...');

    // Retry loop - wait for SWPtest.dll to load
    var checkInterval = setInterval(function() {
        swptest = Module.findBaseAddress('SWPtest.dll');
        if (swptest) {
            console.log('[+] SWPtest.dll loaded at: ' + swptest);
            clearInterval(checkInterval);

            // Now hook the function
            var downloadMpisp = Module.getExportByName('SWPtest.dll', '_SMIPtestDownloadMPISP');
            if (downloadMpisp) {
                console.log('[+] _SMIPtestDownloadMPISP found at: ' + downloadMpisp);

                Interceptor.attach(downloadMpisp, {
                    onEnter: function(args) {
                        console.log('');
                        console.log('[!!!] DOWNLOAD_MPISP CALLED [!!!]');
                        console.log('  drive: ' + args[0]);
                        console.log('  data: ' + args[1]);
                        console.log('  checksum: 0x' + args[2].toString(16));
                        console.log('  context: ' + args[3]);
                    },
                    onLeave: function(retval) {
                        console.log('[DownloadMPISP returned: ' + retval + ']');
                    }
                });
            }
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
    process_name = "SM2258XTMPToolQ0816A.exe"

    print("[*] Frida DownloadMPISP Capture")
    print(f"[*] Target process: {process_name}")
    print("[*] Waiting for process to start...")

    # Wait for process to be running
    while True:
        try:
            session = frida.attach(process_name)
            print("[+] Attached to process")
            break
        except frida.ProcessNotFoundError:
            print("[*] Process not running yet, waiting 2s...")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(2)

    # Create script and inject
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()

    print("")
    print("=" * 60)
    print("FRIDA CAPTURE ACTIVE")
    print("=" * 60)
    print("")
    print("Now do the following in MPTool GUI:")
    print("1. Click 'SCAN DRIVE' button")
    print("2. When the SSD is detected, watch here for the capture")
    print("")
    print("Press Ctrl+C to stop capture")
    print("")

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()
        sys.exit(0)

if __name__ == "__main__":
    main()
