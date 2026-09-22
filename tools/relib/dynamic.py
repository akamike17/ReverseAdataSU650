#!/usr/bin/env python3
"""dynamic.py - Frida 17-based capture of the real MPTool -> SWPtest.dll flow.

Instruments:
  - the 3 EXE call sites that go through slot 0x507F70
    (RVA 0x3DEF, 0x3D405, 0x40878)
  - SWPtest!_SMIPtestDownloadMPISP entry (once SWPtest.dll loads)
  - KERNEL32!DeviceIoControl
  - KERNEL32 memory allocators (HeapAlloc / VirtualAlloc)
  - exceptions (access violations get full context)

All events are pushed to the host as JSON records. No writes to target
memory. No CDB injection. Pure observation.
"""
import json
import threading
import time
from pathlib import Path

import frida

JS = r"""
'use strict';

const EXE_MOD = Process.getModuleByName('%EXE_NAME%');
const EXE_BASE = EXE_MOD.base;
const exeRva = r => EXE_BASE.add(r);

const CALLERS = [0x3DEF, 0x3D405, 0x40878];
let dllBase = null;

function safeReadByteArray(p, n) {
    try { return p.readByteArray(n); } catch (e) { return null; }
}

function hexDump(u8) {
    return Array.from(u8).map(x => x.toString(16).padStart(2, '0')).join(' ');
}

function readStack(esp, count) {
    const out = [];
    for (let i = 0; i < count; i++) {
        const a = esp.add(i * 4);
        let v = null, deref = null;
        try { v = a.readU32(); } catch (e) {}
        if (v !== null && v > 0x10000 && v < 0x7fff0000) {
            const b = safeReadByteArray(ptr(v), 64);
            if (b) deref = hexDump(new Uint8Array(b));
        }
        out.push({off: i * 4,
                  va: a.toString(),
                  value: v === null ? null : '0x' + v.toString(16),
                  deref});
    }
    return out;
}

function dumpRegs(name, ctx, tid) {
    send({kind: name, ts: Date.now(), tid,
          eip: ctx.eip.toString(), esp: ctx.esp.toString(),
          ebp: ctx.ebp.toString(),
          eax: ctx.eax.toString(), ebx: ctx.ebx.toString(),
          ecx: ctx.ecx.toString(), edx: ctx.edx.toString(),
          esi: ctx.esi.toString(), edi: ctx.edi.toString(),
          stack: readStack(ctx.esp, 13)});
}

// ---- 1. EXE call-site instrumentation --------------------------------
for (const rva of CALLERS) {
    Interceptor.attach(exeRva(rva), {
        onEnter(args) {
            dumpRegs('caller_hit_rva_0x' + rva.toString(16),
                     this.context, this.threadId);
        },
        onLeave(ret) {
            send({kind: 'caller_ret',
                  rva: '0x' + rva.toString(16),
                  retval: ret.toString()});
        }
    });
}

// ---- 2. SWPtest DownloadMPISP entry ----------------------------------
function tryHookSwp() {
    let mod = null;
    try { mod = Process.getModuleByName('SWPtest.dll'); }
    catch (e) { return false; }           // not loaded yet
    if (!mod || dllBase) return !!dllBase;
    dllBase = mod.base;
    const exp = mod.findExportByName('_SMIPtestDownloadMPISP');
    send({kind: 'dll_loaded', base: dllBase.toString(),
          download_export: exp ? exp.toString() : null});
    if (exp) {
        Interceptor.attach(exp, {
            onEnter(args) {
                dumpRegs('downloadmpisp_enter', this.context, this.threadId);
                const cand = [];
                for (let i = 0; i < 6; i++) {
                    const p = args[i];
                    if (!p || p.isNull()) continue;
                    const b = safeReadByteArray(p, 128);
                    cand.push({arg: i, ptr: p.toString(),
                               preview: b ? hexDump(new Uint8Array(b)) : null,
                               readable: b !== null});
                }
                send({kind: 'downloadmpisp_args', args: cand});
            },
            onLeave(ret) {
                send({kind: 'downloadmpisp_leave', retval: ret.toString()});
            }
        });
    }
    return true;
}
const poller = setInterval(() => { tryHookSwp(); }, 250);

// ---- 3. DeviceIoControl ----------------------------------------------
function hookDioControl() {
    const k32 = Process.getModuleByName('KERNEL32.DLL');
    const dio = k32.findExportByName('DeviceIoControl');
    if (!dio) return;
    Interceptor.attach(dio, {
        onEnter(args) {
            const inSize = args[3].toInt32();
            const outSize = args[5].toInt32();
            let inHex = null, cdbPreview = null;
            if (inSize > 0 && inSize <= 4096 && !args[2].isNull()) {
                const b = safeReadByteArray(args[2], inSize);
                if (b) {
                    const u8 = new Uint8Array(b);
                    inHex = hexDump(u8);
                    cdbPreview = hexDump(u8.slice(0, Math.min(64, u8.length)));
                }
            }
            send({kind: 'deviceiocontrol_enter',
                  hDevice: args[0].toString(),
                  ioctl: '0x' + args[1].toInt32().toString(16),
                  inBuf: args[2].toString(), inSize,
                  outBuf: args[4].toString(), outSize,
                  cdb_preview: cdbPreview});
            this._inHex = inHex;
        },
        onLeave(ret) {
            send({kind: 'deviceiocontrol_leave',
                  retval: ret.toString(),
                  inHex: this._inHex});
        }
    });
}
hookDioControl();

// ---- 4. Allocation tracking -------------------------------------------
const k32 = Process.getModuleByName('KERNEL32.DLL');
for (const fn of ['HeapAlloc', 'VirtualAlloc', 'LocalAlloc', 'GlobalAlloc']) {
    const p = k32.findExportByName(fn);
    if (p) Interceptor.attach(p, {
        onEnter(args) { this._sz = args[fn === 'VirtualAlloc' ? 1 : 2]; },
        onLeave(ret) {
            if (!ret.isNull())
                send({kind: 'alloc', fn,
                      size: this._sz.toString(),
                      ptr: ret.toString()});
        }
    });
}

// ---- 5. Exceptions -----------------------------------------------------
Process.setExceptionHandler(details => {
    let ea = null, writeVal = null, regs = null;
    if (details.context) {
        const c = details.context;
        try {
            ea = c.edx.add(c.eax).toString();
            writeVal = c.ecx.and(0xff).toString();
        } catch (e) {}
        regs = {eip: c.eip.toString(), esp: c.esp.toString(),
                ebp: c.ebp.toString(),
                eax: c.eax.toString(), edx: c.edx.toString(),
                ecx: c.ecx.toString()};
    }
    send({kind: 'exception', code: details.type,
          address: details.address.toString(),
          memory: details.memory ? {
              operation: details.memory.operation,
              address: details.memory.address.toString()} : null,
          context: regs,
          probable_ea: ea, write_value: writeVal});
    return false;
});
"""


class DynamicCapture:
    def __init__(self, mptool_path, out_dir):
        self.mptool = str(mptool_path)
        self.exe_name = Path(mptool_path).name
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.events = []
        self.session = None
        self.pid = None
        self._lock = threading.Lock()

    def _on_message(self, msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            with self._lock:
                self.events.append(payload)
            kind = payload.get("kind")
            if kind and kind not in ("alloc",):
                short = {k: v for k, v in payload.items()
                         if k in ("eip", "esp", "eax", "ecx", "edx",
                                  "ioctl", "retval", "code",
                                  "probable_ea", "ioctl_class")}
                print(f"  [{kind}] {json.dumps(short, default=str)[:220]}")
        elif msg.get("type") == "error":
            print(f"[frida-error] {msg.get('description', msg)}")

    def run(self, duration=60, resume=True):
        print(f"[*] spawning {self.mptool}")
        self.pid = frida.spawn([self.mptool])
        self.session = frida.attach(self.pid)
        script_src = JS.replace("%EXE_NAME%", self.exe_name)
        script = self.session.create_script(script_src)
        script.on("message", self._on_message)
        script.load()
        if resume:
            frida.resume(self.pid)
        print(f"[*] hooked. MPTool pid={self.pid}. Capturing {duration}s.")
        print("    >> INTERACT WITH MPTool NOW (Scan / Start / etc.) <<")
        time.sleep(duration)
        try:
            self.session.detach()
        except Exception:
            pass
        try:
            frida.kill(self.pid)
        except Exception:
            pass
        f = self.out / "dynamic_trace.json"
        f.write_text(json.dumps(self.events, indent=2, default=str))
        print(f"[+] {len(self.events)} events -> {f}")
        return self.events


def run_capture(mptool, out_dir, duration=60):
    return DynamicCapture(mptool, out_dir).run(duration)
