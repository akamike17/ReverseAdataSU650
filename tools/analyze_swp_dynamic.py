#!/usr/bin/env python3
"""analyze_swp_dynamic.py - surgical RE pipeline for SWPtest.dll / MPTool.

Phases implemented (static, evidence-based):
  A module discovery   B export resolution   C call graph
  D/D' callers via EXE GetProcAddress slots   E context access candidates
  F SCSI / DeviceIoControl sites

Dynamic phases (G-I) require a live drive + debugger harness and are
explicitly reported as NOT RUN here. No guessing: every finding carries
a status CONFIRMED / OBSERVED / HYPOTHESIS / UNKNOWN.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from relib.pe import PEImage                      # noqa: E402
from relib.exports import ExportResolver          # noqa: E402
from relib.calls import CallAnalyzer              # noqa: E402
from relib.exe_resolver import ExeResolver        # noqa: E402
from relib.context import ContextAnalyzer         # noqa: E402
from relib.scsi import ScsiAnalyzer              # noqa: E402

KEY_EXPORTS = [
    "_SMIPtestDownloadMPISP",
    "_SMIPtestCheckRunMode",
    "_SMIPtestDriveReset",
    "_SMIReadFlashID",
    "_SMIScanSMIDrive",
    "_SMISetPassThroughType",
]


def find_candidates(project_root):
    root = Path(project_root)
    mptools = [p for p in root.glob("*.exe") if "MPTool" in p.name]
    dlls = list(root.glob("Dll/SWPtest.dll")) or list(root.glob("SWPtest.dll"))
    return mptools, dlls


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mptool", help="Path to MPTool exe (e.g. SM2258XTMPToolQ0816A.exe)")
    ap.add_argument("--dll", help="Path to SWPtest.dll")
    ap.add_argument("--output", default=None, help="Artifact output directory")
    ap.add_argument("--dump-size", default="0x10000",
                    help="Context dump size for the (not-yet-run) dynamic phase")
    ap.add_argument("--self-test", action="store_true",
                    help="Import-check all modules and exit")
    args = ap.parse_args()

    if args.self_test:
        # imports happened at module load; if we got here they resolved
        print("self-test OK: pefile, capstone, re.{pe,exports,calls,exe_resolver,context,scsi}")
        return 0

    project_root = Path(__file__).resolve().parent.parent

    mptool, dll = args.mptool, args.dll
    if not mptool or not dll:
        mptools, dlls = find_candidates(project_root)
        if not mptool:
            if len(mptools) != 1:
                print(f"[ERROR] ambiguous MPTool candidates: {mptools}; pass --mptool")
                return 2
            mptool = str(mptools[0])
        if not dll:
            if len(dlls) != 1:
                print(f"[ERROR] ambiguous SWPtest.dll candidates: {dlls}; pass --dll")
                return 2
            dll = str(dlls[0])

    out = Path(args.output) if args.output else project_root / "artifacts" / "re"
    out.mkdir(parents=True, exist_ok=True)

    dll_img = PEImage(dll)
    exe_img = PEImage(mptool)

    # ---- PHASE A: module discovery -------------------------------------
    module_map = {
        "status": "CONFIRMED",
        "mptool": {
            "path": str(mptool), "sha256": exe_img.sha256(),
            "bits": exe_img.bits(), "image_base": hex(exe_img.image_base),
            "sections": len(exe_img.sections()),
        },
        "dll": {
            "path": str(dll), "sha256": dll_img.sha256(),
            "bits": dll_img.bits(), "image_base": hex(dll_img.image_base),
            "sections": len(dll_img.sections()),
            "export_count": len(dll_img.exports()),
        },
        "dll_imports_summary": sorted({i["dll"] for i in dll_img.imports()}),
    }
    (out / "module_map.json").write_text(json.dumps(module_map, indent=2))

    # ---- PHASE B: exports ----------------------------------------------
    exports = ExportResolver(dll_img).resolve(KEY_EXPORTS)
    (out / "exports.json").write_text(json.dumps(exports, indent=2))

    # ---- PHASE C: call graph around DownloadMPISP -----------------------
    ca = CallAnalyzer(dll_img)
    root_rva = dll_img.exports()
    root_rva = next((e["rva"] for e in root_rva
                     if e["name"] == "_SMIPtestDownloadMPISP"), None)
    callgraph = ca.build_graph_around(root_rva, depth=4) if root_rva else {}
    (out / "callgraph.json").write_text(
        json.dumps(callgraph, indent=2, default=str))

    # ---- PHASE F: real callers via EXE GetProcAddress slots ------------
    resolver = ExeResolver(mptool)
    slots = resolver.resolve_slots(KEY_EXPORTS)
    callers = {}
    for name, info in slots.items():
        if info.get("slot"):
            callers[name] = {
                "status": "CONFIRMED" if resolver.slot_callers(int(info["slot"], 16))
                else "OBSERVED",
                "slot": info["slot"],
                "call_sites": resolver.slot_callers(int(info["slot"], 16)),
            }
        else:
            callers[name] = {"status": "UNKNOWN",
                             "reason": "no GetProcAddress slot found in EXE"}
    (out / "callers_downloadmpisp.json").write_text(json.dumps(callers, indent=2))

    # ---- PHASE E: context access candidates ----------------------------
    ctx = ContextAnalyzer(dll_img).analyze(root_rva) if root_rva else []
    (out / "context_accesses.json").write_text(
        json.dumps(ctx, indent=2, default=str))

    # ---- SCSI / DeviceIoControl ----------------------------------------
    scsi = ScsiAnalyzer(dll_img)
    dio_sites = scsi.find_deviceiocontrol_sites()
    cdb_cands = scsi.cdb_candidates(dio_sites)
    (out / "scsi_candidates.json").write_text(json.dumps({
        "deviceiocontrol_sites": dio_sites,
        "cdb_candidates": cdb_cands,
    }, indent=2))

    # ---- conclusions ----------------------------------------------------
    dl = callers.get("_SMIPtestDownloadMPISP", {})
    conclusions = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target": {"device": "ADATA SU650 120GB", "controller": "SM2258XT",
                   "bus": "SATA", "status": "CONFIRMED (per project scope)"},
        "downloadmpisp_caller": {
            "status": dl.get("status", "UNKNOWN"),
            "slot": dl.get("slot"),
            "call_sites": dl.get("call_sites", []),
        },
        "calling_convention": {
            "status": "OBSERVED",
            "note": "cdecl per add esp,N after calls; arg count pending dynamic capture",
        },
        "cdb_0xE0": {
            "status": "HYPOTHESIS",
            "note": "candidate byte pattern near DeviceIoControl sites; NOT proven ROM-entry",
        },
        "runmode_5": {"status": "UNKNOWN",
                      "note": "observed on hardware; meaning not traced in this run"},
        "flashid_zeros": {"status": "UNKNOWN"},
        "dynamic_phases_G_to_I": {
            "status": "NOT RUN",
            "reason": "require live drive + debugger capture; script is static-only",
        },
    }
    (out / "conclusions.json").write_text(json.dumps(conclusions, indent=2))

    print(f"[OK] artifacts written to {out}")
    print(json.dumps({k: (v.get("status") if isinstance(v, dict) else "OK")
                      for k, v in conclusions.items() if isinstance(v, dict)},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
