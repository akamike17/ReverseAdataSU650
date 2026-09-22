"""tests/test_pe.py - PE parsing primitives."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from relib.pe import PEImage  # noqa: E402

DLL = "Dll/SWPtest.dll"


def test_exports_resolve():
    img = PEImage(DLL)
    exports = {e["name"]: e for e in img.exports()}
    assert "_SMIPtestDownloadMPISP" in exports
    e = exports["_SMIPtestDownloadMPISP"]
    assert e["rva"] == 0x7AD8, f"expected 0x7AD8, got {hex(e['rva'])}"
    assert e["file_offset"] is not None
    assert e["section"] == ".text"


def test_rva_offset_roundtrip():
    img = PEImage(DLL)
    for s in img.sections():
        if s["name"] == ".text":
            rva = s["virtual_address"] + 0x100
            off = img.rva_to_offset(rva)
            assert off is not None
            assert img.offset_to_rva(off) == rva


def test_sha256_stable():
    img = PEImage(DLL)
    assert len(img.sha256()) == 64
