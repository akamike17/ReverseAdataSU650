#!/usr/bin/env python3
"""exports.py - resolve key SWPtest.dll exports with bytes and references.
"""
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

BYTES_AROUND = 32


class ExportResolver:
    def __init__(self, image):
        self.img = image
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

    def resolve(self, names):
        exports = {e["name"]: e for e in self.img.exports() if e["name"]}
        result = {}
        for name in names:
            e = exports.get(name)
            if not e:
                result[name] = {"status": "UNKNOWN", "reason": "export not present"}
                continue
            off = e["file_offset"]
            raw = self.img.data[max(0, off - 0): off + BYTES_AROUND]
            result[name] = {
                "status": "CONFIRMED",
                "name": name,
                "ordinal": e["ordinal"],
                "rva": e["rva"],
                "va": e["va"],
                "file_offset": off,
                "section": e["section"],
                "bytes_at_entry": raw[:BYTES_AROUND].hex(),
                "references": self._find_references(e["rva"]),
            }
        return result

    def _find_references(self, rva):
        """Direct CALL rel32 / JMP rel32 that land on this RVA (whole .text scan)."""
        refs = []
        text = next((s for s in self.img.sections() if s["name"] == ".text"), None)
        if not text:
            return refs
        base = text["virtual_address"]
        data = self.img.read_rva(base, text["virtual_size"])
        for insn in self.md.disasm(data, self.img.image_base + base):
            if insn.mnemonic in ("call", "jmp") and insn.operands and \
               insn.operands[0].type == CS_OP_IMM:
                target_rva = insn.operands[0].imm - self.img.image_base
                if target_rva == rva:
                    refs.append({
                        "site_rva": insn.address - self.img.image_base,
                        "kind": insn.mnemonic,
                    })
        return refs


def run(image, names, out_dir):
    res = ExportResolver(image).resolve(names)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(out_dir) / "exports.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    return res
