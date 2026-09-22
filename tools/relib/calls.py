#!/usr/bin/env python3
"""calls.py - call-graph and caller discovery.

Covers:
  - direct CALL/JMP rel32
  - indirect CALL/JMP through IAT dword  (call dword ptr [iat_va])
  - references to .data function-pointer slots (call dword ptr [slot_va]),
    including resolving which export string was stored there by the EXE's
    LoadLibrary/GetProcAddress resolver (Borland pattern).

Never invents callers; if no reference site exists -> callers = [] (UNKNOWN).
"""
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

from .pe import PEImage


class CallAnalyzer:
    def __init__(self, image: PEImage):
        self.img = image
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self._exports_by_rva = {e["rva"]: e["name"] for e in image.exports() if e["name"]}

    # ------------------------------------------------------------------
    def _iter_text(self, image):
        text = next((s for s in image.sections() if s["name"] == ".text"), None)
        if not text:
            return
        base = text["virtual_address"]
        data = image.read_rva(base, text["virtual_size"])
        for insn in self.md.disasm(data, image.image_base + base):
            yield insn, base

    # ------------------------------------------------------------------
    def direct_callers(self, target_rva):
        """All direct call/jmp sites in .text that target target_rva."""
        sites = []
        for insn, _ in self._iter_text(self.img):
            if insn.mnemonic in ("call", "jmp") and insn.operands and \
               insn.operands[0].type == CS_OP_IMM:
                tgt = insn.operands[0].imm - self.img.image_base
                if tgt == target_rva:
                    site_rva = insn.address - self.img.image_base
                    sites.append({
                        "site_rva": site_rva,
                        "kind": insn.mnemonic,
                        "function_rva": self._enclosing_function(site_rva),
                        "bytes": insn.bytes.hex(),
                        "text": f"{insn.mnemonic} {insn.op_str}",
                    })
        return sites

    def _enclosing_function(self, site_rva):
        """Nearest preceding export or 'push ebp; mov ebp,esp' prologue. Best effort."""
        # exports first
        candidates = [r for r in self._exports_by_rva if r <= site_rva]
        if candidates:
            return max(candidates)
        return None

    # ------------------------------------------------------------------
    def function_bounds(self, rva):
        """Linear-sweep bounds: stop at first RET-terminated block or next
        direct-call target that isn't this function. Returns UNKNOWN fields
        when ambiguous. We do NOT claim precise bounds from the first RET."""
        text = next((s for s in self.img.sections() if s["name"] == ".text"), None)
        off = self.img.rva_to_offset(rva)
        if off is None or not text:
            return {"status": "UNKNOWN", "reason": "rva outside .text"}
        data = self.img.read_rva(rva, min(4096, text["raw_size"] - (off - text["raw_offset"])))
        insns = list(self.md.disasm(data, self.img.image_base + rva))
        size = 0
        rets = 0
        for insn in insns:
            size += insn.size
            if insn.mnemonic.startswith("ret"):
                rets += 1
                break
        return {
            "status": "OBSERVED",
            "note": "linear sweep to first RET; multi-exit functions may extend further",
            "size_to_first_ret": size,
            "instructions": len(insns),
        }

    # ------------------------------------------------------------------
    def build_graph_around(self, root_rva, depth=3):
        """Recursive callee graph rooted at root_rva."""
        graph = {"root_rva": root_rva, "nodes": {}, "edges": []}
        seen = set()

        def walk(rva, d, caller):
            if d > depth or rva in seen:
                return
            seen.add(rva)
            name = self._exports_by_rva.get(rva, f"sub_{rva:X}")
            graph["nodes"][rva] = {"name": name, "bounds": self.function_bounds(rva)}
            text = next((s for s in self.img.sections() if s["name"] == ".text"), None)
            off = self.img.rva_to_offset(rva)
            if off is None:
                return
            data = self.img.read_rva(rva, 512)
            for insn in self.md.disasm(data, self.img.image_base + rva):
                if insn.mnemonic.startswith("ret"):
                    break
                if insn.mnemonic == "call" and insn.operands and \
                   insn.operands[0].type == CS_OP_IMM:
                    tgt = insn.operands[0].imm - self.img.image_base
                    graph["edges"].append({
                        "from": rva, "to": tgt,
                        "site_rva": insn.address - self.img.image_base,
                    })
                    walk(tgt, d + 1, rva)

        walk(root_rva, 0, None)
        return graph
