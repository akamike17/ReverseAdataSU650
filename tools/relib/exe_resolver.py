#!/usr/bin/env python3
"""exe_resolver.py - trace Borland-style LoadLibrary/GetProcAddress
function-pointer slots in the MPTool EXE.

Pattern searched (from skill notes):
  push <export_name_string_VA>
  ...
  call dword ptr [GetProcAddress]
  ...
  mov [0x50xxxx], eax        <-- slot

Then find call sites:  call dword ptr [0x50xxxx]  -> real callers.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

from .pe import PEImage


class ExeResolver:
    def __init__(self, exe_path):
        self.img = PEImage(exe_path)
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

    # ------------------------------------------------------------------
    def find_export_string_vas(self, names):
        """VA of each export-name string inside the EXE."""
        out = {}
        for name in names:
            variants = [name, name.lstrip("_"), "_" + name.lstrip("_")]
            vas = set()
            for v in set(variants):
                for off in self.img.find_ascii(v):
                    rva = self.img.offset_to_rva(off)
                    if rva is not None:
                        vas.add(self.img.image_base + rva)
            out[name] = sorted(vas)
        return out

    # ------------------------------------------------------------------
    def _disasm_text(self):
        text = next((s for s in self.img.sections() if s["name"] == ".text"), None)
        if not text:
            return []
        data = self.img.read_rva(text["virtual_address"], text["virtual_size"])
        return list(self.md.disasm(data, self.img.image_base + text["virtual_address"]))

    # ------------------------------------------------------------------
    def resolve_slots(self, names):
        """For each export name: string VA -> GetProcAddress store -> slot VA."""
        string_vas = self.find_export_string_vas(names)
        insns = self._disasm_text()
        result = {}

        for name, vas in string_vas.items():
            entry = {"string_vas": [hex(v) for v in vas], "slot": None, "evidence": []}
            if not vas:
                entry["status"] = "UNKNOWN"
                result[name] = entry
                continue
            # find 'push <string_va>' followed (within 32 insns) by
            # 'call dword ptr [x]' and then 'mov [slot], eax'
            for i, insn in enumerate(insns):
                if insn.mnemonic == "push" and insn.operands and \
                   insn.operands[0].type == CS_OP_IMM and \
                   insn.operands[0].imm in vas:
                    window = insns[i:i + 32]
                    gpa_seen = False
                    for w in window:
                        if w.mnemonic == "call" and w.operands and \
                           w.operands[0].type == CS_OP_MEM:
                            gpa_seen = True  # GetProcAddress thunk (best effort)
                        if gpa_seen and w.mnemonic == "mov" and \
                           "[eax]" not in w.op_str and w.op_str.endswith(", eax") and \
                           w.operands[0].type == CS_OP_MEM:
                            slot_va = w.operands[0].mem.disp
                            entry["slot"] = hex(slot_va)
                            entry["evidence"].append({
                                "push_site": hex(insn.address),
                                "store_site": hex(w.address),
                            })
                            break
                    if entry["slot"]:
                        break
            entry["status"] = "CONFIRMED" if entry["slot"] else "UNKNOWN"
            result[name] = entry
        return result

    # ------------------------------------------------------------------
    def slot_callers(self, slot_va):
        """All 'call dword ptr [slot_va]' sites in .text."""
        sites = []
        for insn in self._disasm_text():
            if insn.mnemonic == "call" and insn.operands and \
               insn.operands[0].type == CS_OP_MEM and \
               insn.operands[0].mem.disp == slot_va:
                sites.append({
                    "site_rva": insn.address - self.img.image_base,
                    "site_va": insn.address,
                    "text": f"{insn.mnemonic} {insn.op_str}",
                })
        return sites
