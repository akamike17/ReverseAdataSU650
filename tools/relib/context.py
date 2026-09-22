#!/usr/bin/env python3
"""context.py - static context-access analysis for DownloadMPISP chain.

Finds memory accesses of the form [reg + imm] inside the DownloadMPISP
callee graph, tagging them as context-access CANDIDATES (observed
instruction, hypothesized base). Ground truth requires the dynamic phase.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_MEM

from .calls import CallAnalyzer


class ContextAnalyzer:
    def __init__(self, image):
        self.img = image
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.calls = CallAnalyzer(image)

    def analyze(self, root_rva, max_scan=2048):
        accesses = []
        graph = self.calls.build_graph_around(root_rva, depth=4)
        for node_rva in graph["nodes"]:
            off = self.img.rva_to_offset(node_rva)
            if off is None:
                continue
            data = self.img.read_rva(node_rva, max_scan)
            for insn in self.md.disasm(data, self.img.image_base + node_rva):
                if insn.mnemonic.startswith("ret"):
                    break
                for iop, op in enumerate(insn.operands):
                    if op.type == CS_OP_MEM and op.mem.base != 0 and op.mem.disp != 0:
                        base = insn.reg_name(op.mem.base)
                        if base in ("ebp", "esp"):
                            continue  # stack-relative: args/locals, not context
                        # operand 0 is the destination in Intel syntax:
                        # memory in op0 => WRITE, otherwise READ
                        accesses.append({
                            "status": "HYPOTHESIS",
                            "function": graph["nodes"][node_rva]["name"],
                            "rva": insn.address - self.img.image_base,
                            "text": f"{insn.mnemonic} {insn.op_str}",
                            "base_reg": base,
                            "offset": op.mem.disp,
                            "access": "WRITE" if iop == 0 else "READ",
                        })
        return accesses
