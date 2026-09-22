#!/usr/bin/env python3
"""scsi.py - locate DeviceIoControl call sites in SWPtest.dll and classify
SCSI_PASS_THROUGH / SCSI_PASS_THROUGH_DIRECT IOCTL values.

Borland-style DLL: imports are reached via `jmp dword ptr [IAT]` thunks
inside .text, not direct FF15 calls. We:
  1. locate the thunk stub for DeviceIoControl (FF 25 <IAT-VA>),
  2. find every E8 rel32 that lands on that thunk,
  3. walk backwards from each caller to recover pushed immediates.

Evidence classification:
  - IOCTL value read from an immediate push before the thunk call: OBSERVED
    (real bytes in the file).
  - Meaning of CDB opcodes: HYPOTHESIS unless traced from live traffic.
"""
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

IOCTL_NAMES = {
    0x4D014: "IOCTL_SCSI_PASS_THROUGH (0x4D014)",
    0x4D030: "IOCTL_SCSI_PASS_THROUGH_DIRECT (0x4D030)",
    0x4D112: "IOCTL? 0x4D112 (ForceROM.cs value; not present in DLL)",
}


class ScsiAnalyzer:
    def __init__(self, image):
        self.img = image
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.text = next(s for s in self.img.sections() if s["name"] == ".text")
        self.text_data = self.img.read_rva(self.text["virtual_address"],
                                           self.text["virtual_size"])
        self.dio_iat_va = None
        for i in self.img.imports():
            if i["name"] == "DeviceIoControl":
                # pefile gives VA (image_base already added) for this dll
                self.dio_iat_va = i["iat_rva"]
                break

    # ------------------------------------------------------------------
    def _rva_to_va(self, rva):
        return rva  # this PE's IAT entries already carry image_base-added VAs

    def _find_thunk(self, va):
        """Find `jmp dword ptr [va]` inside .text; return thunk file-offset list."""
        pat = b"\xff\x25" + struct.pack("<I", va)
        out = []
        idx = 0
        while True:
            i = self.text_data.find(pat, idx)
            if i < 0:
                break
            out.append(self.text["virtual_address"] + i)
            idx = i + 1
        return out

    def _find_callers_of_rva(self, target_rva):
        """Direct E8 rel32 call sites that land on target_rva (covers .text)."""
        out = []
        data = self.text_data
        base_rva = self.text["virtual_address"]
        image_base = self.img.image_base
        target_va = image_base + target_rva
        idx = 0
        while True:
            i = data.find(b"\xe8", idx)
            if i < 0:
                break
            if i + 5 <= len(data):
                rel = struct.unpack("<i", data[i + 1:i + 5])[0]
                caller_va = image_base + base_rva + i
                dest = (caller_va + 5 + rel) & 0xFFFFFFFF
                if dest == target_va:
                    out.append(base_rva + i)
            idx = i + 1
        return out

    # ------------------------------------------------------------------
    def find_deviceiocontrol_sites(self):
        sites = []
        if not self.dio_iat_va:
            return sites
        for thunk_rva in self._find_thunk(self.dio_iat_va):
            for site_rva in self._find_callers_of_rva(thunk_rva):
                pushes = self._args_before(site_rva)
                imm_pushes = [p for p in pushes if isinstance(p, int)]
                ioctl = next((p for p in imm_pushes
                              if 0x4D000 <= p <= 0x4DFFF), None)
                site = {
                    "site_rva": site_rva,
                    "thunk_rva": thunk_rva,
                    "ioctl": hex(ioctl) if ioctl is not None else None,
                    "ioctl_class": IOCTL_NAMES.get(ioctl, "UNKNOWN"),
                    "pushed_args": [hex(p) if isinstance(p, int) else p
                                    for p in pushes],
                }
                sites.append(site)
        return sites

    def _args_before(self, site_rva, max_back=64):
        """Walk backwards from site_rva collecting pushes. To avoid
        desync on random-code windows, find a known-aligned start by
        scanning backwards for `push ebp` (function prologue)."""
        data = self.text_data
        # search backwards for prologue pattern 55 8B EC (push ebp; mov ebp,esp)
        # within a 4 KB window before site_rva
        target_off_in_buf = site_rva - self.text["virtual_address"]
        search = data[max(0, target_off_in_buf - 4096): target_off_in_buf]
        start_off_in_buf = None
        for i in range(len(search) - 3, -1, -1):
            if search[i:i + 3] == b"\x55\x8b\xec":
                start_off_in_buf = max(0, target_off_in_buf - 4096) + i
                break
        if start_off_in_buf is None:
            # fall back to a window ending at prologue-free scan
            start_off_in_buf = max(0, target_off_in_buf - 256)
        code = data[start_off_in_buf: target_off_in_buf]
        insns = list(self.md.disasm(
            code, self.img.image_base + self.text["virtual_address"] + start_off_in_buf))
        insns = [i for i in insns
                 if i.address < self.img.image_base + site_rva]
        pushes = []
        for b in reversed(insns):
            if b.mnemonic == "push" and b.operands:
                op = b.operands[0]
                if hasattr(op, "imm") and op.type == CS_OP_IMM:
                    pushes.append(op.imm)
                elif op.type == CS_OP_MEM:
                    pushes.append(f"dword ptr [mem:{hex(op.mem.disp)}]")
                else:
                    pushes.append(f"reg:{b.op_str.split()[-1]}")
                if len(pushes) >= 12:
                    break
            elif b.mnemonic in ("call", "ret", "jmp"):
                break
        return pushes

    # ------------------------------------------------------------------
    def cdb_candidates(self, sites):
        """Bytes patterns near DeviceIoControl caller sites that look like CDBs.
        Status: HYPOTHESIS until dynamically traced."""
        out = []
        data = self.text_data
        for site in sites:
            rva = site["site_rva"]
            start = max(0, rva - self.text["virtual_address"] - 0x600)
            end = min(len(data), rva - self.text["virtual_address"] + 0x600)
            window = data[start:end]
            for i in range(len(window) - 16):
                chunk = window[i:i + 16]
                nz = [b for b in chunk if b != 0]
                if 1 <= len(nz) <= 3 and any(b >= 0xA0 or b == 0xE0 for b in nz):
                    out.append({
                        "near_site_rva": hex(rva),
                        "candidate_file_offset": hex(
                            self.text["raw_offset"] + start + i),
                        "cdb_hex": chunk.hex(),
                        "status": "HYPOTHESIS",
                        "note": ("byte pattern near DeviceIoControl caller;"
                                 " not yet traced to a live call"),
                    })
        return out
