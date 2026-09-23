"""Disassemble a DLL RVA range with capstone from SWPtest.dll."""
import sys
import pefile
import capstone

def load_dll(path="SWPtest.dll"):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    return pe, base

def get_bytes(pe, rva, size):
    for s in pe.sections:
        va = s.VirtualAddress
        end = va + s.Misc_VirtualSize
        if va <= rva < end:
            off = s.PointerToRawData + (rva - va)
            return pe.__data__[off:off+size]
    raise ValueError(f"RVA {rva:#x} not in sections")

def disasm(path, rva, size=0x400, stop_at_ret=False, comment=True):
    pe, base = load_dll(path)
    data = get_bytes(pe, rva, size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    va = base + rva
    lines = []
    for ins in md.disasm(data, va):
        rva_i = ins.address - base
        line = f"{ins.address:#010x} (RVA {rva_i:#07x}): {ins.mnemonic:8s} {ins.op_str}"
        lines.append(line)
        if stop_at_ret and ins.mnemonic.startswith("ret"):
            break
    return lines

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "SWPtest.dll"
    rva = int(sys.argv[2], 16)
    size = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x400
    for l in disasm(path, rva, size, stop_at_ret=True):
        print(l)
