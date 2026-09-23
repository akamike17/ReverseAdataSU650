# exhaustive_writes.py — every instruction writing to 0x507FD0 or 0x507FC4,
# regardless of opcode form. Then find callers of the dispatch fn.
import pefile, capstone, struct
from capstone.x86 import X86_OP_MEM

p = pefile.PE('SM2258XTMPToolQ0816A.exe')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def rd(rva,n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    return b''

text = rd(0x1000, 0xCE000)

# Targets as absolute VAs
T1 = 0x507FD0   # type-2 gate flag
T2 = 0x507FC4   # type-1 gate flag

# Walk ALL of .text disassembling linear-sweep; collect any insn whose operands touch T1/T2
# Memory-operand absolute addressing encodes the VA directly.
writer_opcodes = {'mov','movzx','movsx','xchg','stos','rep movs','rep stos',
                  'or','and','add','sub','xor','inc','dec','pop','push'}

t1_writes = []
t1_reads  = []
t2_writes = []
t2_reads  = []

addr_pack1 = struct.pack('<I', T1)
addr_pack2 = struct.pack('<I', T2)

# Speed optimization: only disasm windows around raw byte hits of the VA
offsets_t1 = []
i = 0
while True:
    j = text.find(addr_pack1, i)
    if j < 0: break
    offsets_t1.append(j)
    i = j + 1

offsets_t2 = []
i = 0
while True:
    j = text.find(addr_pack2, i)
    if j < 0: break
    offsets_t2.append(j)
    i = j + 1

print(f'Raw hits to VA 0x507FD0: {len(offsets_t1)}, hits to 0x507FC4: {len(offsets_t2)}')

def classify(hits_off):
    out = []
    for off in hits_off:
        # Try instruction starts from off-7..off (VA operand inside the insn)
        got = None
        for back in range(1, 12):
            st = off - back
            if st < 0: continue
            code6 = text[st:st+16]
            for ins in md.disasm(code6, base + 0x1000 + st):
                if ins.address == base + 0x1000 + st and st < off < st + ins.size:
                    # Verify the VA operand actually appears within
                    ops = ins.op_str
                    if f'{0x507FD0:x}'.lower() in ops.lower() or f'{0x507FC4:x}'.lower() in ops.lower():
                        got = (0x1000+st, ins.mnemonic, ops)
                        break
            if got: break
        # If not found, try matching at exact byte boundary (jump-table entry / data ref)
        if not got:
            # Show the bytes before to decide if it's really an instruction operand
            got = (0x1000+off, '?raw-operand?', f'... bytes around hit')
        out.append(got)
    return out

print()
print('=== classify hits on 0x507FD0 ===')
for rva, mn, ops in classify(offsets_t1):
    write_op = mn.lower() in writer_opcodes and (',' in ops and ops.startswith('dword ptr [0x507fd0]') or ops.startswith('byte ptr [0x507fd0]') or ops.startswith('word ptr [0x507fd0]'))
    kind = 'WRITE' if write_op else 'READ/other'
    print(f'  {rva:#x}: {mn:10s} {ops:60s}  [{kind}]')

print()
print('=== classify hits on 0x507FC4 ===')
for rva, mn, ops in classify(offsets_t2):
    write_op = mn.lower() in writer_opcodes and (',' in ops and ops.startswith('dword ptr [0x507fc4]') or ops.startswith('byte ptr [0x507fc4]') or ops.startswith('word ptr [0x507fc4]'))
    kind = 'WRITE' if write_op else 'READ/other'
    print(f'  {rva:#x}: {mn:10s} {ops:60s}  [{kind}]')
