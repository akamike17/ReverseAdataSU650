#!/usr/bin/env python3
"""
SWPtest.dll Full Reverse Engineering
Complete analysis of DownloadMPISP and context structure
"""
import pefile
import capstone
from typing import Dict, List, Tuple, Optional
import struct

class SWPtestReverser:
    def __init__(self, dll_path: str):
        self.pe = pefile.PE(dll_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.code = self.pe.sections[0]
        self.code_data = self.code.get_data()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        
        # Export map
        self.exports = {}
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f"ord_{exp.ordinal}"
            self.exports[name] = exp.address
        
        # Import map
        self.imports = {}
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            for imp in entry.imports:
                if imp.name:
                    self.imports[imp.address] = f"{dll_name}!{imp.name.decode()}"
                else:
                    self.imports[imp.address] = f"{dll_name}!ord{imp.ordinal}"
        
        # Known MPTool global slots (from previous analysis)
        self.global_slots = {
            0x507f70: "pDownloadMPISP",
            0x507efc: "pDownloadISP",
            0x507f74: "pCheckRunMode",
            0x507fa0: "pScanSMIDrive",
            0x507f78: "pReadFlashID",
            0x507f7c: "pDriveReset",
            0x507f80: "pEraseAll",
            0x507f84: "pProgramDummyAll",
        }
        
        # Discovered structures
        self.context_struct = {}
        self.call_chains = {}
        
    def rva_to_offset(self, rva: int) -> int:
        """Convert RVA to file offset"""
        return rva - self.code.VirtualAddress
    
    def disassemble_function(self, name: str, max_insns: int = 500) -> List:
        """Disassemble an exported function"""
        if name not in self.exports:
            print(f"[!] Export not found: {name}")
            return []
        
        rva = self.exports[name]
        offset = self.rva_to_offset(rva)
        
        instructions = []
        size = 0
        for insn in self.md.disasm(self.code_data[offset:offset+max_insns*15], 
                                   self.image_base + rva):
            instructions.append(insn)
            size += insn.size
            if size > 0x1000:  # Safety limit
                break
        
        return instructions
    
    def trace_call_chain(self, entry_rva: int, max_depth: int = 5, depth: int = 0) -> List[Tuple[int, str]]:
        """Trace call chain recursively"""
        chain = []
        visited = set()
        
        def _trace(rva: int, depth: int):
            if depth > max_depth or rva in visited:
                return
            visited.add(rva)
            
            offset = self.rva_to_offset(rva)
            if offset < 0 or offset >= len(self.code_data):
                return
            
            for insn in self.md.disasm(self.code_data[offset:offset+0x1000], 
                                       self.image_base + rva):
                if insn.mnemonic == "call":
                    # Get target
                    target = insn.operands[0]
                    if target.type == capstone.x86.X86_OP_IMM:
                        call_rva = target.imm - self.image_base
                        target_name = self.exports.get(call_rva, f"sub_{call_rva:08X}")
                        chain.append((call_rva, target_name, depth))
                        _trace(call_rva, depth + 1)
                    elif target.type == capstone.x86.X86_OP_MEM:
                        # Indirect call - check if it's a global slot
                        if target.mem.base == 0 and target.mem.index == 0:
                            addr = target.mem.disp
                            if self.image_base <= addr < self.image_base + self.pe.OPTIONAL_HEADER.SizeOfImage:
                                rva = addr - self.image_base
                                if rva in self.global_slots:
                                    chain.append((addr, f"CALL [{self.global_slots[rva]}]", depth))
                                elif addr in self.imports:
                                    chain.append((addr, f"CALL [{self.imports[addr]}]", depth))
        
        _trace(entry_rva, 0)
        return chain
    
    def analyze_context_structure(self, func_name: str):
        """Analyze the context structure used by a function"""
        print(f"\n{'='*70}")
        print(f"CONTEXT STRUCTURE ANALYSIS: {func_name}")
        print(f"{'='*70}")
        
        insns = self.disassemble_function(func_name, 300)
        if not insns:
            return
        
        # Look for context accesses (ebp+N patterns)
        context_accesses = []
        for insn in insns:
            # Look for [ebp+X] or [ebp-X] patterns
            if insn.mnemonic in ['mov', 'lea', 'push', 'pop', 'add', 'sub', 'cmp', 'test']:
                op_str = insn.op_str
                if '[ebp+' in op_str or '[ebp-' in op_str:
                    # Extract offset
                    import re
                    matches = re.findall(r'\[ebp([+\-])(0x]?[0-9a-fA-F]+)\]', op_str)
                    for sign, offset_str in matches:
                        try:
                            offset = int(offset_str, 0)
                            if sign == '-':
                                offset = -offset
                            context_accesses.append({
                                'offset': offset,
                                'insn': insn,
                                'operation': insn.mnemonic
                            })
                        except:
                            pass
        
        # Group by offset
        offset_map = {}
        for acc in context_accesses:
            off = acc['offset']
            if off not in offset_map:
                offset_map[off] = []
            offset_map[off].append(acc)
        
        print(f"\nContext structure map (offset -> operations):")
        for offset in sorted(offset_map.keys()):
            ops = offset_map[offset]
            print(f"\n  Offset {offset:+#05x} ({offset:5}):")
            for op in ops[:3]:  # Show first 3
                print(f"    0x{op['insn'].address:08X}: {op['insn'].mnemonic:8} {op['insn'].op_str}")
            if len(ops) > 3:
                print(f"    ... and {len(ops)-3} more")
        
        return offset_map
    
    def analyze_all_exports(self):
        """Analyze all exports"""
        print(f"\n{'='*70}")
        print(f"SWPtest.dll Complete Export Analysis")
        print(f"{'='*70}")
        print(f"Image base: 0x{self.image_base:08X}")
        print(f"Total exports: {len(self.exports)}")
        
        # Categorize exports
        categories = {
            'SMI': [], 'ISP': [], 'MPT': [], 'Flash': [], 
            'Drive': [], 'Utility': [], 'Unknown': []
        }
        
        for name, rva in sorted(self.exports.items(), key=lambda x: x[1]):
            cat = 'Unknown'
            for c in categories:
                if c.lower() in name.lower():
                    cat = c
                    break
            categories[cat].append((name, rva))
        
        for cat, funcs in categories.items():
            if funcs:
                print(f"\n{cat} functions ({len(funcs)}):")
                for name, rva in funcs:
                    print(f"  0x{rva:08X}: {name}")
        
        # Analyze key functions
        key_functions = [
            '_SMIPtestDownloadMPISP',
            '_SMIPtestCheckRunMode',
            '_SMIPtestDriveReset',
            '_SMIReadFlashID',
            '_SMIScanSMIDrive',
            '_SMISetPassThroughType',
        ]
        
        print(f"\n{'='*70}")
        print(f"KEY FUNCTION SIGNATURES")
        print(f"{'='*70}")
        
        for func_name in key_functions:
            if func_name in self.exports:
                self.analyze_function_signature(func_name)
        
        # Analyze call chains
        print(f"\n{'='*70}")
        print(f"CALL CHAIN ANALYSIS")
        print(f"{'='*70}")
        
        for func_name in ['_SMIPtestDownloadMPISP', '_SMIPtestCheckRunMode']:
            print(f"\n--- Call chain for {func_name} ---")
            entry_rva = self.exports[func_name]
            chain = self.trace_call_chain(entry_rva, max_depth=3)
            
            for rva, name, depth in chain[:20]:
                indent = "  " * depth
                slot = ""
                if rva in self.global_slots:
                    slot = f" [{self.global_slots[rva]}]"
                print(f"{indent}0x{rva:08X}: {name}{slot}")
    
    def analyze_function_signature(self, func_name: str):
        """Analyze function signature from disassembly"""
        print(f"\n{'-'*70}")
        print(f"Function: {func_name}")
        print(f"{'-'*70}")
        
        insns = self.disassemble_function(func_name, 100)
        if not insns:
            print("  (no disassembly)")
            return
        
        # Look for cdecl/stdcall patterns
        # cdecl: caller cleans (add esp, N)
        # stdcall: callee cleans (ret N)
        
        print(f"Entry point: 0x{self.exports[func_name]:08X}")
        print(f"First instructions:")
        for insn in insns[:10]:
            print(f"  0x{insn.address:08X}: {insn.mnemonic:8} {insn.op_str}")
        
        # Check return paradigm
        if insns:
            last = insns[-1]
            if last.mnemonic.startswith('ret'):
                print(f"\nReturn: {last.mnemonic} {last.op_str}")
                if 'ret' in last.mnemonic and last.op_str:
                    # stdcall with cleanup
                    try:
                        cleanup = int(last.op_str, 0)
                        print(f"  -> stdcall, callee cleans {cleanup} bytes = {cleanup//4} params")
                    except:
                        pass
                else:
                    print(f"  -> cdecl, caller cleans")
            elif last.mnemonic == 'retn':
                print(f"\nReturn: retn (cdecl, caller cleans)")
        
        # Look for parameter accesses in first N instructions
        print(f"\nParameter access patterns (first 50 instructions):")
        for insn in insns[:50]:
            if '[ebp+' in insn.op_str or '[esp+' in insn.op_str:
                print(f"  0x{insn.address:08X}: {insn.mnemonic:8} {insn.op_str}")


def main():
    dll_path = r"C:\SM2258XT_MPTool\Dll\SWPtest.dll"
    
    print("SWPtest.dll Reverse Engineering - Starting...")
    print(f"Analyzing: {dll_path}")
    
    re = SWPtestReverser(dll_path)
    
    # Full analysis
    re.analyze_all_exports()
    
    # Context structure for DownloadMPISP
    re.analyze_context_structure('_SMIPtestDownloadMPISP')
    
    # Context structure for CheckRunMode
    re.analyze_context_structure('_SMIPtestCheckRunMode')
    
    print(f"\n{'='*70}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
