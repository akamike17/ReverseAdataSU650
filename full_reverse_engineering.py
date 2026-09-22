#!/usr/bin/env python3
"""
SWPtest.dll Static Analysis - Complete Reverse Engineering
Focus: DownloadMPISP context structure and parameter flow
"""
import pefile
import struct
import sys
from pathlib import Path
from capstone import *

# Configuration
DLL_PATH = r"C:\SM2258XT_MPTool\Dll\SWPtest.dll"
OUTPUT_DIR = Path(r"C:\SM2258XT_MPTool\analysis")

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

class SWPtestAnalyzer:
    def __init__(self, dll_path):
        self.pe = pefile.PE(dll_path)
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        
        # Get .text section
        self.text_section = None
        for section in self.pe.sections:
            if section.Name.startswith(b'.text'):
                self.text_section = section
                break
        
        if not self.text_section:
            raise Exception(".text section not found")
        
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text_data = self.text_section.get_data()
        self.text_rva = self.text_section.VirtualAddress
        
        # Exports map
        self.exports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    self.exports[exp.name.decode()] = exp.address
        
        print(f"Loaded: {dll_path}")
        print(f"  Image base: 0x{self.image_base:08X}")
        print(f"  Exports: {len(self.exports)} functions")
        print(f"  .text RVA: 0x{self.text_rva:08X}")
        print(f"  .text size: 0x{len(self.text_data):08X}")
    
    def rva_to_offset(self, rva):
        """Convert RVA to file offset in .text section"""
        if self.text_rva <= rva < self.text_rva + self.text_section.Misc_VirtualSize:
            return rva - self.text_rva
        return None
    
    def disassemble(self, rva, size):
        """Disassemble bytes at RVA"""
        offset = self.rva_to_offset(rva)
        if offset is None:
            return []
        
        code = self.text_data[offset:offset+size]
        return list(self.md.disasm(code, self.image_base + rva))
    
    def analyze_export_structure(self, func_name):
        """Complete analysis of an export's structure"""
        if func_name not in self.exports:
            print(f"[!] Export not found: {func_name}")
            return None
        
        rva = self.exports[func_name]
        print(f"\n{'='*70}")
        print(f"Analyzing: {func_name} @ RVA 0x{rva:08X}")
        print(f"{'='*70}")
        
        # Disassemble the function
        instructions = self.disassemble(rva, 512)
        
        # Find prologue size to understand stack frame
        prologue_end = 0
        for i, insn in enumerate(instructions):
            if insn.mnemonic == 'push' and 'ebp' in insn.op_str:
                prologue_end = i + 1
                if i + 1 < len(instructions) and instructions[i+1].mnemonic == 'mov':
                    if 'ebp, esp' in instructions[i+1].op_str:
                        prologue_end = i + 2
            elif insn.mnemonic == 'sub' and 'esp,' in insn.op_str:
                prologue_end = i + 1
                break
        
        print(f"Prologue ends at instruction {prologue_end}")
        
        # Analyze parameter access pattern
        params = {}
        for insn in instructions[prologue_end:prologue_end+100]:
            # Look for [ebp+X] access (parameters)
            if insn.mnemonic in ['mov', 'lea', 'push', 'pop', 'movzx', 'movsx']:
                op_str = insn.op_str
                
                # Check for [ebp+...]
                if '[ebp+' in op_str:
                    # Extract offset
                    import re
                    match = re.search(r'\[ebp\+(0x[0-9a-fA-F]+)\]', op_str)
                    if match:
                        offset = int(match.group(1), 16)
                        if offset not in params:
                            params[offset] = []
                        params[offset].append(insn)
        
        print(f"\nParameter structure (ebp-relative):")
        for offset in sorted(params.keys()):
            accesses = params[offset]
            print(f"  [ebp+{offset:+4d}] = arg{offset//4}:")
            for insn in accesses[:2]:  # Show first 2 accesses
                print(f"    0x{insn.address:08X}: {insn.mnemonic:10} {insn.op_str}")
            if len(accesses) > 2:
                print(f"    ... ({len(accesses)} total accesses)")
        
        return {
            'name': func_name,
            'rva': rva,
            'instructions': instructions,
            'params': params,
            'prologue_end': prologue_end
        }
    
    def find_sub_function(self, rva):
        """Find sub-function at given RVA"""
        # Look for function prologue pattern
        off = self.rva_to_offset(rva)  # FIX: was bare `rva_to_offset(...)`
        if off is None:
            return False
        code = self.text_data[off:off+32]
        for insn in self.md.disasm(code, self.image_base + rva):
            if insn.mnemonic == 'push' and 'ebp' in insn.op_str:
                # Found it
                return True
        return False
    
    def trace_call_chain(self, func_name, max_depth=3):
        """Trace the complete call chain"""
        if func_name not in self.exports:
            print(f"[!] Export not found: {func_name}")
            return []
        
        rva = self.exports[func_name]
        chain = [(func_name, rva)]
        
        visited = set()
        
        def _trace(current_rva, depth):
            if depth > max_depth or current_rva in visited:
                return
            visited.add(current_rva)
            
            # Disassemble this function
            instructions = self.disassemble(current_rva, 256)
            
            for insn in instructions:
                # Look for call instructions
                if insn.mnemonic == 'call':
                    # Get target
                    if insn.operands[0].type == CS_OP_IMM:
                        target = insn.operands[0].imm
                        target_rva = target - self.image_base
                        
                        # Check if it's a sub-function or another export
                        if target_rva in self.exports.values():
                            name = [k for k, v in self.exports.items() if v == target_rva][0]
                            print(f"{'  ' * depth}call {name} (0x{target_rva:08X})")
                        else:
                            print(f"{'  ' * depth}call sub_{target_rva:X} (0x{target_rva:08X})")
                        
                        # Recurse
                        _trace(target_rva, depth + 1)
        
        print(f"\nCall chain for {func_name}:")
        _trace(rva, 0)
        
        return chain
    
    def analyze_context_structure(self, func_name):
        """Analyze how context parameter is used"""
        if func_name not in self.exports:
            return None
        
        analysis = self.analyze_export_structure(func_name)
        if not analysis:
            return
        
        print(f"\n{'='*70}")
        print(f"CONTEXT STRUCTURE ANALYSIS: {func_name}")
        print(f"{'='*70}")
        
        # Look at all [ebp+X] patterns
        # The context parameter is usually [ebp+16] (4th parameter in stdcall/cdecl)
        
        for insn in analysis['instructions']:
            if '[ebp+16]' in insn.op_str or '[ebp+0x10]' in insn.op_str:
                # This is likely the context parameter
                print(f"Context access at 0x{insn.address:08X}:")
                print(f"  {insn.mnemonic:12} {insn.op_str}")
                
                # If loading context into register, trace what it does
                if insn.mnemonic == 'mov' and 'edi' in insn.op_str:
                    print(f"  -> Context loaded into EDI")
                elif insn.mnemonic == 'mov' and 'esi' in insn.op_str:
                    print(f"  -> Context loaded into ESI")
                elif insn.mnemonic == 'mov' and 'edx' in insn.op_str:
                    print(f"  -> Context loaded into EDX")
    
    def get_function_size(self, func_name):
        """Estimate function size by finding next function or ret"""
        if func_name not in self.exports:
            return 0
        
        rva = self.exports[func_name]
        code = self.text_data[self.rva_to_offset(rva):self.rva_to_offset(rva)+4096]
        
        insns = list(self.md.disasm(code, self.image_base + rva))
        
        # Find ret instruction
        for i, insn in enumerate(insns):
            if insn.mnemonic.startswith('ret'):
                return sum(i.size for i in insns[:i+1])
        
        return len(code)  # Fallback

def main():
    print("=" * 70)
    print("SWPtest.dll Complete Reverse Engineering")
    print("=" * 70)
    
    analyzer = SWPtestAnalyzer(DLL_PATH)
    
    # Analyze key exports
    key_exports = [
        '_SMIPtestDownloadMPISP',
        '_SMIPtestCheckRunMode',
        '_SMIPtestDriveReset',
        '_SMIReadFlashID',
        '_SMIScanSMIDrive',
        '_SMISetPassThroughType',
        '_SMIPtestDownloadISP',
        '_SMIPtestLoadDgISP',
        '_SMIPtestEraseAll',
        '_SMIPtestProgramDummyAll',
    ]
    
    # First pass: basic structure
    print("\n[PHASE 1] Basic Export Structure")
    print("=" * 70)
    
    for func in key_exports:
        if func in analyzer.exports:
            info = analyzer.analyze_export_structure(func)
            if info:
                size = analyzer.get_function_size(func)
                print(f"  {func}: {size} bytes, RVA 0x{info['rva']:08X}, {len(info['params'])} params")
    
    # Second pass: call chains
    print("\n[PHASE 2] Call Chain Analysis")
    print("=" * 70)
    
    for func in ['_SMIPtestDownloadMPISP', '_SMIPtestCheckRunMode']:
        if func in analyzer.exports:
            print(f"\nTracing {func}:")
            analyzer.trace_call_chain(func, max_depth=4)
    
    # Third pass: context structure
    print("\n[PHASE 3] Context Structure Analysis")
    print("=" * 70)
    
    for func in ['_SMIPtestDownloadMPISP', '_SMIPtestCheckRunMode']:
        if func in analyzer.exports:
            print(f"\nAnalyzing context for {func}:")
            analyzer.analyze_context_structure(func)
    
    # Save results
    results_file = OUTPUT_DIR / "analysis_results.txt"
    with open(results_file, 'w') as f:
        f.write("SWPtest.dll Analysis Results\n")
        f.write("=" * 70 + "\n\n")
        
        for func in key_exports:
            if func in analyzer.exports:
                f.write(f"\n{func}:\n")
                f.write(f"  RVA: 0x{analyzer.exports[func]:08X}\n")
                size = analyzer.get_function_size(func)
                f.write(f"  Size: {size} bytes\n")
    
    print(f"\n[+] Results saved to {results_file}")
    print("=" * 70)

if __name__ == "__main__":
    main()
