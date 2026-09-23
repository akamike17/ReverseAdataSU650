# cv_audit2.py — CV.md section 12+: harness history, arch verification, mode-range hunt
import struct, sys, os
import pefile, capstone

ROOT = r'C:\SM2258XT_MPTool'
# 12.6 Harness history: which smiflash*.log show modeOut=5 and what changed between runs
print('=== CV S12.6: harness logs with a non-zero RunMode ===')
import glob
for f in sorted(glob.glob(os.path.join(ROOT, 'log', 'smiflash*.log'))):
    try: t = open(f, errors='ignore').read()
    except: continue
    if 'RunMode:' in t:
        line = [l for l in t.splitlines() if 'RunMode:' in l]
        print(f' {os.path.basename(f)}: {line[0].strip()}')

# 8. x86/x64 verification of historical harness build
print('\n=== CV S8: as-built architecture of the harness that produced RunMode=5 ===')
# look for last built PE
for root, dirs, files in os.walk(os.path.join(ROOT, 'smiflash_build', 'bin')):
    for n in files:
        if n.endswith('.exe') or n.endswith('.dll'):
            ff = os.path.join(root, n)
            try:
                pp = pefile.PE(ff)
                print(f' {ff}: Machine={hex(pp.FILE_HEADER.Machine)}')
            except Exception as e:
                pass

# In harness, search for any write to modeOut anywhere
print('\n=== CV S12.6: all references to modeOut in smiflash.cs ===')
p = open(os.path.join(ROOT, 'smiflash.cs')).read()
import re
for i, line in enumerate(p.splitlines(), 1):
    if 'modeOut' in line:
        print(f'  L{i}: {line.rstrip()}')

# Search for any '= 5' or '=5' literal pattern / suspicious writes around modeOut usage
print('\n=== CV S12.6: any literal 5 written to modeOut or similar ===')
for i, line in enumerate(p.splitlines(), 1):
    if 'WriteInt8' in line or 'WriteByte' in line or '= 5' in line:
        print(f'  L{i}: {line.rstrip()}')
