# adata_sdk_scan.py — scan ADATA SSD ToolBox for RomCode-related references
import os, re

toolbox = r'C:\Program Files\ADATA\SSD ToolBox'
print('=== Files in ADATA SSD ToolBox ===')
for f in os.listdir(toolbox):
    fp = os.path.join(toolbox, f)
    if os.path.isfile(fp):
        sz = os.path.getsize(fp)
        if f.endswith(('.exe', '.dll')):
            print(f'  {sz:>10}  {f}')

# Most promising binaries for RomCode handling:
target_files = ['SSDToolBox.exe', 'DiskAccessLibrary.dll', 'RawDiskLib.dll', 'DeviceIOControlLib.dll']

# Find strings that suggest RomCode/Reset/ISP mechanism in binaries
KEY_PATTERNS = [b'RomCode', b'Rommode', b'Rom_Mode', b'SMIPC', b'setRom', b'setrom',
                b'ForceRom', b'forcetoRom', b'DownloadISP', b'DownloadFW', b'initPage',
                b'SM2258XT', b'SM2258', b'PatchNand', b'MPISP', b'Physics', b'BusReset',
                b'PassThrough', b'Pass_Through', b'EnterISP', b'EnterBoot']

import subprocess, struct
results = {}
for fname in target_files:
    fp = os.path.join(toolbox, fname)
    if not os.path.exists(fp): continue
    data = open(fp, 'rb').read()
    results[fname] = {}
    for pat in KEY_PATTERNS:
        positions = []
        i = 0
        while True:
            j = data.find(pat, i)
            if j < 0: break
            positions.append(j)
            i = j + 1
        if positions:
            results[fname][pat.decode()] = positions[:10]

print()
print('=== RomCode-related string hits in each binary ===')
for f, r in results.items():
    if not r: continue
    print(f'\n{f}:')
    for pat, positions in r.items():
        print(f'  "{pat}": {len(positions)} occurrences')
