# adata_decompile.py — extract meaningful insights from ADATA SSDToolBox using ildasm-style scan
import pefile, struct, sys

# Since SSDToolBox.exe is .NET, we need to parse IL or use Capstone on native stubs.
# Let's start by examining its manifest and the strings it contains.

targets = {
    'SSDToolBox.exe': r'C:\Program Files\ADATA\SSD ToolBox\SSDToolBox.exe',
    'DiskAccessLibrary.dll': r'C:\Program Files\ADATA\SSD ToolBox\DiskAccessLibrary.dll',
    'RawDiskLib.dll': r'C:\Program Files\ADATA\SSD ToolBox\RawDiskLib.dll',
    'DeviceIOControlLib.dll': r'C:\Program Files\ADATA\SSD ToolBox\DeviceIOControlLib.dll',
}

# Simple metadata analysis — look for .NET IL metadata header
def analyze_pe(path):
    p = pefile.PE(path)
    print(f'\n=== {path.split(chr(92))[-1]} ===')
    print(f'  ImageBase: {p.OPTIONAL_HEADER.ImageBase:#x}')
    print(f'  Has .NET CLR: {"Yes" if (p.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0) else "No"}')
    
    data = p.__data__
    
    # Find ADATA-specific strings
    for needle in [b'FirmwareUpdateOnReboot', b'FwUpdate', b'FwLoadPage', b'init mode', 
                   b'flash_rom', b'RomMode', b'Rom Code', b'RomMode', b'reset rom',
                   b'SecureErase', b'ForceReboot', b'HardReset', b'PfailReset', b'ResetSata',
                   b'LoadFirmware', b'UploadFirmware', b'SendFirmware', b'Firmware.Send',
                   b'SetRomMode', b' Rom Mode', b'ModelNumber', b'Specific Function']:
        i = data.find(needle)
        while i >= 0:
            # decode file offset to VA
            for s in p.sections:
                if s.PointerToRawData <= i < s.PointerToRawData + s.SizeOfRawData:
                    rva = s.VirtualAddress + (i - s.PointerToRawData)
                    end = data.find(b'\x00', i)
                    if 0 < end < i+80:
                        snippet = data[i:end].decode('ascii', 'ignore')
                        print(f'  "{needle.decode()}" @{rva:#x}: "{snippet}"')
                    break
            i = data.find(needle, i+1)

for name, fpath in targets.items():
    try:
        analyze_pe(fpath)
    except Exception as e:
        print(f'{name}: error {e}')
