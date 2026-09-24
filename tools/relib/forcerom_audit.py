# forcerom_audit.py — extract ForceROM.exe's IOCTL/kernel32 SCSI pipeline
import pefile
p = pefile.PE(r'C:\SM2258XT_MPTool\ForceROM.exe')
base = p.OPTIONAL_HEADER.ImageBase

# Show all imports (which DLL functions it calls)
print('=== ForceROM.exe imports ===')
for dll in p.DIRECTORY_ENTRY_IMPORT:
    nm = dll.dll.decode()
    print(f'{nm}:')
    for imp in dll.imports:
        inm = imp.name.decode() if imp.name else f'@{imp.ordinal}'
        print(f'    {inm}')
