#!/usr/bin/env python3
"""pe.py - PE file wrapper: sections, RVA<->offset, exports, imports.

Evidence rules:
  - All conversions are arithmetic over PE headers (CONFIRMED by definition).
  - Anything not present in the headers is reported as UNKNOWN, never guessed.
"""
import hashlib
from pathlib import Path

import pefile


class PEImage:
    def __init__(self, path):
        self.path = Path(path)
        self.pe = pefile.PE(str(self.path))
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.path.read_bytes()

    # ------------------------------------------------------------------
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    def machine(self):
        return self.pe.FILE_HEADER.Machine

    def bits(self):
        return 64 if self.pe.OPTIONAL_HEADER.Magic == 0x20B else 32

    def sections(self):
        out = []
        for s in self.pe.sections:
            out.append({
                "name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                "virtual_address": s.VirtualAddress,
                "virtual_size": s.Misc_VirtualSize,
                "raw_offset": s.PointerToRawData,
                "raw_size": s.SizeOfRawData,
            })
        return out

    # ------------------------------------------------------------------
    def rva_to_offset(self, rva):
        """RVA -> file offset. Returns None if RVA is outside all sections."""
        for s in self.pe.sections:
            start = s.VirtualAddress
            end = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if start <= rva < end:
                off = rva - start
                if off < s.SizeOfRawData:
                    return s.PointerToRawData + off
                return None
        return None

    def offset_to_rva(self, offset):
        for s in self.pe.sections:
            if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
                return s.VirtualAddress + (offset - s.PointerToRawData)
        return None

    def rva_to_va(self, rva):
        return self.image_base + rva

    def section_of_rva(self, rva):
        for s in self.pe.sections:
            start = s.VirtualAddress
            end = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if start <= rva < end:
                return s.Name.rstrip(b"\x00").decode("ascii", "replace")
        return None

    def read_rva(self, rva, size):
        off = self.rva_to_offset(rva)
        if off is None:
            return b""
        return self.data[off:off + size]

    # ------------------------------------------------------------------
    def exports(self):
        out = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = e.name.decode("ascii", "replace") if e.name else None
                out.append({
                    "name": name,
                    "ordinal": e.ordinal,
                    "rva": e.address,
                    "va": self.image_base + e.address,
                    "file_offset": self.rva_to_offset(e.address),
                    "section": self.section_of_rva(e.address),
                    "forwarder": (
                        e.forwarder.decode("ascii", "replace") if e.forwarder else None
                    ),
                })
        return out

    def imports(self):
        out = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("ascii", "replace")
                for imp in entry.imports:
                    out.append({
                        "dll": dll,
                        "name": imp.name.decode("ascii", "replace") if imp.name else None,
                        "ordinal": imp.ordinal,
                        "iat_rva": imp.address,  # pefile returns VA here when rebased
                    })
        return out

    def find_ascii(self, needle):
        """All file offsets of an ASCII byte string."""
        if isinstance(needle, str):
            needle = needle.encode("ascii")
        found = []
        start = 0
        while True:
            i = self.data.find(needle, start)
            if i < 0:
                break
            found.append(i)
            start = i + 1
        return found
