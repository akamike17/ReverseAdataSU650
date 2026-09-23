# PASS-THROUGH-TYPE SELECTOR — definitive callers chain (BREAKTHROUGH)

## The modifier:

**Function @ RVA 0x3ACB4** (EXE): the **INI configuration loader** at startup.

Inside it, ALWAYS executed unconditionally at app startup:
```
0x43AD47:  mov dword ptr [0x507FD0], eax      ; type2 gate flag
0x43AD68:  mov dword ptr [0x507FC4], eax      ; type1 gate flag
0x43AD88:  mov dword ptr [0x507FC8], eax      ; skip-smi-test-scan flag
0x43ADA9:  mov dword ptr [0x507FDC], eax      ; sort usb flag
```

These `eax`'es come from the immediately preceding `call dword ptr [0x4CF348]` = **`GetPrivateProfileIntA`** imported from KERNEL32. The args around the call (pushed right-to-left) are:
- 0       (default value)
- 'ENABLEPATAPASSTHROUGHUDMA'  (key)
- 'OPTION'                     (section)
- [ebp-0x24]+0x568             (INI file path buffer)

So the **operating semantics**:
- if INI section `[OPTION]` has `ENABLEPATAPASSTHROUGHUDMA` set to **non-zero** then `[0x507FD0]=1` → the dual helper's `cmp byte ptr [0x45DD4C], 2` path is PREFERED (when modeType==2 is set elsewhere, which happens in the `0x507FD0`-guarded branch of sub_3A807).
- if INI `[OPTION]` has `ENABLEUASPMODE` non-zero then `[0x507FC4]=1` → type==1 path preferred (with CDB[0]=0xA1 vendor ATA).
- If both are zero, the default branch uses **CDB[0]=0x28** (standard READ10) — i.e. plain SCSI.

## The actual gate-through-to-2 story:

Looking around 0x3A7FA:
```
0x43A7F2:  cmp dword ptr [0x507FD0], 0   ; INI flag [OPTION]/ENABLEPATAPASSTHROUGHUDMA == 0?
0x43A7F9:  je  0x43A808                  ; if so, skip 'push 2' path
0x43A7FB:  push 2                         ; type=2
0x43A7FD:  call dword ptr [0x507FA4]     ; _SMISetPassThroughType(2)
0x43A803:  add esp, 4
0x43A806:  jmp 0x43A829
0x43A808:  cmp dword ptr [0x507FC4], 0   ; INI [OPTION]/ENABLEUASPMODE == 0?
0x43A80F:  je  0x43A81E                  ; if so, skip 'push 1' path
0x43A811:  push 1                         ; type=1
0x43A813:  call dword ptr [0x507FA4]
0x43A819:  add esp, 4
0x43A81C:  jmp 0x43A829
0x43A81E:  push 0                         ; type=0 (default)
0x43A820:  call dword ptr [0x507FA4]
0x43A826:  add esp, 4
0x43A829:  ...
```

So the passType selection is decided by reading INI keys at startup:
```
[OPTION] ENABLEPATAPASSTHROUGHUDMA = non-zero   →  type=2 (DIRECT, 0x4D030, SMI vendor)
[OPTION] ENABLEUASPMODE = non-zero             →  type=1 (0x4D014 CDB[0]=0xA1, ATA PT)
otherwise (both 0 or unset, defaults)          →  type=0 (0x4D014 CDB[0]=0x28, READ10)
```

And the call site 0x3A7FB ('push 2; call _SMISetPassThroughType') is INSIDE a function called from all over the EXE — it's a **lazily-executed UI handler** that reads the persisted INI flags to decide which pass-through type to use **for the next operation**.

## Caller of the INI loader:

**RVA 0x43A01B** calls fn RVA 0x43ACB4 unconditionally every time the application runs (it is inside a bigger function at RVA 0x3A000-ish that also checks the resulting flags at 0x43A020/0x43A05E, throwing "wrong controller" if [0x508008] ≠ 0x979 = 2258XT).

The outer caller of that bigger function walks through `ecx=[ebp-0x5B8]` (a TForm object pointer) and accesses virtual method table `dword [eax+0xC8]` — i.e., the **FormCreate** / **FormShow** handler for the main MPTool window.

## Conclusion

`_SMISetPassThroughType(2)` IS called, but only when:
1. The MPTool form creation runs
2. `[OPTION] ENABLEPATAPASSTHROUGHUDMA` in the MPTool INI is non-zero
3. The startup succeeds past the controller-version check (0x508008 == 0x979 = SM2258XT)

Then `_SMISetPassThroughType(2)` writes `[0x45DD4C]=2`, and ALL five helpers (sub_1838 sub_19D8 sub_1B84 sub_1D18 sub_1E14) switch to the **sub_171C/0x4D030 PASS_THROUGH_DIRECT** transport with CDB bytes 0xCA/0xC8/0x35/0x25/0x06/0xEA variants.

This means the "legitimate mode==2" path **does exist in the binary** but is **gated by an INI setting that the historical harness never touched**.

## Default INI value

Exemplar INI files shipped with the package may already set these. Search for `[OPTION]/ENABLEPATAPASSTHROUGHUDMA` in the existing project file tree (next step).
