"""tests/test_exe_resolver.py - EXE GetProcAddress slot resolution."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from relib.exe_resolver import ExeResolver  # noqa: E402


def test_downloadmpisp_slot():
    r = ExeResolver("SM2258XTMPToolQ0816A.exe")
    slots = r.resolve_slots(["_SMIPtestDownloadMPISP"])
    info = slots["_SMIPtestDownloadMPISP"]
    assert info["status"] == "CONFIRMED", info
    slot = int(info["slot"], 16)
    callers = r.slot_callers(slot)
    assert callers, f"no callers of slot {info['slot']}"
