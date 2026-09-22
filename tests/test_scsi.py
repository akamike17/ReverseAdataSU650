"""tests/test_scsi.py - SCSI transport detection."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from relib.pe import PEImage           # noqa: E402
from relib.scsi import ScsiAnalyzer   # noqa: E402


def test_deviceiocontrol_sites():
    img = PEImage("Dll/SWPtest.dll")
    s = ScsiAnalyzer(img)
    sites = s.find_deviceiocontrol_sites()
    by_rva = {x["site_rva"]: x for x in sites}
    assert 0x169F in by_rva, f"sub_165C call missing: {sites}"
    assert 0x1818 in by_rva, f"sub_171C call missing: {sites}"
    assert by_rva[0x169F]["ioctl"] == "0x4d014"
    assert by_rva[0x1818]["ioctl"] == "0x4d030"
    assert "PASS_THROUGH_DIRECT" in by_rva[0x1818]["ioctl_class"]
