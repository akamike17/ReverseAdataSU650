// drive_reset_probe.cs — DriveReset -> (long delay) -> CheckRunMode
using System;
using System.Runtime.InteropServices;
using System.Threading;

class DriveResetProbe {
    [DllImport("SWPtest.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern bool _SMISetPassThroughType(byte t);

    [DllImport("SWPtest.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern bool _SMIPtestDriveReset(IntPtr hDrivePtr, byte bank, IntPtr resultOut);

    [DllImport("SWPtest.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern bool _SMIPtestCheckRunMode(IntPtr hDrivePtr, IntPtr ctx, IntPtr modeOut);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    static IntPtr AllocZeroed(int sz) {
        IntPtr p = Marshal.AllocHGlobal(sz);
        for (int i=0; i<sz; i++) Marshal.WriteByte(p, i, 0);
        return p;
    }
    static string Hex(IntPtr p, int n) {
        var b = new byte[n]; Marshal.Copy(p, b, 0, n);
        return BitConverter.ToString(b);
    }

    static void Main() {
        IntPtr h = CreateFileW("\\\\.\\PhysicalDrive1", 0x80000000u|0x40000000u, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) {
            Console.WriteLine("open failed"); return;
        }
        Console.WriteLine("Handle OK.");

        IntPtr hSlot = AllocZeroed(4);
        Marshal.WriteInt32(hSlot, h.ToInt32());
        IntPtr ctx = AllocZeroed(0x8400);
        IntPtr modeOut = AllocZeroed(0x4204);

        // Step 1: Set passType 2 (SMI direct)
        var ptOk = _SMISetPassThroughType(2);
        Console.WriteLine($"SetPT(2)={ptOk}");

        // Step 2: DriveReset
        Marshal.WriteInt32(modeOut, 0);
        var before = DateTime.Now;
        var resetOk = _SMIPtestDriveReset(hSlot, 1, modeOut);  // bank=1
        var after = DateTime.Now;
        Console.WriteLine($"DriveReset={resetOk} elapsed={(after-before).TotalSeconds:F2}s  modeOut[0]={Marshal.ReadByte(modeOut)}");

        // Step 3: wait
        Console.WriteLine("Waiting 800ms for RomCode...");
        Thread.Sleep(800);

        // Step 4: re-detect (According to SMI docs, slot might be busy for a moment after reset)
        // The handle might be invalid now — try a fresh connection. Physically the drive will re-appear
        // with a new device name (typically "SMI Loader Mode Generic").
        // For now, just close + re-open -- or use a fresh connection
        CloseHandle(h);
        Marshal.WriteInt32(hSlot, 0);

        // We should be re-scanning here; but for a quick experiment, use sleep then re-open same path
        Thread.Sleep(500);
        h = CreateFileW("\\\\.\\PhysicalDrive1", 0x80000000u|0x40000000u, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) {
            Console.WriteLine("Couldn't re-open drive after reset.");
            return;
        }
        Marshal.WriteInt32(hSlot, h.ToInt32());

        // Step 5: CheckRunMode with passType=2
        for (int i=0;i<4;i++) Marshal.WriteByte(modeOut, i, 0);
        Marshal.WriteInt32(ctx, 0);
        var crOk = _SMIPtestCheckRunMode(hSlot, ctx, modeOut);
        Console.WriteLine($"CheckRunMode={crOk}");
        Console.WriteLine($"   ctx[0]     = {Marshal.ReadByte(ctx)}");
        Console.WriteLine($"   ctx[0x210] = {Marshal.ReadByte(ctx, 0x210)}");
        Console.WriteLine($"   ctx first 32: {Hex(ctx, 32)}");

        CloseHandle(h);
        Marshal.FreeHGlobal(hSlot);
        Marshal.FreeHGlobal(ctx);
        Marshal.FreeHGlobal(modeOut);
    }
}
