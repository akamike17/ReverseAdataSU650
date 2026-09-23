// cv_offline_probe.cs — Phase C final: prove/disprove native writes to modeOut
// PER kk.md §16-§18: NO hardware. Handle is INVALID_HANDLE_VALUE synthetic
// (0xFFFFFFFF) — never opened via CreateFile. This exercises only the
// DLL's argument-validation / early-exit path. We expect the native code
// to bail out before issuing any I/O.
using System;
using System.Runtime.InteropServices;

class CvOfflineProbe {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [DllImport("SWPtest.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern bool _SMISetPassThroughType(byte t);
    [DllImport("SWPtest.dll", CallingConvention=CallingConvention.Cdecl)]
    static extern bool _SMIPtestCheckRunMode(IntPtr hDrivePtr, IntPtr ctx, IntPtr modeOut);

    static long Diff(IntPtr p, int size, byte sentinel) {
        byte[] b = new byte[size];
        Marshal.Copy(p, b, 0, size);
        long n = 0; foreach (var x in b) if (x != sentinel) n++;
        return n;
    }
    static string Hex(IntPtr p, int n) {
        byte[] b = new byte[n]; Marshal.Copy(p, b, 0, n); return BitConverter.ToString(b);
    }

    static void RunOnce(byte patternA, byte patternB, int run) {
        // match historical harness: 0x8400 ctx, 4-byte modeOut, 4-byte handlePtr
        IntPtr hp = Marshal.AllocHGlobal(4);
        IntPtr ctx = Marshal.AllocHGlobal(0x8400);
        // size modeOut to native expectation: arg3 must be >= 0x4204 per
        // static analysis (ptr cell at +0x4200 read by sub_CF98).
        IntPtr mo = Marshal.AllocHGlobal(0x4204);
        for (int i = 0; i < 0x4204; i++) Marshal.WriteByte(mo, i, patternB);
        for (int i = 0; i < 0x8400; i++) Marshal.WriteByte(ctx, i, patternA);
        // NUL: valid Win32 handle pointing at the null-device, not a physical drive
        IntPtr hNull = CreateFile("NUL", 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (hNull.ToInt32() <= 0) { Console.WriteLine($"NUL open failed {Marshal.GetLastWin32Error()}"); return; }
        Marshal.WriteInt32(hp, hNull.ToInt32());

        bool ok = _SMIPtestCheckRunMode(hp, ctx, mo);
        long ctxChanged = Diff(ctx, 0x8400, patternA);
        long moChanged = Diff(mo, 0x4204, patternB);
        Console.WriteLine($"run {run}: arg0=NUL-handle  pattern_ctx=0x{patternA:X2}  pattern_mo=0x{patternB:X2}");
        Console.WriteLine($"  -> return={ok}  ctx changed bytes: {ctxChanged}  mo changed bytes: {moChanged}");
        Console.WriteLine($"     ctx[0..16]={Hex(ctx,16)}");
        Console.WriteLine($"     mo[0..16] ={Hex(mo,16)}");
        Console.WriteLine($"     mo[0x4200..0x4204]={Hex(mo+0x4200,4)}");

        Marshal.FreeHGlobal(hp);
        Marshal.FreeHGlobal(ctx);
        Marshal.FreeHGlobal(mo);
    }

    static void Main() {
        Console.WriteLine("=== CV OFFLINE PROBE (kk.md Part 8) ===");
        Console.WriteLine("No hardware. Handle=INVALID_HANDLE_VALUE synthetic.");
        bool ok = _SMISetPassThroughType(0); Console.WriteLine($"SetPassThroughType={ok}");
        RunOnce(0xCC, 0xCC, 1);
        RunOnce(0xA5, 0xA5, 2);
        RunOnce(0xF1, 0xF1, 3);
        RunOnce(0x7E, 0x7E, 4);
        Console.WriteLine("=== END ===");
    }
}
