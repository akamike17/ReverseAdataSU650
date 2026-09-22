using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SMIFlash
{
    class Program
    {
        // SEH for crash analysis
        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public IntPtr[] ExceptionInformation;
        }
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
        
        private delegate int VectoredExceptionHandler(ref EXCEPTION_POINTERS ep);
        
        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS {
            public IntPtr ExceptionRecord;
            public IntPtr ContextRecord;
        }
        
        private static IntPtr _ctxBuf;
        private static IntPtr _hPtr;
        private static bool _crashed = false;
        
        private static int CrashHandler(ref EXCEPTION_POINTERS ep)
        {
            if (_crashed) return 0;
            _crashed = true;
            
            var rec = Marshal.PtrToStructure<EXCEPTION_RECORD>(ep.ExceptionRecord);
            Log("=== CRASH CAPTURED ===");
            Log($"Code: 0x{rec.ExceptionCode:X8}");
            Log($"Addr: 0x{rec.ExceptionAddress.ToInt32():X8}");
            
            if (rec.ExceptionCode == 0xC0000005 && rec.NumberParameters >= 2)
            {
                uint access = (uint)rec.ExceptionInformation[0].ToInt32();
                IntPtr faultAddr = rec.ExceptionInformation[1];
                Log($"Access: {(access == 0 ? "READ" : access == 1 ? "WRITE" : "DEP")}");
                Log($"Fault: 0x{faultAddr.ToInt32():X8}");
                Log($"CtxBuf: 0x{_ctxBuf.ToInt32():X8}");
                Log($"HdlPtr: 0x{_hPtr.ToInt32():X8}");
                if (_hPtr != IntPtr.Zero)
                    Log($"  *Hdl: 0x{Marshal.ReadInt32(_hPtr):X8}");
            }
            return 0; // continue search
        }
        
        // SWPtest.dll — cdecl, x86
        // Verified from disasm: functions take DWORD handle value (not pointer) + context ptr
        [DllImport("SWPtest.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool _SMISetPassThroughType(byte type);
        
        [DllImport("SWPtest.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool _SMIScanSMIDrive(IntPtr handleArray, IntPtr count);
        
        // CheckRunMode takes DWORD* (pointer to handle) — sub_171C dereferences it
        [DllImport("SWPtest.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool _SMIPtestCheckRunMode(IntPtr hDrivePtr, IntPtr ctx, IntPtr modeOut);
        
        [DllImport("SWPtest.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool _SMIReadFlashID(IntPtr hDrivePtr, byte[] buf, int len);
        
        // _SMIPtestDownloadMPISP(DWORD driveHandle, PVOID data, WORD cmdParam, PVOID context)
        // data: 0x400-byte buffer containing BootISP2258.bin segment
        // wordParam: likely a segment index or checksum (passed as 32-bit but used as 16-bit)
        // context: logging/status structure (writes to +0x4200)
        [DllImport("SWPtest.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool _SMIPtestDownloadMPISP(IntPtr hDrivePtr, byte[] mpispData, ushort wordParam, IntPtr context);
        
        private static string LogFile = "";
        private static int TargetDrive = 1;
        
        static void Main(string[] args)
        {
            string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            LogFile = $@"C:\SM2258XT_MPTool\log\smiflash_crash_{ts}.log";
            Directory.CreateDirectory(Path.GetDirectoryName(LogFile));
            
            // Install crash handler FIRST
            IntPtr h = Marshal.GetFunctionPointerForDelegate(new VectoredExceptionHandler(CrashHandler));
            AddVectoredExceptionHandler(1, h);
            Log("[INIT] SEH handler installed");
            
            Log("=== SM2258XT PoC v3 — CRASH ANALYSIS ===");
            Log($"Start: {DateTime.Now}");
            
            if (File.Exists(@"C:\SM2258XT_MPTool\target_drive.txt"))
                int.TryParse(File.ReadAllText(@"C:\SM2258XT_MPTool\target_drive.txt").Trim(), out TargetDrive);
            Log($"Target: PhysicalDrive{TargetDrive}");
            
            Run();
        }
        
        static void Run()
        {
            // Verify files
            string[] files = { @"Dll\SWPtest.dll", @"Firmware\2258\IMB16\BootISP2258.bin", 
                              @"Firmware\2258\IMB16\00\ISP2258.bin", @"FlashDB\2258\Flash.SET" };
            foreach (var f in files)
            {
                string p = Path.Combine(@"C:\SM2258XT_MPTool", f);
                if (!File.Exists(p)) { Log($"MISSING: {f}"); return; }
                Log($"OK: {f}");
            }
            
            // Open PhysicalDrive1
            string path = $@"\\.\PhysicalDrive{TargetDrive}";
            IntPtr hDrive = CreateFile(path, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (hDrive.ToInt32() <= 0)
            {
                Log($"FAILED: OpenPhysicalDrive = {Marshal.GetLastWin32Error()}");
                return;
            }
            Log($"Opened: 0x{hDrive.ToInt32():X8}");
            
            _hPtr = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(_hPtr, hDrive.ToInt32());
            
            // Set pass through
            SafeCall(() => _SMISetPassThroughType(0), "SetPassThroughType");
            
            // Scan — should find 0 (drive is healthy/normal)
            IntPtr arr = Marshal.AllocHGlobal(256);
            IntPtr cnt = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(cnt, 0);
            SafeCall(() => _SMIScanSMIDrive(arr, cnt), "ScanSMIDrive");
            Log($"Scan found: {Marshal.ReadInt32(cnt)}");
            
            // CheckRunMode — THIS IS WHERE IT CRASHED
            // Pass pointer-to-handle (DWORD*), context buffer, mode output buffer
            _ctxBuf = Marshal.AllocHGlobal(0x8400);
            IntPtr modeOut = Marshal.AllocHGlobal(4);
            IntPtr handlePtr = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(handlePtr, hDrive.ToInt32());
            _hPtr = handlePtr; // for crash analysis
            
            Log("[TEST] Calling CheckRunMode...");
            Log($"  hDrive (as uint): 0x{(uint)hDrive.ToInt32():X8}");
            Log($"  ctxBuf: 0x{_ctxBuf.ToInt32():X8}");
            Log($"  modeOut: 0x{modeOut.ToInt32():X8}");
            
            // Zero the mode out
            Marshal.WriteInt32(modeOut, 0);
            
            // Try the call — now with handlePtr (pointer to handle)
            bool ok = SafeCall(() => _SMIPtestCheckRunMode(handlePtr, _ctxBuf, modeOut), "CheckRunMode");
            
            if (ok)
            {
                byte mode = Marshal.ReadByte(modeOut);
                Log($"RunMode: {mode} ({(mode == 1 ? "NORMAL" : mode == 2 ? "ROM/ISP" : "OTHER")})");
                
                // Read NAND ID
                byte[] fid = new byte[6];
                if (SafeCall(() => _SMIReadFlashID(handlePtr, fid, 6), "ReadFlashID"))
                {
                    string hex = BitConverter.ToString(fid);
                    Log($"NAND: {hex}");
                    if (hex == "2C-A4-08-32-A1-00") Log("*** NAND MATCH (NORMAL mode) ***");
                }
                
                // ===== DOWNLOAD MPISP =====
                // BootISP2258.bin = first stage ISP loader (11264 bytes)
                string mpispPath = @"C:\SM2258XT_MPTool\Firmware\2258\IMB16\BootISP2258.bin";
                byte[] mpispData = File.ReadAllBytes(mpispPath);
                Log($"[DownloadMPISP] File: {mpispPath} ({mpispData.Length} bytes)");
                Log($"  SHA256: {ComputeSHA256(mpispData)}");
                
                // First 0x400 bytes as data chunk + word param (likely 0 for first chunk)
                byte[] chunk = new byte[0x400];
                Array.Copy(mpispData, 0, chunk, 0, Math.Min(0x400, mpispData.Length));
                
                Log("[DownloadMPISP] Calling _SMIPtestDownloadMPISP...");
                Log($"  hDrivePtr: 0x{handlePtr.ToInt32():X8}");
                Log($"  data[0:16]: {BitConverter.ToString(chunk, 0, 16)}");
                Log($"  wordParam: 0x0000 (first chunk)");
                Log($"  context: 0x{_ctxBuf.ToInt32():X8}");
                
                bool dlOk = SafeCall(() => _SMIPtestDownloadMPISP(handlePtr, chunk, 0x0000, _ctxBuf), "DownloadMPISP");
                
                if (dlOk)
                {
                    Log("DownloadMPISP: SUCCESS - checking device state...");
                    
                    // Re-enumerate after MPISP (device may have reset)
                    Log("[POST-MPISP] Re-enumerating drives...");
                    _SMIScanSMIDrive(arr, cnt); // re-scan if needed
                    
                    // Wait a bit for re-enumeration
                    System.Threading.Thread.Sleep(2000);
                    
                    // CheckRunMode again
                    Log("[POST-MPISP] CheckRunMode...");
                    byte mode2 = 0;
                    Marshal.WriteInt32(modeOut, 0);
                    bool ok2 = SafeCall(() => _SMIPtestCheckRunMode(handlePtr, _ctxBuf, modeOut), "CheckRunMode2");
                    mode2 = Marshal.ReadByte(modeOut);
                    Log($"  RunMode after MPISP: {mode2} ({(mode2 == 1 ? "NORMAL" : mode2 == 2 ? "ROM/ISP" : "OTHER")})");
                    
                    // ReadFlashID again
                    byte[] fid2 = new byte[6];
                    Log("[POST-MPISP] ReadFlashID...");
                    if (SafeCall(() => _SMIReadFlashID(handlePtr, fid2, 6), "ReadFlashID2"))
                    {
                        string hex2 = BitConverter.ToString(fid2);
                        Log($"  NAND after MPISP: {hex2}");
                        if (hex2 == "2C-A4-08-32-A1-00") 
                            Log("*** NAND MATCH: B16A confirmed after MPISP ***");
                        else if (hex2 == "00-00-00-00-00-00")
                            Log("  (zeros - may need full ISP download for ID)");
                    }
                }
                else
                {
                    Log("DownloadMPISP: FAILED");
                }
            }
            
            Marshal.FreeHGlobal(handlePtr);
            Marshal.FreeHGlobal(modeOut);
            Marshal.FreeHGlobal(_ctxBuf);
            Marshal.FreeHGlobal(_hPtr);
            Marshal.FreeHGlobal(arr);
            Marshal.FreeHGlobal(cnt);
            CloseHandle(hDrive);
            
            Log("=== END ===");
        }
        
        static string ComputeSHA256(byte[] data)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
        
        static bool SafeCall(Func<bool> f, string n)
        {
            try { bool r = f(); Log($"{n}: {r}"); return r; }
            catch (Exception ex) { Log($"{n} EX: {ex.Message}"); return false; }
        }
        
        static void Log(string m)
        {
            string l = $"[{DateTime.Now:HH:mm:ss.fff}] {m}";
            Console.WriteLine(l);
            if (!string.IsNullOrEmpty(LogFile)) try { File.AppendAllText(LogFile, l + "\r\n"); } catch { }
        }
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
