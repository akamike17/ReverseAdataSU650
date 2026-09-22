using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ForceROM
{
    class Program
    {
        // SCSI_PASS_THROUGH_DIRECT structure
        [StructLayout(LayoutKind.Sequential)]
        public struct SCSI_PASS_THROUGH_DIRECT
        {
            public ushort Length;
            public byte ScsiStatus;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte CdbLength;
            public byte SenseInfoLength;
            public byte DataIn;  // 0 = OUT, 1 = IN, 2 = NONE
            public uint DataTransferLength;
            public uint TimeOutValue;
            public IntPtr DataBuffer;
            public uint SenseInfoOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Cdb;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

        public const uint IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D112; // CTL_CODE(0x00000022, 0x0802, 2, 3) = SCSI_PASS_THROUGH_DIRECT
        public const byte SCSI_IOCTL_DATA_OUT = 0;
        public const byte SCSI_IOCTL_DATA_IN = 1;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            int nInBufferSize,
            IntPtr lpOutBuffer,
            int nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        public static bool CallWin32DeviceIoControl(IntPtr hDevice, IntPtr sptdPtr)
        {
            // SCSI_PASS_THROUGH_DIRECT = 0x4D112 (from ntddscsi.h)
            // CTL_CODE(0x00000022, 0x0802, 2, 3) = 0x4D112
            return DeviceIoControl(hDevice, IOCTL_SCSI_PASS_THROUGH_DIRECT, sptdPtr,
                Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)),
                IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        static void Main(string[] args)
        {
            Console.WriteLine("=========================================");
            Console.WriteLine("SM2258XT Force ROM Mode - Vendor Command");
            Console.WriteLine("=========================================");
            Console.WriteLine("[DLL: SWPtest.dll - sub_171C]");
            Console.WriteLine("[CDB:  00 00 00 00 E0 00 E0 00 00 00 00 00]");
            Console.WriteLine("");

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: ForceROM.exe <PhysicalDriveNumber>");
                Console.WriteLine("Example: ForceROM.exe 1  (for PhysicalDrive1)");
                Console.WriteLine("");
                Console.WriteLine("IMPORTANT: This command puts the SSD into ROM/ISP mode.");
                Console.WriteLine("After this, the drive will appear as ~1GB 'SMI Factory'");
                Console.WriteLine("and can be flashed with MPTool.");
                Console.WriteLine("");
                Console.WriteLine("WARNING: This is a DESTRUCTIVE operation if used on a working drive!");
                return;
            }

            string drivePath = $@"\\.\PhysicalDrive{args[0]}";
            Console.WriteLine($"Target: {drivePath}");

            // Open the physical drive
            IntPtr hDrive = CreateFile(
                drivePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (hDrive == IntPtr.Zero || hDrive == new IntPtr(-1))
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"ERROR: Cannot open {drivePath}, error={error}");
                Console.WriteLine("Make sure:");
                Console.WriteLine("1. Running as Administrator");
                Console.WriteLine("2. Drive number is correct (check Disk Management)");
                return;
            }

            Console.WriteLine($"Drive opened, handle: 0x{hDrive.ToInt64():X}");

            // Build the SCSI pass-through structure
            SCSI_PASS_THROUGH_DIRECT sptd = new SCSI_PASS_THROUGH_DIRECT();
            sptd.Length = (ushort)Marshal.SizeOf(sptd);
            sptd.CdbLength = 16;
            sptd.DataIn = SCSI_IOCTL_DATA_OUT;
            sptd.DataTransferLength = 0;
            sptd.TimeOutValue = 10000;
            sptd.SenseInfoLength = 32;
            sptd.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_DIRECT), "Cdb").ToInt32() + 16;

            // Force ROM CDB
            // From SWPtest.dll reverse engineering: 0xE0 = Force ROM command
            sptd.Cdb = new byte[16];
            sptd.Cdb[0] = 0x00;  // Vendor specific opcode
            sptd.Cdb[4] = 0xE0;  // Force ROM (primary service action)
            sptd.Cdb[6] = 0xE0;  // Force ROM (secondary service action)
            // Rest are zeros

            // Allocate buffers
            IntPtr senseBuffer = Marshal.AllocHGlobal(32);
            IntPtr dataBuffer = Marshal.AllocHGlobal(1); // Minimal for OUT with 0 length

            try
            {
                Console.WriteLine("Sending Force ROM command (0xE0)...");
                Console.WriteLine("CDB bytes: 00 00 00 00 E0 00 E0 00 00 00 00 00 00 00 00 00");

                sptd.DataBuffer = dataBuffer;
                IntPtr sptdPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sptd));
                Marshal.StructureToPtr(sptd, sptdPtr, false);

                uint bytesReturned = 0;
                bool result = DeviceIoControl(
                    hDrive,
                    IOCTL_SCSI_PASS_THROUGH_DIRECT,
                    sptdPtr,
                    (uint)Marshal.SizeOf(sptd),
                    sptdPtr,  // Same buffer for output
                    (uint)Marshal.SizeOf(sptd) + 32, // Extra space for sense data
                    out bytesReturned,
                    IntPtr.Zero);

                int lastError = Marshal.GetLastWin32Error();

                if (result)
                {
                    Console.WriteLine("[PASS] Force ROM command sent successfully");
                    Console.WriteLine($"       Bytes returned: {bytesReturned}");
                    Console.WriteLine($"       SCSI Status: 0x{sptd.ScsiStatus:X2}");
                    Console.WriteLine("");
                    Console.WriteLine("[*] The SSD should now be in ROM/ISP mode.");
                    Console.WriteLine("[*] It may appear as a small (1-4GB) 'SMI Factory' device.");
                    Console.WriteLine("[*] Run MPTool to verify and continue with flashing.");
                }
                else
                {
                    Console.WriteLine($"[FAIL] DeviceIoControl failed, error: {lastError}");

                    // Read sense data if available
                    byte[] senseData = new byte[32];
                    Marshal.Copy(senseBuffer, senseData, 0, 32);
                    Console.WriteLine($"Sense data: {BitConverter.ToString(senseData)}");
                }

                Marshal.FreeHGlobal(sptdPtr);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"EXCEPTION: {ex.Message}");
            }
            finally
            {
                Marshal.FreeHGlobal(senseBuffer);
                Marshal.FreeHGlobal(dataBuffer);
                CloseHandle(hDrive);
            }

            Console.WriteLine("Done.");
        }
    }
}
