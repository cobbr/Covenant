using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace SharpDPAPI
{
    public class Helpers
    {
        public static bool TestRemote(string computerName)
        {
            try
            {
                string remotePath = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                string[] dirs = Directory.GetDirectories(remotePath);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error accessing computer '{0}' : {1}", computerName, e.Message);
                return false;
            }
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            // helper to combine two byte arrays
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static string[] Combine(string[] first, string[] second)
        {
            // helper to combine two string arrays
            string[] ret = new string[first.Length + second.Length];
            Array.Copy(first, 0, ret, 0, first.Length);
            Array.Copy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static string RemoveWhiteSpaces(string input)
        {
            return Regex.Replace(input, @"\ +(?=(\n|\r?$))", "");
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM via token impersonation
            //  used for LSA secret (DPAPI_SYSTEM) retrieval

            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                string name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (name != "NT AUTHORITY\\SYSTEM")
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static byte[] GetRegKeyValue(string keyPath)
        {
            // takes a given HKLM key path and returns the registry value

            int result = 0;
            IntPtr hKey = IntPtr.Zero;

            // open the specified key with read (0x19) privileges
            //  0x80000002 == HKLM
            result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error opening {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            int cbData = 0;
            result = Interop.RegQueryValueEx(hKey, null, 0, IntPtr.Zero, IntPtr.Zero, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            IntPtr dataPtr = Marshal.AllocHGlobal(cbData);
            result = Interop.RegQueryValueEx(hKey, null, 0, IntPtr.Zero, dataPtr, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }
            byte[] data = new byte[cbData];

            Marshal.Copy(dataPtr, data, 0, cbData);
            Interop.RegCloseKey(hKey);

            return data;
        }

        public static byte[] StringToByteArray(string hex)
        {
            // helper to convert a string hex representation to a byte array
            // yes, I know this inefficient :)
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static IEnumerable<string> Split(string text, int partLength)
        {
            // helper to split strings into blobs of particular length

            if (text == null) { Console.WriteLine("[!] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[!] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static int ArrayIndexOf(byte[] arrayToSearchThrough, byte[] patternToFind, int offset = 0)
        {
            // helper to search for byte array patterns in another byte array
            //  used to search for headers in decrypted policy blobs

            if (patternToFind.Length > arrayToSearchThrough.Length)
                return -1;
            for (int i = offset; i < arrayToSearchThrough.Length - patternToFind.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < patternToFind.Length; j++)
                {
                    if (arrayToSearchThrough[i + j] != patternToFind[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i;
                }
            }
            return -1;
        }
    }
}