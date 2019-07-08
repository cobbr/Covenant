// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Management;
using System.Collections.Generic;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// WMI is a class for executing WMI lateral movement techniques.
    /// </summary>
    public class WMI
    {
        /// <summary>
        /// Execute a process on a remote system using the WMI Win32_Process.Create method.
        /// </summary>
        /// <param name="ComputerName">ComputerName of remote system to execute process.</param>
        /// <param name="Command">Command to execute on remote system.</param>
        /// <param name="Username">Username to authenticate as to the remote system.</param>
        /// <param name="Password">Password to authenticate the user.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        public static bool WMIExecute(string ComputerName, string Command, string Username = "", string Password = "")
        {
            ConnectionOptions options = new ConnectionOptions();
            if ((Username != null && Username != "") && Password != null)
            {
                options.Username = Username;
                options.Password = Password;
            }

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\root\\cimv2", ComputerName), options);

            try
            {
                scope.Connect();
                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

                ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");
                PropertyDataCollection properties = inParams.Properties;
                inParams["CommandLine"] = Command;

                ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);

                Console.WriteLine("Win32_Process Create returned: " + outParams["returnValue"].ToString());
                Console.WriteLine("ProcessID: " + outParams["processId"].ToString());
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("WMI Exception:" + e.Message);
            }
            return false;
        }

        /// <summary>
        /// Execute a process on a remote system using the WMI Win32_Process.Create method.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames of remote systems to execute process.</param>
        /// <param name="Command">Command to execute on remote system.</param>
        /// <param name="Username">Username to authenticate as to the remote system.</param>
        /// <param name="Password">Password to authenticate the user.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        public static List<bool> WMIExecute(List<string> ComputerNames, string Command, string Username, string Password)
        {
            return ComputerNames.Select(CN => WMIExecute(CN, Command, Username, Password)).ToList();
        }
    }
}
