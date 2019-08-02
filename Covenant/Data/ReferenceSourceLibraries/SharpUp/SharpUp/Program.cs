using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.Win32;
using System.Security.Cryptography;


namespace SharpUp
{
    class Program
    {
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool LookupPrivilegeName(
            string lpSystemName,
            IntPtr lpLuid,
            System.Text.StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceObjectSecurity(
            IntPtr serviceHandle,
            System.Security.AccessControl.SecurityInfos secInfo,
            byte[] lpSecDesrBuf,
            uint bufSize,
            out uint bufSizeNeeded);


        // PInvoke structures/contants
        public const uint SE_GROUP_LOGON_ID = 0xC0000000; // from winnt.h
        public const int TokenGroups = 2; // from TOKEN_INFORMATION_CLASS
        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        protected struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 35)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        protected struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        protected struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [Flags]
        public enum LuidAttributes : uint
        {
            DISABLED = 0x00000000,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_REMOVED = 0x00000004,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
        }

        [Flags]
        public enum ServiceAccessRights : uint
        {
            QueryConfig = 0x00000001,
            ChangeConfig = 0x00000002,
            QueryStatus = 0x00000004,
            EnumerateDependents = 0x00000008,
            Start = 0x00000010,
            Stop = 0x00000020,
            PauseContinue = 0x00000040,
            Interrogate = 0x00000080,
            UserDefinedControl = 0x00000100,
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            Synchronize = 0x00100000,
            AccessSystemSecurity = 0x01000000,
            GenericAll = 0x10000000,
            GenericExecute = 0x20000000,
            GenericWrite = 0x40000000,
            GenericRead = 0x80000000,
            AllAccess = 0x000F01FF,
        }


        // helpers
        public static string GetRegValue(string hive, string path, string value)
        {
            // returns a single registry value under the specified path in the specified hive (HKLM/HKCU)
            string regKeyValue = "";
            if (hive == "HKCU")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
            else if (hive == "HKU")
            {
                var regKey = Registry.Users.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
            else
            {
                var regKey = Registry.LocalMachine.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
        }

        public static Dictionary<string, object> GetRegValues(string hive, string path)
        {
            // returns all registry values under the specified path in the specified hive (HKLM/HKCU)
            Dictionary<string, object> keyValuePairs = null;

            if (hive == "HKCU")
            {
                using (var regKeyValues = Registry.CurrentUser.OpenSubKey(path))
                {
                    if (regKeyValues != null)
                    {
                        var valueNames = regKeyValues.GetValueNames();
                        keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                    }
                }
            }
            else if (hive == "HKU")
            {
                using (var regKeyValues = Registry.Users.OpenSubKey(path))
                {
                    if (regKeyValues != null)
                    {
                        var valueNames = regKeyValues.GetValueNames();
                        keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                    }
                }
            }
            else
            {
                using (var regKeyValues = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (regKeyValues != null)
                    {
                        var valueNames = regKeyValues.GetValueNames();
                        keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                    }
                }
            }
            return keyValuePairs;
        }

        public static string[] GetRegSubkeys(string hive, string path)
        {
            // returns an array of the subkeys names under the specified path in the specified hive (HKLM/HKCU/HKU)
            try
            {
                Microsoft.Win32.RegistryKey myKey = null;
                if (hive == "HKLM")
                {
                    myKey = Registry.LocalMachine.OpenSubKey(path);
                }
                else if (hive == "HKU")
                {
                    myKey = Registry.Users.OpenSubKey(path);
                }
                else
                {
                    myKey = Registry.CurrentUser.OpenSubKey(path);
                }
                String[] subkeyNames = myKey.GetSubKeyNames();
                return myKey.GetSubKeyNames();
            }
            catch
            {
                return new string[0];
            }
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string[] GetTokenGroupSIDs()
        {
            // Returns all SIDs that the current user is a part of, whether they are disabled or not.

            // adapted almost directly from https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418

            int TokenInfLength = 0;

            // first call gets length of TokenInformation
            bool Result = GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            Result = GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenGroups, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                return null;
            }

            TOKEN_GROUPS groups = (TOKEN_GROUPS)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_GROUPS));
            string[] userSIDS = new string[groups.GroupCount];
            int sidAndAttrSize = Marshal.SizeOf(new SID_AND_ATTRIBUTES());
            for (int i = 0; i < groups.GroupCount; i++)
            {
                SID_AND_ATTRIBUTES sidAndAttributes = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    new IntPtr(TokenInformation.ToInt64() + i * sidAndAttrSize + IntPtr.Size), typeof(SID_AND_ATTRIBUTES));

                IntPtr pstr = IntPtr.Zero;
                ConvertSidToStringSid(sidAndAttributes.Sid, out pstr);
                userSIDS[i] = Marshal.PtrToStringAuto(pstr);
                LocalFree(pstr);
            }

            Marshal.FreeHGlobal(TokenInformation);
            return userSIDS;
        }

        public static bool IsLocalAdmin()
        {
            // checks if the "S-1-5-32-544" in the current token groups set, meaning the user is a local administrator
            string[] SIDs = GetTokenGroupSIDs();

            foreach (string SID in SIDs)
            {
                if (SID == "S-1-5-32-544")
                {
                    return true;
                }
            }
            return false;
        }

        public static bool CheckAccess(string Path, FileSystemRights AccessRight)
        {
            // checks if the current user has the specified AccessRight to the specified file or folder
            // from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

            if (string.IsNullOrEmpty(Path)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(Path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        public static bool CheckModifiableAccess(string Path)
        {
            // checks if the current user has rights to modify the given file/directory
            // adapted from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

            if (string.IsNullOrEmpty(Path)) return false;
            // TODO: check if file exists, check file's parent folder

            // rights that signify modiable access
            FileSystemRights[] ModifyRights =
            {
                FileSystemRights.ChangePermissions,
                FileSystemRights.FullControl,
                FileSystemRights.Modify,
                FileSystemRights.TakeOwnership,
                FileSystemRights.Write,
                FileSystemRights.WriteData,
                FileSystemRights.CreateDirectories,
                FileSystemRights.CreateFiles
            };

            ArrayList paths = new ArrayList();
            paths.Add(Path);

            try
            {
                FileAttributes attr = System.IO.File.GetAttributes(Path);
                if ((attr & FileAttributes.Directory) != FileAttributes.Directory)
                {
                    string parentFolder = System.IO.Path.GetDirectoryName(Path);
                    paths.Add(parentFolder);
                }
            }
            catch
            {
                return false;
            }


            try
            {
                foreach (string candidatePath in paths)
                {
                    AuthorizationRuleCollection rules = Directory.GetAccessControl(candidatePath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();

                    foreach (FileSystemAccessRule rule in rules)
                    {
                        if (identity.Groups.Contains(rule.IdentityReference))
                        {
                            foreach (FileSystemRights AccessRight in ModifyRights)
                            {
                                if ((AccessRight & rule.FileSystemRights) == AccessRight)
                                {
                                    if (rule.AccessControlType == AccessControlType.Allow)
                                        return true;
                                }
                            }
                        }
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static List<string> FindFiles(string path, string patterns)
        {
            // finds files matching one or more patterns under a given path, recursive
            // adapted from http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/
            //      pattern: "*pass*;*.png;"

            var files = new List<string>();

            try
            {
                // search every pattern in this directory's files
                foreach (string pattern in patterns.Split(';'))
                {
                    files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
                }

                // go recurse in all sub-directories
                foreach (var directory in Directory.GetDirectories(path))
                    files.AddRange(FindFiles(directory, patterns));
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }

            return files;
        }


        // privesc checks
        public static void GetModifiableServiceBinaries()
        {
            try
            {
                // finds any service binaries that the current can modify
                //      TODO: or modify the parent folder

                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
                ManagementObjectCollection data = wmiData.Get();

                Console.WriteLine("\r\n\r\n=== Modifiable Service Binaries ===\r\n");

                foreach (ManagementObject result in data)
                {
                    if (result["PathName"] != null)
                    {
                        Match path = Regex.Match(result["PathName"].ToString(), @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase);
                        String binaryPath = path.Groups[1].ToString();

                        if (CheckModifiableAccess(binaryPath))
                        {
                            Console.WriteLine("  Name             : {0}", result["Name"]);
                            Console.WriteLine("  DisplayName      : {0}", result["DisplayName"]);
                            Console.WriteLine("  Description      : {0}", result["Description"]);
                            Console.WriteLine("  State            : {0}", result["State"]);
                            Console.WriteLine("  StartMode        : {0}", result["StartMode"]);
                            Console.WriteLine("  PathName         : {0}", result["PathName"]);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex.Message));
            }
        }

        public static void GetAlwaysInstallElevated()
        {
            Console.WriteLine("\r\n\r\n=== AlwaysInstallElevated Registry Keys ===\r\n");

            string AlwaysInstallElevatedHKLM = GetRegValue("HKLM", "Software\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated");
            string AlwaysInstallElevatedHKCU = GetRegValue("HKCU", "Software\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated");

            if (!string.IsNullOrEmpty(AlwaysInstallElevatedHKLM))
            {
                Console.WriteLine("  HKLM:    {0}", AlwaysInstallElevatedHKLM);
            }

            if (!string.IsNullOrEmpty(AlwaysInstallElevatedHKCU))
            {
                Console.WriteLine("  HKCU:    {0}", AlwaysInstallElevatedHKCU);
            }
        }

        public static void GetPathHijacks()
        {
            Console.WriteLine("\r\n\r\n=== Modifiable Folders in %PATH% ===\r\n");

            // grabbed from the registry instead of System.Environment.GetEnvironmentVariable to prevent false positives
            string path = GetRegValue("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path");
            string[] pathFolders = path.Split(';');

            foreach (string pathFolder in pathFolders)
            {
                if (CheckModifiableAccess(pathFolder))
                {
                    Console.WriteLine("  Modifable %PATH% Folder  : {0}", pathFolder);
                }
            }
        }

        public static void GetModifiableRegistryAutoRuns()
        {
            Console.WriteLine("\r\n\r\n=== Modifiable Registry Autoruns ===\r\n");

            string[] autorunLocations = new string[] {
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
            };

            foreach (string autorunLocation in autorunLocations)
            {
                Dictionary<string, object> settings = GetRegValues("HKLM", autorunLocation);
                if ((settings != null) && (settings.Count != 0))
                {
                    foreach (KeyValuePair<string, object> kvp in settings)
                    {
                        Match path = Regex.Match(kvp.Value.ToString(), @"^\W*([a-z]:\\.+?(\.exe|\.bat|\.ps1|\.vbs))\W*", RegexOptions.IgnoreCase);
                        String binaryPath = path.Groups[1].ToString();

                        if (CheckModifiableAccess(binaryPath))
                        {
                            Console.WriteLine(String.Format("  HKLM:\\{0} : {1}", autorunLocation, binaryPath));
                        }
                    }
                }
            }
        }

        public static void GetSpecialTokenGroupPrivs()
        {
            // Returns all "special" privileges that the current process/user possesses
            // adapted from https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni

            Console.WriteLine("\r\n\r\n=== *Special* User Privileges ===\r\n");

            string[] SpecialPrivileges = {
                "SeSecurityPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
                "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
                "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"
            };

            int TokenInfLength = 0;
            IntPtr ThisHandle = WindowsIdentity.GetCurrent().Token;
            GetTokenInformation(ThisHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            if (GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out TokenInfLength))
            {
                TOKEN_PRIVILEGES ThisPrivilegeSet = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES));
                for (int index = 0; index < ThisPrivilegeSet.PrivilegeCount; index++)
                {
                    LUID_AND_ATTRIBUTES laa = ThisPrivilegeSet.Privileges[index];
                    System.Text.StringBuilder StrBuilder = new System.Text.StringBuilder();
                    int LuidNameLen = 0;
                    IntPtr LuidPointer = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
                    Marshal.StructureToPtr(laa.Luid, LuidPointer, true);
                    LookupPrivilegeName(null, LuidPointer, null, ref LuidNameLen);
                    StrBuilder.EnsureCapacity(LuidNameLen + 1);
                    if (LookupPrivilegeName(null, LuidPointer, StrBuilder, ref LuidNameLen))
                    {
                        string privilege = StrBuilder.ToString();
                        foreach (string SpecialPrivilege in SpecialPrivileges)
                        {
                            if (privilege == SpecialPrivilege)
                            {
                                Console.WriteLine(String.Format("  {0,43}:  {1}", privilege, (LuidAttributes)laa.Attributes));
                            }
                        }
                    }
                    Marshal.FreeHGlobal(LuidPointer);
                }
            }
        }

        public static void GetModifiableServices()
        {
            // finds any services that the current can modify (or modify the parent folder)
            // modified from https://stackoverflow.com/questions/15771998/how-to-give-a-user-permission-to-start-and-stop-a-particular-service-using-c-sha/15796352#15796352

            ServiceController[] scServices;
            scServices = ServiceController.GetServices();

            var GetServiceHandle = typeof(System.ServiceProcess.ServiceController).GetMethod("GetServiceHandle", BindingFlags.Instance | BindingFlags.NonPublic);

            object[] readRights = { 0x00020000 };

            ServiceAccessRights[] ModifyRights =
            {
                ServiceAccessRights.ChangeConfig,
                ServiceAccessRights.WriteDac,
                ServiceAccessRights.WriteOwner,
                ServiceAccessRights.GenericAll,
                ServiceAccessRights.GenericWrite,
                ServiceAccessRights.AllAccess
            };


            Console.WriteLine("\r\n\r\n=== Modifiable Services ===\r\n");

            foreach (ServiceController sc in scServices)
            {
                try
                {
                    IntPtr handle = (IntPtr)GetServiceHandle.Invoke(sc, readRights);
                    ServiceControllerStatus status = sc.Status;
                    byte[] psd = new byte[0];
                    uint bufSizeNeeded;
                    bool ok = QueryServiceObjectSecurity(handle, SecurityInfos.DiscretionaryAcl, psd, 0, out bufSizeNeeded);

                    if (!ok)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == 122 || err == 0)
                        { // ERROR_INSUFFICIENT_BUFFER
                          // expected; now we know bufsize
                            psd = new byte[bufSizeNeeded];
                            ok = QueryServiceObjectSecurity(handle, SecurityInfos.DiscretionaryAcl, psd, bufSizeNeeded, out bufSizeNeeded);
                        }
                        else
                        {
                            //throw new ApplicationException("error calling QueryServiceObjectSecurity() to get DACL for " + _name + ": error code=" + err);
                            continue;
                        }
                    }
                    if (!ok)
                    {
                        //throw new ApplicationException("error calling QueryServiceObjectSecurity(2) to get DACL for " + _name + ": error code=" + Marshal.GetLastWin32Error());
                        continue;
                    }

                    // get security descriptor via raw into DACL form so ACE ordering checks are done for us.
                    RawSecurityDescriptor rsd = new RawSecurityDescriptor(psd, 0);
                    RawAcl racl = rsd.DiscretionaryAcl;
                    DiscretionaryAcl dacl = new DiscretionaryAcl(false, false, racl);

                    WindowsIdentity identity = WindowsIdentity.GetCurrent();

                    foreach (System.Security.AccessControl.CommonAce ace in dacl)
                    {
                        if (identity.Groups.Contains(ace.SecurityIdentifier))
                        {
                            ServiceAccessRights serviceRights = (ServiceAccessRights)ace.AccessMask;
                            foreach (ServiceAccessRights ModifyRight in ModifyRights)
                            {
                                if ((ModifyRight & serviceRights) == ModifyRight)
                                {
                                    ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", String.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'", sc.ServiceName));
                                    ManagementObjectCollection data = wmiData.Get();

                                    foreach (ManagementObject result in data)
                                    {
                                        Console.WriteLine("  Name             : {0}", result["Name"]);
                                        Console.WriteLine("  DisplayName      : {0}", result["DisplayName"]);
                                        Console.WriteLine("  Description      : {0}", result["Description"]);
                                        Console.WriteLine("  State            : {0}", result["State"]);
                                        Console.WriteLine("  StartMode        : {0}", result["StartMode"]);
                                        Console.WriteLine("  PathName         : {0}", result["PathName"]);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Console.WriteLine("Exception: " + ex);
                }
            }
        }

        public static void GetUnattendedInstallFiles()
        {
            try
            {
                Console.WriteLine("\r\n\r\n=== Unattended Install Files ===\r\n");

                string windir = System.Environment.GetEnvironmentVariable("windir");
                string[] SearchLocations =
                {
                    String.Format("{0}\\sysprep\\sysprep.xml", windir),
                    String.Format("{0}\\sysprep\\sysprep.inf", windir),
                    String.Format("{0}\\sysprep.inf", windir),
                    String.Format("{0}\\Panther\\Unattended.xml", windir),
                    String.Format("{0}\\Panther\\Unattend.xml", windir),
                    String.Format("{0}\\Panther\\Unattend\\Unattend.xml", windir),
                    String.Format("{0}\\Panther\\Unattend\\Unattended.xml", windir),
                    String.Format("{0}\\System32\\Sysprep\\unattend.xml", windir),
                    String.Format("{0}\\System32\\Sysprep\\Panther\\unattend.xml", windir)
                };
                
                foreach (string SearchLocation in SearchLocations)
                {
                    if (System.IO.File.Exists(SearchLocation))
                    {
                        Console.WriteLine(" {0}", SearchLocation);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex.Message));
            }
        }

        public static void GetMcAfeeSitelistFiles()
        {
            try
            {
                Console.WriteLine("\r\n\r\n=== McAfee Sitelist.xml Files ===\r\n");

                string drive = System.Environment.GetEnvironmentVariable("SystemDrive");

                string[] SearchLocations =
                {
                    String.Format("{0}\\Program Files\\", drive),
                    String.Format("{0}\\Program Files (x86)\\", drive),
                    String.Format("{0}\\Documents and Settings\\", drive),
                    String.Format("{0}\\Users\\", drive)
                };

                foreach (string SearchLocation in SearchLocations)
                {
                    List<string> files = FindFiles(SearchLocation, "SiteList.xml");

                    foreach (string file in files)
                    {
                        Console.WriteLine(" {0}", file);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex.Message));
            }
        }

      
        public static void GetCachedGPPPassword()
        {
            try
            {
                Console.WriteLine("\r\n\r\n=== Cached GPP Password ===\r\n");

                string allUsers = System.Environment.GetEnvironmentVariable("ALLUSERSPROFILE");

                if (!allUsers.Contains("ProgramData"))
                {
                    // Before Windows Vista, the default value of AllUsersProfile was "C:\Documents and Settings\All Users"
                    // And after, "C:\ProgramData"
                    allUsers += "\\Application Data";
                }
                allUsers += "\\Microsoft\\Group Policy\\History"; // look only in the GPO cache folder

                List<String> files = FindFiles(allUsers, "*.xml");

                // files will contain all XML files
                foreach (string file in files)
                {
                    if (!(file.Contains("Groups.xml") || file.Contains("Services.xml")
                        || file.Contains("Scheduledtasks.xml") || file.Contains("DataSources.xml")
                        || file.Contains("Printers.xml") || file.Contains("Drives.xml")))
                    {
                        continue; // uninteresting XML files, move to next
                    }

                    XmlDocument xmlDoc = new XmlDocument();
                    xmlDoc.Load(file);

                    if (!xmlDoc.InnerXml.Contains("cpassword"))
                    {
                        continue; // no "cpassword" => no interesting content, move to next
                    }

                    Console.WriteLine("\r\n{0}", file);

                    string cPassword = "";
                    string UserName = "";
                    string NewName = "";
                    string Changed = "";
                    if (file.Contains("Groups.xml"))
                    {
                        XmlNode a = xmlDoc.SelectSingleNode("/Groups/User/Properties");
                        XmlNode b = xmlDoc.SelectSingleNode("/Groups/User");
                        foreach (XmlAttribute attr in a.Attributes)
                        {
                            if (attr.Name.Equals("cpassword"))
                            {
                                cPassword = attr.Value;
                            }
                            if (attr.Name.Equals("userName"))
                            {
                                UserName = attr.Value;
                            }
                            if (attr.Name.Equals("newName"))
                            {
                                NewName = attr.Value;
                            }
                        }
                        foreach (XmlAttribute attr in b.Attributes)
                        {
                            if (attr.Name.Equals("changed"))
                            {
                                Changed = attr.Value;
                            }
                        }
                        //Console.WriteLine("\r\nA{0}", a.Attributes[0].Value);
                    }
                    else if (file.Contains("Services.xml"))
                    {
                        XmlNode a = xmlDoc.SelectSingleNode("/NTServices/NTService/Properties");
                        XmlNode b = xmlDoc.SelectSingleNode("/NTServices/NTService");
                        foreach (XmlAttribute attr in a.Attributes)
                        {
                            if (attr.Name.Equals("cpassword"))
                            {
                                cPassword = attr.Value;
                            }
                            if (attr.Name.Equals("accountName"))
                            {
                                UserName = attr.Value;
                            }
                        }
                        foreach (XmlAttribute attr in b.Attributes)
                        {
                            if (attr.Name.Equals("changed"))
                            {
                                Changed = attr.Value;
                            }
                        }

                    }
                    else if (file.Contains("Scheduledtasks.xml"))
                    {
                        XmlNode a = xmlDoc.SelectSingleNode("/ScheduledTasks/Task/Properties");
                        XmlNode b = xmlDoc.SelectSingleNode("/ScheduledTasks/Task");
                        foreach (XmlAttribute attr in a.Attributes)
                        {
                            if (attr.Name.Equals("cpassword"))
                            {
                                cPassword = attr.Value;
                            }
                            if (attr.Name.Equals("runAs"))
                            {
                                UserName = attr.Value;
                            }
                        }
                        foreach (XmlAttribute attr in b.Attributes)
                        {
                            if (attr.Name.Equals("changed"))
                            {
                                Changed = attr.Value;
                            }
                        }

                    }
                    else if (file.Contains("DataSources.xml"))
                    {
                        XmlNode a = xmlDoc.SelectSingleNode("/DataSources/DataSource/Properties");
                        XmlNode b = xmlDoc.SelectSingleNode("/DataSources/DataSource");
                        foreach (XmlAttribute attr in a.Attributes)
                        {
                            if (attr.Name.Equals("cpassword"))
                            {
                                cPassword = attr.Value;
                            }
                            if (attr.Name.Equals("username"))
                            {
                                UserName = attr.Value;
                            }
                        }
                        foreach (XmlAttribute attr in b.Attributes)
                        {
                            if (attr.Name.Equals("changed"))
                            {
                                Changed = attr.Value;
                            }
                        }
                    }
                    else if (file.Contains("Printers.xml"))
                    {
                        XmlNode a = xmlDoc.SelectSingleNode("/Printers/SharedPrinter/Properties");
                        XmlNode b = xmlDoc.SelectSingleNode("/Printers/SharedPrinter");
                        foreach (XmlAttribute attr in a.Attributes)
                        {
                            if (attr.Name.Equals("cpassword"))
                            {
                                cPassword = attr.Value;
                            }
                            if (attr.Name.Equals("username"))
                            {
                                UserName = attr.Value;
                            }
                        }
                        foreach (XmlAttribute attr in b.Attributes)
                        {
                            if (attr.Name.Equals("changed"))
                            {
                                Changed = attr.Value;
                            }
                        }
                    }
                    else
                    {
                        // Drives.xml
                        XmlNode a = xmlDoc.SelectSingleNode("/Drives/Drive/Properties");
                        XmlNode b = xmlDoc.SelectSingleNode("/Drives/Drive");
                        foreach (XmlAttribute attr in a.Attributes)
                        {
                            if (attr.Name.Equals("cpassword"))
                            {
                                cPassword = attr.Value;
                            }
                            if (attr.Name.Equals("username"))
                            {
                                UserName = attr.Value;
                            }
                        }
                        foreach (XmlAttribute attr in b.Attributes)
                        {
                            if (attr.Name.Equals("changed"))
                            {
                                Changed = attr.Value;
                            }
                        }

                    }

                    if (UserName.Equals(""))
                    {
                        UserName = "[BLANK]";
                    }

                    if (NewName.Equals(""))
                    {
                        NewName = "[BLANK]";
                    }


                    if (cPassword.Equals(""))
                    {
                        cPassword = "[BLANK]";
                    }
                    else
                    {
                        cPassword = DecryptGPP(cPassword);
                    }

                    if (Changed.Equals(""))
                    {
                        Changed = "[BLANK]";
                    }


                    Console.WriteLine("UserName: {0}", UserName);
                    Console.WriteLine("NewName: {0}", NewName);
                    Console.WriteLine("cPassword: {0}", cPassword);
                    Console.WriteLine("Changed: {0}", Changed);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  [X] Exception: {0}", ex.Message));
            }
        }


        public static string DecryptGPP(string cpassword)
        {
            int mod = cpassword.Length % 4;

            switch (mod)
            {
                case 1:
                    cpassword = cpassword.Substring(0, cpassword.Length - 1);
                    break;
                case 2:
                    cpassword += "".PadLeft(4 - mod, '=');
                    break;
                case 3:
                    cpassword += "".PadLeft(4 - mod, '=');
                    break;
                default:
                    break;
            }
            
            byte[] base64decoded = Convert.FromBase64String(cpassword);
            
            AesCryptoServiceProvider aesObject = new AesCryptoServiceProvider();
            
            byte[] aesKey = { 0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b };
            byte[] aesIV = new byte[aesObject.IV.Length];

            aesObject.IV = aesIV;
            aesObject.Key = aesKey;

            ICryptoTransform aesDecryptor = aesObject.CreateDecryptor();
            byte[] outBlock = aesDecryptor.TransformFinalBlock(base64decoded, 0, base64decoded.Length);

            return System.Text.UnicodeEncoding.Unicode.GetString(outBlock);
        }

        public static void PrivescChecks(bool auditMode)
        {
            bool isHighIntegrity = IsHighIntegrity();
            bool isLocalAdmin = IsLocalAdmin();
            bool shouldQuit = false;

            if (isHighIntegrity)
            {
                Console.WriteLine("\r\n[*] Already in high integrity, no need to privesc!");
                shouldQuit = true;
            }
            else if (!isHighIntegrity && isLocalAdmin)
            {
                Console.WriteLine("\r\n[*] In medium integrity but user is a local administrator- UAC can be bypassed.");
                shouldQuit = true;
            }

            // if already admin we can quit without running all checks
            if (shouldQuit)
            {
                if (!auditMode)
                {
                    Console.WriteLine("\r\n[*] Quitting now, re-run with \"audit\" argument to run all checks anyway (audit mode).");
                    return;
                }
                else
                {
                    // except if auditMode has explictly been asked
                    Console.WriteLine("\r\n[*] Audit mode: running all checks anyway.");
                }
            }

            GetModifiableServices();
            GetModifiableServiceBinaries();
            GetAlwaysInstallElevated();
            GetPathHijacks();
            GetModifiableRegistryAutoRuns();
            GetSpecialTokenGroupPrivs();
            GetUnattendedInstallFiles();
            GetMcAfeeSitelistFiles();
            GetCachedGPPPassword();
        }

        static void Main(string[] args)
        {
            bool auditMode = args.Contains("audit", StringComparer.CurrentCultureIgnoreCase);

            var watch = System.Diagnostics.Stopwatch.StartNew();

            Console.WriteLine("\r\n=== SharpUp: Running Privilege Escalation Checks ===");

            PrivescChecks(auditMode);

            watch.Stop();
            Console.WriteLine(String.Format("\r\n\r\n[*] Completed Privesc Checks in {0} seconds\r\n", watch.ElapsedMilliseconds / 1000));
        }
    }
}

