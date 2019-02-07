// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Runtime.InteropServices;
using MW32 = Microsoft.Win32;

namespace SharpSploit.Execution
{

    /// <summary>
    /// Win32 is a library of PInvoke signatures for Win32 API functions.
    /// </summary>
    /// <remarks>
    /// A majority of this library is adapted from signatures found at www.pinvoke.net.
    /// </remarks>
    public static class Win32
    {
        public static class Kernel32
        {
            public static uint MEM_COMMIT = 0x1000;
            public static uint MEM_RESERVE = 0x2000;

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_IMPORT_DESCRIPTOR
            {
                public uint OriginalFirstThunk;
                public uint TimeDateStamp;
                public uint ForwarderChain;
                public uint Name;
                public uint FirstThunk;
            }

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentThread();

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            public static extern IntPtr GetProcAddress(
                IntPtr hModule,
                string procName
            );

            [DllImport("kernel32.dll")]
            public static extern void GetSystemInfo(
                out WinBase._SYSTEM_INFO lpSystemInfo
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GlobalSize(
                IntPtr hMem
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(
                ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean OpenProcessToken(
                IntPtr hProcess,
                UInt32 dwDesiredAccess,
                out IntPtr hToken
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean OpenThreadToken(
                IntPtr ThreadHandle,
                UInt32 DesiredAccess,
                Boolean OpenAsSelf,
                ref IntPtr TokenHandle
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenThread(
                UInt32 dwDesiredAccess,
                Boolean bInheritHandle,
                UInt32 dwThreadId
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean ReadProcessMemory(
                IntPtr hProcess,
                UInt32 lpBaseAddress,
                IntPtr lpBuffer,
                UInt32 nSize,
                ref UInt32 lpNumberOfBytesRead
            );

            [DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory")]
            public static extern Boolean ReadProcessMemory64(
                IntPtr hProcess,
                UInt64 lpBaseAddress,
                IntPtr lpBuffer,
                UInt64 nSize,
                ref UInt32 lpNumberOfBytesRead
            );

            [DllImport("kernel32.dll")]
            public static extern UInt32 SearchPath(
                String lpPath,
                String lpFileName,
                String lpExtension,
                UInt32 nBufferLength,
                [MarshalAs(UnmanagedType.LPTStr)]
                StringBuilder lpBuffer,
                ref IntPtr lpFilePart
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx32(
                IntPtr hProcess,
                IntPtr lpAddress,
                out WinNT._MEMORY_BASIC_INFORMATION32 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx64(
                IntPtr hProcess,
                IntPtr lpAddress,
                out WinNT._MEMORY_BASIC_INFORMATION64 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAlloc(
                IntPtr lpStartAddr,
                uint size,
                uint flAllocationType,
                uint flProtect
            );

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtect(
                IntPtr lpAddress,
                UIntPtr dwSize,
                uint flNewProtect,
                out uint lpflOldProtect
            );

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern IntPtr LoadLibrary(
                string lpFileName
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateThread(
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr param,
                uint dwCreationFlags,
                IntPtr lpThreadId
            );

            [DllImport("kernel32.dll")]
            public static extern UInt32 WaitForSingleObject(
                IntPtr hHandle,
                UInt32 dwMilliseconds
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr LocalFree(
                IntPtr hMem
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean CloseHandle(
                IntPtr hProcess
            );

            [Flags]
            public enum ProcessAccessFlags : UInt32
            {
                // https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
                PROCESS_ALL_ACCESS = 0x001F0FFF,
                PROCESS_CREATE_PROCESS = 0x0080,
                PROCESS_CREATE_THREAD = 0x0002,
                PROCESS_DUP_HANDLE = 0x0040,
                PROCESS_QUERY_INFORMATION = 0x0400,
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
                PROCESS_SET_INFORMATION = 0x0200,
                PROCESS_SET_QUOTA = 0x0100,
                PROCESS_SUSPEND_RESUME = 0x0800,
                PROCESS_TERMINATE = 0x0001,
                PROCESS_VM_OPERATION = 0x0008,
                PROCESS_VM_READ = 0x0010,
                PROCESS_VM_WRITE = 0x0020,
                SYNCHRONIZE = 0x00100000
            }
    }

        public static class Netapi32
        {
            [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
            public struct LOCALGROUP_USERS_INFO_0
            {
                [MarshalAs(UnmanagedType.LPWStr)] internal string name;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LOCALGROUP_USERS_INFO_1
            {
                [MarshalAs(UnmanagedType.LPWStr)] public string name;
                [MarshalAs(UnmanagedType.LPWStr)] public string comment;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_MEMBERS_INFO_2
            {
                public IntPtr lgrmi2_sid;
                public int lgrmi2_sidusage;
                [MarshalAs(UnmanagedType.LPWStr)] public string lgrmi2_domainandname;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WKSTA_USER_INFO_1
            {
                public string wkui1_username;
                public string wkui1_logon_domain;
                public string wkui1_oth_domains;
                public string wkui1_logon_server;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SESSION_INFO_10
            {
                public string sesi10_cname;
                public string sesi10_username;
                public int sesi10_time;
                public int sesi10_idle_time;
            }

            public enum SID_NAME_USE : UInt16
            {
                SidTypeUser = 1,
                SidTypeGroup = 2,
                SidTypeDomain = 3,
                SidTypeAlias = 4,
                SidTypeWellKnownGroup = 5,
                SidTypeDeletedAccount = 6,
                SidTypeInvalid = 7,
                SidTypeUnknown = 8,
                SidTypeComputer = 9
            }

            [DllImport("netapi32.dll")]
            public static extern int NetLocalGroupEnum(
                [MarshalAs(UnmanagedType.LPWStr)] string servername,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll")]
            public static extern int NetLocalGroupGetMembers(
                [MarshalAs(UnmanagedType.LPWStr)] string servername,
                [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern int NetWkstaUserEnum(
                string servername,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", SetLastError = true)]
            public static extern int NetSessionEnum(
                [In, MarshalAs(UnmanagedType.LPWStr)] string ServerName,
                [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
                [In, MarshalAs(UnmanagedType.LPWStr)] string UserName,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", SetLastError = true)]
            public static extern int NetApiBufferFree(IntPtr Buffer);
        }

        public static class Advapi32
        {

            // http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
            public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
            public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
            public const UInt32 TOKEN_DUPLICATE = 0x0002;
            public const UInt32 TOKEN_IMPERSONATE = 0x0004;
            public const UInt32 TOKEN_QUERY = 0x0008;
            public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
            public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
            public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
            public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
            public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
            public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID);
            public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);


            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AdjustTokenPrivileges(
                IntPtr TokenHandle,
                Boolean DisableAllPrivileges,
                ref WinNT._TOKEN_PRIVILEGES NewState,
                UInt32 BufferLengthInBytes,
                ref WinNT._TOKEN_PRIVILEGES PreviousState,
                out UInt32 ReturnLengthInBytes
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AllocateAndInitializeSid(
                ref WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount,
                Int32 dwSubAuthority0,
                Int32 dwSubAuthority1,
                Int32 dwSubAuthority2,
                Int32 dwSubAuthority3,
                Int32 dwSubAuthority4,
                Int32 dwSubAuthority5,
                Int32 dwSubAuthority6,
                Int32 dwSubAuthority7,
                out IntPtr pSid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AllocateAndInitializeSid(
                ref WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount,
                Int32 dwSubAuthority0,
                Int32 dwSubAuthority1,
                Int32 dwSubAuthority2,
                Int32 dwSubAuthority3,
                Int32 dwSubAuthority4,
                Int32 dwSubAuthority5,
                Int32 dwSubAuthority6,
                Int32 dwSubAuthority7,
                ref WinNT._SID pSid
            );

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool ConvertSidToStringSid(
                IntPtr Sid,
                out IntPtr StringSid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessAsUser(
                IntPtr hToken,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                ref WinBase._SECURITY_ATTRIBUTES lpProcessAttributes,
                ref WinBase._SECURITY_ATTRIBUTES lpThreadAttributes,
                Boolean bInheritHandles,
                CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessAsUserW(
                IntPtr hToken,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                Boolean bInheritHandles,
                CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessWithLogonW(
                String userName,
                String domain,
                String password,
                int logonFlags,
                String applicationName,
                String commandLine,
                int creationFlags,
                IntPtr environment,
                String currentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO startupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION processInformation
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessWithTokenW(
                IntPtr hToken,
                LOGON_FLAGS dwLogonFlags,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredEnumerateW(
                String Filter,
                Int32 Flags,
                out Int32 Count,
                out IntPtr Credentials
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredFree(
                IntPtr Buffer
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredReadW(
                String target,
                WinCred.CRED_TYPE type,
                Int32 reservedFlag,
                out IntPtr credentialPtr
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredWriteW(
                ref WinCred._CREDENTIAL userCredential,
                UInt32 flags
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean DuplicateTokenEx(
                IntPtr hExistingToken,
                UInt32 dwDesiredAccess,
                ref WinBase._SECURITY_ATTRIBUTES lpTokenAttributes,
                WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                WinNT.TOKEN_TYPE TokenType,
                out IntPtr phNewToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean GetTokenInformation(
                IntPtr TokenHandle,
                WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass,
                IntPtr TokenInformation,
                UInt32 TokenInformationLength,
                out UInt32 ReturnLength
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean GetTokenInformation(
                IntPtr TokenHandle,
                WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass,
                ref WinNT._TOKEN_STATISTICS TokenInformation,
                UInt32 TokenInformationLength,
                out UInt32 ReturnLength
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean ImpersonateLoggedOnUser(
                IntPtr hToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean ImpersonateSelf(
                WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LogonUserA(
                string lpszUsername,
                string lpszDomain,
                string lpszPassword,
                LOGON_TYPE dwLogonType,
                LOGON_PROVIDER dwLogonProvider,
                out IntPtr phToken
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool LookupAccountSid(
                String lpSystemName,
                //[MarshalAs(UnmanagedType.LPArray)] 
                IntPtr Sid,
                StringBuilder lpName,
                ref UInt32 cchName,
                StringBuilder ReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out WinNT._SID_NAME_USE peUse
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean LookupPrivilegeName(
                String lpSystemName,
                IntPtr lpLuid,
                StringBuilder lpName,
                ref Int32 cchName
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean LookupPrivilegeValue(
                String lpSystemName,
                String lpName,
                ref WinNT._LUID luid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean PrivilegeCheck(
                IntPtr ClientToken,
                WinNT._PRIVILEGE_SET RequiredPrivileges,
                out IntPtr pfResult
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern int RegOpenKeyEx(
                UIntPtr hKey,
                String subKey,
                Int32 ulOptions,
                Int32 samDesired,
                out UIntPtr hkResult
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern uint RegQueryValueEx(
                UIntPtr hKey,
                String lpValueName,
                Int32 lpReserved,
                ref MW32.RegistryValueKind lpType,
                IntPtr lpData,
                ref Int32 lpcbData
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Int32 RegQueryInfoKey(
                UIntPtr hKey,
                StringBuilder lpClass,
                ref UInt32 lpcchClass,
                IntPtr lpReserved,
                out UInt32 lpcSubkey,
                out UInt32 lpcchMaxSubkeyLen,
                out UInt32 lpcchMaxClassLen,
                out UInt32 lpcValues,
                out UInt32 lpcchMaxValueNameLen,
                out UInt32 lpcbMaxValueLen,
                IntPtr lpSecurityDescriptor,
                IntPtr lpftLastWriteTime
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean RevertToSelf();

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
            [Flags]
            public enum CREATION_FLAGS
            {
                NONE = 0x0,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SUSPENDED = 0x00000004,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            }

            [Flags]
            public enum LOGON_FLAGS
            {
                LOGON_WITH_PROFILE = 0x00000001,
                LOGON_NETCREDENTIALS_ONLY = 0x00000002
            }

            public enum LOGON_TYPE
            {
                LOGON32_LOGON_INTERACTIVE = 2,
                LOGON32_LOGON_NETWORK,
                LOGON32_LOGON_BATCH,
                LOGON32_LOGON_SERVICE,
                LOGON32_LOGON_UNLOCK = 7,
                LOGON32_LOGON_NETWORK_CLEARTEXT,
                LOGON32_LOGON_NEW_CREDENTIALS
            }

            public enum LOGON_PROVIDER
            {
                LOGON32_PROVIDER_DEFAULT,
                LOGON32_PROVIDER_WINNT35,
                LOGON32_PROVIDER_WINNT40,
                LOGON32_PROVIDER_WINNT50
            }
        }

        public static class Dbghelp
        {
            public enum MINIDUMP_TYPE
            {
                MiniDumpNormal = 0x00000000,
                MiniDumpWithDataSegs = 0x00000001,
                MiniDumpWithFullMemory = 0x00000002,
                MiniDumpWithHandleData = 0x00000004,
                MiniDumpFilterMemory = 0x00000008,
                MiniDumpScanMemory = 0x00000010,
                MiniDumpWithUnloadedModules = 0x00000020,
                MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
                MiniDumpFilterModulePaths = 0x00000080,
                MiniDumpWithProcessThreadData = 0x00000100,
                MiniDumpWithPrivateReadWriteMemory = 0x00000200,
                MiniDumpWithoutOptionalData = 0x00000400,
                MiniDumpWithFullMemoryInfo = 0x00000800,
                MiniDumpWithThreadInfo = 0x00001000,
                MiniDumpWithCodeSegs = 0x00002000,
                MiniDumpWithoutAuxiliaryState = 0x00004000,
                MiniDumpWithFullAuxiliaryState = 0x00008000,
                MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
                MiniDumpIgnoreInaccessibleMemory = 0x00020000,
                MiniDumpWithTokenInformation = 0x00040000,
                MiniDumpWithModuleHeaders = 0x00080000,
                MiniDumpFilterTriage = 0x00100000,
                MiniDumpValidTypeFlags = 0x001fffff
            }

            [DllImport("dbghelp.dll", SetLastError = true)]
            public static extern bool MiniDumpWriteDump(
                IntPtr hProcess,
                UInt32 ProcessId,
                SafeHandle hFile,
                MINIDUMP_TYPE DumpType,
                IntPtr ExceptionParam,
                IntPtr UserStreamParam,
                IntPtr CallbackParam
            );
        }

        public static class ActiveDs
        {
            [DllImport("activeds.dll")]
            public static extern IntPtr Init(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] string bstrADsPath
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr Set(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] string bstrADsPath
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr Get(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] ref string pbstrADsPath
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr InitEx(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] string bstrADsPath,
                [MarshalAs(UnmanagedType.BStr)] string bstrUserID,
                [MarshalAs(UnmanagedType.BStr)] string bstrDomain,
                [MarshalAs(UnmanagedType.BStr)] string bstrPassword
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr put_ChaseReferral(
                Int32 lnChangeReferral
            );
        }

        public class WinBase
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct _SYSTEM_INFO
            {
                public UInt16 wProcessorArchitecture;
                public UInt16 wReserved;
                public UInt32 dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public IntPtr dwActiveProcessorMask;
                public UInt32 dwNumberOfProcessors;
                public UInt32 dwProcessorType;
                public UInt32 dwAllocationGranularity;
                public UInt16 wProcessorLevel;
                public UInt16 wProcessorRevision;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SECURITY_ATTRIBUTES
            {
                UInt32 nLength;
                IntPtr lpSecurityDescriptor;
                Boolean bInheritHandle;
            };
        }

        public class WinNT
        {
            public const UInt32 PAGE_NOACCESS = 0x01;
            public const UInt32 PAGE_READONLY = 0x02;
            public const UInt32 PAGE_READWRITE = 0x04;
            public const UInt32 PAGE_WRITECOPY = 0x08;
            public const UInt32 PAGE_EXECUTE = 0x10;
            public const UInt32 PAGE_EXECUTE_READ = 0x20;
            public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
            public const UInt32 PAGE_GUARD = 0x100;
            public const UInt32 PAGE_NOCACHE = 0x200;
            public const UInt32 PAGE_WRITECOMBINE = 0x400;
            public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
            public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

            public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

            public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
            public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
            public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
            public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
            public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
            public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
            public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
            public const UInt64 SE_GROUP_OWNER = 0x00000008L;
            public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
            public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

            public enum _SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum _TOKEN_ELEVATION_TYPE
            {
                TokenElevationTypeDefault = 1,
                TokenElevationTypeFull,
                TokenElevationTypeLimited
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION32
            {
                public UInt32 BaseAddress;
                public UInt32 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION64
            {
                public UInt64 BaseAddress;
                public UInt64 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 __alignment1;
                public UInt64 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
                public UInt32 __alignment2;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID_AND_ATTRIBUTES
            {
                public _LUID Luid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID
            {
                public UInt32 LowPart;
                public UInt32 HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_STATISTICS
            {
                public _LUID TokenId;
                public _LUID AuthenticationId;
                public UInt64 ExpirationTime;
                public TOKEN_TYPE TokenType;
                public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                public UInt32 DynamicCharged;
                public UInt32 DynamicAvailable;
                public UInt32 GroupCount;
                public UInt32 PrivilegeCount;
                public _LUID ModifiedId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_PRIVILEGES
            {
                public UInt32 PrivilegeCount;
                public _LUID_AND_ATTRIBUTES Privileges;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_MANDATORY_LABEL
            {
                public _SID_AND_ATTRIBUTES Label;
            }

            public struct _SID
            {
                public byte Revision;
                public byte SubAuthorityCount;
                public WinNT._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public ulong[] SubAuthority;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_IDENTIFIER_AUTHORITY
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_AND_ATTRIBUTES
            {
                public IntPtr Sid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _PRIVILEGE_SET
            {
                public UInt32 PrivilegeCount;
                public UInt32 Control;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public _LUID_AND_ATTRIBUTES[] Privilege;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_USER
            {
                public _SID_AND_ATTRIBUTES User;
            }

            public enum _SID_NAME_USE
            {
                SidTypeUser = 1,
                SidTypeGroup,
                SidTypeDomain,
                SidTypeAlias,
                SidTypeWellKnownGroup,
                SidTypeDeletedAccount,
                SidTypeInvalid,
                SidTypeUnknown,
                SidTypeComputer,
                SidTypeLabel
            }

            public enum _TOKEN_INFORMATION_CLASS
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
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                TokenIsAppContainer,
                TokenCapabilities,
                TokenAppContainerSid,
                TokenAppContainerNumber,
                TokenUserClaimAttributes,
                TokenDeviceClaimAttributes,
                TokenRestrictedUserClaimAttributes,
                TokenRestrictedDeviceClaimAttributes,
                TokenDeviceGroups,
                TokenRestrictedDeviceGroups,
                TokenSecurityAttributes,
                TokenIsRestricted,
                MaxTokenInfoClass
            }

            // http://www.pinvoke.net/default.aspx/Enums.ACCESS_MASK
            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F
            };
        }

        public class ProcessThreadsAPI
        {
            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFO
            {
                public UInt32 cb;
                public String lpReserved;
                public String lpDesktop;
                public String lpTitle;
                public UInt32 dwX;
                public UInt32 dwY;
                public UInt32 dwXSize;
                public UInt32 dwYSize;
                public UInt32 dwXCountChars;
                public UInt32 dwYCountChars;
                public UInt32 dwFillAttribute;
                public UInt32 dwFlags;
                public UInt16 wShowWindow;
                public UInt16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            };

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFOEX
            {
                _STARTUPINFO StartupInfo;
                // PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
            };

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public UInt32 dwProcessId;
                public UInt32 dwThreadId;
            };
        }

        public class WinCred
        {
            #pragma warning disable 0618
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct _CREDENTIAL
            {
                public CRED_FLAGS Flags;
                public UInt32 Type;
                public IntPtr TargetName;
                public IntPtr Comment;
                public FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public UInt32 Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public IntPtr TargetAlias;
                public IntPtr UserName;
            }
            #pragma warning restore 0618

            public enum CRED_FLAGS : uint
            {
                NONE = 0x0,
                PROMPT_NOW = 0x2,
                USERNAME_TARGET = 0x4
            }

            public enum CRED_PERSIST : uint
            {
                Session = 1,
                LocalMachine,
                Enterprise
            }

            public enum CRED_TYPE : uint
            {
                Generic = 1,
                DomainPassword,
                DomainCertificate,
                DomainVisiblePassword,
                GenericCertificate,
                DomainExtended,
                Maximum,
                MaximumEx = Maximum + 1000,
            }
        }

        public class Secur32
        {
            [DllImport("Secur32.dll", SetLastError = false)]
            public static extern uint LsaGetLogonSessionData(
                IntPtr luid,
                out IntPtr ppLogonSessionData
            );

            public struct _SECURITY_LOGON_SESSION_DATA
            {
                public UInt32 Size;
                public WinNT._LUID LoginID;
                public _LSA_UNICODE_STRING Username;
                public _LSA_UNICODE_STRING LoginDomain;
                public _LSA_UNICODE_STRING AuthenticationPackage;
                public UInt32 LogonType;
                public UInt32 Session;
                public IntPtr pSid;
                public UInt64 LoginTime;
                public _LSA_UNICODE_STRING LogonServer;
                public _LSA_UNICODE_STRING DnsDomainName;
                public _LSA_UNICODE_STRING Upn;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LSA_UNICODE_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }
        }

        public class NtDll
        {
            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern int NtFilterToken(
                IntPtr TokenHandle,
                UInt32 Flags,
                IntPtr SidsToDisable,
                IntPtr PrivilegesToDelete,
                IntPtr RestrictedSids,
                ref IntPtr hToken
            );

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern Int32 NtSetInformationToken(
                IntPtr TokenHandle,
                Int32 TokenInformationClass,
                ref WinNT._TOKEN_MANDATORY_LABEL TokenInformation,
                Int32 TokenInformationLength
            );
        }
    }
}