using System;
using System.Collections;
using System.Collections.Generic;
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
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using System.Xml;

namespace Seatbelt
{
    // used to fignal whether filtering should be done on results
    public static class FilterResults
    {
        public static bool filter = true;
    }

    public static class NetworkAPI
    {
        // from boboes' code at https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889

        [DllImport("Netapi32.dll")]
        public extern static uint NetLocalGroupGetMembers([MarshalAs(UnmanagedType.LPWStr)] string servername, [MarshalAs(UnmanagedType.LPWStr)] string localgroupname, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, out IntPtr resumehandle);

        [DllImport("Netapi32.dll")]
        public extern static int NetApiBufferFree(IntPtr Buffer);

        // LOCALGROUP_MEMBERS_INFO_2 - Structure for holding members details
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public int lgrmi2_sidusage;
            public string lgrmi2_domainandname;
        }

        // documented in MSDN
        public const uint ERROR_ACCESS_DENIED = 0x0000005;
        public const uint ERROR_MORE_DATA = 0x00000EA;
        public const uint ERROR_NO_SUCH_ALIAS = 0x0000560;
        public const uint NERR_InvalidComputer = 0x000092F;

        // found by testing
        public const uint NERR_GroupNotFound = 0x00008AC;
        public const uint SERVER_UNAVAILABLE = 0x0006BA;
    }

    public static class VaultCli
    {
        // pulled directly from @djhohnstein's SharpWeb project: https://github.com/djhohnstein/SharpWeb/blob/master/Edge/SharpEdge.cs
        public enum VAULT_ELEMENT_TYPE : Int32
        {
            Undefined = -1,
            Boolean = 0,
            Short = 1,
            UnsignedShort = 2,
            Int = 3,
            UnsignedInt = 4,
            Double = 5,
            Guid = 6,
            String = 7,
            ByteArray = 8,
            TimeStamp = 9,
            ProtectedArray = 10,
            Attribute = 11,
            Sid = 12,
            Last = 13
        }

        public enum VAULT_SCHEMA_ELEMENT_ID : Int32
        {
            Illegal = 0,
            Resource = 1,
            Identity = 2,
            Authenticator = 3,
            Tag = 4,
            PackageSid = 5,
            AppStart = 100,
            AppEnd = 10000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct VAULT_ITEM_WIN8
        {
            public Guid SchemaId;
            public IntPtr pszCredentialFriendlyName;
            public IntPtr pResourceElement;
            public IntPtr pIdentityElement;
            public IntPtr pAuthenticatorElement;
            public IntPtr pPackageSid;
            public UInt64 LastModified;
            public UInt32 dwFlags;
            public UInt32 dwPropertiesCount;
            public IntPtr pPropertyElements;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct VAULT_ITEM_WIN7
        {
            public Guid SchemaId;
            public IntPtr pszCredentialFriendlyName;
            public IntPtr pResourceElement;
            public IntPtr pIdentityElement;
            public IntPtr pAuthenticatorElement;
            public UInt64 LastModified;
            public UInt32 dwFlags;
            public UInt32 dwPropertiesCount;
            public IntPtr pPropertyElements;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi)]
        public struct VAULT_ITEM_ELEMENT
        {
            [FieldOffset(0)]
            public VAULT_SCHEMA_ELEMENT_ID SchemaElementId;
            [FieldOffset(8)]
            public VAULT_ELEMENT_TYPE Type;
        }

        [DllImport("vaultcli.dll")]
        public extern static Int32 VaultOpenVault(ref Guid vaultGuid, UInt32 offset, ref IntPtr vaultHandle);

        [DllImport("vaultcli.dll")]
        public extern static Int32 VaultCloseVault(ref IntPtr vaultHandle);

        [DllImport("vaultcli.dll")]
        public extern static Int32 VaultFree(ref IntPtr vaultHandle);

        [DllImport("vaultcli.dll")]
        public extern static Int32 VaultEnumerateVaults(Int32 offset, ref Int32 vaultCount, ref IntPtr vaultGuid);

        [DllImport("vaultcli.dll")]
        public extern static Int32 VaultEnumerateItems(IntPtr vaultHandle, Int32 chunkSize, ref Int32 vaultItemCount, ref IntPtr vaultItem);

        [DllImport("vaultcli.dll", EntryPoint = "VaultGetItem")]
        public extern static Int32 VaultGetItem_WIN8(IntPtr vaultHandle, ref Guid schemaId, IntPtr pResourceElement, IntPtr pIdentityElement, IntPtr pPackageSid, IntPtr zero, Int32 arg6, ref IntPtr passwordVaultPtr);

        [DllImport("vaultcli.dll", EntryPoint = "VaultGetItem")]
        public extern static Int32 VaultGetItem_WIN7(IntPtr vaultHandle, ref Guid schemaId, IntPtr pResourceElement, IntPtr pIdentityElement, IntPtr zero, Int32 arg5, ref IntPtr passwordVaultPtr);

    }


    class Program
    {
        // PInvoke signature definitions
        [DllImport("mpr.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int WNetGetConnection(
            [MarshalAs(UnmanagedType.LPTStr)] string localName,
            [MarshalAs(UnmanagedType.LPTStr)] StringBuilder remoteName,
            ref int length);

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

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] String pServerName);

        [DllImport("wtsapi32.dll")]
        static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern Int32 WTSEnumerateSessions(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] Int32 Reserved,
            [MarshalAs(UnmanagedType.U4)] Int32 Version,
            ref IntPtr ppSessionInfo,
            [MarshalAs(UnmanagedType.U4)] ref Int32 pCount);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern Int32 WTSEnumerateSessionsEx(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] ref Int32 pLevel,
            [MarshalAs(UnmanagedType.U4)] Int32 Filter,
            ref IntPtr ppSessionInfo,
            [MarshalAs(UnmanagedType.U4)] ref Int32 pCount);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            uint sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out IntPtr ppBuffer,
            out uint pBytesReturned
        );

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref uint dwOutBufLen,
            bool sort,
            int ipVersion,
            TCP_TABLE_CLASS tblClass,
            int reserved);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint I_QueryTagInformation(
            IntPtr Unknown,
            SC_SERVICE_TAG_QUERY_TYPE Type,
            ref SC_SERVICE_TAG_QUERY Query
            );

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref uint dwOutBufLen,
            bool sort,
            int ipVersion,
            UDP_TABLE_CLASS tblClass,
            int reserved);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaRegisterLogonProcess(LSA_STRING_IN LogonProcessName, out IntPtr LsaHandle, out ulong SecurityMode);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle, [In] ref LSA_STRING_IN PackageName, [Out] out int AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, int AuthenticationPackage, ref KERB_QUERY_TKT_CACHE_REQUEST ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

        [DllImport("secur32.dll", EntryPoint = "LsaCallAuthenticationPackage", SetLastError = false)]
        private static extern int LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(IntPtr LsaHandle, int AuthenticationPackage, ref KERB_RETRIEVE_TKT_REQUEST ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

        [DllImport("secur32.dll", EntryPoint = "LsaCallAuthenticationPackage", SetLastError = false)]
        private static extern int LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT_UNI(IntPtr LsaHandle, int AuthenticationPackage, ref KERB_RETRIEVE_TKT_REQUEST_UNI ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern uint LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("Secur32.dll", SetLastError = false)]
        private static extern uint LsaEnumerateLogonSessions(out UInt64 LogonSessionCount, out IntPtr LogonSessionList);

        [DllImport("Secur32.dll", SetLastError = false)]
        private static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalAlloc(uint uFlags, uint uBytes);

        [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

        [DllImport("IpHlpApi.dll")]
        [return: MarshalAs(UnmanagedType.U4)]
        internal static extern int GetIpNetTable(IntPtr pIpNetTable, [MarshalAs(UnmanagedType.U4)]ref int pdwSize, bool bOrder);

        [DllImport("IpHlpApi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern int FreeMibTable(IntPtr plpNetTable);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(
          string lpSystemName,
          [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
          StringBuilder lpName,
          ref uint cchName,
          StringBuilder ReferencedDomainName,
          ref uint cchReferencedDomainName,
          out SID_NAME_USE peUse);

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
        public enum FirewallProfiles : int
        {
            DOMAIN = 1,
            PRIVATE = 2,
            PUBLIC = 4,
            ALL = 2147483647
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

        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public Int32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public String pWinStationName;

            public WTS_CONNECTSTATE_CLASS State;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO_1
        {
            public Int32 ExecEnvId;

            public WTS_CONNECTSTATE_CLASS State;

            public Int32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public String pSessionName;

            [MarshalAs(UnmanagedType.LPStr)]
            public String pHostName;

            [MarshalAs(UnmanagedType.LPStr)]
            public String pUserName;

            [MarshalAs(UnmanagedType.LPStr)]
            public String pDomainName;

            [MarshalAs(UnmanagedType.LPStr)]
            public String pFarmName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_CLIENT_ADDRESS
        {
            public uint AddressFamily;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] Address;
        }

        public enum WTS_CONNECTSTATE_CLASS
        {
            Active,
            Connected,
            ConnectQuery,
            Shadow,
            Disconnected,
            Idle,
            Listen,
            Reset,
            Down,
            Init
        }

        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram = 0,
            WTSApplicationName = 1,
            WTSWorkingDirectory = 2,
            WTSOEMId = 3,
            WTSSessionId = 4,
            WTSUserName = 5,
            WTSWinStationName = 6,
            WTSDomainName = 7,
            WTSConnectState = 8,
            WTSClientBuildNumber = 9,
            WTSClientName = 10,
            WTSClientDirectory = 11,
            WTSClientProductId = 12,
            WTSClientHardwareId = 13,
            WTSClientAddress = 14,
            WTSClientDisplay = 15,
            WTSClientProtocolType = 16,
            WTSIdleTime = 17,
            WTSLogonTime = 18,
            WTSIncomingBytes = 19,
            WTSOutgoingBytes = 20,
            WTSIncomingFrames = 21,
            WTSOutgoingFrames = 22,
            WTSClientInfo = 23,
            WTSSessionInfo = 24,
            WTSSessionInfoEx = 25,
            WTSConfigInfo = 26,
            WTSValidationInfo = 27,
            WTSSessionAddressV4 = 28,
            WTSIsRemoteSession = 29
        }

        public enum TCP_TABLE_CLASS : int
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        public enum UDP_TABLE_CLASS : int
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SC_SERVICE_TAG_QUERY
        {
            public uint ProcessId;
            public uint ServiceTag;
            public uint Unknown;
            public IntPtr Buffer;
        }

        public enum SC_SERVICE_TAG_QUERY_TYPE
        {
            ServiceNameFromTagInformation = 1,
            ServiceNamesReferencingModuleInformation = 2,
            ServiceNameTagMappingInformation = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_MODULE
        {
            public uint NumEntries;
            MIB_TCPROW_OWNER_MODULE Table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_MODULE
        {
            public readonly MIB_TCP_STATE State;
            public readonly uint LocalAddr;
            private readonly byte LocalPort1;
            private readonly byte LocalPort2;
            private readonly byte LocalPort3;
            private readonly byte LocalPort4;
            public readonly uint RemoteAddr;
            private readonly byte RemotePort1;
            private readonly byte RemotePort2;
            private readonly byte RemotePort3;
            private readonly byte RemotePort4;
            public readonly uint OwningPid;
            public readonly UInt64 CreateTimestamp;
            public readonly UInt64 OwningModuleInfo0;
            public readonly UInt64 OwningModuleInfo1;
            public readonly UInt64 OwningModuleInfo2;
            public readonly UInt64 OwningModuleInfo3;
            public readonly UInt64 OwningModuleInfo4;
            public readonly UInt64 OwningModuleInfo5;
            public readonly UInt64 OwningModuleInfo6;
            public readonly UInt64 OwningModuleInfo7;
            public readonly UInt64 OwningModuleInfo8;
            public readonly UInt64 OwningModuleInfo9;
            public readonly UInt64 OwningModuleInfo10;
            public readonly UInt64 OwningModuleInfo11;
            public readonly UInt64 OwningModuleInfo12;
            public readonly UInt64 OwningModuleInfo13;
            public readonly UInt64 OwningModuleInfo14;
            public readonly UInt64 OwningModuleInfo15;


            public ushort LocalPort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { LocalPort2, LocalPort1 }, 0);
                }
            }

            public IPAddress LocalAddress
            {
                get { return new IPAddress(LocalAddr); }
            }

            public IPAddress RemoteAddress
            {
                get { return new IPAddress(RemoteAddr); }
            }

            public ushort RemotePort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { RemotePort2, RemotePort1 }, 0);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_MODULE
        {
            public uint NumEntries;
            MIB_UDPROW_OWNER_MODULE Table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_MODULE
        {
            public readonly uint LocalAddr;
            private readonly byte LocalPort1;
            private readonly byte LocalPort2;
            private readonly byte LocalPort3;
            private readonly byte LocalPort4;
            public readonly uint OwningPid;
            public readonly UInt64 CreateTimestamp;
            public readonly UInt32 SpecificPortBind_Flags;
            // public readonly UInt32 Flags;
            public readonly UInt64 OwningModuleInfo0;
            public readonly UInt64 OwningModuleInfo1;
            public readonly UInt64 OwningModuleInfo2;
            public readonly UInt64 OwningModuleInfo3;
            public readonly UInt64 OwningModuleInfo4;
            public readonly UInt64 OwningModuleInfo5;
            public readonly UInt64 OwningModuleInfo6;
            public readonly UInt64 OwningModuleInfo7;
            public readonly UInt64 OwningModuleInfo8;
            public readonly UInt64 OwningModuleInfo9;
            public readonly UInt64 OwningModuleInfo10;
            public readonly UInt64 OwningModuleInfo11;
            public readonly UInt64 OwningModuleInfo12;
            public readonly UInt64 OwningModuleInfo13;
            public readonly UInt64 OwningModuleInfo14;
            public readonly UInt64 OwningModuleInfo15;

            public ushort LocalPort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { LocalPort2, LocalPort1 }, 0);
                }
            }

            public IPAddress LocalAddress
            {
                get { return new IPAddress(LocalAddr); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;

            public ushort LocalPort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { localPort2, localPort1 }, 0);
                }
            }

            public IPAddress LocalAddress
            {
                get { return new IPAddress(localAddr); }
            }

            public IPAddress RemoteAddress
            {
                get { return new IPAddress(remoteAddr); }
            }

            public ushort RemotePort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { remotePort2, remotePort1 }, 0);
                }
            }

            public MIB_TCP_STATE State
            {
                get { return (MIB_TCP_STATE)state; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public int owningPid;

            public ushort LocalPort
            {
                get
                {
                    return BitConverter.ToUInt16(
                        new byte[2] { localPort2, localPort1 }, 0);
                }
            }

            public IPAddress LocalAddress
            {
                get { return new IPAddress(localAddr); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            MIB_TCPROW_OWNER_PID table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            MIB_TCPROW_OWNER_PID table;
        }

        public enum MIB_TCP_STATE
        {
            CLOSED = 1,
            LISTEN = 2,
            SYN_SENT = 3,
            SYN_RCVD = 4,
            ESTAB = 5,
            FIN_WAIT1 = 6,
            FIN_WAIT2 = 7,
            CLOSE_WAIT = 8,
            CLOSING = 9,
            LAST_ACK = 10,
            TIME_WAIT = 11,
            DELETE_TCB = 12
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        public enum KERB_PROTOCOL_MESSAGE_TYPE : UInt32
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage = 1,
            KerbChangeMachinePasswordMessage = 2,
            KerbVerifyPacMessage = 3,
            KerbRetrieveTicketMessage = 4,
            KerbUpdateAddressesMessage = 5,
            KerbPurgeTicketCacheMessage = 6,
            KerbChangePasswordMessage = 7,
            KerbRetrieveEncodedTicketMessage = 8,
            KerbDecryptDataMessage = 9,
            KerbAddBindingCacheEntryMessage = 10,
            KerbSetPasswordMessage = 11,
            KerbSetPasswordExMessage = 12,
            KerbVerifyCredentialsMessage = 13,
            KerbQueryTicketCacheExMessage = 14,
            KerbPurgeTicketCacheExMessage = 15,
            KerbRefreshSmartcardCredentialsMessage = 16,
            KerbAddExtraCredentialsMessage = 17,
            KerbQuerySupplementalCredentialsMessage = 18,
            KerbTransferCredentialsMessage = 19,
            KerbQueryTicketCacheEx2Message = 20,
            KerbSubmitTicketMessage = 21,
            KerbAddExtraCredentialsExMessage = 22,
            KerbQueryKdcProxyCacheMessage = 23,
            KerbPurgeKdcProxyCacheMessage = 24,
            KerbQueryTicketCacheEx3Message = 25,
            KerbCleanupMachinePkinitCredsMessage = 26,
            KerbAddBindingCacheEntryExMessage = 27,
            KerbQueryBindingCacheMessage = 28,
            KerbPurgeBindingCacheMessage = 29,
            KerbQueryDomainExtendedPoliciesMessage = 30,
            KerbQueryS4U2ProxyCacheMessage = 31
        }

        public enum KERB_ENCRYPTION_TYPE : UInt32
        {
            reserved0 = 0,
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            reserved1 = 4,
            des3_cbc_md5 = 5,
            reserved2 = 6,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1_96 = 17,
            aes256_cts_hmac_sha1_96 = 18,
            aes128_cts_hmac_sha256_128 = 19,
            aes256_cts_hmac_sha384_192 = 20,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            camellia128_cts_cmac = 25,
            camellia256_cts_cmac = 26,
            subkey_keymaterial = 65
        }

        [Flags]
        private enum KERB_CACHE_OPTIONS : UInt64
        {
            KERB_RETRIEVE_TICKET_DEFAULT = 0x0,
            KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1,
            KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2,
            KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4,
            KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8,
            KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10,
            KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20,
            KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40,
        }

        // TODO: double check these flags...
        // https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_external_ticket
        [Flags]
        public enum KERB_TICKET_FLAGS : UInt32
        {
            reserved = 2147483648,
            forwardable = 0x40000000,
            forwarded = 0x20000000,
            proxiable = 0x10000000,
            proxy = 0x08000000,
            may_postdate = 0x04000000,
            postdated = 0x02000000,
            invalid = 0x01000000,
            renewable = 0x00800000,
            initial = 0x00400000,
            pre_authent = 0x00200000,
            hw_authent = 0x00100000,
            ok_as_delegate = 0x00040000,
            name_canonicalize = 0x00010000,
            //cname_in_pa_data = 0x00040000,
            enc_pa_rep = 0x00010000,
            reserved1 = 0x00000001
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
            public SECURITY_HANDLE(int dummy)
            {
                LowPart = HighPart = IntPtr.Zero;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO
        {
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT RealmName;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX
        {
            public LSA_STRING_OUT ClientName;
            public LSA_STRING_OUT ClientRealm;
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT ServerRealm;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
            // public KERB_TICKET_CACHE_INFO[] Tickets;
            public IntPtr Tickets;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_QUERY_TKT_CACHE_EX_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
            // public KERB_TICKET_CACHE_INFO[] Tickets;
            public IntPtr Tickets;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_RETRIEVE_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public LSA_STRING_IN TargetName;
            public UInt64 TicketFlags;
            public KERB_CACHE_OPTIONS CacheOptions;
            public Int64 EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_RETRIEVE_TKT_REQUEST_UNI
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public UNICODE_STRING TargetName;
            public UInt64 TicketFlags;
            public KERB_CACHE_OPTIONS CacheOptions;
            public Int64 EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_CRYPTO_KEY
        {
            public Int32 KeyType;
            public Int32 Length;
            public IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_EXTERNAL_NAME
        {
            public Int16 NameType;
            public UInt16 NameCount;
            public LSA_STRING_OUT Names;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_STRING_OUT DomainName;
            public LSA_STRING_OUT TargetDomainName;
            public LSA_STRING_OUT AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public UInt32 TicketFlags;
            public UInt32 Flags;
            public Int64 KeyExpirationTime;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewUntil;
            public Int64 TimeSkew;
            public Int32 EncodedTicketSize;
            public IntPtr EncodedTicket;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }

        private enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,        // logging on interactively.
            Network,                // logging using a network.
            Batch,                  // logon for a batch process.
            Service,                // logon for a service account.
            Proxy,                  // Not supported.
            Unlock,                 // Tattempt to unlock a workstation.
            NetworkCleartext,       // network logon with cleartext credentials
            NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
            RemoteInteractive,      // terminal server session that is both remote and interactive
            CachedInteractive,      // attempt to use the cached credentials without going out across the network
            CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
            CachedUnlock            // attempt to unlock a workstation
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            public LUID LoginID;
            public LSA_STRING_OUT Username;
            public LSA_STRING_OUT LoginDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr PSiD;
            public UInt64 LoginTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
        }

        public const int MAXLEN_PHYSADDR = 8;
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;

        [StructLayout(LayoutKind.Sequential)]
        internal struct MIB_IPNETROW
        {
            [MarshalAs(UnmanagedType.U4)]
            public int dwIndex;
            [MarshalAs(UnmanagedType.U4)]
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac0;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac1;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac2;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac3;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac4;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac5;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac6;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac7;
            [MarshalAs(UnmanagedType.U4)]
            public int dwAddr;
            [MarshalAs(UnmanagedType.U4)]
            public int dwType;
        }

        public enum ArpEntryType
        {
            Other = 1,
            Invalid = 2,
            Dynamic = 3,
            Static = 4,
        }


        // helpers (registry, UNC paths, etc.)

        public static IntPtr OpenServer(String Name)
        {
            IntPtr server = WTSOpenServer(Name);
            return server;
        }
        public static void CloseServer(IntPtr ServerHandle)
        {
            WTSCloseServer(ServerHandle);
        }

        public static string TranslateSid(string Sid)
        {
            // adapted from http://www.pinvoke.net/default.aspx/advapi32.LookupAccountSid
            SecurityIdentifier accountSid = new SecurityIdentifier(Sid);
            byte[] accountSidByes = new byte[accountSid.BinaryLength];
            accountSid.GetBinaryForm(accountSidByes, 0);

            StringBuilder name = new StringBuilder();
            uint cchName = (uint)name.Capacity;
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            SID_NAME_USE sidUse;

            int err = 0;
            if (!LookupAccountSid(null, accountSidByes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
            {
                err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                if (err == ERROR_INSUFFICIENT_BUFFER)
                {
                    name.EnsureCapacity((int)cchName);
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = 0;
                    if (!LookupAccountSid(null, accountSidByes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }
            if (err == 0)
                return String.Format("{0}\\{1}", referencedDomainName.ToString(), name.ToString());
            else
                return "";
        }

        public static void PrintLogo()
        {
            Console.WriteLine("\r\n\r\n                        %&&@@@&&                                                                                  ");
            Console.WriteLine("                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         ");
            Console.WriteLine("                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%");
            Console.WriteLine("%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((");
            Console.WriteLine("#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((");
            Console.WriteLine("#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((");
            Console.WriteLine("#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((");
            Console.WriteLine("#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####");
            Console.WriteLine("###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####");
            Console.WriteLine("#####%######################  %%%..                       @////(((&%%%%%%%################                        ");
            Console.WriteLine("                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         ");
            Console.WriteLine("                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,                                 ");
            Console.WriteLine("                         #%%%%##,                                                                                 \r\n\r\n");
        }

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

        public static byte[] GetRegValueBytes(string hive, string path, string value)
        {
            // returns a byte array of single registry value under the specified path in the specified hive (HKLM/HKCU)
            byte[] regKeyValue = null;
            if (hive == "HKCU")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = (byte[])regKey.GetValue(value);
                }
                return regKeyValue;
            }
            else if (hive == "HKU")
            {
                var regKey = Registry.Users.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = (byte[])regKey.GetValue(value);
                }
                return regKeyValue;
            }
            else
            {
                var regKey = Registry.LocalMachine.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = (byte[])regKey.GetValue(value);
                }
                return regKeyValue;
            }
        }

        public static Dictionary<string, object> GetRegValues(string hive, string path)
        {
            // returns all registry values under the specified path in the specified hive (HKLM/HKCU)
            Dictionary<string, object> keyValuePairs = null;
            try
            {
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
            catch
            {
                return null;
            }
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

        public static string GetUNCPath(string originalPath)
        {
            // uses WNetGetConnection to map a drive letter to a possible UNC mount path
            // Pulled from @ambyte's gist at https://gist.github.com/ambyte/01664dc7ee576f69042c

            StringBuilder sb = new StringBuilder(512);
            int size = sb.Capacity;

            // look for the {LETTER}: combination ...
            if (originalPath.Length > 2 && originalPath[1] == ':')
            {
                // don't use char.IsLetter here - as that can be misleading
                // the only valid drive letters are a-z && A-Z.
                char c = originalPath[0];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
                {
                    int error = WNetGetConnection(originalPath.Substring(0, 2),
                        sb, ref size);
                    if (error == 0)
                    {
                        DirectoryInfo dir = new DirectoryInfo(originalPath);

                        string path = Path.GetFullPath(originalPath)
                            .Substring(Path.GetPathRoot(originalPath).Length);
                        return Path.Combine(sb.ToString().TrimEnd(), path);
                    }
                }
            }

            return originalPath;
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string[] GetLocalGroupMembers(string groupName)
        {
            // returns the "DOMAIN\user" members for a specified local group name
            // adapted from boboes' code at https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889

            string computerName = null; // null for the local machine

            int EntriesRead;
            int TotalEntries;
            IntPtr Resume;
            IntPtr bufPtr;

            uint retVal = NetworkAPI.NetLocalGroupGetMembers(computerName, groupName, 2, out bufPtr, -1, out EntriesRead, out TotalEntries, out Resume);

            if (retVal != 0)
            {
                if (retVal == NetworkAPI.ERROR_ACCESS_DENIED) { Console.WriteLine("Access denied"); return null; }
                if (retVal == NetworkAPI.ERROR_MORE_DATA) { Console.WriteLine("ERROR_MORE_DATA"); return null; }
                if (retVal == NetworkAPI.ERROR_NO_SUCH_ALIAS) { Console.WriteLine("Group not found"); return null; }
                if (retVal == NetworkAPI.NERR_InvalidComputer) { Console.WriteLine("Invalid computer name"); return null; }
                if (retVal == NetworkAPI.NERR_GroupNotFound) { Console.WriteLine("Group not found"); return null; }
                if (retVal == NetworkAPI.SERVER_UNAVAILABLE) { Console.WriteLine("Server unavailable"); return null; }
                Console.WriteLine("Unexpected NET_API_STATUS: " + retVal.ToString());
                return null;
            }

            if (EntriesRead > 0)
            {
                string[] names = new string[EntriesRead];
                NetworkAPI.LOCALGROUP_MEMBERS_INFO_2[] Members = new NetworkAPI.LOCALGROUP_MEMBERS_INFO_2[EntriesRead];
                IntPtr iter = bufPtr;

                for (int i = 0; i < EntriesRead; i++)
                {
                    Members[i] = (NetworkAPI.LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, typeof(NetworkAPI.LOCALGROUP_MEMBERS_INFO_2));

                    //x64 safe
                    iter = new IntPtr(iter.ToInt64() + Marshal.SizeOf(typeof(NetworkAPI.LOCALGROUP_MEMBERS_INFO_2)));

                    names[i] = Members[i].lgrmi2_domainandname;
                }
                NetworkAPI.NetApiBufferFree(bufPtr);

                return names;
            }
            else
            {
                return null;
            }
        }

        public static string[] GetTokenGroupSIDs()
        {
            // Returns all SIDs that the current user is a part of, whether they are disabled or not.
            // slightly adapted from https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418

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

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation

            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                CloseHandle(hToken);
                CloseHandle(hDupToken);

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

        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            //  used for Kerberos ticket enumeration

            string logonProcessName = "User32LogonProcesss";
            LSA_STRING_IN LSAString;
            IntPtr lsaHandle = IntPtr.Zero;
            UInt64 securityMode = 0;

            LSAString.Length = (ushort)logonProcessName.Length;
            LSAString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            LSAString.Buffer = logonProcessName;

            int ret = LsaRegisterLogonProcess(LSAString, out lsaHandle, out securityMode);

            return lsaHandle;
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

        public static bool IsVirtualMachine()
        {
            // returns true if the system is likely a virtual machine
            // Adapted from RobSiklos' code from https://stackoverflow.com/questions/498371/how-to-detect-if-my-application-is-running-in-a-virtual-machine/11145280#11145280

            using (var searcher = new System.Management.ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (var items = searcher.Get())
                {
                    foreach (var item in items)
                    {
                        string manufacturer = item["Manufacturer"].ToString().ToLower();
                        if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                            || manufacturer.Contains("vmware")
                            || item["Model"].ToString() == "VirtualBox")
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static bool CheckAccess(string Path, FileSystemRights AccessRight)
        {
            // checks if the current user has the specified AccessRight to the specified file or folder
            // adapted from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

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

        public static IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

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


        // start of checks

        // system-focused checks
        public static void ListBasicOSInfo()
        {
            // returns basic OS/host information, including:
            //      Windows version information
            //      integrity/admin levels
            //      processor count/architecture
            //      basic user and domain information
            //      whether the system is a VM
            //      etc.

            string ProductName = GetRegValue("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
            string EditionID = GetRegValue("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion", "EditionID");
            string ReleaseId = GetRegValue("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId");
            string BuildBranch = GetRegValue("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion", "BuildBranch");
            string CurrentMajorVersionNumber = GetRegValue("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion", "CurrentMajorVersionNumber");
            string CurrentVersion = GetRegValue("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion", "CurrentVersion");

            bool isHighIntegrity = IsHighIntegrity();
            bool isLocalAdmin = IsLocalAdmin();

            string arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            string userName = System.Environment.GetEnvironmentVariable("USERNAME");
            string ProcessorCount = System.Environment.ProcessorCount.ToString();
            bool isVM = IsVirtualMachine();

            DateTime now = DateTime.UtcNow;
            DateTime boot = now - TimeSpan.FromMilliseconds(Environment.TickCount);
            DateTime BootTime = boot + TimeSpan.FromMilliseconds(System.Environment.TickCount);

            String strHostName = Dns.GetHostName();
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            string dnsDomain = properties.DomainName;

            Console.WriteLine("\r\n\r\n=== Basic OS Information ===\r\n");
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "Hostname", strHostName));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "Domain Name", dnsDomain));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "Username", WindowsIdentity.GetCurrent().Name));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "ProductName", ProductName));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "EditionID", EditionID));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "ReleaseId", ReleaseId));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "BuildBranch", BuildBranch));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "CurrentMajorVersionNumber", CurrentMajorVersionNumber));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "CurrentVersion", CurrentVersion));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "Architecture", arch));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "ProcessorCount", ProcessorCount));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "IsVirtualMachine", isVM));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "BootTime (approx)", BootTime));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "HighIntegrity", isHighIntegrity));
            Console.WriteLine(String.Format("  {0,-30}:  {1}", "IsLocalAdmin", isLocalAdmin));
            if (!isHighIntegrity && isLocalAdmin)
            {
                Console.WriteLine("    [*] In medium integrity but user is a local administrator- UAC can be bypassed.");
            }
        }

        public static void ListRebootSchedule()
        {
            // queries event IDs 12 (kernel boot) and 13 (kernel shutdown), sorts, and gives reboot schedule
            // grab events from the last X days - 15 for default
            int lastDays = 15;

            Console.WriteLine("\r\n\r\n=== Reboot Schedule (event ID 12/13 from last {0} days) ===\r\n", lastDays);

            SortedDictionary<System.DateTime, string> events = new SortedDictionary<System.DateTime, string>();

            var startTime = System.DateTime.Now.AddDays(-lastDays);
            var endTime = System.DateTime.Now;

            // eventID 12 == start up
            var query = string.Format(@"*[System/EventID=12] and *[System[TimeCreated[@SystemTime >= '{0}']]] and *[System[TimeCreated[@SystemTime <= '{1}']]]",
                startTime.ToUniversalTime().ToString("o"),
                endTime.ToUniversalTime().ToString("o"));

            EventLogQuery eventsQuery = new EventLogQuery("System", PathType.LogName, query);

            try
            {
                EventLogReader logReader = new EventLogReader(eventsQuery);

                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    System.DateTime time = DateTime.Parse(eventdetail.Properties[6].Value.ToString());
                    events.Add(time, "startup");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }

            // eventID 13 == shutdown
            var query2 = string.Format(@"*[System/EventID=13] and *[System[TimeCreated[@SystemTime >= '{0}']]] and *[System[TimeCreated[@SystemTime <= '{1}']]]",
                startTime.ToUniversalTime().ToString("o"),
                endTime.ToUniversalTime().ToString("o"));

            EventLogQuery eventsQuery2 = new EventLogQuery("System", PathType.LogName, query2);

            try
            {
                EventLogReader logReader2 = new EventLogReader(eventsQuery2);

                for (EventRecord eventdetail2 = logReader2.ReadEvent(); eventdetail2 != null; eventdetail2 = logReader2.ReadEvent())
                {
                    System.DateTime time = DateTime.Parse(eventdetail2.Properties[0].Value.ToString());
                    events.Add(time, "shutdown");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }

            foreach (var kvp in events)
            {
                Console.WriteLine(String.Format("  {0,-23} :  {1}", kvp.Key, kvp.Value));
                if (kvp.Value == "shutdown")
                {
                    Console.WriteLine();
                }
            }
        }

        public static void ListTokenGroupPrivs()
        {
            // Returns all privileges that the current process/user possesses
            // adapted from https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni

            try
            {
                Console.WriteLine("\r\n\r\n=== Current Privileges ===\r\n");

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
                            Console.WriteLine(String.Format("  {0,43}:  {1}", StrBuilder.ToString(), (LuidAttributes)laa.Attributes));
                        }
                        Marshal.FreeHGlobal(LuidPointer);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListUserEnvVariables()
        {
            try
            {
                // dumps out current user environment variables
                Console.WriteLine("\r\n\r\n=== User Environment Variables ===\r\n");
                foreach (System.Collections.DictionaryEntry env in Environment.GetEnvironmentVariables())
                {
                    string name = (string)env.Key;
                    string value = (string)env.Value;
                    Console.WriteLine("  {0,-35} : {1}", name, value);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListSystemEnvVariables()
        {
            // dumps out current system environment variables
            Console.WriteLine("\r\n\r\n=== System Environment Variables ===\r\n");
            Dictionary<string, object> settings = GetRegValues("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
            if ((settings != null) && (settings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in settings)
                {
                    Console.WriteLine("  {0,-35} : {1}", kvp.Key, kvp.Value);
                }
            }
        }

        public static void ListNonstandardServices()
        {
            // lists installed servics that don't have "Microsoft Corporation" as the company name in their file info
            //      or all services if "full" is passed

            if (FilterResults.filter)
            {
                Console.WriteLine("\r\n\r\n=== Non Microsoft Services (via WMI) ===\r\n");
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== All Services (via WMI) ===\r\n");
            }

            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    //OLD - if ((result["PathName"] != null) && ((!FilterResults.filter) || (!Regex.IsMatch(result["PathName"].ToString(), "C:\\\\WINDOWS\\\\", RegexOptions.IgnoreCase))))
                    if (result["PathName"] != null)
                    {
                        Match path = Regex.Match(result["PathName"].ToString(), @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase);
                        String binaryPath = path.Groups[1].ToString();
                        FileVersionInfo myFileVersionInfo = FileVersionInfo.GetVersionInfo(binaryPath);
                        string companyName = myFileVersionInfo.CompanyName;
                        if ((String.IsNullOrEmpty(companyName)) || (!FilterResults.filter) || (!Regex.IsMatch(companyName, @"^Microsoft.*", RegexOptions.IgnoreCase)))
                        {
                            bool isDotNet = false;
                            try
                            {
                                AssemblyName myAssemblyName = AssemblyName.GetAssemblyName(binaryPath);
                                isDotNet = true;
                            }
                            catch (System.IO.FileNotFoundException)
                            {
                                // System.Console.WriteLine("The file cannot be found.");
                            }
                            catch (System.BadImageFormatException exception)
                            {
                                if (Regex.IsMatch(exception.Message, ".*This assembly is built by a runtime newer than the currently loaded runtime and cannot be loaded.*", RegexOptions.IgnoreCase))
                                {
                                    isDotNet = true;
                                }
                            }
                            catch
                            {
                                // System.Console.WriteLine("The assembly has already been loaded.");
                            }

                            Console.WriteLine("  Name             : {0}", result["Name"]);
                            Console.WriteLine("  DisplayName      : {0}", result["DisplayName"]);
                            Console.WriteLine("  Company Name     : {0}", companyName);
                            Console.WriteLine("  Description      : {0}", result["Description"]);
                            Console.WriteLine("  State            : {0}", result["State"]);
                            Console.WriteLine("  StartMode        : {0}", result["StartMode"]);
                            Console.WriteLine("  PathName         : {0}", result["PathName"]);
                            Console.WriteLine("  IsDotNet         : {0}\r\n", isDotNet);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListUserFolders()
        {
            // lists the folders in C:\Users\, showing users who have logged onto the system
            try
            {
                Console.WriteLine("\r\n\r\n=== User Folders ===\r\n");
                string userPath = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));

                string[] dirs = Directory.GetDirectories(userPath);
                Console.WriteLine("  {0,-35}   {1}", "Folder", "Last Modified Time");
                foreach (string dir in dirs)
                {
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        DateTime dt = Directory.GetLastWriteTime(dir);
                        Console.WriteLine("  {0,-35} : {1}", dir, dt);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListUACSystemPolicies()
        {
            // dump out various UAC system policies
            Console.WriteLine("\r\n\r\n=== UAC System Policies ===\r\n");

            string ConsentPromptBehaviorAdmin = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin");
            switch (ConsentPromptBehaviorAdmin)
            {
                case "0":
                    Console.WriteLine("  {0,-30} : {1} - No prompting", "ConsentPromptBehaviorAdmin", ConsentPromptBehaviorAdmin);
                    break;
                case "1":
                    Console.WriteLine("  {0,-30} : {1} - PromptOnSecureDesktop", "ConsentPromptBehaviorAdmin", ConsentPromptBehaviorAdmin);
                    break;
                case "2":
                    Console.WriteLine("  {0,-30} : {1} - PromptPermitDenyOnSecureDesktop", "ConsentPromptBehaviorAdmin", ConsentPromptBehaviorAdmin);
                    break;
                case "3":
                    Console.WriteLine("  {0,-30} : {1} - PromptForCredsNotOnSecureDesktop", "ConsentPromptBehaviorAdmin", ConsentPromptBehaviorAdmin);
                    break;
                case "4":
                    Console.WriteLine("  {0,-30} : {1} - PromptForPermitDenyNotOnSecureDesktop", "ConsentPromptBehaviorAdmin", ConsentPromptBehaviorAdmin);
                    break;
                case "5":
                    Console.WriteLine("  {0,-30} : {1} - PromptForNonWindowsBinaries", "ConsentPromptBehaviorAdmin", ConsentPromptBehaviorAdmin);
                    break;
                default:
                    Console.WriteLine("  {0,-30} : PromptForNonWindowsBinaries", "ConsentPromptBehaviorAdmin");
                    break;
            }

            string EnableLUA = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA");
            Console.WriteLine("  {0,-30} : {1}", "EnableLUA", EnableLUA);
            if ((EnableLUA == "") || (EnableLUA == "0"))
            {
                Console.WriteLine("    [*] EnableLUA != 1, UAC policies disabled.\r\n    [*] Any local account can be used for lateral movement.");
            }

            string LocalAccountTokenFilterPolicy = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "LocalAccountTokenFilterPolicy");
            Console.WriteLine("  {0,-30} : {1}", "LocalAccountTokenFilterPolicy", LocalAccountTokenFilterPolicy);
            if ((EnableLUA == "1") && (LocalAccountTokenFilterPolicy == "1"))
            {
                Console.WriteLine("    [*] LocalAccountTokenFilterPolicy set to 1.\r\n    [*] Any local account can be used for lateral movement.");
            }

            string FilterAdministratorToken = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "FilterAdministratorToken");
            Console.WriteLine("  {0,-30} : {1}", "FilterAdministratorToken", FilterAdministratorToken);

            if ((EnableLUA == "1") && (LocalAccountTokenFilterPolicy != "1") && (FilterAdministratorToken != "1"))
            {
                Console.WriteLine("    [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.\r\n    [*] Only the RID-500 local admin account can be used for lateral movement.");
            }

            if ((EnableLUA == "1") && (LocalAccountTokenFilterPolicy != "1") && (FilterAdministratorToken == "1"))
            {
                Console.WriteLine("    [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken == 1.\r\n    [*] No local accounts can be used for lateral movement.");
            }
        }

        public static void ListPowerShellSettings()
        {
            Console.WriteLine("\r\n\r\n=== PowerShell Settings ===\r\n");

            string PowerShellVersion2 = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", "PowerShellVersion");
            Console.WriteLine("  {0,-30} : {1}", "PowerShell v2 Version", PowerShellVersion2);

            string PowerShellVersion5 = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", "PowerShellVersion");
            Console.WriteLine("  {0,-30} : {1}", "PowerShell v5 Version", PowerShellVersion5);

            Dictionary<string, object> transcriptionSettings = GetRegValues("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription");
            Console.WriteLine("\r\n  Transcription Settings:\r\n");
            if ((transcriptionSettings != null) && (transcriptionSettings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in transcriptionSettings)
                {
                    Console.WriteLine("  {0,30} : {1}\r\n", kvp.Key, kvp.Value);
                }
            }

            Dictionary<string, object> moduleLoggingSettings = GetRegValues("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging");
            Console.WriteLine("  Module Logging Settings:\r\n");
            if ((moduleLoggingSettings != null) && (moduleLoggingSettings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in moduleLoggingSettings)
                {
                    Console.WriteLine("  {0,30} : {1}\r\n", kvp.Key, kvp.Value);
                }
            }

            Dictionary<string, object> scriptBlockSettings = GetRegValues("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging");
            Console.WriteLine("  Scriptblock Logging Settings:\r\n");
            if ((scriptBlockSettings != null) && (scriptBlockSettings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in scriptBlockSettings)
                {
                    Console.WriteLine("  {0,30} : {1}\r\n", kvp.Key, kvp.Value);
                }
            }
        }

        public static void ListInternetSettings()
        {
            // lists user/system internet settings, including default proxy info

            Dictionary<string, object> proxySettings = GetRegValues("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
            Console.WriteLine("\r\n\r\n=== HKCU Internet Settings ===\r\n");
            if ((proxySettings != null) && (proxySettings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in proxySettings)
                {
                    Console.WriteLine("  {0,30} : {1}", kvp.Key, kvp.Value);
                }
            }

            Dictionary<string, object> proxySettings2 = GetRegValues("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
            Console.WriteLine("\r\n\r\n=== HKLM Internet Settings ===\r\n");
            if ((proxySettings2 != null) && (proxySettings2.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in proxySettings2)
                {
                    Console.WriteLine("  {0,30} : {1}", kvp.Key, kvp.Value);
                }
            }
        }

        public static void ListLSASettings()
        {
            Console.WriteLine("\r\n\r\n=== LSA Settings ===\r\n");
            Dictionary<string, object> settings = GetRegValues("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa");
            if ((settings != null) && (settings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in settings)
                {
                    if (kvp.Value.GetType().IsArray && (kvp.Value.GetType().GetElementType().ToString() == "System.String"))
                    {
                        string result = string.Join(",", (string[])kvp.Value);
                        Console.WriteLine("  {0,-30} : {1}", kvp.Key, result);

                        if (kvp.Key.ToString() == "Security Packages")
                        {
                            Regex regex = new Regex(@".*wdigest.*");
                            Match m = regex.Match(result);
                            if (m.Success)
                            {
                                Console.WriteLine("    [*] Wdigest is enabled- plaintext password extraction is possible!");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("  {0,-30} : {1}", kvp.Key, kvp.Value);
                    }
                }
            }
        }

        public static void ListKerberosTickets()
        {
            if (IsHighIntegrity())
            {
                ListKerberosTicketsAllUsers();
            }
            else
            {
                ListKerberosTicketsCurrentUser();
            }
        }
        public static void ListKerberosTicketsAllUsers()
        {
            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n=== Kerberos Tickets (All Users) ===\r\n");

            IntPtr hLsa = LsaRegisterLogonProcessHelper();
            int totalTicketCount = 0;

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (hLsa == IntPtr.Zero)
            {
                GetSystem();
                // should now have the proper privileges to get a Handle to LSA
                hLsa = LsaRegisterLogonProcessHelper();
                // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                RevertToSelf();
            }

            try
            {
                // first return all the logon sessions

                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++)
                {
                    IntPtr sessionData;
                    ret = LsaGetLogonSessionData(luidPtr, out sessionData);
                    SECURITY_LOGON_SESSION_DATA data = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);
                        string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                        string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();
                        SECURITY_LOGON_TYPE logonType = (SECURITY_LOGON_TYPE)data.LogonType;
                        DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                        string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();
                        string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();
                        string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                        // now we want to get the tickets for this logon ID
                        string name = "kerberos";
                        LSA_STRING_IN LSAString;
                        LSAString.Length = (ushort)name.Length;
                        LSAString.MaximumLength = (ushort)(name.Length + 1);
                        LSAString.Buffer = name;

                        IntPtr ticketPointer = IntPtr.Zero;
                        IntPtr ticketsPointer = IntPtr.Zero;
                        DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);
                        int authPack;
                        int returnBufferLength = 0;
                        int protocalStatus = 0;
                        int retCode;

                        KERB_QUERY_TKT_CACHE_REQUEST tQuery = new KERB_QUERY_TKT_CACHE_REQUEST();
                        KERB_QUERY_TKT_CACHE_RESPONSE tickets = new KERB_QUERY_TKT_CACHE_RESPONSE();
                        KERB_TICKET_CACHE_INFO ticket;

                        // obtains the unique identifier for the kerberos authentication package.
                        retCode = LsaLookupAuthenticationPackage(hLsa, ref LSAString, out authPack);

                        // input object for querying the ticket cache for a specific logon ID
                        LUID userLogonID = new LUID();
                        userLogonID.LowPart = data.LoginID.LowPart;
                        userLogonID.HighPart = 0;
                        tQuery.LogonId = userLogonID;
                        tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

                        // query LSA, specifying we want the ticket cache
                        retCode = LsaCallAuthenticationPackage(hLsa, authPack, ref tQuery, Marshal.SizeOf(tQuery), out ticketPointer, out returnBufferLength, out protocalStatus);

                        Console.WriteLine("\r\n  UserName                 : {0}", username);
                        Console.WriteLine("  Domain                   : {0}", domain);
                        Console.WriteLine("  LogonId                  : {0}", data.LoginID.LowPart);
                        Console.WriteLine("  UserSID                  : {0}", sid.AccountDomainSid);
                        Console.WriteLine("  AuthenticationPackage    : {0}", authpackage);
                        Console.WriteLine("  LogonType                : {0}", logonType);
                        Console.WriteLine("  LogonType                : {0}", logonTime);
                        Console.WriteLine("  LogonServer              : {0}", logonServer);
                        Console.WriteLine("  LogonServerDNSDomain     : {0}", dnsDomainName);
                        Console.WriteLine("  UserPrincipalName        : {0}\r\n", upn);

                        if (ticketPointer != IntPtr.Zero)
                        {
                            // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                            tickets = (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketPointer, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
                            int count2 = tickets.CountOfTickets;

                            if (count2 != 0)
                            {
                                Console.WriteLine("    [*] Enumerated {0} ticket(s):\r\n", count2);
                                totalTicketCount += count2;
                                // get the size of the structures we're iterating over
                                Int32 dataSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO));

                                for (int j = 0; j < count2; j++)
                                {
                                    // iterate through the structures
                                    IntPtr currTicketPtr = (IntPtr)(long)((ticketPointer.ToInt64() + (int)(8 + j * dataSize)));

                                    // parse the new ptr to the appropriate structure
                                    ticket = (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(KERB_TICKET_CACHE_INFO));

                                    // extract our fields
                                    string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                                    string realmName = Marshal.PtrToStringUni(ticket.RealmName.Buffer, ticket.RealmName.Length / 2);
                                    DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
                                    DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
                                    DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);
                                    string encryptionType = ((KERB_ENCRYPTION_TYPE)ticket.EncryptionType).ToString();
                                    string ticketFlags = ((KERB_TICKET_FLAGS)ticket.TicketFlags).ToString();

                                    Console.WriteLine("    ServerName         :  {0}", serverName);
                                    Console.WriteLine("    RealmName          :  {0}", realmName);
                                    Console.WriteLine("    StartTime          :  {0}", startTime);
                                    Console.WriteLine("    EndTime            :  {0}", endTime);
                                    Console.WriteLine("    RenewTime          :  {0}", renewTime);
                                    Console.WriteLine("    EncryptionType     :  {0}", encryptionType);
                                    Console.WriteLine("    TicketFlags        :  {0}\r\n", ticketFlags);
                                }
                            }
                        }
                    }
                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                    LsaFreeReturnBuffer(sessionData);
                }
                LsaFreeReturnBuffer(luidPtr);

                // disconnect from LSA
                LsaDeregisterLogonProcess(hLsa);

                Console.WriteLine("\r\n\r\n  [*] Enumerated {0} total tickets\r\n", totalTicketCount);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex);
            }
        }
        public static void ListKerberosTicketsCurrentUser()
        {
            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n=== Kerberos Tickets (Current User) ===\r\n");

            try
            {
                string name = "kerberos";
                LSA_STRING_IN LSAString;
                LSAString.Length = (ushort)name.Length;
                LSAString.MaximumLength = (ushort)(name.Length + 1);
                LSAString.Buffer = name;

                IntPtr ticketPointer = IntPtr.Zero;
                IntPtr ticketsPointer = IntPtr.Zero;
                DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);
                int authPack;
                int returnBufferLength = 0;
                int protocalStatus = 0;
                IntPtr lsaHandle;
                int retCode;

                // If we want to look at tickets from a session other than our own
                // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
                retCode = LsaConnectUntrusted(out lsaHandle);

                KERB_QUERY_TKT_CACHE_REQUEST tQuery = new KERB_QUERY_TKT_CACHE_REQUEST();
                KERB_QUERY_TKT_CACHE_RESPONSE tickets = new KERB_QUERY_TKT_CACHE_RESPONSE();
                KERB_TICKET_CACHE_INFO ticket;

                // obtains the unique identifier for the kerberos authentication package.
                retCode = LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // input object for querying the ticket cache (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_query_tkt_cache_request)
                tQuery.LogonId = new LUID();
                tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

                // query LSA, specifying we want the ticket cache
                retCode = LsaCallAuthenticationPackage(lsaHandle, authPack, ref tQuery, Marshal.SizeOf(tQuery), out ticketPointer, out returnBufferLength, out protocalStatus);

                // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                tickets = (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketPointer, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
                int count = tickets.CountOfTickets;
                Console.WriteLine("  [*] Returned {0} tickets\r\n", count);

                // get the size of the structures we're iterating over
                Int32 dataSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO));

                for (int i = 0; i < count; i++)
                {
                    // iterate through the structures
                    IntPtr currTicketPtr = (IntPtr)(long)((ticketPointer.ToInt64() + (int)(8 + i * dataSize)));

                    // parse the new ptr to the appropriate structure
                    ticket = (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(KERB_TICKET_CACHE_INFO));

                    // extract our fields
                    string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                    string realmName = Marshal.PtrToStringUni(ticket.RealmName.Buffer, ticket.RealmName.Length / 2);
                    DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
                    DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
                    DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);
                    string encryptionType = ((KERB_ENCRYPTION_TYPE)ticket.EncryptionType).ToString();
                    string ticketFlags = ((KERB_TICKET_FLAGS)ticket.TicketFlags).ToString();

                    Console.WriteLine("  ServerName         :  {0}", serverName);
                    Console.WriteLine("  RealmName          :  {0}", realmName);
                    Console.WriteLine("  StartTime          :  {0}", startTime);
                    Console.WriteLine("  EndTime            :  {0}", endTime);
                    Console.WriteLine("  RenewTime          :  {0}", renewTime);
                    Console.WriteLine("  EncryptionType     :  {0}", encryptionType);
                    Console.WriteLine("  TicketFlags        :  {0}\r\n", ticketFlags);
                }

                // disconnect from LSA
                LsaDeregisterLogonProcess(lsaHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListKerberosTGTData()
        {
            if (IsHighIntegrity())
            {
                ListKerberosTGTDataAllUsers();
            }
            else
            {
                ListKerberosTGTDataCurrentUser();
            }
        }
        public static void ListKerberosTGTDataAllUsers()
        {
            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n=== Kerberos TGT Data (All Users) ===\r\n");

            IntPtr hLsa = LsaRegisterLogonProcessHelper();
            int totalTicketCount = 0;

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (hLsa == IntPtr.Zero)
            {
                GetSystem();
                // should now have the proper privileges to get a Handle to LSA
                hLsa = LsaRegisterLogonProcessHelper();
                // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                RevertToSelf();
            }

            try
            {
                // first return all the logon sessions

                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++)
                {
                    IntPtr sessionData;
                    ret = LsaGetLogonSessionData(luidPtr, out sessionData);
                    SECURITY_LOGON_SESSION_DATA data = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);
                        string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                        string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();
                        SECURITY_LOGON_TYPE logonType = (SECURITY_LOGON_TYPE)data.LogonType;
                        DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                        string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();
                        string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();
                        string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                        // now we want to get the tickets for this logon ID
                        string name = "kerberos";
                        LSA_STRING_IN LSAString;
                        LSAString.Length = (ushort)name.Length;
                        LSAString.MaximumLength = (ushort)(name.Length + 1);
                        LSAString.Buffer = name;

                        IntPtr responsePointer = IntPtr.Zero;
                        int authPack;
                        int returnBufferLength = 0;
                        int protocalStatus = 0;
                        int retCode;

                        KERB_RETRIEVE_TKT_REQUEST tQuery = new KERB_RETRIEVE_TKT_REQUEST();
                        KERB_RETRIEVE_TKT_RESPONSE response = new KERB_RETRIEVE_TKT_RESPONSE();

                        // obtains the unique identifier for the kerberos authentication package.
                        retCode = LsaLookupAuthenticationPackage(hLsa, ref LSAString, out authPack);

                        // input object for querying the TGT for a specific logon ID (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_retrieve_tkt_request)
                        LUID userLogonID = new LUID();
                        userLogonID.LowPart = data.LoginID.LowPart;
                        userLogonID.HighPart = 0;
                        tQuery.LogonId = userLogonID;
                        tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage;
                        // indicate we want kerb creds yo'
                        tQuery.CacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED;

                        // query LSA, specifying we want the the TGT data
                        retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(hLsa, authPack, ref tQuery, Marshal.SizeOf(tQuery), out responsePointer, out returnBufferLength, out protocalStatus);

                        if ((retCode) == 0 && (responsePointer != IntPtr.Zero))
                        {
                            Console.WriteLine("\r\n  UserName                 : {0}", username);
                            Console.WriteLine("  Domain                   : {0}", domain);
                            Console.WriteLine("  LogonId                  : {0}", data.LoginID.LowPart);
                            Console.WriteLine("  UserSID                  : {0}", sid.AccountDomainSid);
                            Console.WriteLine("  AuthenticationPackage    : {0}", authpackage);
                            Console.WriteLine("  LogonType                : {0}", logonType);
                            Console.WriteLine("  LogonType                : {0}", logonTime);
                            Console.WriteLine("  LogonServer              : {0}", logonServer);
                            Console.WriteLine("  LogonServerDNSDomain     : {0}", dnsDomainName);
                            Console.WriteLine("  UserPrincipalName        : {0}", upn);

                            // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                            response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(KERB_RETRIEVE_TKT_RESPONSE));

                            KERB_EXTERNAL_NAME serviceNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(KERB_EXTERNAL_NAME));
                            string serviceName = Marshal.PtrToStringUni(serviceNameStruct.Names.Buffer, serviceNameStruct.Names.Length / 2).Trim();

                            string targetName = "";
                            if (response.Ticket.TargetName != IntPtr.Zero)
                            {
                                KERB_EXTERNAL_NAME targetNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(KERB_EXTERNAL_NAME));
                                targetName = Marshal.PtrToStringUni(targetNameStruct.Names.Buffer, targetNameStruct.Names.Length / 2).Trim();
                            }

                            KERB_EXTERNAL_NAME clientNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(KERB_EXTERNAL_NAME));
                            string clientName = Marshal.PtrToStringUni(clientNameStruct.Names.Buffer, clientNameStruct.Names.Length / 2).Trim();

                            string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
                            string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
                            string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

                            // extract the session key
                            KERB_ENCRYPTION_TYPE sessionKeyType = (KERB_ENCRYPTION_TYPE)response.Ticket.SessionKey.KeyType;
                            Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                            byte[] sessionKey = new byte[sessionKeyLength];
                            Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
                            string base64SessionKey = Convert.ToBase64String(sessionKey);

                            DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
                            DateTime startTime = DateTime.FromFileTime(response.Ticket.StartTime);
                            DateTime endTime = DateTime.FromFileTime(response.Ticket.EndTime);
                            DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
                            Int64 timeSkew = response.Ticket.TimeSkew;
                            Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

                            string ticketFlags = ((KERB_TICKET_FLAGS)response.Ticket.TicketFlags).ToString();

                            // extract the TGT and base64 encode it
                            byte[] encodedTicket = new byte[encodedTicketSize];
                            Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
                            string base64TGT = Convert.ToBase64String(encodedTicket);

                            Console.WriteLine("  ServiceName              : {0}", serviceName);
                            Console.WriteLine("  TargetName               : {0}", targetName);
                            Console.WriteLine("  ClientName               : {0}", clientName);
                            Console.WriteLine("  DomainName               : {0}", domainName);
                            Console.WriteLine("  TargetDomainName         : {0}", targetDomainName);
                            Console.WriteLine("  AltTargetDomainName      : {0}", altTargetDomainName);
                            Console.WriteLine("  SessionKeyType           : {0}", sessionKeyType);
                            Console.WriteLine("  Base64SessionKey         : {0}", base64SessionKey);
                            Console.WriteLine("  KeyExpirationTime        : {0}", keyExpirationTime);
                            Console.WriteLine("  TicketFlags              : {0}", ticketFlags);
                            Console.WriteLine("  StartTime                : {0}", startTime);
                            Console.WriteLine("  EndTime                  : {0}", endTime);
                            Console.WriteLine("  RenewUntil               : {0}", renewUntil);
                            Console.WriteLine("  TimeSkew                 : {0}", timeSkew);
                            Console.WriteLine("  EncodedTicketSize        : {0}", encodedTicketSize);
                            Console.WriteLine("  Base64EncodedTicket      :\r\n");
                            // display the TGT, columns of 100 chararacters
                            foreach (string line in Split(base64TGT, 100))
                            {
                                Console.WriteLine("    {0}", line);
                            }
                            Console.WriteLine();
                            totalTicketCount++;
                        }
                    }
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                    //move the pointer forward
                    LsaFreeReturnBuffer(sessionData);
                    //free the SECURITY_LOGON_SESSION_DATA memory in the struct
                }
                LsaFreeReturnBuffer(luidPtr);       //free the array of LUIDs

                // disconnect from LSA
                LsaDeregisterLogonProcess(hLsa);

                Console.WriteLine("\r\n\r\n  [*] Extracted {0} total tickets\r\n", totalTicketCount);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex);
            }
        }
        public static void ListKerberosTGTDataCurrentUser()
        {
            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n=== Kerberos TGT Data (Current User) ===\r\n");

            try
            {
                string name = "kerberos";
                LSA_STRING_IN LSAString;
                LSAString.Length = (ushort)name.Length;
                LSAString.MaximumLength = (ushort)(name.Length + 1);
                LSAString.Buffer = name;

                IntPtr responsePointer = IntPtr.Zero;
                int authPack;
                int returnBufferLength = 0;
                int protocalStatus = 0;
                IntPtr lsaHandle;
                int retCode;

                // If we want to look at tickets from a session other than our own
                // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
                retCode = LsaConnectUntrusted(out lsaHandle);

                KERB_RETRIEVE_TKT_REQUEST tQuery = new KERB_RETRIEVE_TKT_REQUEST();
                KERB_RETRIEVE_TKT_RESPONSE response = new KERB_RETRIEVE_TKT_RESPONSE();

                // obtains the unique identifier for the kerberos authentication package.
                retCode = LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // input object for querying the TGT (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_retrieve_tkt_request)
                tQuery.LogonId = new LUID();
                tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage;
                // indicate we want kerb creds yo'
                //tQuery.CacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED;

                // query LSA, specifying we want the the TGT data
                retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(lsaHandle, authPack, ref tQuery, Marshal.SizeOf(tQuery), out responsePointer, out returnBufferLength, out protocalStatus);

                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(KERB_RETRIEVE_TKT_RESPONSE));

                KERB_EXTERNAL_NAME serviceNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(KERB_EXTERNAL_NAME));
                string serviceName = Marshal.PtrToStringUni(serviceNameStruct.Names.Buffer, serviceNameStruct.Names.Length / 2).Trim();

                string targetName = "";
                if (response.Ticket.TargetName != IntPtr.Zero)
                {
                    KERB_EXTERNAL_NAME targetNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(KERB_EXTERNAL_NAME));
                    targetName = Marshal.PtrToStringUni(targetNameStruct.Names.Buffer, targetNameStruct.Names.Length / 2).Trim();
                }

                KERB_EXTERNAL_NAME clientNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(KERB_EXTERNAL_NAME));
                string clientName = Marshal.PtrToStringUni(clientNameStruct.Names.Buffer, clientNameStruct.Names.Length / 2).Trim();

                string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
                string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
                string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

                // extract the session key
                KERB_ENCRYPTION_TYPE sessionKeyType = (KERB_ENCRYPTION_TYPE)response.Ticket.SessionKey.KeyType;
                Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                byte[] sessionKey = new byte[sessionKeyLength];
                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
                string base64SessionKey = Convert.ToBase64String(sessionKey);

                DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
                DateTime startTime = DateTime.FromFileTime(response.Ticket.StartTime);
                DateTime endTime = DateTime.FromFileTime(response.Ticket.EndTime);
                DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
                Int64 timeSkew = response.Ticket.TimeSkew;
                Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

                string ticketFlags = ((KERB_TICKET_FLAGS)response.Ticket.TicketFlags).ToString();

                // extract the TGT and base64 encode it
                byte[] encodedTicket = new byte[encodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
                string base64TGT = Convert.ToBase64String(encodedTicket);

                Console.WriteLine("  ServiceName              : {0}", serviceName);
                Console.WriteLine("  TargetName               : {0}", targetName);
                Console.WriteLine("  ClientName               : {0}", clientName);
                Console.WriteLine("  DomainName               : {0}", domainName);
                Console.WriteLine("  TargetDomainName         : {0}", targetDomainName);
                Console.WriteLine("  AltTargetDomainName      : {0}", altTargetDomainName);
                Console.WriteLine("  SessionKeyType           : {0}", sessionKeyType);
                Console.WriteLine("  Base64SessionKey         : {0}", base64SessionKey);
                Console.WriteLine("  KeyExpirationTime        : {0}", keyExpirationTime);
                Console.WriteLine("  TicketFlags              : {0}", ticketFlags);
                Console.WriteLine("  StartTime                : {0}", startTime);
                Console.WriteLine("  EndTime                  : {0}", endTime);
                Console.WriteLine("  RenewUntil               : {0}", renewUntil);
                Console.WriteLine("  TimeSkew                 : {0}", timeSkew);
                Console.WriteLine("  EncodedTicketSize        : {0}", encodedTicketSize);
                Console.WriteLine("  Base64EncodedTicket      :\r\n");
                // display the TGT, columns of 100 chararacters
                foreach (string line in Split(base64TGT, 100))
                {
                    Console.WriteLine("    {0}", line);
                }
                Console.WriteLine();

                // disconnect from LSA
                LsaDeregisterLogonProcess(lsaHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        // https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/security/authorization/klist/KList.c#L585
        // currently not working :(
        //public static void ListKerberosTicketDataCurrentUser()
        //{
        //    // adapted partially from Vincent LE TOUX' work
        //    //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
        //    // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
        //    // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

        //    Console.WriteLine("\r\n\r\n=== Kerberos Ticket Data (Current User) ===\r\n");

        //    //try
        //    //{
        //    string name = "kerberos";
        //    LSA_STRING_IN LSAString;
        //    LSAString.Length = (ushort)name.Length;
        //    LSAString.MaximumLength = (ushort)(name.Length + 1);
        //    LSAString.Buffer = name;

        //    IntPtr ticketPointer = IntPtr.Zero;
        //    IntPtr ticketsPointer = IntPtr.Zero;
        //    int authPack;
        //    int returnBufferLength = 0;
        //    int protocalStatus = 0;
        //    IntPtr lsaHandle;
        //    int retCode;

        //    // If we want to look at tickets from a session other than our own
        //    // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
        //    retCode = LsaConnectUntrusted(out lsaHandle);

        //    // obtains the unique identifier for the kerberos authentication package.
        //    retCode = LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

        //    UNICODE_STRING targetName = new UNICODE_STRING("krbtgt/TESTLAB.LOCAL");
        //    UNICODE_STRING target = new UNICODE_STRING();

        //    KERB_RETRIEVE_TKT_RESPONSE CacheResponse = new KERB_RETRIEVE_TKT_RESPONSE();

        //    // LMEM_ZEROINIT -> 0x0040
        //    IntPtr temp = LocalAlloc(0x0040, (uint)(targetName.Length + Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST))));

        //    IntPtr unmanagedAddr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)));
        //    //Marshal.StructureToPtr(managedObj, unmanagedAddr, true);
        //    KERB_RETRIEVE_TKT_REQUEST_UNI CacheRequest = (KERB_RETRIEVE_TKT_REQUEST_UNI)Marshal.PtrToStructure(temp, typeof(KERB_RETRIEVE_TKT_REQUEST_UNI));
        //    CacheRequest.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

        //    // KERB_RETRIEVE_TKT_REQUEST_UNI
        //    IntPtr CacheRequestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)));
        //    Marshal.StructureToPtr(CacheRequest, CacheRequestPtr, false);
        //    target.buffer = (IntPtr)(CacheRequestPtr.ToInt64() + 1);
        //    target.Length = targetName.Length;
        //    target.MaximumLength = targetName.MaximumLength;

        //    CopyMemory(target.buffer, targetName.buffer, targetName.Length);

        //    CacheRequest.TargetName = target;

        //    IntPtr responsePointer = IntPtr.Zero;
        //    int returnBufferLength2 = 0;
        //    // query LSA, specifying we want the the specified ticket data
        //    retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT_UNI(lsaHandle, authPack, ref CacheRequest, Marshal.SizeOf(CacheRequest) + targetName.Length, out responsePointer, out returnBufferLength2, out protocalStatus);
        //    Console.WriteLine("LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT_UNI retCode: {0}", retCode);
        //    Console.WriteLine("returnBufferLength: {0}", returnBufferLength2);
        //    Console.WriteLine("responsePointer: {0}\r\n", responsePointer);
        //    Console.WriteLine("protocalStatus: {0}\r\n", (uint)protocalStatus);
        //    Console.Out.Flush();


        //    //string clientName = Marshal.PtrToStringUni(CacheResponse.Ticket.ClientName, CacheResponse.Ticket.ClientName.L / 2);
        //    DateTime startTime = DateTime.FromFileTime(CacheResponse.Ticket.StartTime);
        //    DateTime endTime = DateTime.FromFileTime(CacheResponse.Ticket.EndTime);
        //    Console.WriteLine("startTime: {0}", startTime);
        //    Console.WriteLine("endTime: {0}", endTime);

        //    //// query LSA, specifying we want the ticket cache
        //    //retCode = LsaCallAuthenticationPackage(lsaHandle, authPack, ref tQuery, Marshal.SizeOf(tQuery), out ticketPointer, out returnBufferLength, out protocalStatus);

        //    //// parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
        //    //tickets = (KERB_QUERY_TKT_CACHE_EX_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketPointer, typeof(KERB_QUERY_TKT_CACHE_EX_RESPONSE));
        //    //int count = tickets.CountOfTickets;
        //    //Console.WriteLine("  [*] Returned {0} tickets\r\n", count);

        //    //// get the size of the structures we're iterating over
        //    //Int32 dataSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO_EX));

        //    //for (int i = 0; i < count; i++)
        //    //{
        //    //    // iterate through the structures
        //    //    IntPtr currTicketPtr = (IntPtr)(long)((ticketPointer.ToInt64() + (int)(8 + i * dataSize)));

        //    //    // parse the new ptr to the appropriate structure
        //    //    ticket = (KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(currTicketPtr, typeof(KERB_TICKET_CACHE_INFO_EX));

        //    //    // extract our fields
        //    //    string clientName = Marshal.PtrToStringUni(ticket.ClientName.Buffer, ticket.ClientName.Length / 2);
        //    //    string clientRealm = Marshal.PtrToStringUni(ticket.ClientRealm.Buffer, ticket.ClientRealm.Length / 2);
        //    //    string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
        //    //    string serverRealm = Marshal.PtrToStringUni(ticket.ServerRealm.Buffer, ticket.ServerRealm.Length / 2);
        //    //    Console.WriteLine("clientName: {0}", clientName);
        //    //    Console.WriteLine("clientRealm: {0}", clientRealm);
        //    //    Console.WriteLine("serverName: {0}", serverName);
        //    //    Console.WriteLine("serverRealm: {0}", serverRealm);
        //    //    DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
        //    //    DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
        //    //    DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);
        //    //    string encryptionType = ((KERB_ENCRYPTION_TYPE)ticket.EncryptionType).ToString();
        //    //    string ticketFlags = ((KERB_TICKET_FLAGS)ticket.TicketFlags).ToString();

        //    //KERB_RETRIEVE_TKT_REQUEST ticketQuery = new KERB_RETRIEVE_TKT_REQUEST();
        //    //KERB_RETRIEVE_TKT_RESPONSE response = new KERB_RETRIEVE_TKT_RESPONSE();

        //    //// input object for querying the ticket cache
        //    ////ticketQuery.LogonId = new LUID();
        //    //ticketQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
        //    //// indicate we want kerb creds yo'
        //    //ticketQuery.CacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        //    //ticketQuery.TicketFlags = ticket.TicketFlags;
        //    ////ticketQuery.TargetName = ticket.ServerName;

        //    //string targetName2 = "krbtgt/TESTLAB.LOCAL";
        //    //LSA_STRING_IN LSAString2;
        //    //LSAString2.Length = (ushort)targetName2.Length;
        //    //LSAString2.MaximumLength = (ushort)(targetName2.Length + 1);
        //    //LSAString2.Buffer = targetName2;
        //    //ticketQuery.TargetName = LSAString2;

        //    //Console.WriteLine("flags: {0}\r\n", ticket.TicketFlags.ToString("X2"));

        //    //IntPtr responsePointer = IntPtr.Zero;
        //    //int returnBufferLength2 = 0;
        //    //// query LSA, specifying we want the the specified ticket data
        //    //retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(lsaHandle, authPack, ref ticketQuery, Marshal.SizeOf(ticketQuery), out responsePointer, out returnBufferLength2, out protocalStatus);
        //    //Console.WriteLine("LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT retCode: {0}", retCode);
        //    //Console.WriteLine("returnBufferLength: {0}", returnBufferLength2);
        //    //Console.WriteLine("responsePointer: {0}\r\n", responsePointer);
        //    //// parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure

        //    //response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(KERB_RETRIEVE_TKT_RESPONSE));

        //    //KERB_EXTERNAL_NAME serviceNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(KERB_EXTERNAL_NAME));
        //    //string serviceName = Marshal.PtrToStringUni(serviceNameStruct.Names.Buffer, serviceNameStruct.Names.Length / 2).Trim();

        //    //string targetName = "";
        //    //if (response.Ticket.TargetName != IntPtr.Zero)
        //    //{
        //    //    KERB_EXTERNAL_NAME targetNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(KERB_EXTERNAL_NAME));
        //    //    targetName = Marshal.PtrToStringUni(targetNameStruct.Names.Buffer, targetNameStruct.Names.Length / 2).Trim();
        //    //}

        //    //KERB_EXTERNAL_NAME clientNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(KERB_EXTERNAL_NAME));
        //    ////string clientName = Marshal.PtrToStringUni(clientNameStruct.Names.Buffer, clientNameStruct.Names.Length / 2).Trim();

        //    //string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
        //    //string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
        //    //string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

        //    //// extract the session key
        //    //KERB_ENCRYPTION_TYPE sessionKeyType = (KERB_ENCRYPTION_TYPE)response.Ticket.SessionKey.KeyType;
        //    //Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
        //    //byte[] sessionKey = new byte[sessionKeyLength];
        //    //Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
        //    //string base64SessionKey = Convert.ToBase64String(sessionKey);

        //    //DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
        //    //DateTime startTime2 = DateTime.FromFileTime(response.Ticket.StartTime);
        //    //DateTime endTime2 = DateTime.FromFileTime(response.Ticket.EndTime);
        //    //DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
        //    //Int64 timeSkew = response.Ticket.TimeSkew;
        //    //Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

        //    //string ticketFlags2 = ((KERB_TICKET_FLAGS)response.Ticket.TicketFlags).ToString();

        //    //// extract the ticket and base64 encode it
        //    //byte[] encodedTicket = new byte[encodedTicketSize];
        //    //Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
        //    //string base64Ticket = Convert.ToBase64String(encodedTicket);

        //    //Console.WriteLine("  ServiceName              : {0}", serviceName);
        //    //Console.WriteLine("  TargetName               : {0}", targetName);
        //    //Console.WriteLine("  ClientName               : {0}", clientName);
        //    //Console.WriteLine("  DomainName               : {0}", domainName);
        //    //Console.WriteLine("  TargetDomainName         : {0}", targetDomainName);
        //    //Console.WriteLine("  AltTargetDomainName      : {0}", altTargetDomainName);
        //    //Console.WriteLine("  SessionKeyType           : {0}", sessionKeyType);
        //    //Console.WriteLine("  Base64SessionKey         : {0}", base64SessionKey);
        //    //Console.WriteLine("  KeyExpirationTime        : {0}", keyExpirationTime);
        //    //Console.WriteLine("  TicketFlags              : {0}", ticketFlags2);
        //    //Console.WriteLine("  StartTime                : {0}", startTime2);
        //    //Console.WriteLine("  EndTime                  : {0}", endTime2);
        //    //Console.WriteLine("  RenewUntil               : {0}", renewUntil);
        //    //Console.WriteLine("  EncodedTicketSize        : {0}", encodedTicketSize);
        //    //Console.WriteLine("  Base64EncodedTicket      :\r\n");
        //    //// display the TGT, columns of 80 chararacters
        //    //foreach (string line in Split(base64Ticket, 80))
        //    //{
        //    //    Console.WriteLine("    {0}", line);
        //    //}
        //    //Console.WriteLine();
        //    //}

        //    // disconnect from LSA
        //    LsaDeregisterLogonProcess(lsaHandle);
        //    //}
        //    //catch (Exception ex)
        //    //{
        //    //    Console.WriteLine("  [X] Exception: {0}", ex.Message);
        //    //}
        //}


        public static void ListLogonSessions()
        {
            if (!IsHighIntegrity())
            {
                // https://www.pinvoke.net/default.aspx/secur32.lsalogonuser

                // list user logons combined with logon session data via WMI

                Regex userDomainRegex = new Regex(@"Domain=""(.*)"",Name=""(.*)""");
                Regex logonIdRegex = new Regex(@"LogonId=""(\d+)""");

                Console.WriteLine("\r\n\r\n=== Logon Sessions (via WMI) ===\r\n\r\n");

                Dictionary<string, string[]> logonMap = new Dictionary<string, string[]>();

                try
                {
                    ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM Win32_LoggedOnUser");
                    ManagementObjectCollection data = wmiData.Get();

                    foreach (ManagementObject result in data)
                    {
                        Match m = logonIdRegex.Match(result["Dependent"].ToString());
                        if (m.Success)
                        {
                            string logonId = m.Groups[1].ToString();
                            Match m2 = userDomainRegex.Match(result["Antecedent"].ToString());
                            if (m2.Success)
                            {
                                string domain = m2.Groups[1].ToString();
                                string user = m2.Groups[2].ToString();
                                logonMap.Add(logonId, new string[] { domain, user });
                            }
                        }
                    }

                    ManagementObjectSearcher wmiData2 = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM Win32_LogonSession");
                    ManagementObjectCollection data2 = wmiData2.Get();

                    foreach (ManagementObject result2 in data2)
                    {
                        string[] userDomain = logonMap[result2["LogonId"].ToString()];
                        string domain = userDomain[0];
                        string userName = userDomain[1];
                        System.DateTime startTime = System.Management.ManagementDateTimeConverter.ToDateTime(result2["StartTime"].ToString());

                        string logonType = String.Format("{0}", ((SECURITY_LOGON_TYPE)(Int32.Parse(result2["LogonType"].ToString()))));

                        Console.WriteLine("  UserName                 : {0}", userName);
                        Console.WriteLine("  Domain                   : {0}", domain);
                        Console.WriteLine("  LogonId                  : {0}", result2["LogonId"].ToString());
                        Console.WriteLine("  LogonType                : {0}", logonType);
                        Console.WriteLine("  AuthenticationPackage    : {0}", result2["AuthenticationPackage"].ToString());
                        Console.WriteLine("  StartTime                : {0}\r\n", startTime);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("  [X] Exception: {0}", ex.Message);
                }
            }
            else
            {
                // heavily adapted from from Jared Hill:
                //      https://www.codeproject.com/Articles/18179/Using-the-Local-Security-Authority-to-Enumerate-Us

                Console.WriteLine("\r\n\r\n=== Logon Sessions (via LSA) ===\r\n\r\n");

                try
                {
                    DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                    UInt64 count;
                    IntPtr luidPtr = IntPtr.Zero;
                    IntPtr iter = luidPtr;

                    uint ret = LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                    for (ulong i = 0; i < count; i++)
                    {
                        IntPtr sessionData;

                        ret = LsaGetLogonSessionData(luidPtr, out sessionData);
                        SECURITY_LOGON_SESSION_DATA data = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA));

                        // if we have a valid logon
                        if (data.PSiD != IntPtr.Zero)
                        {
                            // get the account username
                            string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();

                            // convert the security identifier of the user
                            System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);

                            // domain for this account
                            string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();

                            // authentication package
                            string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();

                            // logon type
                            SECURITY_LOGON_TYPE logonType = (SECURITY_LOGON_TYPE)data.LogonType;

                            // datetime the session was logged in
                            DateTime logonTime = systime.AddTicks((long)data.LoginTime);

                            // user's logon server
                            string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();

                            // logon server's DNS domain
                            string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();

                            // user principalname
                            string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                            Console.WriteLine("  UserName                 : {0}", username);
                            Console.WriteLine("  Domain                   : {0}", domain);
                            Console.WriteLine("  LogonId                  : {0}", data.LoginID.LowPart);
                            Console.WriteLine("  UserSID                  : {0}", sid.AccountDomainSid);
                            Console.WriteLine("  AuthenticationPackage    : {0}", authpackage);
                            Console.WriteLine("  LogonType                : {0}", logonType);
                            Console.WriteLine("  LogonType                : {0}", logonTime);
                            Console.WriteLine("  LogonServer              : {0}", logonServer);
                            Console.WriteLine("  LogonServerDNSDomain     : {0}", dnsDomainName);
                            Console.WriteLine("  UserPrincipalName        : {0}\r\n", upn);
                        }
                        // move the pointer forward
                        luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                        LsaFreeReturnBuffer(sessionData);
                    }
                    LsaFreeReturnBuffer(luidPtr);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("  [X] Exception: {0}", ex);
                }
            }
        }

        public static void ListAuditSettings()
        {
            Console.WriteLine("\r\n\r\n=== Audit Settings ===\r\n");
            Dictionary<string, object> settings = GetRegValues("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit");
            if ((settings != null) && (settings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in settings)
                {
                    if (kvp.Value.GetType().IsArray && (kvp.Value.GetType().GetElementType().ToString() == "System.String"))
                    {
                        string result = string.Join(",", (string[])kvp.Value);
                        Console.WriteLine("  {0,-30} : {1}", kvp.Key, result);
                    }
                    else
                    {
                        Console.WriteLine("  {0,-30} : {1}", kvp.Key, kvp.Value);
                    }
                }
            }
        }

        public static void ListWEFSettings()
        {
            Console.WriteLine("\r\n\r\n=== WEF Settings ===\r\n");
            Dictionary<string, object> settings = GetRegValues("HKLM", "Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager");
            if ((settings != null) && (settings.Count != 0))
            {
                foreach (KeyValuePair<string, object> kvp in settings)
                {
                    if (kvp.Value.GetType().IsArray && (kvp.Value.GetType().GetElementType().ToString() == "System.String"))
                    {
                        string result = string.Join(",", (string[])kvp.Value);
                        Console.WriteLine("  {0,-30} : {1}", kvp.Key, result);
                    }
                    else
                    {
                        Console.WriteLine("  {0,-30} : {1}", kvp.Key, kvp.Value);
                    }
                }
            }
        }

        public static void ListLapsSettings()
        {
            Console.WriteLine("\r\n\r\n=== LAPS Settings ===\r\n");

            string AdmPwdEnabled = GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "AdmPwdEnabled");

            if (AdmPwdEnabled != "")
            {
                Console.WriteLine("  {0,-37} : {1}", "LAPS Enabled", AdmPwdEnabled);

                string LAPSAdminAccountName = GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "AdminAccountName");
                Console.WriteLine("  {0,-37} : {1}", "LAPS Admin Account Name", LAPSAdminAccountName);

                string LAPSPasswordComplexity = GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PasswordComplexity");
                Console.WriteLine("  {0,-37} : {1}", "LAPS Password Complexity", LAPSPasswordComplexity);

                string LAPSPasswordLength = GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PasswordLength");
                Console.WriteLine("  {0,-37} : {1}", "LAPS Password Length", LAPSPasswordLength);

                string LASPwdExpirationProtectionEnabled = GetRegValue("HKLM", "Software\\Policies\\Microsoft Services\\AdmPwd", "PwdExpirationProtectionEnabled");
                Console.WriteLine("  {0,-37} : {1}", "LAPS Expiration Protection Enabled", LASPwdExpirationProtectionEnabled);
            }
            else
            {
                Console.WriteLine("  [*] LAPS not installed");
            }
        }

        public static void ListLocalGroupMembers()
        {
            // adapted from https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889

            try
            {
                Console.WriteLine("\r\n\r\n=== Local Group Memberships ===\r\n");

                // localization for @cnotin ;)
                string[] groupsSIDs = {
                    "S-1-5-32-544", // Administrators
                    "S-1-5-32-555", // RDP
                    "S-1-5-32-562", // COM
                    "S-1-5-32-580" // Remote Management
                };

                foreach (string sid in groupsSIDs)
                {
                    string groupNameFull = TranslateSid(sid);
                    if (string.IsNullOrEmpty(groupNameFull))
                    {
                        // e.g. "S-1-5-32-580" for "Remote Management Users" can be missing on older versions of Windows
                        Console.WriteLine("  [X] Cannot find SID translation for '{0}'", sid);
                        continue;
                    }

                    string groupName = groupNameFull.Substring(groupNameFull.IndexOf('\\') + 1);
                    Console.WriteLine("  * {0} *\r\n", groupName);
                    string[] members = GetLocalGroupMembers(groupName);
                    if (members != null)
                    {
                        foreach (string member in members)
                        {
                            Console.WriteLine("    {0}", member);
                        }
                    }

                    Console.WriteLine("");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListMappedDrives()
        {
            try
            {
                Console.WriteLine("\r\n\r\n=== Drive Information (via .NET) ===\r\n");

                // grab all drive letters
                DriveInfo[] driveInfos = DriveInfo.GetDrives();

                Console.WriteLine("  {0,-10}   {1}", "Drive", "Mapped Location");

                foreach (DriveInfo driveInfo in driveInfos)
                {
                    // try to resolve each drive to a UNC mapped location
                    string path = GetUNCPath(driveInfo.Name);

                    Console.WriteLine("  {0,-10} : {1}", driveInfo.Name, path);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListWMIMappedDrives()
        {
            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_networkconnection");
                ManagementObjectCollection data = wmiData.Get();

                Console.WriteLine("\r\n\r\n=== Mapped Drives (via WMI) ===\r\n");

                foreach (ManagementObject result in data)
                {
                    Console.WriteLine("  LocalName        : {0}", result["LocalName"]);
                    Console.WriteLine("  RemoteName       : {0}", result["RemoteName"]);
                    Console.WriteLine("  RemotePath       : {0}", result["RemotePath"]);
                    Console.WriteLine("  Status           : {0}", result["Status"]);
                    Console.WriteLine("  ConnectionState  : {0}", result["ConnectionState"]);
                    Console.WriteLine("  Persistent       : {0}", result["Persistent"]);
                    Console.WriteLine("  UserName         : {0}", result["UserName"]);
                    Console.WriteLine("  Description      : {0}\r\n", result["Description"]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListNetworkShares()
        {
            // lists current network shares for this system via WMI

            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM Win32_Share");
                ManagementObjectCollection data = wmiData.Get();

                Console.WriteLine("\r\n\r\n=== Network Shares (via WMI) ===\r\n");

                foreach (ManagementObject result in data)
                {
                    Console.WriteLine("  Name             : {0}", result["Name"]);
                    Console.WriteLine("  Path             : {0}", result["Path"]);
                    Console.WriteLine("  Description      : {0}\r\n", result["Description"]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListAntiVirusWMI()
        {
            // lists installed VA products via WMI (the AntiVirusProduct class)

            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                ManagementObjectCollection data = wmiData.Get();

                Console.WriteLine("\r\n\r\n=== Registered Antivirus (via WMI) ===\r\n");

                foreach (ManagementObject virusChecker in data)
                {
                    Console.WriteLine("  Engine        : {0}", virusChecker["displayName"]);
                    Console.WriteLine("  ProductEXE    : {0}", virusChecker["pathToSignedProductExe"]);
                    Console.WriteLine("  ReportingEXE  : {0}\r\n", virusChecker["pathToSignedReportingExe"]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListInterestingProcesses()
        {
            // TODO: check out https://github.com/harleyQu1nn/AggressorScripts/blob/master/ProcessColor.cna#L10

            // from https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1#L985-L1033
            Hashtable defensiveProcesses = new Hashtable()
            {
                {"mcshield.exe"                , "McAfee AV"},
                {"windefend.exe"               , "Windows Defender AV"},
                {"MSASCui.exe"                 , "Windows Defender AV"},
                {"MSASCuiL.exe"                , "Windows Defender AV"},
                {"msmpeng.exe"                 , "Windows Defender AV"},
                {"msmpsvc.exe"                 , "Windows Defender AV"},
                {"WRSA.exe"                    , "WebRoot AV"},
                {"savservice.exe"              , "Sophos AV"},
                {"TMCCSF.exe"                  , "Trend Micro AV"},
                {"symantec antivirus.exe"      , "Symantec AV"},
                {"mbae.exe"                    , "MalwareBytes Anti-Exploit"},
                {"parity.exe"                  , "Bit9 application whitelisting"},
                {"cb.exe"                      , "Carbon Black behavioral analysis"},
                {"bds-vision.exe"              , "BDS Vision behavioral analysis"},
                {"Triumfant.exe"               , "Triumfant behavioral analysis"},
                {"CSFalcon.exe"                , "CrowdStrike Falcon EDR"},
                {"ossec.exe"                   , "OSSEC intrusion detection"},
                {"TmPfw.exe"                   , "Trend Micro firewall"},
                {"dgagent.exe"                 , "Verdasys Digital Guardian DLP"},
                {"kvoop.exe"                   , "Unknown DLP process" },
                {"AAWTray.exe"              , "UNKNOWN"},
                {"ackwin32.exe"             , "UNKNOWN"},
                {"Ad-Aware.exe"             , "UNKNOWN"},
                {"adaware.exe"              , "UNKNOWN"},
                {"advxdwin.exe"             , "UNKNOWN"},
                {"agentsvr.exe"             , "UNKNOWN"},
                {"agentw.exe"               , "UNKNOWN"},
                {"alertsvc.exe"             , "UNKNOWN"},
                {"alevir.exe"               , "UNKNOWN"},
                {"alogserv.exe"             , "UNKNOWN"},
                {"amon9x.exe"               , "UNKNOWN"},
                {"anti-trojan.exe"          , "UNKNOWN"},
                {"antivirus.exe"            , "UNKNOWN"},
                {"ants.exe"                 , "UNKNOWN"},
                {"apimonitor.exe"           , "UNKNOWN"},
                {"aplica32.exe"             , "UNKNOWN"},
                {"apvxdwin.exe"             , "UNKNOWN"},
                {"arr.exe"                  , "UNKNOWN"},
                {"atcon.exe"                , "UNKNOWN"},
                {"atguard.exe"              , "UNKNOWN"},
                {"atro55en.exe"             , "UNKNOWN"},
                {"atupdater.exe"            , "UNKNOWN"},
                {"atwatch.exe"              , "UNKNOWN"},
                {"au.exe"                   , "UNKNOWN"},
                {"aupdate.exe"              , "UNKNOWN"},
                {"auto-protect.nav80try.exe", "UNKNOWN"},
                {"autodown.exe"             , "UNKNOWN"},
                {"autoruns.exe"             , "UNKNOWN"},
                {"autorunsc.exe"            , "UNKNOWN"},
                {"autotrace.exe"            , "UNKNOWN"},
                {"autoupdate.exe"           , "UNKNOWN"},
                {"avconsol.exe"             , "UNKNOWN"},
                {"ave32.exe"                , "UNKNOWN"},
                {"avgcc32.exe"              , "UNKNOWN"},
                {"avgctrl.exe"              , "UNKNOWN"},
                {"avgemc.exe"               , "UNKNOWN"},
                {"avgnt.exe"                , "UNKNOWN"},
                {"avgrsx.exe"               , "UNKNOWN"},
                {"avgserv.exe"              , "UNKNOWN"},
                {"avgserv9.exe"             , "UNKNOWN"},
                {"avguard.exe"              , "UNKNOWN"},
                {"avgwdsvc.exe"             , "UNKNOWN"},
                {"avgui.exe"                , "UNKNOWN"},
                {"avgw.exe"                 , "UNKNOWN"},
                {"avkpop.exe"               , "UNKNOWN"},
                {"avkserv.exe"              , "UNKNOWN"},
                {"avkservice.exe"           , "UNKNOWN"},
                {"avkwctl9.exe"             , "UNKNOWN"},
                {"avltmain.exe"             , "UNKNOWN"},
                {"avnt.exe"                 , "UNKNOWN"},
                {"avp.exe"                  , "UNKNOWN"},
                {"avp32.exe"                , "UNKNOWN"},
                {"avpcc.exe"                , "UNKNOWN"},
                {"avpdos32.exe"             , "UNKNOWN"},
                {"avpm.exe"                 , "UNKNOWN"},
                {"avptc32.exe"              , "UNKNOWN"},
                {"avpupd.exe"               , "UNKNOWN"},
                {"avsched32.exe"            , "UNKNOWN"},
                {"avsynmgr.exe"             , "UNKNOWN"},
                {"avwin.exe"                , "UNKNOWN"},
                {"avwin95.exe"              , "UNKNOWN"},
                {"avwinnt.exe"              , "UNKNOWN"},
                {"avwupd.exe"               , "UNKNOWN"},
                {"avwupd32.exe"             , "UNKNOWN"},
                {"avwupsrv.exe"             , "UNKNOWN"},
                {"avxmonitor9x.exe"         , "UNKNOWN"},
                {"avxmonitornt.exe"         , "UNKNOWN"},
                {"avxquar.exe"              , "UNKNOWN"},
                {"backweb.exe"              , "UNKNOWN"},
                {"bargains.exe"             , "UNKNOWN"},
                {"bd_professional.exe"      , "UNKNOWN"},
                {"beagle.exe"               , "UNKNOWN"},
                {"belt.exe"                 , "UNKNOWN"},
                {"bidef.exe"                , "UNKNOWN"},
                {"bidserver.exe"            , "UNKNOWN"},
                {"bipcp.exe"                , "UNKNOWN"},
                {"bipcpevalsetup.exe"       , "UNKNOWN"},
                {"bisp.exe"                 , "UNKNOWN"},
                {"blackd.exe"               , "UNKNOWN"},
                {"blackice.exe"             , "UNKNOWN"},
                {"blink.exe"                , "UNKNOWN"},
                {"blss.exe"                 , "UNKNOWN"},
                {"bootconf.exe"             , "UNKNOWN"},
                {"bootwarn.exe"             , "UNKNOWN"},
                {"borg2.exe"                , "UNKNOWN"},
                {"bpc.exe"                  , "UNKNOWN"},
                {"brasil.exe"               , "UNKNOWN"},
                {"bs120.exe"                , "UNKNOWN"},
                {"bundle.exe"               , "UNKNOWN"},
                {"bvt.exe"                  , "UNKNOWN"},
                {"ccapp.exe"                , "UNKNOWN"},
                {"ccevtmgr.exe"             , "UNKNOWN"},
                {"ccpxysvc.exe"             , "UNKNOWN"},
                {"ccSvcHst.exe"             , "UNKNOWN"},
                {"cdp.exe"                  , "UNKNOWN"},
                {"cfd.exe"                  , "UNKNOWN"},
                {"cfgwiz.exe"               , "UNKNOWN"},
                {"cfiadmin.exe"             , "UNKNOWN"},
                {"cfiaudit.exe"             , "UNKNOWN"},
                {"cfinet.exe"               , "UNKNOWN"},
                {"cfinet32.exe"             , "UNKNOWN"},
                {"claw95.exe"               , "UNKNOWN"},
                {"claw95cf.exe"             , "UNKNOWN"},
                {"clean.exe"                , "UNKNOWN"},
                {"cleaner.exe"              , "UNKNOWN"},
                {"cleaner3.exe"             , "UNKNOWN"},
                {"cleanpc.exe"              , "UNKNOWN"},
                {"cleanup.exe"              , "UNKNOWN"},
                {"click.exe"                , "UNKNOWN"},
                {"cmdagent.exe"             , "UNKNOWN"},
                {"cmesys.exe"               , "UNKNOWN"},
                {"cmgrdian.exe"             , "UNKNOWN"},
                {"cmon016.exe"              , "UNKNOWN"},
                {"connectionmonitor.exe"    , "UNKNOWN"},
                {"cpd.exe"                  , "UNKNOWN"},
                {"cpf9x206.exe"             , "UNKNOWN"},
                {"cpfnt206.exe"             , "UNKNOWN"},
                {"ctrl.exe"                 , "UNKNOWN"},
                {"cv.exe"                   , "UNKNOWN"},
                {"cwnb181.exe"              , "UNKNOWN"},
                {"cwntdwmo.exe"             , "UNKNOWN"},
                {"CylanceUI.exe"            , "UNKNOWN"},
                {"CyProtect.exe"            , "UNKNOWN"},
                {"CyUpdate.exe"             , "UNKNOWN"},
                {"cyserver.exe"             , "UNKNOWN"},
                {"cytray.exe"               , "UNKNOWN"},
                {"CyveraService.exe"        , "UNKNOWN"},
                {"datemanager.exe"          , "UNKNOWN"},
                {"dcomx.exe"                , "UNKNOWN"},
                {"defalert.exe"             , "UNKNOWN"},
                {"defscangui.exe"           , "UNKNOWN"},
                {"defwatch.exe"             , "UNKNOWN"},
                {"deputy.exe"               , "UNKNOWN"},
                {"divx.exe"                 , "UNKNOWN"},
                {"dgprompt.exe"             , "UNKNOWN"},
                {"DgService.exe"            , "UNKNOWN"},
                {"dllcache.exe"             , "UNKNOWN"},
                {"dllreg.exe"               , "UNKNOWN"},
                {"doors.exe"                , "UNKNOWN"},
                {"dpf.exe"                  , "UNKNOWN"},
                {"dpfsetup.exe"             , "UNKNOWN"},
                {"dpps2.exe"                , "UNKNOWN"},
                {"drwatson.exe"             , "UNKNOWN"},
                {"drweb32.exe"              , "UNKNOWN"},
                {"drwebupw.exe"             , "UNKNOWN"},
                {"dssagent.exe"             , "UNKNOWN"},
                {"dumpcap.exe"              , "UNKNOWN"},
                {"dvp95.exe"                , "UNKNOWN"},
                {"dvp95_0.exe"              , "UNKNOWN"},
                {"ecengine.exe"             , "UNKNOWN"},
                {"efpeadm.exe"              , "UNKNOWN"},
                {"egui.exe"                 , "UNKNOWN"},
                {"ekrn.exe"                 , "UNKNOWN"},
                {"emet_agent.exe"           , "UNKNOWN"},
                {"emet_service.exe"         , "UNKNOWN"},
                {"emsw.exe"                 , "UNKNOWN"},
                {"engineserver.exe"         , "UNKNOWN"},
                {"ent.exe"                  , "UNKNOWN"},
                {"esafe.exe"                , "UNKNOWN"},
                {"escanhnt.exe"             , "UNKNOWN"},
                {"escanv95.exe"             , "UNKNOWN"},
                {"espwatch.exe"             , "UNKNOWN"},
                {"ethereal.exe"             , "UNKNOWN"},
                {"etrustcipe.exe"           , "UNKNOWN"},
                {"evpn.exe"                 , "UNKNOWN"},
                {"exantivirus-cnet.exe"     , "UNKNOWN"},
                {"exe.avxw.exe"             , "UNKNOWN"},
                {"expert.exe"               , "UNKNOWN"},
                {"explore.exe"              , "UNKNOWN"},
                {"f-agnt95.exe"             , "UNKNOWN"},
                {"f-prot.exe"               , "UNKNOWN"},
                {"f-prot95.exe"             , "UNKNOWN"},
                {"f-stopw.exe"              , "UNKNOWN"},
                {"fameh32.exe"              , "UNKNOWN"},
                {"fast.exe"                 , "UNKNOWN"},
                {"fch32.exe"                , "UNKNOWN"},
                {"fcagswd.exe"              , "McAfee DLP Agent"},
                {"fcags.exe"                , "McAfee DLP Agent"},
                {"fih32.exe"                , "UNKNOWN"},
                {"findviru.exe"             , "UNKNOWN"},
                {"firesvc.exe"              , "McAfee Host Intrusion Prevention"},
                {"firetray.exe"             , "UNKNOWN"},
                {"firewall.exe"             , "UNKNOWN"},
                {"fnrb32.exe"               , "UNKNOWN"},
                {"fp-win.exe"               , "UNKNOWN"},
                {"fp-win_trial.exe"         , "UNKNOWN"},
                {"fprot.exe"                , "UNKNOWN"},
                {"frameworkservice.exe"     , "UNKNOWN"},
                {"frminst.exe"              , "UNKNOWN"},
                {"frw.exe"                  , "UNKNOWN"},
                {"fsaa.exe"                 , "UNKNOWN"},
                {"fsav.exe"                 , "UNKNOWN"},
                {"fsav32.exe"               , "UNKNOWN"},
                {"fsav530stbyb.exe"         , "UNKNOWN"},
                {"fsav530wtbyb.exe"         , "UNKNOWN"},
                {"fsav95.exe"               , "UNKNOWN"},
                {"fsgk32.exe"               , "UNKNOWN"},
                {"fsm32.exe"                , "UNKNOWN"},
                {"fsma32.exe"               , "UNKNOWN"},
                {"fsmb32.exe"               , "UNKNOWN"},
                {"gator.exe"                , "UNKNOWN"},
                {"gbmenu.exe"               , "UNKNOWN"},
                {"gbpoll.exe"               , "UNKNOWN"},
                {"generics.exe"             , "UNKNOWN"},
                {"gmt.exe"                  , "UNKNOWN"},
                {"guard.exe"                , "UNKNOWN"},
                {"guarddog.exe"             , "UNKNOWN"},
                {"hacktracersetup.exe"      , "UNKNOWN"},
                {"hbinst.exe"               , "UNKNOWN"},
                {"hbsrv.exe"                , "UNKNOWN"},
                {"HijackThis.exe"           , "UNKNOWN"},
                {"hipsvc.exe"               , "UNKNOWN"},
                {"HipMgmt.exe"              , "McAfee Host Intrusion Protection"},
                {"hotactio.exe"             , "UNKNOWN"},
                {"hotpatch.exe"             , "UNKNOWN"},
                {"htlog.exe"                , "UNKNOWN"},
                {"htpatch.exe"              , "UNKNOWN"},
                {"hwpe.exe"                 , "UNKNOWN"},
                {"hxdl.exe"                 , "UNKNOWN"},
                {"hxiul.exe"                , "UNKNOWN"},
                {"iamapp.exe"               , "UNKNOWN"},
                {"iamserv.exe"              , "UNKNOWN"},
                {"iamstats.exe"             , "UNKNOWN"},
                {"ibmasn.exe"               , "UNKNOWN"},
                {"ibmavsp.exe"              , "UNKNOWN"},
                {"icload95.exe"             , "UNKNOWN"},
                {"icloadnt.exe"             , "UNKNOWN"},
                {"icmon.exe"                , "UNKNOWN"},
                {"icsupp95.exe"             , "UNKNOWN"},
                {"icsuppnt.exe"             , "UNKNOWN"},
                {"idle.exe"                 , "UNKNOWN"},
                {"iedll.exe"                , "UNKNOWN"},
                {"iedriver.exe"             , "UNKNOWN"},
                {"iface.exe"                , "UNKNOWN"},
                {"ifw2000.exe"              , "UNKNOWN"},
                {"inetlnfo.exe"             , "UNKNOWN"},
                {"infus.exe"                , "UNKNOWN"},
                {"infwin.exe"               , "UNKNOWN"},
                {"init.exe"                 , "UNKNOWN"},
                {"intdel.exe"               , "UNKNOWN"},
                {"intren.exe"               , "UNKNOWN"},
                {"iomon98.exe"              , "UNKNOWN"},
                {"istsvc.exe"               , "UNKNOWN"},
                {"jammer.exe"               , "UNKNOWN"},
                {"jdbgmrg.exe"              , "UNKNOWN"},
                {"jedi.exe"                 , "UNKNOWN"},
                {"kavlite40eng.exe"         , "UNKNOWN"},
                {"kavpers40eng.exe"         , "UNKNOWN"},
                {"kavpf.exe"                , "UNKNOWN"},
                {"kazza.exe"                , "UNKNOWN"},
                {"keenvalue.exe"            , "UNKNOWN"},
                {"kerio-pf-213-en-win.exe"  , "UNKNOWN"},
                {"kerio-wrl-421-en-win.exe" , "UNKNOWN"},
                {"kerio-wrp-421-en-win.exe" , "UNKNOWN"},
                {"kernel32.exe"             , "UNKNOWN"},
                {"KeyPass.exe"              , "UNKNOWN"},
                {"killprocesssetup161.exe"  , "UNKNOWN"},
                {"launcher.exe"             , "UNKNOWN"},
                {"ldnetmon.exe"             , "UNKNOWN"},
                {"ldpro.exe"                , "UNKNOWN"},
                {"ldpromenu.exe"            , "UNKNOWN"},
                {"ldscan.exe"               , "UNKNOWN"},
                {"lnetinfo.exe"             , "UNKNOWN"},
                {"loader.exe"               , "UNKNOWN"},
                {"localnet.exe"             , "UNKNOWN"},
                {"lockdown.exe"             , "UNKNOWN"},
                {"lockdown2000.exe"         , "UNKNOWN"},
                {"lookout.exe"              , "UNKNOWN"},
                {"lordpe.exe"               , "UNKNOWN"},
                {"lsetup.exe"               , "UNKNOWN"},
                {"luall.exe"                , "UNKNOWN"},
                {"luau.exe"                 , "UNKNOWN"},
                {"lucomserver.exe"          , "UNKNOWN"},
                {"luinit.exe"               , "UNKNOWN"},
                {"luspt.exe"                , "UNKNOWN"},
                {"mapisvc32.exe"            , "UNKNOWN"},
                {"masvc.exe"                , "McAfee Agent"},
                {"mbamservice.exe"          , "UNKNOWN"},
                {"mcafeefire.exe"           , "UNKNOWN"},
                {"mcagent.exe"              , "UNKNOWN"},
                {"mcmnhdlr.exe"             , "UNKNOWN"},
                {"mcscript.exe"             , "UNKNOWN"},
                {"mcscript_inuse.exe"       , "UNKNOWN"},
                {"mctool.exe"               , "UNKNOWN"},
                {"mctray.exe"               , "UNKNOWN"},
                {"mcupdate.exe"             , "UNKNOWN"},
                {"mcvsrte.exe"              , "UNKNOWN"},
                {"mcvsshld.exe"             , "UNKNOWN"},
                {"md.exe"                   , "UNKNOWN"},
                {"mfeann.exe"               , "McAfee VirusScan Enterprise"},
                {"mfemactl.exe"             , "McAfee VirusScan Enterprise"},
                {"mfevtps.exe"              , "UNKNOWN"},
                {"mfin32.exe"               , "UNKNOWN"},
                {"mfw2en.exe"               , "UNKNOWN"},
                {"mfweng3.02d30.exe"        , "UNKNOWN"},
                {"mgavrtcl.exe"             , "UNKNOWN"},
                {"mgavrte.exe"              , "UNKNOWN"},
                {"mghtml.exe"               , "UNKNOWN"},
                {"mgui.exe"                 , "UNKNOWN"},
                {"minilog.exe"              , "UNKNOWN"},
                {"minionhost.exe"           , "UNKNOWN"},
                {"mmod.exe"                 , "UNKNOWN"},
                {"monitor.exe"              , "UNKNOWN"},
                {"moolive.exe"              , "UNKNOWN"},
                {"mostat.exe"               , "UNKNOWN"},
                {"mpfagent.exe"             , "UNKNOWN"},
                {"mpfservice.exe"           , "UNKNOWN"},
                {"mpftray.exe"              , "UNKNOWN"},
                {"mrflux.exe"               , "UNKNOWN"},
                {"msapp.exe"                , "UNKNOWN"},
                {"msbb.exe"                 , "UNKNOWN"},
                {"msblast.exe"              , "UNKNOWN"},
                {"mscache.exe"              , "UNKNOWN"},
                {"msccn32.exe"              , "UNKNOWN"},
                {"mscman.exe"               , "UNKNOWN"},
                {"msconfig.exe"             , "UNKNOWN"},
                {"msdm.exe"                 , "UNKNOWN"},
                {"msdos.exe"                , "UNKNOWN"},
                {"msiexec16.exe"            , "UNKNOWN"},
                {"msinfo32.exe"             , "UNKNOWN"},
                {"mslaugh.exe"              , "UNKNOWN"},
                {"msmgt.exe"                , "UNKNOWN"},
                {"msmsgri32.exe"            , "UNKNOWN"},
                {"MsSense.exe"              , "Microsoft Defender ATP"},
                {"mssmmc32.exe"             , "UNKNOWN"},
                {"mssys.exe"                , "UNKNOWN"},
                {"msvxd.exe"                , "UNKNOWN"},
                {"mu0311ad.exe"             , "UNKNOWN"},
                {"mwatch.exe"               , "UNKNOWN"},
                {"n32scanw.exe"             , "UNKNOWN"},
                {"naprdmgr.exe"             , "UNKNOWN"},
                {"nav.exe"                  , "UNKNOWN"},
                {"navap.navapsvc.exe"       , "UNKNOWN"},
                {"navapsvc.exe"             , "UNKNOWN"},
                {"navapw32.exe"             , "UNKNOWN"},
                {"navdx.exe"                , "UNKNOWN"},
                {"navlu32.exe"              , "UNKNOWN"},
                {"navnt.exe"                , "UNKNOWN"},
                {"navstub.exe"              , "UNKNOWN"},
                {"navw32.exe"               , "UNKNOWN"},
                {"navwnt.exe"               , "UNKNOWN"},
                {"nc2000.exe"               , "UNKNOWN"},
                {"ncinst4.exe"              , "UNKNOWN"},
                {"ndd32.exe"                , "UNKNOWN"},
                {"neomonitor.exe"           , "UNKNOWN"},
                {"neowatchlog.exe"          , "UNKNOWN"},
                {"netarmor.exe"             , "UNKNOWN"},
                {"netd32.exe"               , "UNKNOWN"},
                {"netinfo.exe"              , "UNKNOWN"},
                {"netmon.exe"               , "UNKNOWN"},
                {"netscanpro.exe"           , "UNKNOWN"},
                {"netspyhunter-1.2.exe"     , "UNKNOWN"},
                {"netstat.exe"              , "UNKNOWN"},
                {"netutils.exe"             , "UNKNOWN"},
                {"nisserv.exe"              , "UNKNOWN"},
                {"nisum.exe"                , "UNKNOWN"},
                {"nmain.exe"                , "UNKNOWN"},
                {"nod32.exe"                , "UNKNOWN"},
                {"normist.exe"              , "UNKNOWN"},
                {"norton_internet_secu_3.0_407.exe" , "UNKNOWN"},
                {"notstart.exe"             , "UNKNOWN"},
                {"npf40_tw_98_nt_me_2k.exe" , "UNKNOWN"},
                {"npfmessenger.exe"         , "UNKNOWN"},
                {"nprotect.exe"             , "UNKNOWN"},
                {"npscheck.exe"             , "UNKNOWN"},
                {"npssvc.exe"               , "UNKNOWN"},
                {"nsched32.exe"             , "UNKNOWN"},
                {"nssys32.exe"              , "UNKNOWN"},
                {"nstask32.exe"             , "UNKNOWN"},
                {"nsupdate.exe"             , "UNKNOWN"},
                {"nt.exe"                   , "UNKNOWN"},
                {"ntrtscan.exe"             , "UNKNOWN"},
                {"ntvdm.exe"                , "UNKNOWN"},
                {"ntxconfig.exe"            , "UNKNOWN"},
                {"nui.exe"                  , "UNKNOWN"},
                {"nupgrade.exe"             , "UNKNOWN"},
                {"nvarch16.exe"             , "UNKNOWN"},
                {"nvc95.exe"                , "UNKNOWN"},
                {"nvsvc32.exe"              , "UNKNOWN"},
                {"nwinst4.exe"              , "UNKNOWN"},
                {"nwservice.exe"            , "UNKNOWN"},
                {"nwtool16.exe"             , "UNKNOWN"},
                {"nxlog.exe"                , "UNKNOWN"},
                {"ollydbg.exe"              , "UNKNOWN"},
                {"onsrvr.exe"               , "UNKNOWN"},
                {"optimize.exe"             , "UNKNOWN"},
                {"ostronet.exe"             , "UNKNOWN"},
                {"osqueryd.exe"             , "UNKNOWN"},
                {"otfix.exe"                , "UNKNOWN"},
                {"outpost.exe"              , "UNKNOWN"},
                {"outpostinstall.exe"       , "UNKNOWN"},
                {"outpostproinstall.exe"    , "UNKNOWN"},
                {"padmin.exe"               , "UNKNOWN"},
                {"panixk.exe"               , "UNKNOWN"},
                {"patch.exe"                , "UNKNOWN"},
                {"pavcl.exe"                , "UNKNOWN"},
                {"pavproxy.exe"             , "UNKNOWN"},
                {"pavsched.exe"             , "UNKNOWN"},
                {"pavw.exe"                 , "UNKNOWN"},
                {"pccwin98.exe"             , "UNKNOWN"},
                {"pcfwallicon.exe"          , "UNKNOWN"},
                {"pcip10117_0.exe"          , "UNKNOWN"},
                {"pcscan.exe"               , "UNKNOWN"},
                {"pdsetup.exe"              , "UNKNOWN"},
                {"periscope.exe"            , "UNKNOWN"},
                {"persfw.exe"               , "UNKNOWN"},
                {"perswf.exe"               , "UNKNOWN"},
                {"pf2.exe"                  , "UNKNOWN"},
                {"pfwadmin.exe"             , "UNKNOWN"},
                {"pgmonitr.exe"             , "UNKNOWN"},
                {"pingscan.exe"             , "UNKNOWN"},
                {"platin.exe"               , "UNKNOWN"},
                {"pop3trap.exe"             , "UNKNOWN"},
                {"poproxy.exe"              , "UNKNOWN"},
                {"popscan.exe"              , "UNKNOWN"},
                {"portdetective.exe"        , "UNKNOWN"},
                {"portmonitor.exe"          , "UNKNOWN"},
                {"powerscan.exe"            , "UNKNOWN"},
                {"ppinupdt.exe"             , "UNKNOWN"},
                {"pptbc.exe"                , "UNKNOWN"},
                {"ppvstop.exe"              , "UNKNOWN"},
                {"prizesurfer.exe"          , "UNKNOWN"},
                {"prmt.exe"                 , "UNKNOWN"},
                {"prmvr.exe"                , "UNKNOWN"},
                {"procdump.exe"             , "UNKNOWN"},
                {"processmonitor.exe"       , "UNKNOWN"},
                {"procexp.exe"              , "UNKNOWN"},
                {"procexp64.exe"            , "UNKNOWN"},
                {"procexplorerv1.0.exe"     , "UNKNOWN"},
                {"procmon.exe"              , "UNKNOWN"},
                {"programauditor.exe"       , "UNKNOWN"},
                {"proport.exe"              , "UNKNOWN"},
                {"protectx.exe"             , "UNKNOWN"},
                {"pspf.exe"                 , "UNKNOWN"},
                {"purge.exe"                , "UNKNOWN"},
                {"qconsole.exe"             , "UNKNOWN"},
                {"qserver.exe"              , "UNKNOWN"},
                {"rapapp.exe"               , "UNKNOWN"},
                {"rav7.exe"                 , "UNKNOWN"},
                {"rav7win.exe"              , "UNKNOWN"},
                {"rav8win32eng.exe"         , "UNKNOWN"},
                {"ray.exe"                  , "UNKNOWN"},
                {"rb32.exe"                 , "UNKNOWN"},
                {"rcsync.exe"               , "UNKNOWN"},
                {"realmon.exe"              , "UNKNOWN"},
                {"reged.exe"                , "UNKNOWN"},
                {"regedit.exe"              , "UNKNOWN"},
                {"regedt32.exe"             , "UNKNOWN"},
                {"rescue.exe"               , "UNKNOWN"},
                {"rescue32.exe"             , "UNKNOWN"},
                {"rrguard.exe"              , "UNKNOWN"},
                {"rtvscan.exe"              , "UNKNOWN"},
                {"rtvscn95.exe"             , "UNKNOWN"},
                {"rulaunch.exe"             , "UNKNOWN"},
                {"run32dll.exe"             , "UNKNOWN"},
                {"rundll.exe"               , "UNKNOWN"},
                {"rundll16.exe"             , "UNKNOWN"},
                {"ruxdll32.exe"             , "UNKNOWN"},
                {"safeweb.exe"              , "UNKNOWN"},
                {"sahagent.exescan32.exe"   , "UNKNOWN"},
                {"save.exe"                 , "UNKNOWN"},
                {"savenow.exe"              , "UNKNOWN"},
                {"sbserv.exe"               , "UNKNOWN"},
                {"scam32.exe"               , "UNKNOWN"},
                {"scan32.exe"               , "UNKNOWN"},
                {"scan95.exe"               , "UNKNOWN"},
                {"scanpm.exe"               , "UNKNOWN"},
                {"scrscan.exe"              , "UNKNOWN"},
                {"SentinelOne.exe"          , "UNKNOWN"},
                {"serv95.exe"               , "UNKNOWN"},
                {"setupvameeval.exe"        , "UNKNOWN"},
                {"setup_flowprotector_us.exe", "UNKNOWN"},
                {"sfc.exe"                  , "UNKNOWN"},
                {"sgssfw32.exe"             , "UNKNOWN"},
                {"sh.exe"                   , "UNKNOWN"},
                {"shellspyinstall.exe"      , "UNKNOWN"},
                {"shn.exe"                  , "UNKNOWN"},
                {"showbehind.exe"           , "UNKNOWN"},
                {"shstat.exe"               , "McAfee VirusScan Enterprise"},
                {"SISIDSService.exe"        , "UNKNOWN"},
                {"SISIPSUtil.exe"           , "UNKNOWN"},
                {"smc.exe"                  , "UNKNOWN"},
                {"sms.exe"                  , "UNKNOWN"},
                {"smss32.exe"               , "UNKNOWN"},
                {"soap.exe"                 , "UNKNOWN"},
                {"sofi.exe"                 , "UNKNOWN"},
                {"sperm.exe"                , "UNKNOWN"},
                {"splunk.exe"               , "Splunk"},
                {"splunkd.exe"              , "Splunk"},
                {"splunk-admon.exe"         , "Splunk"},
                {"splunk-powershell.exe"    , "Splunk"},
                {"splunk-winevtlog.exe"     , "Splunk"},
                {"spf.exe"                  , "UNKNOWN"},
                {"sphinx.exe"               , "UNKNOWN"},
                {"spoler.exe"               , "UNKNOWN"},
                {"spoolcv.exe"              , "UNKNOWN"},
                {"spoolsv32.exe"            , "UNKNOWN"},
                {"spyxx.exe"                , "UNKNOWN"},
                {"srexe.exe"                , "UNKNOWN"},
                {"srng.exe"                 , "UNKNOWN"},
                {"ss3edit.exe"              , "UNKNOWN"},
                {"ssgrate.exe"              , "UNKNOWN"},
                {"ssg_4104.exe"             , "UNKNOWN"},
                {"st2.exe"                  , "UNKNOWN"},
                {"start.exe"                , "UNKNOWN"},
                {"stcloader.exe"            , "UNKNOWN"},
                {"supftrl.exe"              , "UNKNOWN"},
                {"support.exe"              , "UNKNOWN"},
                {"supporter5.exe"           , "UNKNOWN"},
                {"svchostc.exe"             , "UNKNOWN"},
                {"svchosts.exe"             , "UNKNOWN"},
                {"sweep95.exe"              , "UNKNOWN"},
                {"sweepnet.sweepsrv.sys.swnetsup.exe", "UNKNOWN"},
                {"symproxysvc.exe"          , "UNKNOWN"},
                {"symtray.exe"              , "UNKNOWN"},
                {"sysedit.exe"              , "UNKNOWN"},
                {"sysmon.exe"               , "Sysinternals Sysmon"},
                {"sysupd.exe"               , "UNKNOWN"},
                {"TaniumClient.exe"         , "Tanium"},
                {"taskmg.exe"               , "UNKNOWN"},
                {"taskmo.exe"               , "UNKNOWN"},
                {"taumon.exe"               , "UNKNOWN"},
                {"tbmon.exe"                , "UNKNOWN"},
                {"tbscan.exe"               , "UNKNOWN"},
                {"tc.exe"                   , "UNKNOWN"},
                {"tca.exe"                  , "UNKNOWN"},
                {"tcm.exe"                  , "UNKNOWN"},
                {"tcpview.exe"              , "UNKNOWN"},
                {"tds-3.exe"                , "UNKNOWN"},
                {"tds2-98.exe"              , "UNKNOWN"},
                {"tds2-nt.exe"              , "UNKNOWN"},
                {"teekids.exe"              , "UNKNOWN"},
                {"tfak.exe"                 , "UNKNOWN"},
                {"tfak5.exe"                , "UNKNOWN"},
                {"tgbob.exe"                , "UNKNOWN"},
                {"titanin.exe"              , "UNKNOWN"},
                {"titaninxp.exe"            , "UNKNOWN"},
                {"tlaservice.exe"           , "UNKNOWN"},
                {"tlaworker.exe"            , "UNKNOWN"},
                {"tracert.exe"              , "UNKNOWN"},
                {"trickler.exe"             , "UNKNOWN"},
                {"trjscan.exe"              , "UNKNOWN"},
                {"trjsetup.exe"             , "UNKNOWN"},
                {"trojantrap3.exe"          , "UNKNOWN"},
                {"tsadbot.exe"              , "UNKNOWN"},
                {"tshark.exe"               , "UNKNOWN"},
                {"tvmd.exe"                 , "UNKNOWN"},
                {"tvtmd.exe"                , "UNKNOWN"},
                {"udaterui.exe"             , "UNKNOWN"},
                {"undoboot.exe"             , "UNKNOWN"},
                {"updat.exe"                , "UNKNOWN"},
                {"update.exe"               , "UNKNOWN"},
                {"updaterui.exe"            , "UNKNOWN"},
                {"upgrad.exe"               , "UNKNOWN"},
                {"utpost.exe"               , "UNKNOWN"},
                {"vbcmserv.exe"             , "UNKNOWN"},
                {"vbcons.exe"               , "UNKNOWN"},
                {"vbust.exe"                , "UNKNOWN"},
                {"vbwin9x.exe"              , "UNKNOWN"},
                {"vbwinntw.exe"             , "UNKNOWN"},
                {"vcsetup.exe"              , "UNKNOWN"},
                {"vet32.exe"                , "UNKNOWN"},
                {"vet95.exe"                , "UNKNOWN"},
                {"vettray.exe"              , "UNKNOWN"},
                {"vfsetup.exe"              , "UNKNOWN"},
                {"vir-help.exe"             , "UNKNOWN"},
                {"virusmdpersonalfirewall.exe", "UNKNOWN"},
                {"vnlan300.exe"             , "UNKNOWN"},
                {"vnpc3000.exe"             , "UNKNOWN"},
                {"vpc32.exe"                , "UNKNOWN"},
                {"vpc42.exe"                , "UNKNOWN"},
                {"vpfw30s.exe"              , "UNKNOWN"},
                {"vptray.exe"               , "UNKNOWN"},
                {"vscan40.exe"              , "UNKNOWN"},
                {"vscenu6.02d30.exe"        , "UNKNOWN"},
                {"vsched.exe"               , "UNKNOWN"},
                {"vsecomr.exe"              , "UNKNOWN"},
                {"vshwin32.exe"             , "UNKNOWN"},
                {"vsisetup.exe"             , "UNKNOWN"},
                {"vsmain.exe"               , "UNKNOWN"},
                {"vsmon.exe"                , "UNKNOWN"},
                {"vsstat.exe"               , "UNKNOWN"},
                {"vstskmgr.exe"             , "McAfee VirusScan Enterprise"},
                {"vswin9xe.exe"             , "UNKNOWN"},
                {"vswinntse.exe"            , "UNKNOWN"},
                {"vswinperse.exe"           , "UNKNOWN"},
                {"w32dsm89.exe"             , "UNKNOWN"},
                {"w9x.exe"                  , "UNKNOWN"},
                {"watchdog.exe"             , "UNKNOWN"},
                {"webdav.exe"               , "UNKNOWN"},
                {"webscanx.exe"             , "UNKNOWN"},
                {"webtrap.exe"              , "UNKNOWN"},
                {"wfindv32.exe"             , "UNKNOWN"},
                {"whoswatchingme.exe"       , "UNKNOWN"},
                {"wimmun32.exe"             , "UNKNOWN"},
                {"win-bugsfix.exe"          , "UNKNOWN"},
                {"win32.exe"                , "UNKNOWN"},
                {"win32us.exe"              , "UNKNOWN"},
                {"winactive.exe"            , "UNKNOWN"},
                {"window.exe"               , "UNKNOWN"},
                {"windows.exe"              , "UNKNOWN"},
                {"wininetd.exe"             , "UNKNOWN"},
                {"wininitx.exe"             , "UNKNOWN"},
                {"winlogin.exe"             , "UNKNOWN"},
                {"winmain.exe"              , "UNKNOWN"},
                {"winnet.exe"               , "UNKNOWN"},
                {"winppr32.exe"             , "UNKNOWN"},
                {"winrecon.exe"             , "UNKNOWN"},
                {"winservn.exe"             , "UNKNOWN"},
                {"winssk32.exe"             , "UNKNOWN"},
                {"winstart.exe"             , "UNKNOWN"},
                {"winstart001.exe"          , "UNKNOWN"},
                {"wintsk32.exe"             , "UNKNOWN"},
                {"winupdate.exe"            , "UNKNOWN"},
                {"wireshark.exe"            , "UNKNOWN"},
                {"wkufind.exe"              , "UNKNOWN"},
                {"wnad.exe"                 , "UNKNOWN"},
                {"wnt.exe"                  , "UNKNOWN"},
                {"wradmin.exe"              , "UNKNOWN"},
                {"wrctrl.exe"               , "UNKNOWN"},
                {"wsbgate.exe"              , "UNKNOWN"},
                {"wupdater.exe"             , "UNKNOWN"},
                {"wupdt.exe"                , "UNKNOWN"},
                {"wyvernworksfirewall.exe"  , "UNKNOWN"},
                {"xagt.exe"                 , "UNKNOWN"},
                {"xpf202en.exe"             , "UNKNOWN"},
                {"zapro.exe"                , "UNKNOWN"},
                {"zapsetup3001.exe"         , "UNKNOWN"},
                {"zatutor.exe"              , "UNKNOWN"},
                {"zonalm2601.exe"           , "UNKNOWN"},
                {"zonealarm.exe"            , "UNKNOWN"},
                {"_avp32.exe"               , "UNKNOWN"},
                {"_avpcc.exe"               , "UNKNOWN"},
                {"rshell.exe"               , "UNKNOWN"},
                {"_avpm.exe"                , "UNKNOWN"}
            };

            // TODO: cyberark? other password managers?
            Hashtable interestingProcesses = new Hashtable()
            {
                {"CmRcService"             , "Configuration Manager Remote Control Service"},
                {"ftp"                     , "Misc. FTP client"},
                {"LMIGuardian"             , "LogMeIn Reporter"},
                {"LogMeInSystray"          , "LogMeIn System Tray"},
                {"RaMaint"                 , "LogMeIn maintenance sevice"},
                {"mmc"                     , "Microsoft Management Console"},
                {"putty"                   , "Putty SSH client"},
                {"pscp"                    , "Putty SCP client"},
                {"psftp"                   , "Putty SFTP client"},
                {"puttytel"                , "Putty Telnet client"},
                {"plink"                   , "Putty CLI client"},
                {"pageant"                 , "Putty SSH auth agent"},
                {"kitty"                   , "Kitty SSH client"},
                {"telnet"                  , "Misc. Telnet client"},
                {"SecureCRT"               , "SecureCRT SSH/Telnet client"},
                {"TeamViewer"              , "TeamViewer"},
                {"tv_x64"                  , "TeamViewer x64 remote control"},
                {"tv_w32"                  , "TeamViewer x86 remote control"},
                {"keepass"                 , "KeePass password vault"},
                {"mstsc"                   , "Microsoft RDP client"},
                {"vnc"                     , "Possible VNC client"},
                {"powershell"              , "PowerShell host process"},
                {"cmd"                     , "Command Prompt"},
            };

            Hashtable browserProcesses = new Hashtable()
            {
                {"chrome"                  , "Google Chrome"},
                {"iexplore"                , "Microsoft Internet Explorer"},
                {"MicrosoftEdge"           , "Microsoft Edge"},
                {"firefox"                 , "Mozilla Firefox"}
            };

            try
            {
                string wmiQuery = string.Format("SELECT * FROM Win32_Process");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiQuery);
                ManagementObjectCollection retObjectCollection = searcher.Get();

                Console.WriteLine("\r\n\r\n=== Process Enumerations ===\r\n");

                Console.WriteLine("  * Potential Defensive Processes *\r\n");

                foreach (ManagementObject Process in retObjectCollection)
                {
                    foreach (DictionaryEntry defensiveProcess in defensiveProcesses)
                    {
                        if (Process["Name"].ToString().ToLower() == defensiveProcess.Key.ToString().ToLower())
                        {
                            string[] OwnerInfo = new string[2];
                            Process.InvokeMethod("GetOwner", (object[])OwnerInfo);

                            Console.WriteLine("\tName         : {0}", Process["Name"]);
                            Console.WriteLine("\tProduct      : {0}", defensiveProcess.Value);
                            Console.WriteLine("\tProcessID    : {0}", Process["ProcessID"]);
                            if (OwnerInfo[0] != null)
                            {
                                Console.WriteLine("\tOwner        : {0}\\{1}", OwnerInfo[1], OwnerInfo[0]);
                            }
                            else
                            {
                                Console.WriteLine("\tOwner        : ");
                            }
                            Console.WriteLine("\tCommandLine  : {0}\r\n", Process["CommandLine"]);
                        }
                    }
                }

                Console.WriteLine("\r\n  * Browser Processes *\r\n");

                foreach (ManagementObject Process in retObjectCollection)
                {
                    foreach (DictionaryEntry browserProcess in browserProcesses)
                    {
                        if (Regex.IsMatch(Process["Name"].ToString(), browserProcess.Key.ToString(), RegexOptions.IgnoreCase))
                        {
                            string[] OwnerInfo = new string[2];
                            Process.InvokeMethod("GetOwner", (object[])OwnerInfo);

                            Console.WriteLine("\tName         : {0}", Process["Name"]);
                            Console.WriteLine("\tProduct      : {0}", browserProcess.Value);
                            Console.WriteLine("\tProcessID    : {0}", Process["ProcessID"]);
                            if (OwnerInfo[0] != null)
                            {
                                Console.WriteLine("\tOwner        : {0}\\{1}", OwnerInfo[1], OwnerInfo[0]);
                            }
                            else
                            {
                                Console.WriteLine("\tOwner        : ");
                            }
                            Console.WriteLine("\tCommandLine  : {0}\r\n", Process["CommandLine"]);
                        }
                    }
                }

                Console.WriteLine("\r\n  * Other Interesting Processes *\r\n");

                foreach (ManagementObject Process in retObjectCollection)
                {
                    foreach (DictionaryEntry interestingProcess in interestingProcesses)
                    {
                        if (Regex.IsMatch(Process["Name"].ToString(), interestingProcess.Key.ToString(), RegexOptions.IgnoreCase))
                        {
                            string[] OwnerInfo = new string[2];
                            Process.InvokeMethod("GetOwner", (object[])OwnerInfo);

                            Console.WriteLine("\tName         : {0}", Process["Name"]);
                            Console.WriteLine("\tProduct      : {0}", interestingProcess.Value);
                            Console.WriteLine("\tProcessID    : {0}", Process["ProcessID"]);
                            if (OwnerInfo[0] != null)
                            {
                                Console.WriteLine("\tOwner        : {0}\\{1}", OwnerInfo[1], OwnerInfo[0]);
                            }
                            else
                            {
                                Console.WriteLine("\tOwner        : ");
                            }
                            Console.WriteLine("\tCommandLine  : {0}\r\n", Process["CommandLine"]);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListRegistryAutoLogon()
        {
            Console.WriteLine("\r\n\r\n=== Registry Auto-logon Settings ===\r\n");

            string DefaultDomainName = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultDomainName");
            if (DefaultDomainName != "")
            {
                Console.WriteLine("  {0,-23} : {1}", "DefaultDomainName", DefaultDomainName);
            }

            string DefaultUserName = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultUserName");
            if (DefaultUserName != "")
            {
                Console.WriteLine("  {0,-23} : {1}", "DefaultUserName", DefaultUserName);
            }

            string DefaultPassword = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultPassword");
            if (DefaultPassword != "")
            {
                Console.WriteLine("  {0,-23} : {1}", "DefaultPassword", DefaultPassword);
            }

            string AltDefaultDomainName = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "AltDefaultDomainName");
            if (AltDefaultDomainName != "")
            {
                Console.WriteLine("  {0,-23} : {1}", "AltDefaultDomainName", AltDefaultDomainName);
            }

            string AltDefaultUserName = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "AltDefaultUserName");
            if (AltDefaultDomainName != "")
            {
                Console.WriteLine("  {0,-23} : {1}", "AltDefaultUserName", AltDefaultUserName);
            }

            string AltDefaultPassword = GetRegValue("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "AltDefaultPassword");
            if (AltDefaultDomainName != "")
            {
                Console.WriteLine("  {0,-23} : {1}", "AltDefaultPassword", AltDefaultPassword);
            }
        }

        public static void ListRegistryAutoRuns()
        {
            Console.WriteLine("\r\n\r\n=== Registry Autoruns ===");

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
                    Console.WriteLine("\r\n  HKLM:\\{0} :", autorunLocation);
                    foreach (KeyValuePair<string, object> kvp in settings)
                    {
                        Console.WriteLine("    {0}", kvp.Value);
                    }
                }
            }
        }

        public static void ListRDPSessions()
        {
            // adapted from http://www.pinvoke.net/default.aspx/wtsapi32.wtsenumeratesessions
            IntPtr server = IntPtr.Zero;
            List<String> ret = new List<string>();
            server = OpenServer("localhost");

            Console.WriteLine("\r\n\r\n=== Current Host RDP Sessions (qwinsta) ===\r\n");

            try
            {
                IntPtr ppSessionInfo = IntPtr.Zero;

                Int32 count = 0;
                Int32 level = 1;
                Int32 retval = WTSEnumerateSessionsEx(server, ref level, 0, ref ppSessionInfo, ref count);
                Int32 dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO_1));
                Int64 current = (Int64)ppSessionInfo;

                if (retval != 0)
                {
                    for (int i = 0; i < count; i++)
                    {
                        WTS_SESSION_INFO_1 si = (WTS_SESSION_INFO_1)Marshal.PtrToStructure((System.IntPtr)current, typeof(WTS_SESSION_INFO_1));
                        current += dataSize;

                        Console.WriteLine("  SessionID:       {0}", si.SessionID);
                        Console.WriteLine("  SessionName:     {0}", si.pSessionName);
                        Console.WriteLine("  UserName:        {0}", si.pUserName);
                        Console.WriteLine("  DomainName:      {0}", si.pDomainName);
                        Console.WriteLine("  State:           {0}", si.State);

                        // Now use WTSQuerySessionInformation to get the remote IP (if any) for the connection
                        IntPtr addressPtr = IntPtr.Zero;
                        uint bytes = 0;

                        WTSQuerySessionInformation(server, (uint)si.SessionID, WTS_INFO_CLASS.WTSClientAddress, out addressPtr, out bytes);
                        WTS_CLIENT_ADDRESS address = (WTS_CLIENT_ADDRESS)Marshal.PtrToStructure((System.IntPtr)addressPtr, typeof(WTS_CLIENT_ADDRESS));

                        if (address.Address[2] != 0)
                        {
                            string sourceIP = String.Format("{0}.{1}.{2}.{3}", address.Address[2], address.Address[3], address.Address[4], address.Address[5]);
                            Console.WriteLine("  SourceIP:        {0}\r\n", sourceIP);
                        }
                        else
                        {
                            Console.WriteLine("  SourceIP: \r\n");
                        }
                    }

                    WTSFreeMemory(ppSessionInfo);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            finally
            {
                CloseServer(server);
            }
        }

        public static void ListFirewallRules()
        {
            // lists local firewall policies and rules
            //      by default, only "deny" result are output unless "full" is passed

            if (FilterResults.filter)
            {
                Console.WriteLine("\r\n\r\n=== Firewall Rules (Deny) ===\r\n");
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== Firewall Rules (All) ===\r\n");
            }

            try
            {
                // GUID for HNetCfg.FwPolicy2 COM object
                Type firewall = Type.GetTypeFromCLSID(new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD"));
                Object firewallObj = Activator.CreateInstance(firewall);
                Object types = firewallObj.GetType().InvokeMember("CurrentProfileTypes", BindingFlags.GetProperty, null, firewallObj, null);

                Console.WriteLine("  Current Profile(s)          : {0}\r\n", (FirewallProfiles)Int32.Parse(types.ToString()));

                // NET_FW_PROFILE2_DOMAIN = 1, NET_FW_PROFILE2_PRIVATE = 2, NET_FW_PROFILE2_PUBLIC = 4
                Object enabledDomain = firewallObj.GetType().InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, firewallObj, new object[] { 1 });
                Console.WriteLine("  FirewallEnabled (Domain)    : {0}", enabledDomain);
                Object enabledPrivate = firewallObj.GetType().InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, firewallObj, new object[] { 2 });
                Console.WriteLine("  FirewallEnabled (Private)   : {0}", enabledPrivate);
                Object enabledPublic = firewallObj.GetType().InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, firewallObj, new object[] { 4 });
                Console.WriteLine("  FirewallEnabled (Public)    : {0}\r\n", enabledPublic);

                // now grab all the rules
                Object rules = firewallObj.GetType().InvokeMember("Rules", BindingFlags.GetProperty, null, firewallObj, null);

                // manually get the enumerator() method
                System.Collections.IEnumerator enumerator = (System.Collections.IEnumerator)rules.GetType().InvokeMember("GetEnumerator", BindingFlags.InvokeMethod, null, rules, null);

                // move to the first item
                enumerator.MoveNext();
                Object currentItem = enumerator.Current;

                while (currentItem != null)
                {
                    // only display enabled rules
                    Object Enabled = currentItem.GetType().InvokeMember("Enabled", BindingFlags.GetProperty, null, currentItem, null);
                    if (Enabled.ToString() == "True")
                    {
                        Object Action = currentItem.GetType().InvokeMember("Action", BindingFlags.GetProperty, null, currentItem, null);
                        if ((FilterResults.filter && (Action.ToString() == "0")) || !FilterResults.filter)
                        {
                            // extract all of our fields
                            Object Name = currentItem.GetType().InvokeMember("Name", BindingFlags.GetProperty, null, currentItem, null);
                            Object Description = currentItem.GetType().InvokeMember("Description", BindingFlags.GetProperty, null, currentItem, null);
                            Object Protocol = currentItem.GetType().InvokeMember("Protocol", BindingFlags.GetProperty, null, currentItem, null);
                            Object ApplicationName = currentItem.GetType().InvokeMember("ApplicationName", BindingFlags.GetProperty, null, currentItem, null);
                            Object LocalAddresses = currentItem.GetType().InvokeMember("LocalAddresses", BindingFlags.GetProperty, null, currentItem, null);
                            Object LocalPorts = currentItem.GetType().InvokeMember("LocalPorts", BindingFlags.GetProperty, null, currentItem, null);
                            Object RemoteAddresses = currentItem.GetType().InvokeMember("RemoteAddresses", BindingFlags.GetProperty, null, currentItem, null);
                            Object RemotePorts = currentItem.GetType().InvokeMember("RemotePorts", BindingFlags.GetProperty, null, currentItem, null);
                            Object Direction = currentItem.GetType().InvokeMember("Direction", BindingFlags.GetProperty, null, currentItem, null);
                            Object Profiles = currentItem.GetType().InvokeMember("Profiles", BindingFlags.GetProperty, null, currentItem, null);

                            string ruleAction = "ALLOW";
                            if (Action.ToString() != "1")
                            {
                                ruleAction = "DENY";
                            }

                            string ruleDirection = "IN";
                            if (Direction.ToString() != "1")
                            {
                                ruleDirection = "OUT";
                            }

                            string ruleProtocol = "TCP";
                            if (Protocol.ToString() != "6")
                            {
                                ruleProtocol = "UDP";
                            }
                            // TODO: other protocols!

                            Console.WriteLine("  Name                 : {0}", Name);
                            Console.WriteLine("  Description          : {0}", Description);
                            Console.WriteLine("  ApplicationName      : {0}", ApplicationName);
                            Console.WriteLine("  Protocol             : {0}", ruleProtocol);
                            Console.WriteLine("  Action               : {0}", ruleAction);
                            Console.WriteLine("  Direction            : {0}", ruleDirection);
                            Console.WriteLine("  Profiles             : {0}", (FirewallProfiles)Int32.Parse(Profiles.ToString()));
                            Console.WriteLine("  Local Addr:Port      : {0}:{1}", LocalAddresses, LocalPorts);
                            Console.WriteLine("  Remote Addr:Port     : {0}:{1}\r\n", RemoteAddresses, RemotePorts);
                        }
                    }
                    // manually move the enumerator
                    enumerator.MoveNext();
                    currentItem = enumerator.Current;
                }
                Marshal.ReleaseComObject(firewallObj);
                firewallObj = null;
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex);
            }
        }

        public static void ListDNSCache()
        {
            Console.WriteLine("\r\n\r\n=== DNS Cache (via WMI) ===\r\n");

            // lists the local DNS cache via WMI (MSFT_DNSClientCache class)
            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\standardcimv2", "SELECT * FROM MSFT_DNSClientCache");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    Console.WriteLine("  Entry         : {0}", result["Entry"]);
                    Console.WriteLine("  Name          : {0}", result["Name"]);
                    Console.WriteLine("  Data          : {0}\r\n", result["Data"]);
                }
            }
            catch (ManagementException ex) when (ex.ErrorCode == ManagementStatus.InvalidNamespace)
            {
                Console.WriteLine("  [X] 'MSFT_DNSClientCache' WMI class unavailable (minimum supported versions of Windows: 8/2012)", ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListARPTable()
        {
            // adapted from Fred's code at https://social.technet.microsoft.com/Forums/lync/en-US/e949b8d6-17ad-4afc-88cd-0019a3ac9df9/powershell-alternative-to-arp-a?forum=ITCG

            Console.WriteLine("\r\n\r\n=== Current ARP Table ===");

            try
            {
                Dictionary<int, string> adapters = new Dictionary<int, string>();
                Dictionary<string, string> hostNames = new Dictionary<string, string>();

                // build a mapping of index -> interface information
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni != null)
                    {
                        IPInterfaceProperties adapterProperties = ni.GetIPProperties();
                        if (adapterProperties != null)
                        {
                            string dnsServers = "";
                            List<string> dnsServerList = new List<string>();
                            IPAddressCollection dnsServerCollection = adapterProperties.DnsAddresses;
                            if (dnsServerCollection.Count > 0)
                            {
                                foreach (IPAddress dns in dnsServerCollection)
                                {
                                    dnsServerList.Add(dns.ToString());
                                }
                                dnsServers = String.Join(", ", dnsServerList.ToArray());
                            }

                            try
                            {
                                IPv4InterfaceProperties p = adapterProperties.GetIPv4Properties();
                                if (p != null)
                                {
                                    ArrayList ips = new ArrayList();

                                    foreach (UnicastIPAddressInformation info in adapterProperties.UnicastAddresses)
                                    {
                                        if (Regex.IsMatch(info.Address.ToString(), @"^(\d+)\.(\d+)\.(\d+)\.(\d+)$"))
                                        {
                                            // grab all the IPv4 addresses
                                            ips.Add(info.Address.ToString());
                                        }
                                    }
                                    // build a "Ethernet1 (172.16.213.246) --- Index 8" type string for the index
                                    string description = String.Format("{0} ({1}) --- Index {2}", ni.Name, string.Join(",", (string[])ips.ToArray(Type.GetType("System.String"))), p.Index);
                                    if (!String.IsNullOrEmpty(dnsServers))
                                    {
                                        description += String.Format("\r\n    DNS Servers : {0}\r\n", dnsServers);
                                    }
                                    adapters.Add(p.Index, description);
                                }
                            }
                            catch { }
                        }
                    }
                }

                int bytesNeeded = 0;

                int result = GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);

                // call the function, expecting an insufficient buffer.
                if (result != ERROR_INSUFFICIENT_BUFFER)
                {
                    Console.WriteLine("  [X] Exception: {0}", result);
                }

                IntPtr buffer = IntPtr.Zero;

                // allocate sufficient memory for the result structure
                buffer = Marshal.AllocCoTaskMem(bytesNeeded);

                result = GetIpNetTable(buffer, ref bytesNeeded, false);

                if (result != 0)
                {
                    Console.WriteLine("  [X] Exception allocating buffer: {0}", result);
                }

                // now we have the buffer, we have to marshal it. We can read the first 4 bytes to get the length of the buffer
                int entries = Marshal.ReadInt32(buffer);

                // increment the memory pointer by the size of the int
                IntPtr currentBuffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(typeof(int)));

                // allocate a list of entries
                List<MIB_IPNETROW> arpEntries = new List<MIB_IPNETROW>();

                // cycle through the entries
                for (int index = 0; index < entries; index++)
                {
                    arpEntries.Add((MIB_IPNETROW)Marshal.PtrToStructure(new IntPtr(currentBuffer.ToInt64() + (index * Marshal.SizeOf(typeof(MIB_IPNETROW)))), typeof(MIB_IPNETROW)));
                }

                // sort the list by interface index
                List<MIB_IPNETROW> sortedARPEntries = arpEntries.OrderBy(o => o.dwIndex).ToList();
                int currentIndexAdaper = -1;

                foreach (MIB_IPNETROW arpEntry in sortedARPEntries)
                {
                    int indexAdapter = arpEntry.dwIndex;

                    if (currentIndexAdaper != indexAdapter)
                    {
                        if (adapters.ContainsKey(indexAdapter))
                        {
                            Console.WriteLine("\r\n\r\n  Interface     : {0}", adapters[indexAdapter]);
                        }
                        else
                        {
                            Console.WriteLine("\r\n\r\n  Interface     : n/a --- Index {0}", indexAdapter);
                        }
                        Console.WriteLine("    Internet Address      Physical Address      Type");
                        currentIndexAdaper = indexAdapter;
                    }

                    IPAddress ipAddr = new IPAddress(BitConverter.GetBytes(arpEntry.dwAddr));
                    byte[] macBytes = new byte[] { arpEntry.mac0, arpEntry.mac1, arpEntry.mac2, arpEntry.mac3, arpEntry.mac4, arpEntry.mac5 };
                    string physAddr = BitConverter.ToString(macBytes);
                    ArpEntryType entryType = (ArpEntryType)arpEntry.dwType;

                    Console.WriteLine(String.Format("    {0,-22}{1,-22}{2}", ipAddr, physAddr, entryType));
                }

                FreeMibTable(buffer);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex);
            }
        }

        // helper that gets a service name from a service tag
        private static string GetServiceNameFromTag(uint ProcessId, uint ServiceTag)
        {
            SC_SERVICE_TAG_QUERY serviceTagQuery = new SC_SERVICE_TAG_QUERY
            {
                ProcessId = ProcessId,
                ServiceTag = ServiceTag
            };

            uint res = I_QueryTagInformation(IntPtr.Zero, SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, ref serviceTagQuery);
            if (res == ERROR_SUCCESS)
            {
                return Marshal.PtrToStringUni(serviceTagQuery.Buffer);
            }
            else
            {
                return null;
            }
        }

        public static void ListAllTcpConnections()
        {
            int AF_INET = 2;    // IP_v4
            uint tableBufferSize = 0;
            uint ret = 0;
            IntPtr tableBuffer = IntPtr.Zero;
            IntPtr rowPtr = IntPtr.Zero;
            MIB_TCPTABLE_OWNER_MODULE ownerModuleTable;
            MIB_TCPROW_OWNER_MODULE[] TcpRows;
            Dictionary<string, string> processes = new Dictionary<string, string>();

            Console.WriteLine("\r\n\r\n=== Active TCP Network Connections ===\r\n");

            try
            {
                // Adapted from https://stackoverflow.com/questions/577433/which-pid-listens-on-a-given-port-in-c-sharp/577660#577660
                // Build a PID -> process name lookup table
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
                ManagementObjectCollection retObjectCollection = searcher.Get();

                foreach (ManagementObject Process in retObjectCollection)
                {
                    if (Process["CommandLine"] != null)
                    {
                        processes.Add(Process["ProcessId"].ToString(), Process["CommandLine"].ToString());
                    }
                    else
                    {
                        processes.Add(Process["ProcessId"].ToString(), Process["Name"].ToString());
                    }
                }

                // Figure out how much memory we need for the result struct
                ret = GetExtendedTcpTable(IntPtr.Zero, ref tableBufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 0);
                if (ret != ERROR_SUCCESS && ret != ERROR_INSUFFICIENT_BUFFER)
                {
                    // 122 == insufficient buffer size
                    Console.WriteLine(" [X] Bad check value from GetExtendedTcpTable : {0}", ret);
                    return;
                }

                tableBuffer = Marshal.AllocHGlobal((int)tableBufferSize);

                ret = GetExtendedTcpTable(tableBuffer, ref tableBufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 0);
                if (ret != ERROR_SUCCESS)
                {
                    Console.WriteLine(" [X] Bad return value from GetExtendedTcpTable : {0}", ret);
                    return;
                }

                // get the number of entries in the table
                ownerModuleTable = (MIB_TCPTABLE_OWNER_MODULE)Marshal.PtrToStructure(tableBuffer, typeof(MIB_TCPTABLE_OWNER_MODULE));
                rowPtr = (IntPtr)(tableBuffer.ToInt64() + Marshal.OffsetOf(typeof(MIB_TCPTABLE_OWNER_MODULE), "Table").ToInt64());
                TcpRows = new MIB_TCPROW_OWNER_MODULE[ownerModuleTable.NumEntries];

                for (int i = 0; i < ownerModuleTable.NumEntries; i++)
                {
                    MIB_TCPROW_OWNER_MODULE tcpRow =
                        (MIB_TCPROW_OWNER_MODULE)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_MODULE));
                    TcpRows[i] = tcpRow;
                    // next entry
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));
                }

                Console.WriteLine("  Local Address          Foreign Address        State      PID   Service         ProcessName");
                foreach (MIB_TCPROW_OWNER_MODULE entry in TcpRows)
                {
                    string processName = "";
                    try
                    {
                        processName = processes[entry.OwningPid.ToString()];
                    }
                    catch { }

                    string serviceName = GetServiceNameFromTag(entry.OwningPid, (uint)entry.OwningModuleInfo0);

                    Console.WriteLine(String.Format("  {0,-23}{1,-23}{2,-11}{3,-6}{4,-15} {5}", entry.LocalAddress + ":" + entry.LocalPort, entry.RemoteAddress + ":" + entry.RemotePort, entry.State, entry.OwningPid, serviceName, processName));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
            finally
            {
                if (tableBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tableBuffer);
                }
            }
        }

        public static void ListAllUdpConnections()
        {
            int AF_INET = 2;    // IP_v4
            uint tableBufferSize = 0;
            uint ret = 0;
            IntPtr tableBuffer = IntPtr.Zero;
            IntPtr rowPtr = IntPtr.Zero;
            MIB_UDPTABLE_OWNER_MODULE ownerModuleTable;
            MIB_UDPROW_OWNER_MODULE[] UdpRows;
            Dictionary<string, string> processes = new Dictionary<string, string>();

            Console.WriteLine("\r\n\r\n=== Active UDP Network Connections ===\r\n");

            try
            {
                // Adapted from https://stackoverflow.com/questions/577433/which-pid-listens-on-a-given-port-in-c-sharp/577660#577660
                // Build a PID -> process name lookup table
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
                ManagementObjectCollection retObjectCollection = searcher.Get();

                foreach (ManagementObject Process in retObjectCollection)
                {
                    if (Process["CommandLine"] != null)
                    {
                        processes.Add(Process["ProcessId"].ToString(), Process["CommandLine"].ToString());
                    }
                    else
                    {
                        processes.Add(Process["ProcessId"].ToString(), Process["Name"].ToString());
                    }
                }

                // Figure out how much memory we need for the result struct
                ret = GetExtendedUdpTable(IntPtr.Zero, ref tableBufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, 0);
                if (ret != ERROR_SUCCESS && ret != ERROR_INSUFFICIENT_BUFFER)
                {
                    // 122 == insufficient buffer size
                    Console.WriteLine(" [X] Bad check value from GetExtendedUdpTable : {0}", ret);
                    return;
                }

                tableBuffer = Marshal.AllocHGlobal((int)tableBufferSize);

                ret = GetExtendedUdpTable(tableBuffer, ref tableBufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, 0);
                if (ret != ERROR_SUCCESS)
                {
                    Console.WriteLine(" [X] Bad return value from GetExtendedUdpTable : {0}", ret);
                    return;
                }

                // get the number of entries in the table
                ownerModuleTable = (MIB_UDPTABLE_OWNER_MODULE)Marshal.PtrToStructure(tableBuffer, typeof(MIB_UDPTABLE_OWNER_MODULE));
                rowPtr = (IntPtr)(tableBuffer.ToInt64() + Marshal.OffsetOf(typeof(MIB_UDPTABLE_OWNER_MODULE), "Table").ToInt64());
                UdpRows = new MIB_UDPROW_OWNER_MODULE[ownerModuleTable.NumEntries];

                for (int i = 0; i < ownerModuleTable.NumEntries; i++)
                {
                    MIB_UDPROW_OWNER_MODULE udpRow =
                        (MIB_UDPROW_OWNER_MODULE)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_MODULE));
                    UdpRows[i] = udpRow;
                    // next entry
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(udpRow));
                }

                Console.WriteLine("  Local Address          PID    Service                 ProcessName");
                foreach (MIB_UDPROW_OWNER_MODULE entry in UdpRows)
                {
                    string processName = "";
                    try
                    {
                        processName = processes[entry.OwningPid.ToString()];
                    }
                    catch { }
                    
                    string serviceName = GetServiceNameFromTag(entry.OwningPid, (uint)entry.OwningModuleInfo0);

                    Console.WriteLine(String.Format("  {0,-23}{1,-7}{2,-23} {3}", entry.LocalAddress + ":" + entry.LocalPort, entry.OwningPid, serviceName, processName));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
            finally
            {
                if (tableBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tableBuffer);
                }
            }
        }

        public static void ListNonstandardProcesses()
        {
            // lists currently running processes that don't have "Microsoft Corporation" as the company name in their file info
            //      or all processes if "full" is passed

            if (FilterResults.filter)
            {
                Console.WriteLine("\r\n\r\n=== Non Microsoft Processes (via WMI) ===\r\n");
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== All Processes (via WMI) ===\r\n");
            }

            try
            {
                var wmiQueryString = "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process";
                using (var searcher = new ManagementObjectSearcher(wmiQueryString))
                using (var results = searcher.Get())
                {
                    var query = from p in Process.GetProcesses()
                                join mo in results.Cast<ManagementObject>()
                                on p.Id equals (int)(uint)mo["ProcessId"]
                                select new
                                {
                                    Process = p,
                                    Path = (string)mo["ExecutablePath"],
                                    CommandLine = (string)mo["CommandLine"],
                                };
                    foreach (var item in query)
                    {
                        //OLD -  if ((item.Path != null) && ((!FilterResults.filter) || (!Regex.IsMatch(item.Path, "C:\\\\WINDOWS\\\\", RegexOptions.IgnoreCase))))
                        if ((item.Path != null)) {
                            FileVersionInfo myFileVersionInfo = FileVersionInfo.GetVersionInfo(item.Path);
                            string companyName = myFileVersionInfo.CompanyName;
                            if ((String.IsNullOrEmpty(companyName)) || (!FilterResults.filter) || (!Regex.IsMatch(companyName, @"^Microsoft.*", RegexOptions.IgnoreCase)))
                            {
                                bool isDotNet = false;
                                try
                                {
                                    AssemblyName myAssemblyName = AssemblyName.GetAssemblyName(item.Path);
                                    isDotNet = true;
                                }
                                catch (System.IO.FileNotFoundException)
                                {
                                    // System.Console.WriteLine("The file cannot be found.");
                                }
                                catch (System.BadImageFormatException exception)
                                {
                                    if (Regex.IsMatch(exception.Message, ".*This assembly is built by a runtime newer than the currently loaded runtime and cannot be loaded.*", RegexOptions.IgnoreCase))
                                    {
                                        isDotNet = true;
                                    }
                                }
                                catch
                                {
                                    // System.Console.WriteLine("The assembly has already been loaded.");
                                }

                                Console.WriteLine("  Name           : {0}", item.Process.ProcessName);
                                Console.WriteLine("  Company Name   : {0}", companyName);
                                Console.WriteLine("  PID            : {0}", item.Process.Id);
                                Console.WriteLine("  Path           : {0}", item.Path);
                                Console.WriteLine("  CommandLine    : {0}", item.CommandLine);
                                Console.WriteLine("  IsDotNet       : {0}\r\n", isDotNet);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }


        // elevated system checks
        public static void List4624Events()
        {
            var eventId = "4624";

            // grab events from the last X days - 7 for default, 30 for "full" collection
            int lastDays = 7;

            if (!FilterResults.filter)
            {
                lastDays = 30;
            }

            var startTime = System.DateTime.Now.AddDays(-lastDays);
            var endTime = System.DateTime.Now;

            Console.WriteLine("\r\n\r\n=== 4624 Account Logon Events (last {0} days) ===\r\n", lastDays);

            var query = string.Format(@"*[System/EventID={0}] and *[System[TimeCreated[@SystemTime >= '{1}']]] and *[System[TimeCreated[@SystemTime <= '{2}']]]",
                eventId,
                startTime.ToUniversalTime().ToString("o"),
                endTime.ToUniversalTime().ToString("o"));

            EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
            eventsQuery.ReverseDirection = true;

            try
            {
                EventLogReader logReader = new EventLogReader(eventsQuery);

                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    //string SubjectUserSid = eventdetail.Properties[0].Value.ToString();
                    //string SubjectUserName = eventdetail.Properties[1].Value.ToString();
                    //string SubjectDomainName = eventdetail.Properties[2].Value.ToString();
                    //string SubjectLogonId = eventdetail.Properties[3].Value.ToString();
                    string TargetUserSid = eventdetail.Properties[4].Value.ToString();
                    string TargetUserName = eventdetail.Properties[5].Value.ToString();
                    string TargetDomainName = eventdetail.Properties[6].Value.ToString();
                    //string TargetLogonId = eventdetail.Properties[7].Value.ToString();
                    //string LogonType = eventdetail.Properties[8].Value.ToString();
                    string LogonType = String.Format("{0}", (SECURITY_LOGON_TYPE)(Int32.Parse(eventdetail.Properties[8].Value.ToString())));
                    //string LogonProcessName = eventdetail.Properties[9].Value.ToString();
                    string AuthenticationPackageName = eventdetail.Properties[10].Value.ToString();
                    string WorkstationName = eventdetail.Properties[11].Value.ToString();
                    //string LogonGuid = eventdetail.Properties[12].Value.ToString();
                    //string TransmittedServices = eventdetail.Properties[13].Value.ToString();
                    string LmPackageName = eventdetail.Properties[14].Value.ToString();
                    //string KeyLength = eventdetail.Properties[15].Value.ToString();
                    //string ProcessId = eventdetail.Properties[16].Value.ToString();
                    string ProcessName = eventdetail.Properties[17].Value.ToString();
                    //string IpAddress = eventdetail.Properties[18].Value.ToString();
                    //string IpPort = eventdetail.Properties[19].Value.ToString();
                    //string ImpersonationLevel = eventdetail.Properties[20].Value.ToString();
                    //string RestrictedAdminMode = eventdetail.Properties[21].Value.ToString();
                    //string TargetOutboundUserName = eventdetail.Properties[22].Value.ToString();
                    //string TargetOutboundDomainName = eventdetail.Properties[23].Value.ToString();
                    //string VirtualAccount = eventdetail.Properties[24].Value.ToString();
                    //string TargetLinkedLogonId = eventdetail.Properties[25].Value.ToString();
                    //string ElevatedToken = eventdetail.Properties[26].Value.ToString();

                    // filter out SYSTEM, computer accounts, local service accounts, UMFD-X accounts, and DWM-X accounts (for now)
                    Regex ignoreRegex = new Regex(@"SYSTEM|\$$|LOCAL SERVICE|NETWORK SERVICE|UMFD-[0-9]+|DWM-[0-9]+|ANONYMOUS LOGON");
                    Match m = ignoreRegex.Match(TargetUserName);
                    if (!m.Success)
                    {
                        Console.WriteLine("  UserName          : {0}", TargetUserName);
                        Console.WriteLine("  UserDomain        : {0}", TargetDomainName);
                        Console.WriteLine("  UserSID           : {0}", TargetUserSid);
                        Console.WriteLine("  ProcessName       : {0}", ProcessName);
                        Console.WriteLine("  LogonType         : {0}", LogonType);
                        Console.WriteLine("  AuthPKG           : {0}", AuthenticationPackageName);
                        Console.WriteLine("  LmPackageName     : {0}", LmPackageName);
                        Console.WriteLine("  WorkstationName   : {0}", WorkstationName);
                        Console.WriteLine("  TimeCreated       : {0}\r\n", eventdetail.TimeCreated.ToString());

                        //Console.WriteLine(eventdetail.FormatDescription());
                        //break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void List4648Events()
        {
            var eventId = "4648";

            // grab events from the last X days - 7 for default, 30 for "full" collection
            int lastDays = 7;

            if (!FilterResults.filter)
            {
                lastDays = 30;
            }

            var startTime = System.DateTime.Now.AddDays(-lastDays);
            var endTime = System.DateTime.Now;

            Console.WriteLine("\r\n\r\n=== 4624 Explicit Credential Events (last {0} days) - Runas or Outbound RDP ===\r\n", lastDays);


            var query = string.Format(@"*[System/EventID={0}] and *[System[TimeCreated[@SystemTime >= '{1}']]] and *[System[TimeCreated[@SystemTime <= '{2}']]]",
                eventId,
                startTime.ToUniversalTime().ToString("o"),
                endTime.ToUniversalTime().ToString("o"));

            EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
            eventsQuery.ReverseDirection = true;

            try
            {
                EventLogReader logReader = new EventLogReader(eventsQuery);

                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    string SubjectUserSid = eventdetail.Properties[0].Value.ToString();
                    string SubjectUserName = eventdetail.Properties[1].Value.ToString();
                    string SubjectDomainName = eventdetail.Properties[2].Value.ToString();
                    //string SubjectLogonId = eventdetail.Properties[3].Value.ToString();
                    //string LogonGuid = eventdetail.Properties[4].Value.ToString();
                    string TargetUserName = eventdetail.Properties[5].Value.ToString();
                    string TargetDomainName = eventdetail.Properties[6].Value.ToString();
                    //string TargetLogonGuid = eventdetail.Properties[7].Value.ToString();
                    string TargetServerName = eventdetail.Properties[8].Value.ToString();
                    //string TargetInfo = eventdetail.Properties[9].Value.ToString();
                    //string ProcessId = eventdetail.Properties[10].Value.ToString();
                    string ProcessName = eventdetail.Properties[11].Value.ToString();
                    //string IpAddress = eventdetail.Properties[12].Value.ToString();
                    //string IpPort = eventdetail.Properties[13].Value.ToString();

                    // filter out accounts (for now)
                    Regex ignoreRegex = new Regex(@"\$$");
                    Match m = ignoreRegex.Match(SubjectUserName);
                    if (!m.Success)
                    {
                        Console.WriteLine("  SubjectUserName        : {0}", SubjectUserName);
                        Console.WriteLine("  SubjectDomainName      : {0}", SubjectDomainName);
                        Console.WriteLine("  SubjectUserSid         : {0}", SubjectUserSid);
                        Console.WriteLine("  TargetUserName         : {0}", TargetUserName);
                        Console.WriteLine("  TargetDomainName       : {0}", TargetDomainName);
                        Console.WriteLine("  TargetServerName       : {0}", TargetServerName);
                        Console.WriteLine("  ProcessName            : {0}", ProcessName);
                        Console.WriteLine("  TimeCreated            : {0}\r\n", eventdetail.TimeCreated.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListSysmonConfig()
        {
            Console.WriteLine("\r\n\r\n=== Sysmon Configuration ===\r\n");

            string hashing = GetRegValue("HKLM", "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "HashingAlgorithm");
            if (!String.IsNullOrEmpty(hashing))
            {
                Console.WriteLine("  Hashing algorithm: {0}", hashing);
            }

            string options = GetRegValue("HKLM", "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "Options");
            if (!String.IsNullOrEmpty(options))
            {
                Console.WriteLine("  Options: {0}", options);
            }

            byte[] sysmonRules = GetRegValueBytes("HKLM", "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "Rules");
            if (sysmonRules != null)
            {
                Console.WriteLine("  Sysmon rules: " + Convert.ToBase64String(sysmonRules));
            }
        }


        // user-focused checks
        public static void ListCurrentDomainGroups()
        {
            try
            {
                Console.WriteLine("\r\n\r\n=== Current User's Groups ===\r\n");

                WindowsIdentity wi = WindowsIdentity.GetCurrent();
                List<string> groups = new List<string>();

                foreach (IdentityReference group in wi.Groups)
                {
                    try
                    {
                        groups.Add(group.Translate(typeof(NTAccount)).ToString());
                    }
                    catch { }
                }
                groups.Sort();
                foreach (string group in groups)
                {
                    Console.WriteLine("  {0}", group);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListSavedRDPConnections()
        {
            //shows saved RDP connections, including username hints (if present)

            if (IsHighIntegrity())
            {
                string[] SIDs = Registry.Users.GetSubKeyNames();
                foreach (string SID in SIDs)
                {
                    if (SID.StartsWith("S-1-5") && !SID.EndsWith("_Classes"))
                    {
                        string[] subkeys = GetRegSubkeys("HKU", String.Format("{0}\\Software\\Microsoft\\Terminal Server Client\\Servers", SID));
                        if (subkeys != null)
                        {
                            Console.WriteLine("\r\n\r\n=== Saved RDP Connection Information ({0}) ===", SID);
                            foreach (string host in subkeys)
                            {
                                string usernameHint = GetRegValue("HKCU", String.Format("Software\\Microsoft\\Terminal Server Client\\Servers\\{0}", host), "UsernameHint");
                                Console.WriteLine("\r\n  Host           : {0}", host);
                                if (usernameHint != "")
                                {
                                    Console.WriteLine("    UsernameHint : {0}", usernameHint);
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== Saved RDP Connection Information (Current User) ===");
                string[] subkeys = GetRegSubkeys("HKCU", "Software\\Microsoft\\Terminal Server Client\\Servers");
                if (subkeys != null)
                {
                    foreach (string host in subkeys)
                    {
                        string usernameHint = GetRegValue("HKCU", String.Format("Software\\Microsoft\\Terminal Server Client\\Servers\\{0}", host), "UsernameHint");
                        Console.WriteLine("\r\n  Host           : {0}", host);
                        if (usernameHint != "")
                        {
                            Console.WriteLine("    UsernameHint : {0}", usernameHint);
                        }
                    }
                }
            }
        }

        public static void ListMasterKeys()
        {
            // lists any found DPAPI master keys
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for DPAPI Master Keys (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userDPAPIBasePath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Protect\\", dir);
                            if (System.IO.Directory.Exists(userDPAPIBasePath))
                            {
                                string[] directories = Directory.GetDirectories(userDPAPIBasePath);
                                foreach (string directory in directories)
                                {
                                    string[] files = Directory.GetFiles(directory);

                                    Console.WriteLine("    Folder       : {0}\r\n", directory);

                                    foreach (string file in files)
                                    {
                                        if (Regex.IsMatch(file, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                        {
                                            DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                                            DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                                            string fileName = System.IO.Path.GetFileName(file);
                                            Console.WriteLine("    MasterKey    : {0}", fileName);
                                            Console.WriteLine("        Accessed : {0}", lastAccessed);
                                            Console.WriteLine("        Modified : {0}\r\n", lastModified);
                                        }
                                    }
                                    Console.WriteLine();
                                }
                            }
                        }
                    }
                    Console.WriteLine("  [*] Use the Mimikatz \"dpapi::masterkey\" module with appropriate arguments (/pvk or /rpc) to decrypt");
                    Console.WriteLine("  [*] You can also extract many DPAPI masterkeys from memory with the Mimikatz \"sekurlsa::dpapi\" module");
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for DPAPI Master Keys (Current User) ===\r\n");
                    string userName = Environment.GetEnvironmentVariable("USERNAME");
                    string userDPAPIBasePath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Protect\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    if (System.IO.Directory.Exists(userDPAPIBasePath))
                    {
                        string[] directories = Directory.GetDirectories(userDPAPIBasePath);
                        foreach (string directory in directories)
                        {
                            string[] files = Directory.GetFiles(directory);

                            Console.WriteLine("    Folder       : {0}\r\n", directory);

                            foreach (string file in files)
                            {
                                if (Regex.IsMatch(file, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                {
                                    DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                                    DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                                    string fileName = System.IO.Path.GetFileName(file);
                                    Console.WriteLine("    MasterKey    : {0}", fileName);
                                    Console.WriteLine("        Accessed : {0}", lastAccessed);
                                    Console.WriteLine("        Modified : {0}\r\n", lastModified);
                                }
                            }
                        }
                    }
                    Console.WriteLine("  [*] Use the Mimikatz \"dpapi::masterkey\" module with appropriate arguments (/rpc) to decrypt");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListCredFiles()
        {
            // lists any found files in Local\Microsoft\Credentials\*
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Credential Files (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    bool found = false;

                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userCredFilePath = String.Format("{0}\\AppData\\Local\\Microsoft\\Credentials\\", dir);
                            if (System.IO.Directory.Exists(userCredFilePath))
                            {
                                string[] systemFiles = Directory.GetFiles(userCredFilePath);
                                if ((systemFiles != null) && (systemFiles.Length != 0))
                                {
                                    Console.WriteLine("\r\n    Folder       : {0}\r\n", userCredFilePath);

                                    foreach (string file in systemFiles)
                                    {
                                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                                        DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                                        long size = new System.IO.FileInfo(file).Length;
                                        string fileName = System.IO.Path.GetFileName(file);
                                        found = true;
                                        Console.WriteLine("    CredFile     : {0}", fileName);

                                        // jankily parse the bytes to extract the credential type and master key GUID
                                        // reference- https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/modules/kull_m_dpapi.h#L24-L54
                                        byte[] credentialArray = File.ReadAllBytes(file);
                                        byte[] guidMasterKeyArray = new byte[16];
                                        Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16);
                                        Guid guidMasterKey = new Guid(guidMasterKeyArray);

                                        byte[] stringLenArray = new byte[16];
                                        Array.Copy(credentialArray, 56, stringLenArray, 0, 4);
                                        int descLen = BitConverter.ToInt32(stringLenArray, 0);

                                        byte[] descBytes = new byte[descLen];
                                        Array.Copy(credentialArray, 60, descBytes, 0, descLen - 4);

                                        string desc = Encoding.Unicode.GetString(descBytes);
                                        Console.WriteLine("    Description  : {0}", desc);
                                        Console.WriteLine("    MasterKey    : {0}", guidMasterKey.ToString());
                                        Console.WriteLine("    Accessed     : {0}", lastAccessed);
                                        Console.WriteLine("    Modified     : {0}", lastModified);
                                        Console.WriteLine("    Size         : {0}\r\n", size);
                                    }
                                }
                            }
                        }
                    }

                    string systemFolder = String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot"));
                    string[] files = Directory.GetFiles(systemFolder);
                    if ((files != null) && (files.Length != 0))
                    {
                        Console.WriteLine("\r\n    Folder       : {0}\r\n", systemFolder);

                        foreach (string file in files)
                        {
                            DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                            DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                            long size = new System.IO.FileInfo(file).Length;
                            string fileName = System.IO.Path.GetFileName(file);
                            found = true;
                            Console.WriteLine("    CredFile     : {0}", fileName);

                            // jankily parse the bytes to extract the credential type and master key GUID
                            // reference- https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/modules/kull_m_dpapi.h#L24-L54
                            byte[] credentialArray = File.ReadAllBytes(file);
                            byte[] guidMasterKeyArray = new byte[16];
                            Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16);
                            Guid guidMasterKey = new Guid(guidMasterKeyArray);

                            byte[] stringLenArray = new byte[16];
                            Array.Copy(credentialArray, 56, stringLenArray, 0, 4);
                            int descLen = BitConverter.ToInt32(stringLenArray, 0);

                            byte[] descBytes = new byte[descLen];
                            Array.Copy(credentialArray, 60, descBytes, 0, descLen - 4);

                            string desc = Encoding.Unicode.GetString(descBytes);
                            Console.WriteLine("    Description  : {0}", desc);
                            Console.WriteLine("    MasterKey    : {0}", guidMasterKey.ToString());
                            Console.WriteLine("    Accessed     : {0}", lastAccessed);
                            Console.WriteLine("    Modified     : {0}", lastModified);
                            Console.WriteLine("    Size         : {0}\r\n", size);
                        }
                    }

                    if (found)
                    {
                        Console.WriteLine("  [*] Use the Mimikatz \"dpapi::cred\" module with appropriate /masterkey to decrypt");
                        Console.WriteLine("  [*] You can extract many DPAPI masterkeys from memory with the Mimikatz \"sekurlsa::dpapi\" module");
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Credential Files (Current User) ===\r\n");
                    string userName = Environment.GetEnvironmentVariable("USERNAME");
                    string userCredFilePath = String.Format("{0}\\AppData\\Local\\Microsoft\\Credentials\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    bool found = false;

                    if (System.IO.Directory.Exists(userCredFilePath))
                    {
                        string[] files = Directory.GetFiles(userCredFilePath);
                        Console.WriteLine("    Folder       : {0}\r\n", userCredFilePath);

                        foreach (string file in files)
                        {
                            DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                            DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                            long size = new System.IO.FileInfo(file).Length;
                            string fileName = System.IO.Path.GetFileName(file);
                            found = true;
                            Console.WriteLine("    CredFile     : {0}", fileName);

                            // jankily parse the bytes to extract the credential type and master key GUID
                            // reference- https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/modules/kull_m_dpapi.h#L24-L54
                            byte[] credentialArray = File.ReadAllBytes(file);
                            byte[] guidMasterKeyArray = new byte[16];
                            Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16);
                            Guid guidMasterKey = new Guid(guidMasterKeyArray);

                            byte[] stringLenArray = new byte[16];
                            Array.Copy(credentialArray, 56, stringLenArray, 0, 4);
                            int descLen = BitConverter.ToInt32(stringLenArray, 0);

                            byte[] descBytes = new byte[descLen];
                            Array.Copy(credentialArray, 60, descBytes, 0, descLen - 4);

                            string desc = Encoding.Unicode.GetString(descBytes);
                            Console.WriteLine("    Description  : {0}", desc);
                            Console.WriteLine("    MasterKey    : {0}", guidMasterKey.ToString());
                            Console.WriteLine("    Accessed     : {0}", lastAccessed);
                            Console.WriteLine("    Modified     : {0}", lastModified);
                            Console.WriteLine("    Size         : {0}\r\n", size);
                        }
                    }
                    if (found)
                    {
                        Console.WriteLine("  [*] Use the Mimikatz \"dpapi::cred\" module with appropriate /masterkey to decrypt");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListRDCManFiles()
        {
            // lists any found files in Local\Microsoft\Credentials\*
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for RDCMan Settings Files (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    bool found = false;

                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userRDManFile = String.Format("{0}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings", dir);
                            if (System.IO.File.Exists(userRDManFile))
                            {
                                XmlDocument xmlDoc = new XmlDocument();
                                xmlDoc.Load(userRDManFile);

                                // grab the recent RDG files
                                XmlNodeList filesToOpen = xmlDoc.GetElementsByTagName("FilesToOpen");
                                XmlNodeList items = filesToOpen[0].ChildNodes;
                                XmlNode node = items[0];

                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(userRDManFile);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(userRDManFile);
                                Console.WriteLine("    RDCManFile   : {0}", userRDManFile);
                                Console.WriteLine("    Accessed     : {0}", lastAccessed);
                                Console.WriteLine("    Modified     : {0}", lastModified);

                                foreach (XmlNode rdgFile in items)
                                {
                                    found = true;
                                    Console.WriteLine("      .RDG File  : {0}", rdgFile.InnerText);
                                }
                                Console.WriteLine();
                            }
                        }
                    }

                    if (found)
                    {
                        Console.WriteLine("  [*] Use the Mimikatz \"dpapi::rdg\" module with appropriate /masterkey to decrypt any .rdg files");
                        Console.WriteLine("  [*] You can extract many DPAPI masterkeys from memory with the Mimikatz \"sekurlsa::dpapi\" module");
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for RDCMan Settings Files (Current User) ===\r\n");
                    bool found = false;
                    string userName = Environment.GetEnvironmentVariable("USERNAME");
                    string userRDManFile = String.Format("{0}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    if (System.IO.File.Exists(userRDManFile))
                    {
                        XmlDocument xmlDoc = new XmlDocument();
                        xmlDoc.Load(userRDManFile);

                        // grab the recent RDG files
                        XmlNodeList filesToOpen = xmlDoc.GetElementsByTagName("FilesToOpen");
                        XmlNodeList items = filesToOpen[0].ChildNodes;
                        XmlNode node = items[0];

                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(userRDManFile);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(userRDManFile);
                        Console.WriteLine("    RDCManFile   : {0}", userRDManFile);
                        Console.WriteLine("    Accessed     : {0}", lastAccessed);
                        Console.WriteLine("    Modified     : {0}", lastModified);

                        foreach (XmlNode rdgFile in items)
                        {
                            found = true;
                            Console.WriteLine("      .RDG File  : {0}", rdgFile.InnerText);
                        }
                        Console.WriteLine();
                    }
                    if (found)
                    {
                        Console.WriteLine("  [*] Use the Mimikatz \"dpapi::rdg\" module with appropriate /masterkey to decrypt any .rdg files");
                        Console.WriteLine("  [*] You can extract many DPAPI masterkeys from memory with the Mimikatz \"sekurlsa::dpapi\" module");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListIETabs()
        {
            // Lists currently open Internet Explorer tabs, via COM
            // Notes:
            //  https://searchcode.com/codesearch/view/9859954/
            //  https://gist.github.com/yizhang82/a1268d3ea7295a8a1496e01d60ada816

            Console.WriteLine("\r\n\r\n=== Internet Explorer Open Tabs ===\r\n");

            try
            {
                // Shell.Application COM GUID
                Type shell = Type.GetTypeFromCLSID(new Guid("13709620-C279-11CE-A49E-444553540000"));

                // actually instantiate the Shell.Application COM object
                Object shellObj = Activator.CreateInstance(shell);

                // grab all the current windows
                Object windows = shellObj.GetType().InvokeMember("Windows", BindingFlags.InvokeMethod, null, shellObj, null);

                // grab the open tab count
                Object openTabs = windows.GetType().InvokeMember("Count", BindingFlags.GetProperty, null, windows, null);
                int openTabsCount = Int32.Parse(openTabs.ToString());

                for (int i = 0; i < openTabsCount; i++)
                {
                    // grab the acutal tab
                    Object item = windows.GetType().InvokeMember("Item", BindingFlags.InvokeMethod, null, windows, new object[] { i });
                    try
                    {
                        // extract the tab properties
                        Object locationName = item.GetType().InvokeMember("LocationName", BindingFlags.GetProperty, null, item, null);
                        Object locationURL = item.GetType().InvokeMember("LocationUrl", BindingFlags.GetProperty, null, item, null);

                        // ensure we have a site address
                        if (Regex.IsMatch(locationURL.ToString(), @"(^https?://.+)|(^ftp://)"))
                        {
                            Console.WriteLine("  Location Name : {0}", locationName);
                            Console.WriteLine("  Location URL  : {0}\r\n", locationURL);
                        }
                        Marshal.ReleaseComObject(item);
                        item = null;
                    }
                    catch
                    {
                        //
                    }
                }
                Marshal.ReleaseComObject(windows);
                windows = null;
                Marshal.ReleaseComObject(shellObj);
                shellObj = null;
            }
            catch (Exception ex2)
            {
                Console.WriteLine("  [X] Exception: {0}", ex2);
            }
        }
        public static void TriageIE()
        {
            // lists Internt explorer history (last 7 days by default) and favorites

            int lastDays = 7;

            if (!FilterResults.filter)
            {
                lastDays = 90;
            }

            DateTime startTime = System.DateTime.Now.AddDays(-lastDays);

            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Internet Explorer (All Users) Last {0} Days ===", lastDays);

                    string[] SIDs = Registry.Users.GetSubKeyNames();
                    foreach (string SID in SIDs)
                    {
                        if (SID.StartsWith("S-1-5") && !SID.EndsWith("_Classes"))
                        {
                            Dictionary<string, object> settings = GetRegValues("HKU", String.Format("{0}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs", SID));
                            if ((settings != null) && (settings.Count > 1))
                            {
                                Console.WriteLine("\r\n  History ({0}):", SID);
                                foreach (KeyValuePair<string, object> kvp in settings)
                                {
                                    byte[] timeBytes = GetRegValueBytes("HKU", String.Format("{0}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLsTime", SID), kvp.Key.ToString().Trim());
                                    if (timeBytes != null)
                                    {
                                        long timeLong = (long)(BitConverter.ToInt64(timeBytes, 0));
                                        DateTime urlTime = DateTime.FromFileTime(timeLong);
                                        if (urlTime > startTime)
                                        {
                                            Console.WriteLine("    {0,-23} :  {1}", urlTime, kvp.Value.ToString().Trim());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userIEBookmarkPath = String.Format("{0}\\Favorites\\", dir);

                            if (Directory.Exists(userIEBookmarkPath))
                            {
                                string[] bookmarkPaths = Directory.GetFiles(userIEBookmarkPath, "*.url", SearchOption.AllDirectories);
                                if (bookmarkPaths.Length != 0)
                                {
                                    Console.WriteLine("\r\n  Favorites ({0}):", userName);

                                    foreach (string bookmarkPath in bookmarkPaths)
                                    {
                                        using (StreamReader rdr = new StreamReader(bookmarkPath))
                                        {
                                            string line;
                                            string url = "";
                                            while ((line = rdr.ReadLine()) != null)
                                            {
                                                if (line.StartsWith("URL=", StringComparison.InvariantCultureIgnoreCase))
                                                {
                                                    if (line.Length > 4)
                                                        url = line.Substring(4);
                                                    break;
                                                }
                                            }
                                            Console.WriteLine("    {0}", url.ToString().Trim());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Internet Explorer (Current User) Last {0} Days ===", lastDays);

                    Console.WriteLine("\r\n  History:");
                    Dictionary<string, object> settings = GetRegValues("HKCU", "SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs");
                    if ((settings != null) && (settings.Count != 0))
                    {
                        foreach (KeyValuePair<string, object> kvp in settings)
                        {
                            byte[] timeBytes = GetRegValueBytes("HKCU", "SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLsTime", kvp.Key.ToString().Trim());
                            if (timeBytes != null)
                            {
                                long timeLong = (long)(BitConverter.ToInt64(timeBytes, 0));
                                DateTime urlTime = DateTime.FromFileTime(timeLong);
                                if (urlTime > startTime)
                                {
                                    Console.WriteLine("    {0,-23} :  {1}", urlTime, kvp.Value.ToString().Trim());
                                }
                            }
                        }
                    }


                    Console.WriteLine("\r\n  Favorites:");
                    string userIEBookmarkPath = String.Format("{0}\\Favorites\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    string[] bookmarkPaths = Directory.GetFiles(userIEBookmarkPath, "*.url", SearchOption.AllDirectories);

                    foreach (string bookmarkPath in bookmarkPaths)
                    {
                        using (StreamReader rdr = new StreamReader(bookmarkPath))
                        {
                            string line;
                            string url = "";
                            while ((line = rdr.ReadLine()) != null)
                            {
                                if (line.StartsWith("URL=", StringComparison.InvariantCultureIgnoreCase))
                                {
                                    if (line.Length > 4)
                                        url = line.Substring(4);
                                    break;
                                }
                            }
                            Console.WriteLine("    {0}", url.ToString().Trim());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex);
            }
        }

        
        public static object GetVaultElementValue(IntPtr vaultElementPtr)
        {
            // Helper function to extract the ItemValue field from a VAULT_ITEM_ELEMENT struct
            // pulled directly from @djhohnstein's SharpWeb project: https://github.com/djhohnstein/SharpWeb/blob/master/Edge/SharpEdge.cs
            object results;
            object partialElement = System.Runtime.InteropServices.Marshal.PtrToStructure(vaultElementPtr, typeof(VaultCli.VAULT_ITEM_ELEMENT));
            FieldInfo partialElementInfo = partialElement.GetType().GetField("Type");
            var partialElementType = partialElementInfo.GetValue(partialElement);

            IntPtr elementPtr = (IntPtr)(vaultElementPtr.ToInt64() + 16);
            switch ((int)partialElementType)
            {
                case 7: // VAULT_ELEMENT_TYPE == String; These are the plaintext passwords!
                    IntPtr StringPtr = System.Runtime.InteropServices.Marshal.ReadIntPtr(elementPtr);
                    results = System.Runtime.InteropServices.Marshal.PtrToStringUni(StringPtr);
                    break;
                case 0: // VAULT_ELEMENT_TYPE == bool
                    results = System.Runtime.InteropServices.Marshal.ReadByte(elementPtr);
                    results = (bool)results;
                    break;
                case 1: // VAULT_ELEMENT_TYPE == Short
                    results = System.Runtime.InteropServices.Marshal.ReadInt16(elementPtr);
                    break;
                case 2: // VAULT_ELEMENT_TYPE == Unsigned Short
                    results = System.Runtime.InteropServices.Marshal.ReadInt16(elementPtr);
                    break;
                case 3: // VAULT_ELEMENT_TYPE == Int
                    results = System.Runtime.InteropServices.Marshal.ReadInt32(elementPtr);
                    break;
                case 4: // VAULT_ELEMENT_TYPE == Unsigned Int
                    results = System.Runtime.InteropServices.Marshal.ReadInt32(elementPtr);
                    break;
                case 5: // VAULT_ELEMENT_TYPE == Double
                    results = System.Runtime.InteropServices.Marshal.PtrToStructure(elementPtr, typeof(Double));
                    break;
                case 6: // VAULT_ELEMENT_TYPE == GUID
                    results = System.Runtime.InteropServices.Marshal.PtrToStructure(elementPtr, typeof(Guid));
                    break;
                case 12: // VAULT_ELEMENT_TYPE == Sid
                    IntPtr sidPtr = System.Runtime.InteropServices.Marshal.ReadIntPtr(elementPtr);
                    var sidObject = new System.Security.Principal.SecurityIdentifier(sidPtr);
                    results = sidObject.Value;
                    break;
                default:
                    /* Several VAULT_ELEMENT_TYPES are currently unimplemented according to
                     * Lord Graeber. Thus we do not implement them. */
                    results = null;
                    break;
            }
            return results;
        }
        public static void DumpVault()
        {
            // pulled directly from @djhohnstein's SharpWeb project: https://github.com/djhohnstein/SharpWeb/blob/master/Edge/SharpEdge.cs
            Console.WriteLine("\r\n\r\n=== Checking Windows Vaults ===");
            var OSVersion = Environment.OSVersion.Version;
            var OSMajor = OSVersion.Major;
            var OSMinor = OSVersion.Minor;

            Type VAULT_ITEM;

            if (OSMajor >= 6 && OSMinor >= 2)
            {
                VAULT_ITEM = typeof(VaultCli.VAULT_ITEM_WIN8);
            }
            else
            {
                VAULT_ITEM = typeof(VaultCli.VAULT_ITEM_WIN7);
            }

            Int32 vaultCount = 0;
            IntPtr vaultGuidPtr = IntPtr.Zero;
            var result = VaultCli.VaultEnumerateVaults(0, ref vaultCount, ref vaultGuidPtr);

            //var result = CallVaultEnumerateVaults(VaultEnum, 0, ref vaultCount, ref vaultGuidPtr);

            if ((int)result != 0)
            {
                Console.WriteLine("  [ERROR] Unable to enumerate vaults. Error (0x" + result.ToString() + ")");
                return;
            }

            // Create dictionary to translate Guids to human readable elements
            IntPtr guidAddress = vaultGuidPtr;
            Dictionary<Guid, string> vaultSchema = new Dictionary<Guid, string>();
            vaultSchema.Add(new Guid("2F1A6504-0641-44CF-8BB5-3612D865F2E5"), "Windows Secure Note");
            vaultSchema.Add(new Guid("3CCD5499-87A8-4B10-A215-608888DD3B55"), "Windows Web Password Credential");
            vaultSchema.Add(new Guid("154E23D0-C644-4E6F-8CE6-5069272F999F"), "Windows Credential Picker Protector");
            vaultSchema.Add(new Guid("4BF4C442-9B8A-41A0-B380-DD4A704DDB28"), "Web Credentials");
            vaultSchema.Add(new Guid("77BC582B-F0A6-4E15-4E80-61736B6F3B29"), "Windows Credentials");
            vaultSchema.Add(new Guid("E69D7838-91B5-4FC9-89D5-230D4D4CC2BC"), "Windows Domain Certificate Credential");
            vaultSchema.Add(new Guid("3E0E35BE-1B77-43E7-B873-AED901B6275B"), "Windows Domain Password Credential");
            vaultSchema.Add(new Guid("3C886FF3-2669-4AA2-A8FB-3F6759A77548"), "Windows Extended Credential");
            vaultSchema.Add(new Guid("00000000-0000-0000-0000-000000000000"), null);

            for (int i = 0; i < vaultCount; i++)
            {
                // Open vault block
                object vaultGuidString = System.Runtime.InteropServices.Marshal.PtrToStructure(guidAddress, typeof(Guid));
                Guid vaultGuid = new Guid(vaultGuidString.ToString());
                guidAddress = (IntPtr)(guidAddress.ToInt64() + System.Runtime.InteropServices.Marshal.SizeOf(typeof(Guid)));
                IntPtr vaultHandle = IntPtr.Zero;
                string vaultType;
                if (vaultSchema.ContainsKey(vaultGuid))
                {
                    vaultType = vaultSchema[vaultGuid];
                }
                else
                {
                    vaultType = vaultGuid.ToString();
                }
                result = VaultCli.VaultOpenVault(ref vaultGuid, (UInt32)0, ref vaultHandle);
                if (result != 0)
                {
                    Console.WriteLine("  [ERROR] Unable to open the following vault: " + vaultType + ". Error: 0x" + result.ToString());
                    return;
                }
                // Vault opened successfully! Continue.


                Console.WriteLine("\r\n  Vault GUID     : {0}", vaultGuid);
                Console.WriteLine("  Vault Type     : {0}\r\n", vaultType);

                // Fetch all items within Vault
                int vaultItemCount = 0;
                IntPtr vaultItemPtr = IntPtr.Zero;
                result = VaultCli.VaultEnumerateItems(vaultHandle, 512, ref vaultItemCount, ref vaultItemPtr);
                if (result != 0)
                {
                    Console.WriteLine("  [ERROR] Unable to enumerate vault items from the following vault: " + vaultType + ". Error 0x" + result.ToString());
                    return;
                }
                var structAddress = vaultItemPtr;
                if (vaultItemCount > 0)
                {
                    // For each vault item...
                    for (int j = 1; j <= vaultItemCount; j++)
                    {
                        // Begin fetching vault item...
                        var currentItem = System.Runtime.InteropServices.Marshal.PtrToStructure(structAddress, VAULT_ITEM);
                        structAddress = (IntPtr)(structAddress.ToInt64() + System.Runtime.InteropServices.Marshal.SizeOf(VAULT_ITEM));

                        IntPtr passwordVaultItem = IntPtr.Zero;
                        // Field Info retrieval
                        FieldInfo schemaIdInfo = currentItem.GetType().GetField("SchemaId");
                        Guid schemaId = new Guid(schemaIdInfo.GetValue(currentItem).ToString());
                        FieldInfo pResourceElementInfo = currentItem.GetType().GetField("pResourceElement");
                        IntPtr pResourceElement = (IntPtr)pResourceElementInfo.GetValue(currentItem);
                        FieldInfo pIdentityElementInfo = currentItem.GetType().GetField("pIdentityElement");
                        IntPtr pIdentityElement = (IntPtr)pIdentityElementInfo.GetValue(currentItem);
                        FieldInfo dateTimeInfo = currentItem.GetType().GetField("LastModified");
                        UInt64 lastModified = (UInt64)dateTimeInfo.GetValue(currentItem);

                        IntPtr pPackageSid = IntPtr.Zero;
                        if (OSMajor >= 6 && OSMinor >= 2)
                        {
                            // Newer versions have package sid
                            FieldInfo pPackageSidInfo = currentItem.GetType().GetField("pPackageSid");
                            pPackageSid = (IntPtr)pPackageSidInfo.GetValue(currentItem);
                            result = VaultCli.VaultGetItem_WIN8(vaultHandle, ref schemaId, pResourceElement, pIdentityElement, pPackageSid, IntPtr.Zero, 0, ref passwordVaultItem);
                        }
                        else
                        {
                            result = VaultCli.VaultGetItem_WIN7(vaultHandle, ref schemaId, pResourceElement, pIdentityElement, IntPtr.Zero, 0, ref passwordVaultItem);
                        }

                        if (result != 0)
                        {
                            Console.WriteLine("  [ERROR] occured while retrieving vault item. Error: 0x" + result.ToString());
                            return;
                        }
                        object passwordItem = System.Runtime.InteropServices.Marshal.PtrToStructure(passwordVaultItem, VAULT_ITEM);
                        FieldInfo pAuthenticatorElementInfo = passwordItem.GetType().GetField("pAuthenticatorElement");
                        IntPtr pAuthenticatorElement = (IntPtr)pAuthenticatorElementInfo.GetValue(passwordItem);
                        // Fetch the credential from the authenticator element
                        object cred = GetVaultElementValue(pAuthenticatorElement);
                        object packageSid = null;
                        if (pPackageSid != IntPtr.Zero && pPackageSid != null)
                        {
                            packageSid = GetVaultElementValue(pPackageSid);
                        }
                        if (cred != null) // Indicates successful fetch
                        {
                            // Console.WriteLine("  --- IE/Edge Credential ---");
                            // Console.WriteLine("  Vault Type   : {0}", vaultType);
                            object resource = GetVaultElementValue(pResourceElement);
                            if (resource != null)
                            {
                                Console.WriteLine("    Resource     : {0}", resource);
                            }
                            object identity = GetVaultElementValue(pIdentityElement);
                            if (identity != null)
                            {
                                Console.WriteLine("    Identity     : {0}", identity);
                            }
                            if (packageSid != null)
                            {
                                Console.WriteLine("    PacakgeSid  : {0}", packageSid);
                            }
                            Console.WriteLine("    Credential   : {0}", cred);
                            // Stupid datetime
                            Console.WriteLine("    LastModified : {0}", System.DateTime.FromFileTimeUtc((long)lastModified));
                            Console.WriteLine();
                        }
                    }
                }
            }
        }

        public static void CheckChrome()
        {
            // checks if Chrome has a history database
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Chrome (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        bool found = false;
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userChromeHistoryPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", dir);
                            if (System.IO.File.Exists(userChromeHistoryPath))
                            {
                                Console.WriteLine("  [*] Chrome history file exists at {0}", userChromeHistoryPath);
                                Console.WriteLine("      Run the 'TriageChrome' command\r\n");
                                found = true;
                            }
                            string userChromeCookiesPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", dir);
                            if (System.IO.File.Exists(userChromeCookiesPath))
                            {
                                Console.WriteLine("  [*] Chrome cookies database exists at {0}", userChromeCookiesPath);
                                Console.WriteLine("      Run the Mimikatz \"dpapi::chrome\" module\r\n");
                                found = true;
                            }
                            string userChromeLoginDataPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", dir);
                            if (System.IO.File.Exists(userChromeLoginDataPath))
                            {
                                Console.WriteLine("  [*] Chrome saved login database exists at {0}", userChromeLoginDataPath);
                                Console.WriteLine("      Run the Mimikatz \"dpapi::chrome\" module or SharpWeb (https://github.com/djhohnstein/SharpWeb)\r\n");
                                found = true;
                            }
                            if (found)
                            {
                                Console.WriteLine();
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Chrome (Current User) ===\r\n");
                    string userChromeHistoryPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(userChromeHistoryPath))
                    {
                        Console.WriteLine("  [*] Chrome history file exists at {0}", userChromeHistoryPath);
                        Console.WriteLine("      Run the 'TriageChrome' command\r\n");
                    }
                    string userChromeCookiesPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(userChromeCookiesPath))
                    {
                        Console.WriteLine("  [*] Chrome cookies database exists at {0}", userChromeCookiesPath);
                        Console.WriteLine("      Run the Mimikatz \"dpapi::chrome\" module\r\n");
                    }
                    string userChromeLoginDataPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(userChromeLoginDataPath))
                    {
                        Console.WriteLine("  [*] Chrome saved login database exists at {0}", userChromeLoginDataPath);
                        Console.WriteLine("      Run the Mimikatz \"dpapi::chrome\" module or SharpWeb (https://github.com/djhohnstein/SharpWeb)");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }
        public static void ParseChromeHistory(string path, string user)
        {
            // parses a Chrome history file via regex
            if (System.IO.File.Exists(path))
            {
                Console.WriteLine("\r\n    History ({0}):\r\n", user);
                Regex historyRegex = new Regex(@"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?");

                try
                {
                    using (StreamReader r = new StreamReader(path))
                    {
                        string line;
                        while ((line = r.ReadLine()) != null)
                        {
                            Match m = historyRegex.Match(line);
                            if (m.Success)
                            {
                                Console.WriteLine("      {0}", m.Groups[0].ToString().Trim());
                            }
                        }
                    }
                }
                catch (System.IO.IOException exception)
                {
                    Console.WriteLine("\r\n    [x] IO exception, history file likely in use (i.e. Browser is likely running): ", exception.Message);
                }
                catch (Exception exception)
                {
                    Console.WriteLine("\r\n    [x] Exception: {0}", exception.Message);
                }
            }
        }
        public static void ParseChromeBookmarks(string path, string user)
        {
            // parses a Chrome bookmarks
            if (System.IO.File.Exists(path))
            {
                Console.WriteLine("\r\n    Bookmarks ({0}):\r\n", user);

                try
                {
                    string contents = System.IO.File.ReadAllText(path);

                    // reference: http://www.tomasvera.com/programming/using-javascriptserializer-to-parse-json-objects/
                    JavaScriptSerializer json = new JavaScriptSerializer();
                    Dictionary<string, object> deserialized = json.Deserialize<Dictionary<string, object>>(contents);
                    Dictionary<string, object> roots = (Dictionary<string, object>)deserialized["roots"];
                    Dictionary<string, object> bookmark_bar = (Dictionary<string, object>)roots["bookmark_bar"];
                    System.Collections.ArrayList children = (System.Collections.ArrayList)bookmark_bar["children"];

                    foreach (Dictionary<string, object> entry in children)
                    {
                        Console.WriteLine("      Name: {0}", entry["name"].ToString().Trim());
                        Console.WriteLine("      Url:  {0}\r\n", entry["url"].ToString().Trim());
                    }
                }
                catch (System.IO.IOException exception)
                {
                    Console.WriteLine("\r\n    [x] IO exception, Bookmarks file likely in use (i.e. Chrome is likely running).", exception.Message);
                }
                catch (Exception exception)
                {
                    Console.WriteLine("\r\n    [x] Exception: {0}", exception.Message);
                }
            }
        }
        public static void TriageChrome()
        {
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Chrome (All Users) ===");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userChromeHistoryPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", dir);
                            ParseChromeHistory(userChromeHistoryPath, userName);

                            string userChromeBookmarkPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks", dir);
                            ParseChromeBookmarks(userChromeBookmarkPath, userName);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Chrome (Current User) ===");

                    string userChromeHistoryPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    ParseChromeHistory(userChromeHistoryPath, System.Environment.GetEnvironmentVariable("USERNAME"));

                    string userChromeBookmarkPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    ParseChromeBookmarks(userChromeBookmarkPath, System.Environment.GetEnvironmentVariable("USERNAME"));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void CheckFirefox()
        {
            // checks if Firefox has a history database
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Firefox (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            bool found = false;
                            string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", dir);
                            if (System.IO.Directory.Exists(userFirefoxBasePath))
                            {
                                string[] directories = Directory.GetDirectories(userFirefoxBasePath);
                                foreach (string directory in directories)
                                {
                                    string firefoxHistoryFile = String.Format("{0}\\{1}", directory, "places.sqlite");
                                    if (System.IO.File.Exists(firefoxHistoryFile))
                                    {
                                        Console.WriteLine("  [*] Firefox history file exists at {0}", firefoxHistoryFile);
                                        Console.WriteLine("      Run the 'TriageFirefox' command\r\n");
                                        found = true;
                                    }
                                    string firefoxCredentialFile3 = String.Format("{0}\\{1}", directory, "key3.db");
                                    if (System.IO.File.Exists(firefoxCredentialFile3))
                                    {
                                        Console.WriteLine("  [*] Firefox credential file exists at {0}", firefoxCredentialFile3);
                                        Console.WriteLine("      Run SharpWeb (https://github.com/djhohnstein/SharpWeb) \r\n");
                                        found = true;
                                    }
                                    string firefoxCredentialFile4 = String.Format("{0}\\{1}", directory, "key4.db");
                                    if (System.IO.File.Exists(firefoxCredentialFile4))
                                    {
                                        Console.WriteLine("  [*] Firefox credential file exists at {0}", firefoxCredentialFile4);
                                        Console.WriteLine("      Run SharpWeb (https://github.com/djhohnstein/SharpWeb) \r\n");
                                        found = true;
                                    }
                                }
                                if (found)
                                {
                                    Console.WriteLine();
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Firefox (Current User) ===\r\n");
                    string userName = Environment.GetEnvironmentVariable("USERNAME");
                    string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    if (System.IO.Directory.Exists(userFirefoxBasePath))
                    {
                        string[] directories = Directory.GetDirectories(userFirefoxBasePath);
                        foreach (string directory in directories)
                        {
                            string firefoxHistoryFile = String.Format("{0}\\{1}", directory, "places.sqlite");
                            if (System.IO.File.Exists(firefoxHistoryFile))
                            {
                                Console.WriteLine("  [*] Firefox history file exists at {0}", firefoxHistoryFile);
                                Console.WriteLine("      Run the 'TriageFirefox' command\r\n");
                            }
                            string firefoxCredentialFile3 = String.Format("{0}\\{1}", directory, "key3.db");
                            if (System.IO.File.Exists(firefoxCredentialFile3))
                            {
                                Console.WriteLine("  [*] Firefox credential file exists at {0}", firefoxCredentialFile3);
                                Console.WriteLine("      Run SharpWeb (https://github.com/djhohnstein/SharpWeb)\r\n");
                            }
                            string firefoxCredentialFile4 = String.Format("{0}\\{1}", directory, "key4.db");
                            if (System.IO.File.Exists(firefoxCredentialFile4))
                            {
                                Console.WriteLine("  [*] Firefox credential file exists at {0}", firefoxCredentialFile4);
                                Console.WriteLine("      Run SharpWeb (https://github.com/djhohnstein/SharpWeb)\r\n");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }
        public static void ParseFirefoxHistory(string path, string user)
        {
            // parses a Firefox history file via regex
            if (System.IO.Directory.Exists(path))
            {
                string[] directories = Directory.GetDirectories(path);
                foreach (string directory in directories)
                {
                    string firefoxHistoryFile = String.Format("{0}\\{1}", directory, "places.sqlite");

                    Console.WriteLine("\r\n    History ({0}):\r\n", user);
                    Regex historyRegex = new Regex(@"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?");

                    try
                    {
                        using (StreamReader r = new StreamReader(firefoxHistoryFile))
                        {
                            string line;
                            while ((line = r.ReadLine()) != null)
                            {
                                Match m = historyRegex.Match(line);
                                if (m.Success)
                                {
                                    Console.WriteLine("      {0}", m.Groups[0].ToString().Trim());
                                }
                            }
                        }
                    }
                    catch (System.IO.IOException exception)
                    {
                        Console.WriteLine("\r\n    [x] IO exception, places.sqlite file likely in use (i.e. Firefox is likely running).", exception.Message);
                    }
                    catch (Exception exception)
                    {
                        Console.WriteLine("\r\n    [x] Exception: {0}", exception.Message);
                    }
                }
            }
        }
        public static void TriageFirefox()
        {
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Firefox (All Users) ===");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", dir);
                            ParseFirefoxHistory(userFirefoxBasePath, userName);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Firefox (Current User) ===");
                    string userName = Environment.GetEnvironmentVariable("USERNAME");

                    string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    ParseFirefoxHistory(userFirefoxBasePath, userName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListRecentRunCommands()
        {
            // lists recently run commands via the RunMRU registry key
            if (IsHighIntegrity())
            {
                Console.WriteLine("\r\n\r\n=== Recent Typed RUN Commands (All Users) ===");

                string[] SIDs = Registry.Users.GetSubKeyNames();
                foreach (string SID in SIDs)
                {
                    if (SID.StartsWith("S-1-5") && !SID.EndsWith("_Classes"))
                    {
                        Dictionary<string, object> recentCommands = GetRegValues("HKU", String.Format("{0}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", SID));
                        if ((recentCommands != null) && (recentCommands.Count != 0))
                        {
                            Console.WriteLine("\r\n    {0} :", SID);
                            foreach (KeyValuePair<string, object> kvp in recentCommands)
                            {
                                Console.WriteLine("      {0,-10} :  {1}", kvp.Key, kvp.Value);
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== Recent Typed RUN Commands (Current User) ===\r\n");

                Dictionary<string, object> recentCommands = GetRegValues("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
                if ((recentCommands != null) && (recentCommands.Count != 0))
                {
                    foreach (KeyValuePair<string, object> kvp in recentCommands)
                    {
                        Console.WriteLine("    {0,-10} :  {1}", kvp.Key, kvp.Value);
                    }
                }
            }
        }

        public static void ListPuttySessions()
        {
            // extracts saved putty sessions and basic configs (via the registry)
            if (IsHighIntegrity())
            {
                Console.WriteLine("\r\n\r\n=== Putty Saved Session Information (All Users) ===\r\n");

                string[] SIDs = Registry.Users.GetSubKeyNames();
                foreach (string SID in SIDs)
                {
                    if (SID.StartsWith("S-1-5") && !SID.EndsWith("_Classes"))
                    {
                        string[] subKeys = GetRegSubkeys("HKU", String.Format("{0}\\Software\\SimonTatham\\PuTTY\\Sessions\\", SID));

                        foreach (string sessionName in subKeys)
                        {
                            Console.WriteLine("    {0,-20}  :  {1}", "User SID", SID);
                            Console.WriteLine("    {0,-20}  :  {1}", "SessionName", sessionName);

                            string[] keys =
                            {
                                "HostName",
                                "UserName",
                                "PublicKeyFile",
                                "PortForwardings",
                                "ConnectionSharing"
                            };

                            foreach (string key in keys)
                            {
                                string result = GetRegValue("HKU", String.Format("{0}\\Software\\SimonTatham\\PuTTY\\Sessions\\{1}", SID, sessionName), key);
                                if (!String.IsNullOrEmpty(result))
                                {
                                    Console.WriteLine("    {0,-20}  :  {1}", key, result);
                                }
                            }
                            Console.WriteLine();
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== Putty Saved Session Information (Current User) ===\r\n");

                string[] subKeys = GetRegSubkeys("HKCU", "Software\\SimonTatham\\PuTTY\\Sessions\\");
                foreach (string sessionName in subKeys)
                {
                    Console.WriteLine("    {0,-20}  :  {1}", "SessionName", sessionName);

                    string[] keys =
                    {
                        "HostName",
                        "UserName",
                        "PublicKeyFile",
                        "PortForwardings",
                        "ConnectionSharing"
                    };

                    foreach (string key in keys)
                    {
                        string result = GetRegValue("HKCU", String.Format("Software\\SimonTatham\\PuTTY\\Sessions\\{0}", sessionName), key);
                        if (!String.IsNullOrEmpty(result))
                        {
                            Console.WriteLine("    {0,-20}  :  {1}", key, result);
                        }
                    }
                    Console.WriteLine();
                }
            }
        }

        public static void ListPuttySSHHostKeys()
        {
            // extracts saved putty host keys (via the registry)
            if (IsHighIntegrity())
            {
                Console.WriteLine("\r\n\r\n=== Putty SSH Host Hosts (All Users) ===\r\n");

                string[] SIDs = Registry.Users.GetSubKeyNames();
                foreach (string SID in SIDs)
                {
                    if (SID.StartsWith("S-1-5") && !SID.EndsWith("_Classes"))
                    {
                        Dictionary<string, object> hostKeys = GetRegValues("HKU", String.Format("{0}\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\", SID));
                        if ((hostKeys != null) && (hostKeys.Count != 0))
                        {
                            Console.WriteLine("    {0} :", SID);
                            foreach (KeyValuePair<string, object> kvp in hostKeys)
                            {
                                Console.WriteLine("      {0,-10}", kvp.Key);
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n\r\n=== Putty SSH Host Key Recent Hosts (Current User) ===\r\n");

                Dictionary<string, object> hostKeys = GetRegValues("HKCU", "Software\\SimonTatham\\PuTTY\\SshHostKeys\\");
                if ((hostKeys != null) && (hostKeys.Count != 0))
                {
                    foreach (KeyValuePair<string, object> kvp in hostKeys)
                    {
                        Console.WriteLine("    {0,-10}", kvp.Key);
                    }
                }
            }

            //Console.WriteLine("\r\n\r\n=== Putty SSH Host Key Recent Hosts ===\r\n");

            //Dictionary<string, object> sessions = GetRegValues("HKCU", "Software\\SimonTatham\\PuTTY\\SshHostKeys\\");
            //if (sessions != null)
            //{
            //    foreach (KeyValuePair<string, object> kvp in sessions)
            //    {
            //        Console.WriteLine("    {0,-10}", kvp.Key);
            //    }
            //}
        }

        public static void ListCloudCreds()
        {
            // checks for various cloud credential files (AWS, Microsoft Azure, and Google Compute)
            // adapted from https://twitter.com/cmaddalena's SharpCloud project (https://github.com/chrismaddalena/SharpCloud/)
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Cloud Credentials (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        bool found = false;
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string awsKeyFile = String.Format("{0}\\.aws\\credentials", dir);
                            if (System.IO.File.Exists(awsKeyFile))
                            {
                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(awsKeyFile);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(awsKeyFile);
                                long size = new System.IO.FileInfo(awsKeyFile).Length;
                                Console.WriteLine("  [*] AWS key file exists at     : {0}", awsKeyFile);
                                Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                                Console.WriteLine("      Modified                   : {0}", lastModified);
                                Console.WriteLine("      Size                       : {0}\r\n", size);
                                found = true;
                            }
                            string computeCredsDb = String.Format("{0}\\AppData\\Roaming\\gcloud\\credentials.db", dir);
                            if (System.IO.File.Exists(computeCredsDb))
                            {
                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(computeCredsDb);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(computeCredsDb);
                                long size = new System.IO.FileInfo(computeCredsDb).Length;
                                Console.WriteLine("  [*] Compute creds at           : {0}", computeCredsDb);
                                Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                                Console.WriteLine("      Modified                   : {0}", lastModified);
                                Console.WriteLine("      Size                       : {0}\r\n", size);
                                found = true;
                            }
                            string computeLegacyCreds = String.Format("{0}\\AppData\\Roaming\\gcloud\\legacy_credentials", dir);
                            if (System.IO.File.Exists(computeLegacyCreds))
                            {
                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(computeLegacyCreds);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(computeLegacyCreds);
                                long size = new System.IO.FileInfo(computeLegacyCreds).Length;
                                Console.WriteLine("  [*] Compute legacy creds at    : {0}", computeLegacyCreds);
                                Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                                Console.WriteLine("      Modified                   : {0}", lastModified);
                                Console.WriteLine("      Size                       : {0}\r\n", size);
                                found = true;
                            }
                            string computeAccessTokensDb = String.Format("{0}\\AppData\\Roaming\\gcloud\\access_tokens.db", dir);
                            if (System.IO.File.Exists(computeAccessTokensDb))
                            {
                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(computeAccessTokensDb);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(computeAccessTokensDb);
                                long size = new System.IO.FileInfo(computeAccessTokensDb).Length;
                                Console.WriteLine("  [*] Compute access tokens at   : {0}", computeAccessTokensDb);
                                Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                                Console.WriteLine("      Modified                   : {0}", lastModified);
                                Console.WriteLine("      Size                       : {0}\r\n", size);
                                found = true;
                            }
                            string azureTokens = String.Format("{0}\\.azure\\accessTokens.json", dir);
                            if (System.IO.File.Exists(azureTokens))
                            {
                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(azureTokens);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(azureTokens);
                                long size = new System.IO.FileInfo(azureTokens).Length;
                                Console.WriteLine("  [*] Azure access tokens at     : {0}", azureTokens);
                                Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                                Console.WriteLine("      Modified                   : {0}", lastModified);
                                Console.WriteLine("      Size                       : {0}\r\n", size);
                                found = true;
                            }
                            string azureProfile = String.Format("{0}\\.azure\\azureProfile.json", dir);
                            if (System.IO.File.Exists(azureProfile))
                            {
                                DateTime lastAccessed = System.IO.File.GetLastAccessTime(azureProfile);
                                DateTime lastModified = System.IO.File.GetLastWriteTime(azureProfile);
                                long size = new System.IO.FileInfo(azureProfile).Length;
                                Console.WriteLine("  [*] Azure profile at           : {0}", azureProfile);
                                Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                                Console.WriteLine("      Modified                   : {0}", lastModified);
                                Console.WriteLine("      Size                       : {0}\r\n", size);
                                found = true;
                            }
                            if (found)
                            {
                                System.Console.WriteLine();
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Cloud Credentials (Current User) ===\r\n");

                    string awsKeyFile = String.Format("{0}\\.aws\\credentials", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(awsKeyFile))
                    {
                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(awsKeyFile);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(awsKeyFile);
                        long size = new System.IO.FileInfo(awsKeyFile).Length;
                        Console.WriteLine("  [*] AWS key file exists at     : {0}", awsKeyFile);
                        Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                        Console.WriteLine("      Modified                   : {0}", lastModified);
                        Console.WriteLine("      Size                       : {0}\r\n", size);
                    }
                    string computeCredsDb = String.Format("{0}\\AppData\\Roaming\\gcloud\\credentials.db", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(computeCredsDb))
                    {
                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(computeCredsDb);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(computeCredsDb);
                        long size = new System.IO.FileInfo(computeCredsDb).Length;
                        Console.WriteLine("  [*] Compute creds at           : {0}", computeCredsDb);
                        Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                        Console.WriteLine("      Modified                   : {0}", lastModified);
                        Console.WriteLine("      Size                       : {0}\r\n", size);
                    }
                    string computeLegacyCreds = String.Format("{0}\\AppData\\Roaming\\gcloud\\legacy_credentials", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(computeLegacyCreds))
                    {
                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(computeLegacyCreds);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(computeLegacyCreds);
                        long size = new System.IO.FileInfo(computeLegacyCreds).Length;
                        Console.WriteLine("  [*] Compute legacy creds at    : {0}", computeLegacyCreds);
                        Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                        Console.WriteLine("      Modified                   : {0}", lastModified);
                        Console.WriteLine("      Size                       : {0}\r\n", size);
                    }
                    string computeAccessTokensDb = String.Format("{0}\\AppData\\Roaming\\gcloud\\access_tokens.db", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(computeAccessTokensDb))
                    {
                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(computeAccessTokensDb);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(computeAccessTokensDb);
                        long size = new System.IO.FileInfo(computeAccessTokensDb).Length;
                        Console.WriteLine("  [*] Compute access tokens at   : {0}", computeAccessTokensDb);
                        Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                        Console.WriteLine("      Modified                   : {0}", lastModified);
                        Console.WriteLine("      Size                       : {0}\r\n", size);
                    }
                    string azureTokens = String.Format("{0}\\.azure\\accessTokens.json", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(azureTokens))
                    {
                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(azureTokens);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(azureTokens);
                        long size = new System.IO.FileInfo(azureTokens).Length;
                        Console.WriteLine("  [*] Azure access tokens at     : {0}", azureTokens);
                        Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                        Console.WriteLine("      Modified                   : {0}", lastModified);
                        Console.WriteLine("      Size                       : {0}\r\n", size);
                    }
                    string azureProfile = String.Format("{0}\\.azure\\azureProfile.json", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    if (System.IO.File.Exists(azureProfile))
                    {
                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(azureProfile);
                        DateTime lastModified = System.IO.File.GetLastWriteTime(azureProfile);
                        long size = new System.IO.FileInfo(azureProfile).Length;
                        Console.WriteLine("  [*] Azure profile at           : {0}", azureProfile);
                        Console.WriteLine("      Accessed                   : {0}", lastAccessed);
                        Console.WriteLine("      Modified                   : {0}", lastModified);
                        Console.WriteLine("      Size                       : {0}\r\n", size);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListRecentFiles()
        {
            // parses recent file shortcuts via COM

            int lastDays = 7;

            if (!FilterResults.filter)
            {
                lastDays = 30;
            }

            DateTime startTime = System.DateTime.Now.AddDays(-lastDays);

            try
            {
                // WshShell COM object GUID 
                Type shell = Type.GetTypeFromCLSID(new Guid("F935DC22-1CF0-11d0-ADB9-00C04FD58A0B"));
                Object shellObj = Activator.CreateInstance(shell);

                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Recently Accessed Files (All Users) Last {0} Days ===\r\n", lastDays);

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];

                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string recentPath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", dir);
                            try
                            {
                                string[] recentFiles = Directory.GetFiles(recentPath, "*.lnk", SearchOption.AllDirectories);

                                if (recentFiles.Length != 0)
                                {
                                    Console.WriteLine("   {0} :\r\n", userName);
                                    foreach (string recentFile in recentFiles)
                                    {
                                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(recentFile);

                                        if (lastAccessed > startTime)
                                        {
                                            // invoke the WshShell com object, creating a shortcut to then extract the TargetPath from
                                            Object shortcut = shellObj.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shellObj, new object[] { recentFile });
                                            Object TargetPath = shortcut.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, new object[] { });

                                            if (TargetPath.ToString().Trim() != "")
                                            {
                                                Console.WriteLine("      Target:       {0,-10}", TargetPath.ToString());
                                                Console.WriteLine("          Accessed: {0}\r\n", lastAccessed);
                                            }
                                            Marshal.ReleaseComObject(shortcut);
                                            shortcut = null;
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Recently Accessed Files (Current User) Last {0} Days ===\r\n", lastDays);

                    string recentPath = String.Format("{0}\\Microsoft\\Windows\\Recent\\", System.Environment.GetEnvironmentVariable("APPDATA"));

                    string[] recentFiles = Directory.GetFiles(recentPath, "*.lnk", SearchOption.AllDirectories);

                    foreach (string recentFile in recentFiles)
                    {
                        // old method (needed interop dll)
                        //WshShell shell = new WshShell();
                        //IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(recentFile);

                        DateTime lastAccessed = System.IO.File.GetLastAccessTime(recentFile);

                        if (lastAccessed > startTime)
                        {
                            // invoke the WshShell com object, creating a shortcut to then extract the TargetPath from
                            Object shortcut = shellObj.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shellObj, new object[] { recentFile });
                            Object TargetPath = shortcut.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, new object[] { });
                            if (TargetPath.ToString().Trim() != "")
                            {
                                Console.WriteLine("    Target:       {0,-10}", TargetPath.ToString());
                                Console.WriteLine("        Accessed: {0}\r\n", lastAccessed);
                            }
                            Marshal.ReleaseComObject(shortcut);
                            shortcut = null;
                        }
                    }
                }
                // release the WshShell COM object
                Marshal.ReleaseComObject(shellObj);
                shellObj = null;
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListInterestingFiles()
        {
            // returns files (w/ modification dates) that match the given pattern below
            string patterns = "*pass *;*diagram*;*.pdf;*.vsd;*.doc;*docx;*.xls;*.xlsx;*.kdbx;*.key;KeePass.config";

            if (IsHighIntegrity())
            {
                Console.WriteLine("\r\n\r\n=== Interesting Files (All Users) ===\r\n");

                string searchPath = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));

                List<string> files = FindFiles(searchPath, patterns);

                foreach (string file in files)
                {
                    DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                    DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                    Console.WriteLine("    File:         {0}", file);
                    Console.WriteLine("        Accessed: {0}", lastAccessed);
                    Console.WriteLine("        Modified: {0}", lastModified);
                }
            }

            else
            {
                Console.WriteLine("\r\n\r\n=== Interesting Files (Current User) ===\r\n");

                string searchPath = Environment.GetEnvironmentVariable("USERPROFILE");

                List<string> files = FindFiles(searchPath, patterns);

                foreach (string file in files)
                {
                    DateTime lastAccessed = System.IO.File.GetLastAccessTime(file);
                    DateTime lastModified = System.IO.File.GetLastWriteTime(file);
                    Console.WriteLine("    File:         {0}", file);
                    Console.WriteLine("        Accessed: {0}", lastAccessed);
                    Console.WriteLine("        Modified: {0}", lastModified);
                }
            }
        }


        // misc checks
        public static void ListPatches()
        {
            // lists current patches via WMI (win32_quickfixengineering)
            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_quickfixengineering");
                ManagementObjectCollection data = wmiData.Get();

                Console.WriteLine("\r\n\r\n=== Installed Patches (via WMI) ===\r\n");
                Console.WriteLine("  HotFixID   InstalledOn    Description");

                foreach (ManagementObject result in data)
                {
                    Console.WriteLine(String.Format("  {0,-11}{1,-15}{2}", result["HotFixID"], result["InstalledOn"], result["Description"]));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [X] Exception: {0}", ex.Message);
            }
        }

        public static void ListRecycleBin()
        {
            // lists recently deleted files (needs to be run from a user context!)

            // Reference: https://stackoverflow.com/questions/18071412/list-filenames-in-the-recyclebin-with-c-sharp-without-using-any-external-files
            Console.WriteLine("\r\n\r\n=== Recycle Bin Files Within the last 30 Days ===\r\n");

            int lastDays = 30;

            var startTime = System.DateTime.Now.AddDays(-lastDays);

            // Shell COM object GUID
            Type shell = Type.GetTypeFromCLSID(new Guid("13709620-C279-11CE-A49E-444553540000"));
            Object shellObj = Activator.CreateInstance(shell);

            // namespace for recycle bin == 10 - https://msdn.microsoft.com/en-us/library/windows/desktop/bb762494(v=vs.85).aspx
            Object recycle = shellObj.GetType().InvokeMember("Namespace", BindingFlags.InvokeMethod, null, shellObj, new object[] { 10 });
            // grab all the deletes items
            Object items = recycle.GetType().InvokeMember("Items", BindingFlags.InvokeMethod, null, recycle, null);
            // grab the number of deleted items
            Object count = items.GetType().InvokeMember("Count", BindingFlags.GetProperty, null, items, null);
            int deletedCount = Int32.Parse(count.ToString());

            // iterate through each item
            for (int i = 0; i < deletedCount; i++)
            {
                // grab the specific deleted item
                Object item = items.GetType().InvokeMember("Item", BindingFlags.InvokeMethod, null, items, new object[] { i });
                Object DateDeleted = item.GetType().InvokeMember("ExtendedProperty", BindingFlags.InvokeMethod, null, item, new object[] { "System.Recycle.DateDeleted" });
                DateTime modifiedDate = DateTime.Parse(DateDeleted.ToString());
                if (modifiedDate > startTime)
                {
                    // additional extended properties from https://blogs.msdn.microsoft.com/oldnewthing/20140421-00/?p=1183
                    Object Name = item.GetType().InvokeMember("Name", BindingFlags.GetProperty, null, item, null);
                    Object Path = item.GetType().InvokeMember("Path", BindingFlags.GetProperty, null, item, null);
                    Object Size = item.GetType().InvokeMember("Size", BindingFlags.GetProperty, null, item, null);
                    Object DeletedFrom = item.GetType().InvokeMember("ExtendedProperty", BindingFlags.InvokeMethod, null, item, new object[] { "System.Recycle.DeletedFrom" });
                    Console.WriteLine("  Name           : {0}", Name);
                    Console.WriteLine("  Path           : {0}", Path);
                    Console.WriteLine("  Size           : {0}", Size);
                    Console.WriteLine("  Deleted From   : {0}", DeletedFrom);
                    Console.WriteLine("  Date Deleted   : {0}\r\n", DateDeleted);
                }
                Marshal.ReleaseComObject(item);
                item = null;
            }
            Marshal.ReleaseComObject(recycle);
            recycle = null;
            Marshal.ReleaseComObject(shellObj);
            shellObj = null;
        }


        // meta-functions for running various checks
        public static void SystemChecks()
        {
            Console.WriteLine("\r\n=== Running System Triage Checks ===\r\n");
            ListBasicOSInfo();
            ListRebootSchedule();
            ListTokenGroupPrivs();
            ListUACSystemPolicies();
            ListPowerShellSettings();
            ListAuditSettings();
            ListWEFSettings();
            ListLSASettings();
            ListUserEnvVariables();
            ListSystemEnvVariables();
            ListUserFolders();
            ListNonstandardServices();
            ListInternetSettings();
            ListLapsSettings();
            ListLocalGroupMembers();
            ListMappedDrives();
            ListRDPSessions();
            ListWMIMappedDrives();
            ListNetworkShares();
            ListFirewallRules();
            ListAntiVirusWMI();
            ListInterestingProcesses();
            ListRegistryAutoLogon();
            ListRegistryAutoRuns();
            ListDNSCache();
            ListARPTable();
            ListAllTcpConnections();
            ListAllUdpConnections();
            ListNonstandardProcesses();

            // list patches and List4624Events/List4648Events if we're doing "full" collection
            if (!FilterResults.filter)
            {
                ListPatches();
                List4624Events();
                List4648Events();
            }

            if (IsHighIntegrity())
            {
                Console.WriteLine("\r\n\r\n [*] In high integrity, performing elevated collection options.");
                ListSysmonConfig();
            }
        }

        public static void UserChecks()
        {
            Console.WriteLine("\r\n=== Running User Triage Checks ===\r\n");

            if (IsHighIntegrity())
            {
                Console.WriteLine("\r\n [*] In high integrity, attempting triage for all users on the machine.");
                Console.WriteLine("\r\n     Current user : {0} - {1} ", WindowsIdentity.GetCurrent().Name, WindowsIdentity.GetCurrent().User);
            }
            else
            {
                Console.WriteLine("\r\n [*] In medium integrity, attempting triage of current user.");
                Console.WriteLine("\r\n     Current user : {0} - {1} ", WindowsIdentity.GetCurrent().Name, WindowsIdentity.GetCurrent().User);
            }

            CheckFirefox();
            CheckChrome();
            TriageIE();
            DumpVault();
            ListSavedRDPConnections();
            ListRecentRunCommands();
            ListPuttySessions();
            ListPuttySSHHostKeys();
            ListCloudCreds();
            ListRecentFiles();
            ListMasterKeys();
            ListCredFiles();
            ListRDCManFiles();

            if (!FilterResults.filter)
            {
                TriageChrome();
                TriageFirefox();
                ListInterestingFiles();
            }
        }

        static void Usage()
        {
            Console.WriteLine(" \"SeatBelt.exe system\" collects the following system data:\r\n");
            Console.WriteLine("\tBasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)");
            Console.WriteLine("\tRebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13");
            Console.WriteLine("\tTokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)");
            Console.WriteLine("\tUACSystemPolicies     -   UAC system policies via the registry");
            Console.WriteLine("\tPowerShellSettings    -   PowerShell versions and security settings");
            Console.WriteLine("\tAuditSettings         -   Audit settings via the registry");
            Console.WriteLine("\tWEFSettings           -   Windows Event Forwarding (WEF) settings via the registry");
            Console.WriteLine("\tLSASettings           -   LSA settings (including auth packages)");
            Console.WriteLine("\tUserEnvVariables      -   Current user environment variables");
            Console.WriteLine("\tSystemEnvVariables    -   Current system environment variables");
            Console.WriteLine("\tUserFolders           -   Folders in C:\\Users\\");
            Console.WriteLine("\tNonstandardServices   -   Services with file info company names that don't contain 'Microsoft'");
            Console.WriteLine("\tInternetSettings      -   Internet settings including proxy configs");
            Console.WriteLine("\tLapsSettings          -   LAPS settings, if installed");
            Console.WriteLine("\tLocalGroupMembers     -   Members of local admins, RDP, and DCOM");
            Console.WriteLine("\tMappedDrives          -   Mapped drives");
            Console.WriteLine("\tRDPSessions           -   Current incoming RDP sessions");
            Console.WriteLine("\tWMIMappedDrives       -   Mapped drives via WMI");
            Console.WriteLine("\tNetworkShares         -   Network shares");
            Console.WriteLine("\tFirewallRules         -   Deny firewall rules, \"full\" dumps all");
            Console.WriteLine("\tAntiVirusWMI          -   Registered antivirus (via WMI)");
            Console.WriteLine("\tInterestingProcesses  -   \"Interesting\" processes- defensive products and admin tools");
            Console.WriteLine("\tRegistryAutoRuns      -   Registry autoruns");
            Console.WriteLine("\tRegistryAutoLogon     -   Registry autologon information");
            Console.WriteLine("\tDNSCache              -   DNS cache entries (via WMI)");
            Console.WriteLine("\tARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)");
            Console.WriteLine("\tAllTcpConnections     -   Lists current TCP connections and associated processes");
            Console.WriteLine("\tAllUdpConnections     -   Lists current UDP connections and associated processes");
            Console.WriteLine("\tNonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'");
            Console.WriteLine("\t *  If the user is in high integrity, the following additional actions are run:");
            Console.WriteLine("\tSysmonConfig          -   Sysmon configuration from the registry");

            Console.WriteLine("\r\n\r\n \"SeatBelt.exe user\" collects the following user data:\r\n");
            Console.WriteLine("\tSavedRDPConnections   -   Saved RDP connections");
            Console.WriteLine("\tTriageIE              -   Internet Explorer bookmarks and history  (last 7 days)");
            Console.WriteLine("\tDumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb");
            Console.WriteLine("\tRecentRunCommands     -   Recent \"run\" commands");
            Console.WriteLine("\tPuttySessions         -   Interesting settings from any saved Putty configurations");
            Console.WriteLine("\tPuttySSHHostKeys      -   Saved putty SSH host keys");
            Console.WriteLine("\tCloudCreds            -   AWS/Google/Azure cloud credential files");
            Console.WriteLine("\tRecentFiles           -   Parsed \"recent files\" shortcuts  (last 7 days)");
            Console.WriteLine("\tMasterKeys            -   List DPAPI master keys");
            Console.WriteLine("\tCredFiles             -   List Windows credential DPAPI blobs");
            Console.WriteLine("\tRDCManFiles           -   List Windows Remote Desktop Connection Manager settings files");
            Console.WriteLine("\t *  If the user is in high integrity, this data is collected for ALL users instead of just the current user");

            Console.WriteLine("\r\n\r\n Non-default options:\r\n");
            Console.WriteLine("\tCurrentDomainGroups   -   The current user's local and domain groups");
            Console.WriteLine("\tPatches               -   Installed patches via WMI (takes a bit on some systems)");
            Console.WriteLine("\tLogonSessions         -   User logon session data");
            Console.WriteLine("\tKerberosTGTData       -   ALL TEH TGTZ!");
            Console.WriteLine("\tInterestingFiles      -   \"Interesting\" files matching various patterns in the user's folder");
            Console.WriteLine("\tIETabs                -   Open Internet Explorer tabs");
            Console.WriteLine("\tTriageChrome          -   Chrome bookmarks and history");
            Console.WriteLine("\tTriageFirefox         -   Firefox history (no bookmarks)");
            Console.WriteLine("\tRecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!");
            Console.WriteLine("\t4624Events            -   4624 logon events from the security event log");
            Console.WriteLine("\t4648Events            -   4648 explicit logon events from the security event log (runas or outbound RDP)");
            Console.WriteLine("\tKerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.");

            Console.WriteLine("\r\n\r\n \"SeatBelt.exe all\" will run ALL enumeration checks, can be combined with \"full\".\r\n");
            Console.WriteLine("\r\n \"SeatBelt.exe [CheckName] full\" will prevent any filtering and will return complete results.\r\n");
            Console.WriteLine("\r\n \"SeatBelt.exe [CheckName] [CheckName2] ...\" will run one or more specified checks only (case-sensitive naming!)\r\n");
        }

        static void Main(string[] args)
        {
            PrintLogo();

            var watch = System.Diagnostics.Stopwatch.StartNew();

            if (args.Length != 0)
            {
                foreach (string arg in args)
                {
                    if (string.Equals(arg, "full", StringComparison.CurrentCultureIgnoreCase))
                    {
                        FilterResults.filter = false;
                    }
                }

                foreach (string arg in args)
                {
                    if (string.Equals(arg, "full", StringComparison.CurrentCultureIgnoreCase))
                    {
                        FilterResults.filter = false;
                        if (args.Length == 1)
                        {
                            // if "full" is the only argument, run System and User triage
                            SystemChecks();
                            ListKerberosTickets();
                            UserChecks();
                            ListIETabs();
                            ListPatches();
                            ListRecycleBin();

                            watch.Stop();
                            Console.WriteLine("\r\n\r\n[*] Completed All Safety Checks with no filtering in {0} seconds\r\n", (watch.ElapsedMilliseconds / 1000));
                            return;
                        }
                    }
                    if (string.Equals(arg, "all", StringComparison.CurrentCultureIgnoreCase))
                    {
                        SystemChecks();
                        ListKerberosTickets();
                        UserChecks();
                        ListIETabs();
                        ListPatches();
                        TriageChrome();
                        TriageFirefox();
                        ListRecycleBin();
                        ListInterestingFiles();

                        watch.Stop();
                        Console.WriteLine("\r\n\r\n[*] Completed All Safety Checks in {0} seconds\r\n", (watch.ElapsedMilliseconds / 1000));
                        return;
                    }
                }

                foreach (string arg in args)
                {
                    if (string.Equals(arg, "full", StringComparison.CurrentCultureIgnoreCase)) { }
                    else if (string.Equals(arg, "system", StringComparison.CurrentCultureIgnoreCase))
                    {
                        SystemChecks();
                    }
                    else if (string.Equals(arg, "user", StringComparison.CurrentCultureIgnoreCase))
                    {
                        UserChecks();
                    }
                    else
                    {
                        Type type = typeof(Program);

                        MethodInfo info = null;

                        // try to grab the function name via reflection
                        if (Regex.IsMatch(arg, @"^Triage.*"))
                        {
                            // if TriageX(), all good
                            info = type.GetMethod(arg);
                        }
                        else if (Regex.IsMatch(arg, @"^Dump.*"))
                        {
                            // if DumpX, all good
                            info = type.GetMethod(arg);
                        }
                        else
                        {
                            // build List<name>()
                            info = type.GetMethod(String.Format("List{0}", arg));
                        }

                        if (info == null)
                        {
                            Console.WriteLine("[X] Check \"{0}\" not found!", arg);
                        }
                        else
                        {
                            info.Invoke(null, new object[] { });
                        }
                    }
                }
            }
            else
            {
                Usage();
                return;
            }

            watch.Stop();
            Console.WriteLine("\r\n\r\n[*] Completed Safety Checks in {0} seconds\r\n", (watch.ElapsedMilliseconds / 1000));
        }
    }
}
