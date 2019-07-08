# Seatbelt

----

Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.

[@andrewchiles](https://twitter.com/andrewchiles)' [HostEnum.ps1](https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1) script and [@tifkin\_](https://twitter.com/tifkin_)'s [Get-HostProfile.ps1](https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-HostProfile.ps1) provided inspiration for many of the artifacts to collect.

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this implementation.

Seatbelt is licensed under the BSD 3-Clause license.

## Usage

**SeatBelt.exe system** collects the following system data:

    BasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)
    RebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13
    TokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)
    UACSystemPolicies     -   UAC system policies via the registry
    PowerShellSettings    -   PowerShell versions and security settings
    AuditSettings         -   Audit settings via the registry
    WEFSettings           -   Windows Event Forwarding (WEF) settings via the registry
    LSASettings           -   LSA settings (including auth packages)
    UserEnvVariables      -   Current user environment variables
    SystemEnvVariables    -   Current system environment variables
    UserFolders           -   Folders in C:\Users\
    NonstandardServices   -   Services with file info company names that don't contain 'Microsoft'
    InternetSettings      -   Internet settings including proxy configs
    LapsSettings          -   LAPS settings, if installed
    LocalGroupMembers     -   Members of local admins, RDP, and DCOM
    MappedDrives          -   Mapped drives
    RDPSessions           -   Current incoming RDP sessions
    WMIMappedDrives       -   Mapped drives via WMI
    NetworkShares         -   Network shares
    FirewallRules         -   Deny firewall rules, "full" dumps all
    AntiVirusWMI          -   Registered antivirus (via WMI)
    InterestingProcesses  -   "Interesting" processes- defensive products and admin tools
    RegistryAutoRuns      -   Registry autoruns
    RegistryAutoLogon     -   Registry autologon information
    DNSCache              -   DNS cache entries (via WMI)
    ARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)
    AllTcpConnections     -   Lists current TCP connections and associated processes
    AllUdpConnections     -   Lists current UDP connections and associated processes
    NonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'
      *  If the user is in high integrity, the following additional actions are run:
    SysmonConfig          -   Sysmon configuration from the registry

**SeatBelt.exe user** collects the following user data:

    SavedRDPConnections   -   Saved RDP connections
    TriageIE              -   Internet Explorer bookmarks and history (last 7 days)
    DumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb
    RecentRunCommands     -   Recent "run" commands
    PuttySessions         -   Interesting settings from any saved Putty configurations
    PuttySSHHostKeys      -   Saved putty SSH host keys
    CloudCreds            -   AWS/Google/Azure cloud credential files (SharpCloud)
    RecentFiles           -   Parsed "recent files" shortcuts (last 7 days)
    MasterKeys            -   List DPAPI master keys
    CredFiles             -   List Windows credential DPAPI blobs
    RDCManFiles           -   List Windows Remote Desktop Connection Manager settings files
      *  If the user is in high integrity, this data is collected for ALL users instead of just the current user

Non-default collection options:

    CurrentDomainGroups   -   The current user's local and domain groups
    Patches               -   Installed patches via WMI (takes a bit on some systems)
    LogonSessions         -   User logon session data
    KerberosTGTData       -   ALL TEH TGTZ!
    InterestingFiles      -   "Interesting" files matching various patterns in the user's folder
    IETabs                -   Open Internet Explorer tabs
    TriageChrome          -   Chrome bookmarks and history
    TriageFirefox         -   Firefox history (no bookmarks)
    RecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
    4624Events            -   4624 logon events from the security event log
    4648Events            -   4648 explicit logon events from the security event log
    KerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.

**SeatBelt.exe all** will run ALL enumeration checks, can be combined with **full**.

**SeatBelt.exe [CheckName] full** will prevent any filtering and will return complete results.

**SeatBelt.exe [CheckName] [CheckName2] ...** will run one or more specified checks only (case-sensitive naming!)

## Compile Instructions

We are not planning on releasing binaries for Seatbelt, so you will have to compile yourself :)

Seatbelt has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.

## Acknowledgments

Seatbelt incorporates various code C# snippets and bits of PoCs found throughout research for its capabilities. These snippets and authors are highlighted in the appropriate locations in the source code, and include:

* [@andrewchiles](https://twitter.com/andrewchiles)' [HostEnum.ps1](https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1) script and [@tifkin\_](https://twitter.com/tifkin_)'s [Get-HostProfile.ps1](https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-HostProfile.ps1) provided inspiration for many of the artifacts to collect.
* [Boboes' code concerning NetLocalGroupGetMembers](https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889)
* [ambyte's code for converting a mapped drive letter to a network path](https://gist.github.com/ambyte/01664dc7ee576f69042c)
* [Igor Korkhov's code to retrieve current token group information](https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418)
* [RobSiklos' snippet to determine if a host is a virtual machine](https://stackoverflow.com/questions/498371/how-to-detect-if-my-application-is-running-in-a-virtual-machine/11145280#11145280)
* [JGU's snippet on file/folder ACL right comparison](https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345)
* [Rod Stephens' pattern for recursive file enumeration](http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/)
* [SwDevMan81's snippet for enumerating current token privileges](https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni)
* [Jared Atkinson's PowerShell work on Kerberos ticket caches](https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1)
* [Vincent LE TOUX' great C# Kerberos work](https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950)
* [darkmatter08's Kerberos C# snippet](https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/)
* Numerous [PInvoke.net](https://www.pinvoke.net/) samples <3
* [Jared Hill's awesome CodeProject to use Local Security Authority to Enumerate User Sessions](https://www.codeproject.com/Articles/18179/Using-the-Local-Security-Authority-to-Enumerate-Us)
* [Fred's code on querying the ARP cache](https://social.technet.microsoft.com/Forums/lync/en-US/e949b8d6-17ad-4afc-88cd-0019a3ac9df9/powershell-alternative-to-arp-a?forum=ITCG)
* [ShuggyCoUk's snippet on querying the TCP connection table](https://stackoverflow.com/questions/577433/which-pid-listens-on-a-given-port-in-c-sharp/577660#577660)
* [yizhang82's example of using reflection to interact with COM objects through C#](https://gist.github.com/yizhang82/a1268d3ea7295a8a1496e01d60ada816)
* [@cmaddalena](https://twitter.com/cmaddalena)'s [SharpCloud project](https://github.com/chrismaddalena/SharpCloud), BSD 3-Clause
