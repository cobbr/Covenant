# SharpSploit - Quick Command Reference

## SharpSploit.Credentials

### SharpSploit.Credentials.Mimikatz

* `Command()` - Loads the Mimikatz PE with `PE.Load()` and executes a chosen Mimikatz command.
* `LogonPasswords()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve plaintext passwords from LSASS. Equates to `Command("privilege::debug sekurlsa::logonPasswords")`. (Requires Admin)
* `SamDump()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve password hashes from the SAM database. Equates to `Command("privilege::debug lsadump::sam")`. (Requires Admin)
* `LsaSecrets()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve LSA secrets stored in registry. Equates to `Command("privilege::debug lsadump::secrets")`. (Requires Admin)
* `LsaCache()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve Domain Cached Credentials hashes from registry. Equates to `Command("privilege::debug lsadump::cache")`. (Requires Admin)
* `Wdigest()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve Wdigest credentials from registry. Equates to `Command("sekurlsa::wdigest")`.
* `All()` - Loads the Mimikatz PE with `PE.Load()` and executes each of the above builtin, local credential dumping commands. (Requires Admin)
* `DCSync()` - Loads the Mimikatz PE with `PE.Load()` and executes the "dcsync" module to retrieve the NTLM hash of a specified (or all) Domain user. (Requires Domain Admin (or equivalent rights))
* `PassTheHash()` - Loads the Mimikatz PE with `PE.Load()` and executes the "pth" module to start a new process as a user using an NTLM password hash for authentication. (Requires Admin)

### SharpSploit.Credentials.Tokens

* `WhoAmI()` - Gets the username of the currently used/impersonated token.
* `ImpersonateUser()` - Impersonate the token of a process owned by the specified user. Used to execute subsequent commands as the specified user. (Requires Admin)
* `ImpersonateProcess()` - Impersonate the token of the specified process. Used to execute subsequent commands as the user associated with the token of the specified process. (Requires Admin)
* `GetSystem()` - Impersonate the SYSTEM user. Equates to `ImpersonateUser("NT AUTHORITY\SYSTEM")`. (Requires Admin)
* `BypassUAC()` - Bypasses UAC through token duplication and spawns a specified process with high integrity. (Requires Admin)
* `RunAs()` - Makes a new token to run a specified function as a specified user with a specified password. Automatically calls `RevertToSelf()` after executing the function.
* `MakeToken()` - Makes a new token with a specified username and password, and impersonates it to conduct future actions as the specified user.
* `RevertToSelf()` - Ends the impersonation of any token, reverting back to the initial token associated with the current process. Useful in conjuction with functions that impersonate a token and do not automatically RevertToSelf, such as: `ImpersonateUser()`, `ImpersonateProcess()`, `GetSystem()`, and `MakeToken()`.
* `EnableTokenPrivilege()` - Enables a specified security privilege for a specified token. (Requires Admin)

## SharpSploit.Enumeration

### SharpSploit.Enumeration.Host

* `GetProcessList()` - Gets a list of running processes on the system.
* `CreateProcessDump()` - Creates a minidump of the memory of a running process. Useful for offline Mimikatz if dumping the LSASS process. (Requires Admin)
* `GetHostname()` - Gets the hostname of the system.
* `GetUsername()` - Gets the current Domain and username of the process running.
* `GetCurrentDirectory()` - Gets the current working directory full path.
* `GetDirectoryListing()` - Gets a directory listing of the current working directory.
* `ChangeCurrentDirectory()` - Changes the current directory by appending a specified string to the current working directory.

### SharpSploit.Enumeration.Network

* `PortScan()` - Conducts a port scan of specified computer(s) and port(s) and reports open ports.
* `Ping()` - Pings specified computer(s) to identify live systems.

### SharpSploit.Enumeration.Domain

### SharpSploit.Enumeration.Domain.DomainSearcher

* `GetDomainUsers()` - Gets a list of specified (or all) user `DomainObject`s in the current Domain.
* `GetDomainGroups()` - Gets a list of specified (or all) group `DomainObject`s in the current Domain.
* `GetDomainComputers()` - Gets a list of specified (or all) computer `DomainObject`s in the current Domain.
* `GetDomainSPNTickets()` - Gets `SPNTicket`s for specified `DomainObject`s.
* `Kerberoast()` - Gets a list of `SPNTicket`s for specified (or all) users with a SPN set in the current Domain.

### SharpSploit.Enumeration.Net

* `GetNetLocalGroups()` - Gets a list of `LocalGroup`s from specified remote computer(s).
* `GetNetLocalGroupMembers()` - Gets a list of `LocalGroupMember`s from specified remote computer(s) for a specified group.
* `GetNetLoggedOnUsers()` - Gets a list of `LoggedOnUser`s from specified remote computer(s).
* `GetNetSessions()` - Gets a list of `SessionInfo`s from specified remote computer(s).

## SharpSploit.Execution

### SharpSploit.Execution.Assembly

* `Load()` - Loads a .NET assembly byte array or base64-encoded byte array.
* `AssemblyExecute()` - Loads a .NET assembly byte array or base64-encoded byte array and executes a specified method within a specified type with specified parameters using reflection.

### SharpSploit.Execution.PE

* `Load()` - Loads a PE with a specified byte array. (Requires Admin) **(*Currently broken. Works for Mimikatz, but not arbitrary PEs*)
* `GetFunctionExport()` - Get a pointer to an exported function in a loaded PE. The pointer can then be used to execute the function in the PE.

### SharpSploit.Execution.Shell

* `PowerShellExecute()` - Executes specified PowerShell code using System.Management.Automation.dll and bypasses AMSI, ScriptBlock Logging, and Module Logging (but not Transcription Logging).
* `ShellExecute()` - Executes a specified Shell command, optionally with an alternative username and password. Equates to `ShellExecuteWithPath(ShellCommand, "C:\\WINDOWS\\System32")`
* `ShellExecuteWithPath()` - Executes a specified Shell command from a specified directory, optoinally with an alternative username and password.

### SharpSploit.Execution.ShellCode

The `SharpSploit.Execution.ShellCode` class includes a method for executing shellcode. Shellcode execution is accomplished by copying it to pinned memory, modifying the memory permissions with `Win32.Kernel32.VirtualProtect()`, and executing with a .NET `delegate`.

The `SharpSploit.Execution.ShellCode` class includes the following primary function:

* `ShellCodeExecute()` - Executes a specified shellcode byte array by copying it to pinned memory, modifying the memory permissions with `Win32.Kernel32.VirtualProtect()`, and executing with a .NET `delegate`.

### SharpSploit.Execution.Win32

Win32 contains a large library of PInvoke signatures for Win32 API functions.

## SharpSploit.LateralMovement

### SharpSploit.LateralMovement.WMI

* `WMIExecute()` - Execute a process on a remote system with Win32_Process Create4 with specified credentials.