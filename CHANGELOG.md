# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Added ability to specify custom admin port number

### Changed
- Disallow Administrators from changing other user's passwords
- Restrict non-admin users from visiting other user's profile in UI
- Updated ShellCode task to use file upload of raw binary
- Updated streaming tasks to autoflush the console
- Updated Keylogger to handle VK_PACKET virtual keys
- Update max LauncherString length in UI
- Changed Grunt ActivationTime and Events to not update on reconnected Lost grunt
- Lock task execution during upload, display upload load animation

### Fixed
- Fix edit roles for CovenantUser UI bug
- Fix profile bug when HttpGetResponse differs from HttpPostResponse
- Fix TaskKill display bug
- Fix token impersonation issues
- Fix streaming output to capture output after Delay time elapsed
- Fix streaming output does not capture exceptions issue
- Fix Keylogger task Delegate gets garbage collected
- Fix ImplantTemplate becomes null on GruntTable
- Fix P2P routing when disconnecting/reconnecting to same Grunt repeatedly
- Fixed and improved P2P stability for GruntSMB
- Fix streaming output immediate write for push implants (SMB/Bridge)
- Fix streaming output leftover buffer remaining output
- Fix Download Task adding extra byte to files
- Fix Download task exception on unexpected output
- Fix credential tracking missing some credentials
- Fix credential tracking missing Kerberos tickets
- Fixed missing DonutCore nuget package

## [v0.6] - 2020-08-04
### Added
- Added CreateDirectory task
- Add SharpSC submodule, ReferenceSourceLibrary, and GruntTask
- Added CreateProcessWithToken task
- Added aliases for Shell tasks
- Added ShellCodeLauncher using Donut
- Added Copy command
- Added missing Keylogger task
- Added streaming task output
- Added Download/Upload .NET Core Tasks
- Added ReadTextFile,CreateDirectory,Delete .NET Core Tasks
- Added UI Themes, new Heathen Mode theme
- Added a TabbedTerminal view to GruntIndex component
- Added message that Covenant has started

### Changed
- Add SharpSploit.LateralMovement namespace to SharpShell command
- Updated PowerShellRemoting tasks to show output
- Update implants to use WellKnownSidType enum rather than string for non-english systems
- Update all launchers to support non-http profiles
- Changed Shell tasks to use CreateProcess to get output
- Updated SharpSploit, Rubeus, Seatbelt ReferenceSourceLibaries to latest versions
- Simplified compilation optimization to use HashSet
- Limited compilation optimization for SharpSC
- Updated Seatbelt to latest version
- Updated SharpSploit to latest version, PowerShell task should include verbose/error output
- Changed GruntTask export to exclude GruntTaskOption value property
- Updated codemirror, added night theme for codemirror
- Removed Covenant certificate hash message

### Fixed
- Fixed order of Upload parameters
- Fixed Brute compilation path for case-sensitive file systems
- Fixed HttpPost issue on Linux servers
- Fixed Listeners stop issue
- Fixed Seatbelt command group suggestions
- Fixed EditGruntTask for task with aliases, validationmessage issue
- Fixed Task aliases to be able to be edited
- Fixed InstallUtil launcher
- Fixed PowerShellLauncher maxlength too short
- Fixed BridgeListener null exception on creation
- Fixed Dockerfile to use sdk for runtime
- Fixed ordering of deserialized GruntTask Options
- Fixed Assembly tasks to do command-line style parsing
- Updated YAML task file code options to use literal strings, may have been causing some problems
- Fixed parameter parsing bug when multiple trailing double-quotes
- Fixed command parameter parsing bug when multiple trailing double-quotes
- Fixed command parameter parsing bug when labeled parameter
- Fixed CovenantUser default properties set to null, not following OpenApi spec
- Fixed task aliases use incorrect case comparisons
- Fixed LauncherForm exception when no active listeners
- Fixed missing ReferenceAssemblies for SharpSploit
- Fixed WMICommand/WMIGrunt output format
- Fixed ConnectAttempts bug
- Fixed BridgeListener ArgumentOutOfRangeException
- Fix/tweak Connect/Disconnect tasks
- Fixed JwtKey issue
- Fixed ImplantTemplateForm options resetting issue
- Fixed terminal typeahead issues
- Fixed HttpProfile editing issue
- Fixed POST /api/users API endpoint authentication issue
- Fixed profiles using Cookie header
- Fixed profile using curly brace character
- Fix create/edit for ReferenceSourceLibraries,ReferenceAssemblies,EmbeddedResources
- Fix launcher commands (i.e. BypassUacGrunt, WMIGrunt, PowerShellRemotingGrunt)
- Fix Launcher properties not being applied during generation
- Fixed Graph with BridgeListener issue

## [v0.5] - 2020-06-04
### Added
- Added GetNetShare task
- Added Keylogger task
- Added Brute .NET Core implant
- Added .NET Core tasks: shell, shellcmd, ls, cd, ps, assembly
- Added GruntTask import/export ability

### Changed
- Improved ComputerName parsing and output for Domain tasks
- Upgraded to .NET Core 3.1
- Changed UI to use Blazor
- Changed profiles to use .NET Core 3.1
- Downloaded launchers filename set to implanttemplate name
- Update Dockerfile for .NET Core 3.1
- Moved GruntTasks to yaml files
- Changed delay/jitter/killdate commands to not use 'Set'

### Fixed
- Fixed missing http profiles on Ubuntu w/ workaround due to corefx issue
- Made changes necessary for C3 integration, allowing outbound SMB grunts
- Fixed missing http profiles on Ubuntu w/ workaround due to corefx issue
- Fix GET /api/gruntcommand/{id} endpoint missing output
- Fix #122 multiple connection addresses issue
- Fix #137 grunt last checked-in field sorting issue on table

## [v0.4] - 2019-10-30
### Added
- Added ShellRunAs and ShellCmdRunAs tasks
- Added GetCurrentDirectory task
- Added DCSync task
- Added ReadTextFile (cat) task
- Added support to supply CLI options via environment variables
- Added Delete (rm/del) task
- Added PowerShellRemotingCommand/PowerShellRemotingGrunt tasks
- Added Kill task
- Added /api/grunts/{id}/interact API endpoint
- Added BridgeListeners
- Added BridgeProfiles
- Added GruntBridge implant

### Changed
- Changed command-line parsing, Task parsing, added DefaultValue for optional parameters
- Changed DCOM, WMI, BypassUAC task handling
- Updated SharpSploit to latest version
- Changed PowerShellImport Task tab to use file control
- Changed PowerShellImport to strip PowerShell ISE magic header value
- Updated SharpSploit to latest version, updated powerkatz dlls
- Improved PortScan to accept port ranges
- Updated SharpSploit to latest version

### Fixed
- Fixed ConnectAttemptCount incrementing on valid response w/o a task
- Fixed null tasking display
- Fixed BindPort changes to ConnectPort on listener restart
- Fixed command-line parsing issues
- Fixed PersistAutorun option ordering
- Fixed ImpersonateProcess using wrong task code
- Fixed InstallUtilLauncher dll was base64 encoded when hosted
- Fixed SharpUp error when no CLI args provided
- Fixed Connect/Disconnect/Set/SharpShell error when using Task tab
- Fixed missing DefaultValues for Assembly and GhostPack tasks
- Fixed bug preventing files with the same name being hosted on different Listeners
- Fixed WMIGrunt adding executable name twice to command
- Fixed CapturedCredential parsing with ':' character
- Fixed change Grunt name, SetOption commands
- Fixed changing Grunt status to Exited
- Fixed SignalR GetInteract occasionally could not determine requesting username
- Fixed InstallUtil dll download output format

## [v0.3.2] - 2019-09-11
### Added
- Added PersistAutorun task, PersistStartup task, and PersistWMI task
- Added Screenshot task, added ScreenshotEvent
- Added displaying image for ScreenShot events/tasks in Grunt interact view, GruntTasking interact view, and Data view
- Added BypassAmsi task

### Changed
- Updated SharpSploit referencesourcelibrary
- Updated Rubeus referencesourcelibrary

### Fixed
- Fixed hosting files issue
- Fixed profile edit/create javascript issue

## [v0.3.1] - 2019-08-26
### Added
- Added codemirror code editing
- Added ability to hide a Grunt
- Added lost grunt calculations
- Added toast notifications on events
- Added multiple connectaddresses to HttpListener

### Changed
- Lost grunts faded in table
- Modularized Listeners to make adding new listener types easier

### Fixed
- Fixed Download task to work with remote downloads over shares
- ReferenceSourceLibraries converted back to git submodules
- Fix https URL calculation for Listener Create
- Fix SSLCertificate upload error

## [v0.3] - 2019-08-02
### Added
- Added web interface

### Changed
- Updated powerkatz dlls
- Reduced resource utilization

## [v0.2] - 2019-05-01
### Added
- Added p2p communications over SMB named pipes
- Added TaskingUser and TaskingCommand to GruntTaskings
- Added Elite display events on user tasking (prior to completed)
- Added better Elite error messages
- Added forked version of ReadLine, with better tab-complete
- Added change user password
- Added shellcmd task
- Added sharpdpapi task
- Added sharpup task
- Added sharpdump task
- Added sharpwmi task
- Added safetykatz task
- Added Seatbelt task
- Added remote registry tasks
- Added KillDate to launchers and grunts

### Changed
- Moved Eventing from Listeners/Elite to Covenant Controllers
- AdminPassword no longer encrypts certificate file, can be changed
- TaskMenu now displays full task description, detailed parameter info
- Updated SharpSploit code
- Tasks now catch Exceptions, return better error messages

### Fixed
- Fixed RegistryWrite Task
- Fixed Create user error message
- Fixed ssl certificate password error, no longer need to use CovenantDev

## [v0.1.3] - 2019-03-18
### Added
- Added Credential Manager and mimikatz/rubeus parser
- Added PrivExchange, PersistCOMHijack tasks

### Changed
- Split wmi, dcom, and bypassuac tasks to wmicommand, wmigrunt, dcomcommand, dcomgrunt, bypassuaccommand, bypassuacgrunt tasks
- Updated SharpSploit to latest commit
- Updated Rubeus to latest commit
- Changed Grunts to use CookieContainer WebClient for Cookie authentication

### Fixed
- Re-added missing appsettings.json, moved to Data folder
- Check for initialized submodules
- Fixed download task (missing folder)
- Fixed xls vs xsl typo

## [v0.1.2] - 2019-02-14
### Added
- Added Rubeus as a git submodule
- Added Rubeus task
- Added AssemblyReflect task
- Added 'ReferenceSourceLibrary' and 'EmbeddedResources' properties to GruntTask

### Changed
- Changed Assembly task to execute EntryPoint
- Changed SharpSploit source to a git submodule
- Changed Compiler source optimization
- Updated Microsoft.AspNetCore.App package version

### Fixed
- Fixed Assembly task

## [v0.1.1] - 2019-02-09
### Added
- Added CHANGELOG.md

### Changed
- Updated SharpSploit Mimikatz.cs source code

### Fixed
- Temporary fix for source code optimization removing "System" imports, causing issues with PortScan task

## [v0.1] - 2019-02-07
- Initial release

[v0.1.1]: https://github.com/cobbr/Covenant/compare/v0.1...v0.1.1
[v0.1.2]: https://github.com/cobbr/Covenant/compare/v0.1.1...v0.1.2
[v0.1.3]: https://github.com/cobbr/Covenant/compare/v0.1.2...v0.1.3
[v0.2]: https://github.com/cobbr/Covenant/compare/v0.1.3...v0.2
[v0.3]: https://github.com/cobbr/Covenant/compare/v0.2...v0.3
[v0.3.1]: https://github.com/cobbr/Covenant/compare/v0.3...v0.3.1
[v0.3.2]: https://github.com/cobbr/Covenant/compare/v0.3.1...v0.3.2
[v0.4]: https://github.com/cobbr/Covenant/compare/v0.3.2...v0.4
[v0.5]: https://github.com/cobbr/Covenant/compare/v0.4...v0.5
[v0.6]: https://github.com/cobbr/Covenant/compare/v0.5...v0.6
