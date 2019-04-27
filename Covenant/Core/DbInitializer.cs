using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Collections.Generic;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Launchers;
using Covenant.Models.Listeners;
using Covenant.Models.Grunts;

namespace Covenant.Core
{
    public static class DbInitializer
    {
		public static void Initialize(CovenantContext context, UserManager<CovenantUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, Dictionary<int, CancellationTokenSource> cancellationTokens)
        {
            context.Database.EnsureCreated();

			InitializeListeners(context, cancellationTokens);
            InitializeLaunchers(context);
            InitializeTasks(context);
			InitializeRoles(roleManager);
            InitializeUsers(userManager, configuration);          
        }

		public static void InitializeListeners(CovenantContext context, Dictionary<int, CancellationTokenSource> cancellationTokens)
        {
            if (!context.ListenerTypes.Any())
            {
				context.ListenerTypes.Add(ListenerType.HttpListenerType);
                context.SaveChanges();
            }
            if (!context.Profiles.Any())
            {
                HttpProfile defaultProfile = HttpProfile.Create(Common.CovenantDefaultHttpProfile);
                int idNum = 1;
                defaultProfile.Id = idNum;
                context.Profiles.Add(defaultProfile);
                List<HttpProfile> profiles = Directory.GetFiles(Common.CovenantProfileDirectory, "*.yaml", SearchOption.AllDirectories)
                                                 .Where(F => F != Common.CovenantDefaultHttpProfile)
                                                 .Select(F => HttpProfile.Create(F))
                                                 .ToList();
                foreach (HttpProfile p in profiles)
                {
                    idNum++;
                    p.Id = idNum;
                    context.Profiles.Add(p);
                }
            }

			foreach (Listener l in context.Listeners.Where(L => L.Status == Listener.ListenerStatus.Active))
			{
                HttpProfile profile = (HttpProfile)context.Profiles.FirstOrDefault(HP => HP.Id == l.ProfileId);
                cancellationTokens[l.Id] = l.Start(profile);
			}
        }

        public static void InitializeLaunchers(CovenantContext context)
        {
            if (!context.Launchers.Any())
            {
                var launchers = new List<Launcher>
                {
                    new WmicLauncher(),
                    new Regsvr32Launcher(),
                    new MshtaLauncher(),
                    new CscriptLauncher(),
                    new WscriptLauncher(),
                    new InstallUtilLauncher(),
                    new MSBuildLauncher(),
                    new PowerShellLauncher(),
                    new BinaryLauncher()
                };
                foreach (Launcher l in launchers)
                {
                    context.Launchers.Add(l);
                }
            }
        }

        public static void InitializeTasks(CovenantContext context)
        {
            if (!context.GruntTasks.Any())
            {
				var GruntTasks = new List<GruntTask>
				{
					new GruntTask
					{
						Name = "Shell",
						Description = "Execute a Shell command.",
						ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
						Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Shell" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
                                Id = 1,
								Name = "ShellCommand",
								Description = "The ShellCommand to execute.",
								Value = "whoami"
							}
						}
					},
                    new GruntTask
                    {
                        Name = "ShellCmd",
                        Description = "Execute a Shell command using \"cmd.exe /c\"",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ShellCmd" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 2,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami"
                            }
                        }
                    },
                    new GruntTask
					{
						Name = "PowerShell",
						Description = "Execute a PowerShell command.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "PowerShell" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
                                Id = 3,
                                Name = "PowerShellCommand",
								Description = "The PowerShellCommand to execute.",
								Value = "Get-ChildItem Env:"
							}
						}
					},
                    new GruntTask
                    {
                        Name = "Assembly",
                        Description = "Execute a dotnet Assembly EntryPoint.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Assembly" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 4,
                                Name = "EncodedAssembly",
                                Description = "The Base64 encoded Assembly bytes.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 5,
                                Name = "Parameters",
                                Description = "The command-line parameters to pass to the assembly's EntryPoint.",
                                Value = ""
                            }
                        }
                    },
					new GruntTask
					{
						Name = "AssemblyReflect",
						Description = "Execute a dotnet Assembly method using reflection.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "AssemblyReflect" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
                                Id = 6,
                                Name = "EncodedAssembly",
								Description = "The Base64 encoded Assembly bytes.",
								Value = ""
							},
							new GruntTask.GruntTaskOption
							{
                                Id = 7,
                                Name = "TypeName",
								Description = "The name of the Type that contains the method to execute.",
								Value = ""
							},
							new GruntTask.GruntTaskOption
							{
                                Id = 8,
                                Name = "MethodName",
								Description = "The name of the method to execute.",
								Value = ""
							},
                            new GruntTask.GruntTaskOption
                            {
                                Id = 9,
                                Name = "Parameters",
                                Description = "The parameters to pass to the method.",
                                Value = ""
                            }
                        }
					},
					new GruntTask
					{
						Name = "ListDirectory",
						Description = "Get a listing of the current directory.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ListDirectory" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 10,
                                Name = "Path",
                                Description = "Directory to list.",
                                Value = "."
                            }
                        }
                    },
					new GruntTask
					{
						Name = "ChangeDirectory",
						Description = "Change the current directory.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ChangeDirectory" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
                                Id = 11,
                                Name = "Directory",
								Description = "Directory to change to.",
								Value = "."
							}
						}
					},
					new GruntTask
					{
						Name = "ProcessList",
						Description = "Get a list of currently running processes.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ProcessList" + ".task")),
						Options = new List<GruntTask.GruntTaskOption> { }
					},
					new GruntTask
					{
						Name = "Upload",
						Description = "Upload a file.",
                        ReferenceAssemblies = new List<string>(),
                        ReferenceSourceLibraries = new List<string>(),
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Upload" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
                                Id = 12,
                                Name = "FileName",
								Description = "Local file name to write to.",
                                Value = ""
							},
							new GruntTask.GruntTaskOption
							{
                                Id = 13,
                                Name = "FileContents",
								Description = "Base64 contents of the file to be written."
							}
						}
					},
					new GruntTask
                    {
                        Name = "Download",
                        Description = "Download a file.",
                        ReferenceAssemblies = new List<string>(),
                        ReferenceSourceLibraries = new List<string>(),
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Download" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 14,
                                Name = "FileName",
                                Description = "Remote file name to download.",
                                Value = ""
                            }
                        }
                    },
					new GruntTask
					{
						Name = "Mimikatz",
                        Description = "Execute a mimikatz command.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string> { "SharpSploit.Resources.powerkatz_x64.dll" },
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Mimikatz" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
                                Id = 15,
                                Name = "Command",
                                Description = "Mimikatz command to execute.",
								Value = "sekurlsa::logonPasswords"
							}
						}
                    },
                    new GruntTask
                    {
                        Name = "PortScan",
                        Description = "Perform a TCP port scan.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "PortScan" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 16,
                                Name = "ComputerNames",
                                Description = "ComputerName(s) to port scan. Can be a DNS name, IP address, or CIDR range.",
                                Value = "127.0.0.1"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 17,
                                Name = "Ports",
                                Description = "Ports to scan. Comma-delimited port list.",
                                Value = "80,443,445"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 18,
                                Name = "Ping",
                                Description = "Boolean, whether to ping hosts prior to port scanning.",
                                Value = "False"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Rubeus",
                        Description = "Use a rubeus command.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.DirectoryServices.AccountManagement.dll", "System.IdentityModel.dll" },
                        ReferenceSourceLibraries = new List<string> { "Rubeus" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Rubeus" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 19,
                                Name = "Command",
                                Description = "Rubeus command to execute.",
                                Value = "triage"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Kerberoast",
                        Description = "Perform a \"Kerberoast\" attack that retrieves crackable service tickets for Domain User's w/ an SPN set.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Kerberoast" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 20,
                                Name = "Usernames",
                                Description = "Username(s) to port scan. Comma-delimited username list.",
                                Value = "DOMAIN\\username1,DOMAIN\\username2"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 21,
                                Name = "HashFormat",
                                Description = "Format to output the hashes (\"Hashcat\" or \"John\").",
                                Value = "Hashcat"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SafetyKatz",
                        Description = "Use SafetyKatz.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string> { "SharpSploit.Resources.powerkatz_x64.dll" },
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SafetyKatz" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "SharpDPAPI",
                        Description = "Use a SharpDPAPI command.",
                        ReferenceAssemblies = new List<string>(),
                        ReferenceSourceLibraries = new List<string> { "SharpDPAPI" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SharpDPAPI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 22,
                                Name = "Command",
                                Description = "SharpDPAPI command to execute.",
                                Value = "triage"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SharpUp",
                        Description = "Use a SharpUp command.",
                        ReferenceAssemblies = new List<string> { "System.ServiceProcess.dll", "System.Management.dll", "System.XML.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpUp" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SharpUp" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 23,
                                Name = "Command",
                                Description = "SharpUp command to execute.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SharpDump",
                        Description = "Use a SharpDump command.",
                        ReferenceAssemblies = new List<string>(),
                        ReferenceSourceLibraries = new List<string> { "SharpDump" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SharpDump" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 24,
                                Name = "ProcessID",
                                Description = "ProcessID of the process to createa dump file of.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Seatbelt",
                        Description = "Use a Seatbelt command.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.Management.dll", "System.ServiceProcess.dll", "System.XML.dll", "System.Web.Extensions.dll" },
                        ReferenceSourceLibraries = new List<string> { "Seatbelt" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Seatbelt" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 25,
                                Name = "Command",
                                Description = "Seatbelt command to execute.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SharpWMI",
                        Description = "Use a SharpWMI command.",
                        ReferenceAssemblies = new List<string> { "System.Management.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpWMI" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SharpWMI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 26,
                                Name = "Command",
                                Description = "SharpWMI command to execute.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "WhoAmI",
                        Description = "Gets the username of the currently used/impersonated token.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "WhoAmI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "ImpersonateUser",
                        Description = "Find a process owned by the specified user and impersonate the token. Used to execute subsequent commands as the specified user.",
                        TokenTask = true,
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ImpersonateUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 27,
                                Name = "Username",
                                Description = "User to impersonate. \"DOMAIN\\Username\" format expected.",
                                Value = "DOMAIN\\Username"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ImpersonateProcess",
                        Description = "Impersonate the token of the specified process. Used to execute subsequent commands as the user associated with the token of the specified process.",
                        TokenTask = true,
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ImpersonateUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 28,
                                Name = "ProcessID",
                                Description = "Process ID of the process to impersonate.",
                                Value = "1234"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetSystem",
                        Description = "Impersonate the SYSTEM user. Equates to ImpersonateUser(\"NT AUTHORITY\\SYSTEM\").",
                        TokenTask = true,
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetSystem" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "MakeToken",
                        Description = "Makes a new token with a specified username and password, and impersonates it to conduct future actions as the specified user.",
                        TokenTask = true,
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "MakeToken" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 29,
                                Name = "Username",
                                Description = "Username to authenticate as.",
                                Value = "username1"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 30,
                                Name = "Domain",
                                Description = "Domain to authenticate the user to.",
                                Value = "DOMAIN"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 31,
                                Name = "Password",
                                Description = "Password to authenticate the user.",
                                Value = "Password123"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 32,
                                Name = "LogonType",
                                Description = "LogonType to use. Defaults to LOGON32_LOGON_NEW_CREDENTIALS, which is suitable to perform actions that require remote authentication. LOGON32_LOGON_INTERACTIVE is suitable for local actions.",
                                Value = "LOGON32_LOGON_NEW_CREDENTIALS"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "RevertToSelf",
                        Description = "Ends the impersonation of any token, reverting back to the initial token associated with the current process. Useful in conjuction with functions impersonate a token and do not automatically RevertToSelf, such as ImpersonateUser(), ImpersonateProcess(), GetSystem(), and MakeToken().",
                        TokenTask = true,
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "RevertToSelf" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "WMICommand",
                        Description = "Execute a process on a remote system using Win32_Process Create, optionally with alternate credentials.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "WMI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 33,
                                Name = "ComputerName",
                                Description = "ComputerName to create the process on.",
                                Value = "localhost"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 34,
                                Name = "Command",
                                Description = "Command line to execute on the remote system.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 35,
                                Name = "Username",
                                Description = "Username to authenticate as. Format: DOMAIN\\Username (optional)",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 36,
                                Name = "Password",
                                Description = "Password to authenticate the user. (optional)",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "WMIGrunt",
                        Description = "Execute a Grunt Launcher on a remote system using Win32_Process Create, optionally with alternate credentials.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "WMI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 37,
                                Name = "ComputerName",
                                Description = "ComputerName to launch the Grunt on.",
                                Value = "localhost"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 38,
                                Name = "Launcher",
                                Description = "Grunt Launcher to execute on the remote system.",
                                Value = "PowerShell"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 39,
                                Name = "Username",
                                Description = "Username to authenticate as. Format: DOMAIN\\Username (optional)",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 40,
                                Name = "Password",
                                Description = "Password to authenticate the user. (optional)",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "DCOMCommand",
                        Description = "Execute a process on a remote system using various DCOM methods.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "DCOM" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 41,
                                Name = "ComputerName",
                                Description = "ComputerName to execute the process on.",
                                Value = "localhost"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 42,
                                Name = "Command",
                                Description = "Command line to execute on the remote system.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 43,
                                Name = "Method",
                                Description = "DCOM method to use for execution.",
                                Value = "MMC20.Application"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "DCOMGrunt",
                        Description = "Execute a Grunt Launcher on a remote system using various DCOM methods.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "DCOM" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 44,
                                Name = "ComputerName",
                                Description = "ComputerName to execute the process on.",
                                Value = "locate"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 45,
                                Name = "Launcher",
                                Description = "Grunt Launcher to execute on the remote system.",
                                Value = "PowerShell"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 46,
                                Name = "Method",
                                Description = "DCOM method to use for execution.",
                                Value = "MMC20.Application"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "BypassUACCommand",
                        Description = "Bypasses UAC through token duplication and executes a command with high integrity.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "BypassUAC" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 47,
                                Name = "Command",
                                Description = "Command to execute with high integrity.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "BypassUACGrunt",
                        Description = "Bypasses UAC through token duplication and executes a Grunt Launcher with high integrity.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "BypassUAC" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 48,
                                Name = "Launcher",
                                Description = "Launcher to execute with high integrity.",
                                Value = "PowerShell"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetDomainUser",
                        Description = "Gets a list of specified (or all) user `DomainObject`s in the current Domain.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetDomainUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 49,
                                Name = "Identities",
                                Description = "List of comma-delimited usernames to retrieve.",
                                Value = "username"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetDomainGroup",
                        Description = "Gets a list of specified (or all) group `DomainObject`s in the current Domain.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetDomainGroup" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 50,
                                Name = "Identities",
                                Description = "List of comma-delimited groups to retrieve.",
                                Value = "Domain Admins"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetDomainComputer",
                        Description = "Gets a list of specified (or all) computer `DomainObject`s in the current Domain.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetDomainComputer" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 51,
                                Name = "Identities",
                                Description = "List of comma-delimited computers to retrieve.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetLocalGroup",
                        Description = "Gets a list of `LocalGroup`s from specified remote computer(s).",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetLocalGroup" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 52,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetLocalGroupMember",
                        Description = "Gets a list of `LocalGroupMember`s from specified remote computer(s).",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetLocalGroupMember" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 53,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 54,
                                Name = "LocalGroup",
                                Description = "LocalGroup name to query for members.",
                                Value = "Administrators"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetLoggedOnUser",
                        Description = "Gets a list of `LoggedOnUser`s from specified remote computer(s).",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetLoggedOnUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 55,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetSession",
                        Description = "Gets a list of `SessionInfo`s from specified remote computer(s).",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetSession" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 56,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetRegistryKey",
                        Description = "Gets a value stored in registry.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetRegistryKey" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 57,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SetRegistryKey",
                        Description = "Sets a value into the registry.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SetRegistryKey" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 58,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 59,
                                Name = "Value",
                                Description = "The value to write to the registry key.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetRemoteRegistryKey",
                        Description = "Gets a value stored in registry on a remote system.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetRemoteRegistryKey" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 60,
                                Name = "Hostname",
                                Description = "The Hostname of the remote system to query.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 61,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SetRemoteRegistryKey",
                        Description = "Sets a value into the registry on a remote system.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "SetRemoteRegistryKey" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 62,
                                Name = "Hostname",
                                Description = "The Hostname of the remote system to write to.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 63,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                Id = 64,
                                Name = "Value",
                                Description = "The value to write to the registry key.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ShellCode",
                        Description = "Executes a specified shellcode byte array by copying it to pinned memory, modifying the memory permissions, and executing.",
                        ReferenceAssemblies = new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" },
                        ReferenceSourceLibraries = new List<string> { "SharpSploit" },
                        EmbeddedResources = new List<string>(),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ShellCode" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                Id = 65,
                                Name = "Hex",
                                Description = "Hex string representing the Shellcode bytes to execute.",
                                Value = ""
                            }
                        }
                    }
                };

                foreach (GruntTask task in GruntTasks)
                {
                    context.GruntTasks.Add(task);
                }
            }
        }

		public static async void InitializeRoles(RoleManager<IdentityRole> roleManager)
        {
			List<string> roles = new List<string> { "Administrator", "User", "Listener" };
			foreach (string role in roles)
			{
				if (!(await roleManager.RoleExistsAsync(role)))
				{
					IdentityResult roleResult = await roleManager.CreateAsync(new IdentityRole(role));
				}
			}
        }

		public static async void InitializeUsers(UserManager<CovenantUser> userManager, IConfiguration configuration)
        {
			CovenantUser existing = await userManager.FindByNameAsync(configuration["CovenantUsername"]);
			if (existing == null)
			{
				CovenantUser user = new CovenantUser { UserName = configuration["CovenantUsername"] };
				IdentityResult userResult = await userManager.CreateAsync(user, configuration["CovenantPassword"]);
				await userManager.AddToRoleAsync(user, "User");
				await userManager.AddToRoleAsync(user, "Administrator");
			}
        }
    }
}
