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
using Covenant.Core;

namespace Covenant.Data
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
						Id = 1,
						Name = "Shell",
						Description = "Execute a Shell command.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
						Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Shell" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
								TaskId = 1,
								OptionId = 1,
								Name = "ShellCommand",
								Description = "The ShellCommand to execute.",
								Value = "whoami"
							}
						}
					},
					new GruntTask
					{
						Id = 2,
						Name = "PowerShell",
						Description = "Execute a PowerShell command.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "PowerShell" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
								TaskId = 2,
								OptionId = 1,
								Name = "PowerShellCommand",
								Description = "The PowerShellCommand to execute.",
								Value = "Get-ChildItem Env:"
							}
						}
					},
                    new GruntTask
                    {
                        Id = 3,
                        Name = "Assembly",
                        Description = "Execute a dotnet Assembly EntryPoint.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Assembly" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 3,
                                OptionId = 1,
                                Name = "EncodedAssembly",
                                Description = "The Base64 encoded Assembly bytes.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 3,
                                OptionId = 2,
                                Name = "Parameters",
                                Description = "The command-line parameters to pass to the assembly's EntryPoint.",
                                Value = ""
                            }
                        }
                    },
					new GruntTask
					{
						Id = 4,
						Name = "AssemblyReflect",
						Description = "Execute a dotnet Assembly method using reflection.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "AssemblyReflect" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
								TaskId = 4,
								OptionId = 1,
								Name = "EncodedAssembly",
								Description = "The Base64 encoded Assembly bytes.",
								Value = ""
							},
							new GruntTask.GruntTaskOption
							{
								TaskId = 4,
								OptionId = 2,
								Name = "TypeName",
								Description = "The name of the Type that contains the method to execute.",
								Value = ""
							},
							new GruntTask.GruntTaskOption
							{
								TaskId = 4,
								OptionId = 3,
								Name = "MethodName",
								Description = "The name of the method to execute.",
								Value = ""
							},
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 4,
                                OptionId = 4,
                                Name = "Parameters",
                                Description = "The parameters to pass to the method.",
                                Value = ""
                            }
                        }
					},
					new GruntTask
					{
						Id = 5,
						Name = "ListDirectory",
						Description = "Get a listing of the current directory.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ListDirectory" + ".task")),
						Options = new List<GruntTask.GruntTaskOption> { }
					},
					new GruntTask
					{
						Id = 6,
						Name = "ChangeDirectory",
						Description = "Change the current directory.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ChangeDirectory" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
								TaskId = 6,
								OptionId = 1,
								Name = "AppendDirectory",
								Description = "Directory to change to.",
								Value = "."
							}
						}
					},
					new GruntTask
					{
						Id = 7,
						Name = "ProcessList",
						Description = "Get a list of currently running processes.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ProcessList" + ".task")),
						Options = new List<GruntTask.GruntTaskOption> { }
					},
					new GruntTask
					{
						Id = 8,
						Name = "Upload",
						Description = "Upload a file.",
						ReferenceAssemblies = String.Join(",", new List<string>()),
                        ReferenceSourceLibraries = String.Join(",", new List<string>()),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Upload" + ".task")),
						Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
								TaskId = 8,
                                OptionId = 1,
                                Name = "FileName",
								Description = "Local file name to write to.",
                                Value = ""
							},
							new GruntTask.GruntTaskOption
							{
								TaskId = 8,
								OptionId = 2,
                                Name = "FileContents",
								Description = "Base64 contents of the file to be written."
							}
						}
					},
					new GruntTask
                    {
						Id = 9,
                        Name = "Download",
                        Description = "Download a file.",
                        ReferenceAssemblies = String.Join(",", new List<string>()),
                        ReferenceSourceLibraries = String.Join(",", new List<string>()),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Download" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 9,
                                OptionId = 1,
                                Name = "FileName",
                                Description = "Remote file name to download.",
                                Value = ""
                            }
                        }
                    },
					new GruntTask
					{
						Id = 10,
						Name = "Mimikatz",
                        Description = "Execute a mimikatz command.",
						ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string> { "SharpSploit.Resources.powerkatz_x64.dll" }),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Mimikatz" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
						{
							new GruntTask.GruntTaskOption
							{
								TaskId = 10,
                                OptionId = 1,
                                Name = "Command",
                                Description = "Mimikatz command to execute.",
								Value = "sekurlsa::logonPasswords"
							}
						}
                    },
                    new GruntTask
                    {
                        Id = 11,
                        Name = "PortScan",
                        Description = "Perform a TCP port scan.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "PortScan" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 11,
                                OptionId = 1,
                                Name = "ComputerNames",
                                Description = "ComputerName(s) to port scan. Can be a DNS name, IP address, or CIDR range.",
                                Value = "127.0.0.1"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 11,
                                OptionId = 2,
                                Name = "Ports",
                                Description = "Ports to scan. Comma-delimited port list.",
                                Value = "80,443,445"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 11,
                                OptionId = 3,
                                Name = "Ping",
                                Description = "Boolean, whether to ping hosts prior to port scanning.",
                                Value = "False"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 12,
                        Name = "Rubeus",
                        Description = "Use a rubeus command.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.DirectoryServices.AccountManagement.dll", "System.IdentityModel.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "Rubeus" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Rubeus" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 12,
                                OptionId = 1,
                                Name = "Command",
                                Description = "Rubeus command to execute.",
                                Value = "triage"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 13,
                        Name = "Kerberoast",
                        Description = "Perform a \"Kerberoast\" attack that retrieves crackable service tickets for Domain User's w/ an SPN set.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "Kerberoast" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 13,
                                OptionId = 1,
                                Name = "Usernames",
                                Description = "Username(s) to port scan. Comma-delimited username list.",
                                Value = "DOMAIN\\username1,DOMAIN\\username2"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 13,
                                OptionId = 2,
                                Name = "HashFormat",
                                Description = "Format to output the hashes (\"Hashcat\" or \"John\").",
                                Value = "Hashcat"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 14,
                        Name = "WhoAmI",
                        Description = "Gets the username of the currently used/impersonated token.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "WhoAmI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Id = 15,
                        Name = "ImpersonateUser",
                        Description = "Find a process owned by the specified user and impersonate the token. Used to execute subsequent commands as the specified user.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ImpersonateUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 15,
                                OptionId = 1,
                                Name = "Username",
                                Description = "User to impersonate. \"DOMAIN\\Username\" format expected.",
                                Value = "DOMAIN\\Username"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 16,
                        Name = "ImpersonateProcess",
                        Description = "Impersonate the token of the specified process. Used to execute subsequent commands as the user associated with the token of the specified process.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ImpersonateUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 16,
                                OptionId = 1,
                                Name = "ProcessID",
                                Description = "Process ID of the process to impersonate.",
                                Value = "1234"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 17,
                        Name = "GetSystem",
                        Description = "Impersonate the SYSTEM user. Equates to ImpersonateUser(\"NT AUTHORITY\\SYSTEM\").",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetSystem" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Id = 18,
                        Name = "MakeToken",
                        Description = "Makes a new token with a specified username and password, and impersonates it to conduct future actions as the specified user.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "MakeToken" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 18,
                                OptionId = 1,
                                Name = "Username",
                                Description = "Username to authenticate as.",
                                Value = "username1"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 18,
                                OptionId = 2,
                                Name = "Domain",
                                Description = "Domain to authenticate the user to.",
                                Value = "DOMAIN"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 18,
                                OptionId = 3,
                                Name = "Password",
                                Description = "Password to authenticate the user.",
                                Value = "Password123"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 18,
                                OptionId = 4,
                                Name = "LogonType",
                                Description = "LogonType to use. Defaults to LOGON32_LOGON_NEW_CREDENTIALS, which is suitable to perform actions that require remote authentication. LOGON32_LOGON_INTERACTIVE is suitable for local actions.",
                                Value = "LOGON32_LOGON_NEW_CREDENTIALS"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 19,
                        Name = "RevertToSelf",
                        Description = "Ends the impersonation of any token, reverting back to the initial token associated with the current process. Useful in conjuction with functions impersonate a token and do not automatically RevertToSelf, such as ImpersonateUser(), ImpersonateProcess(), GetSystem(), and MakeToken().",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "RevertToSelf" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Id = 20,
                        Name = "WMI",
                        Description = "Execute a process on a remote system using Win32_Process Create with specified credentials.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "WMI" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 20,
                                OptionId = 1,
                                Name = "ComputerName",
                                Description = "Username to authenticate as.",
                                Value = "192.168.1.1"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 20,
                                OptionId = 2,
                                Name = "Username",
                                Description = "Username to authenticate as.",
                                Value = "DOMAIN\\Username"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 20,
                                OptionId = 3,
                                Name = "Password",
                                Description = "Password to authenticate the user.",
                                Value = "Password123"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 20,
                                OptionId = 4,
                                Name = "Launcher",
                                Description = "Launcher to execute on the remote system.",
                                Value = "PowerShell"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 20,
                                OptionId = 5,
                                Name = "Command",
                                Description = "Command line to execute on the remote system.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 21,
                        Name = "DCOM",
                        Description = "Execute a process on a remote system using various DCOM methods.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "DCOM" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 21,
                                OptionId = 1,
                                Name = "ComputerName",
                                Description = "Username to authenticate as.",
                                Value = "192.168.1.1"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 21,
                                OptionId = 2,
                                Name = "Launcher",
                                Description = "Launcher to execute on the remote system.",
                                Value = "PowerShell"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 21,
                                OptionId = 3,
                                Name = "Command",
                                Description = "Command line to execute on the remote system.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 21,
                                OptionId = 4,
                                Name = "Method",
                                Description = "DCOM method to use for execution.",
                                Value = "MMC20.Application"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 22,
                        Name = "BypassUAC",
                        Description = "Bypasses UAC through token duplication and spawns a specified process with high integrity.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "BypassUAC" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 22,
                                OptionId = 1,
                                Name = "Launcher",
                                Description = "Launcher to execute on the remote system.",
                                Value = "PowerShell"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 22,
                                OptionId = 2,
                                Name = "Command",
                                Description = "Launcher to execute on the remote system.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 23,
                        Name = "GetDomainUser",
                        Description = "Gets a list of specified (or all) user `DomainObject`s in the current Domain.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetDomainUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 23,
                                OptionId = 1,
                                Name = "Identities",
                                Description = "List of comma-delimited usernames to retrieve.",
                                Value = "username"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 24,
                        Name = "GetDomainGroup",
                        Description = "Gets a list of specified (or all) group `DomainObject`s in the current Domain.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetDomainGroup" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 24,
                                OptionId = 1,
                                Name = "Identities",
                                Description = "List of comma-delimited groups to retrieve.",
                                Value = "Domain Admins"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 25,
                        Name = "GetDomainComputer",
                        Description = "Gets a list of specified (or all) computer `DomainObject`s in the current Domain.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetDomainComputer" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 25,
                                OptionId = 1,
                                Name = "Identities",
                                Description = "List of comma-delimited computers to retrieve.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 26,
                        Name = "GetNetLocalGroup",
                        Description = "Gets a list of `LocalGroup`s from specified remote computer(s).",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetLocalGroup" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 26,
                                OptionId = 1,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 27,
                        Name = "GetNetLocalGroupMember",
                        Description = "Gets a list of `LocalGroupMember`s from specified remote computer(s).",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetLocalGroupMember" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 27,
                                OptionId = 1,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 27,
                                OptionId = 2,
                                Name = "LocalGroup",
                                Description = "LocalGroup name to query for members.",
                                Value = "Administrators"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 28,
                        Name = "GetNetLoggedOnUser",
                        Description = "Gets a list of `LoggedOnUser`s from specified remote computer(s).",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetLoggedOnUser" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 28,
                                OptionId = 1,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 29,
                        Name = "GetNetSession",
                        Description = "Gets a list of `SessionInfo`s from specified remote computer(s).",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "GetNetSession" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 29,
                                OptionId = 1,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 30,
                        Name = "RegistryRead",
                        Description = "Reads a value stored in registry.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "RegistryRead" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 30,
                                OptionId = 1,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 31,
                        Name = "RegistryWrite",
                        Description = "Writes a value into the registry.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "RegistryWrite" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 31,
                                OptionId = 1,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 31,
                                OptionId = 2,
                                Name = "Value",
                                Description = "The value to write to the registry key.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 32,
                        Name = "ShellCode",
                        Description = "Executes a specified shellcode byte array by copying it to pinned memory, modifying the memory permissions, and executing.",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.DirectoryServices.dll", "System.IdentityModel.dll", "System.Management.dll", "System.Management.Automation.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        EmbeddedResources = String.Join(",", new List<string>()),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ShellCode" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 32,
                                OptionId = 1,
                                Name = "Hex",
                                Description = "Hex string representing the Shellcode bytes to execute.",
                                Value = ""
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 33,
                        Name = "PrivExchange",
                        Description = "Performs the PrivExchange attack by sending a push notification to EWS",
                        ReferenceAssemblies = String.Join(",", new List<string> { "System.XML.dll" }),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "PrivExchange" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 1,
                                Name = "TargetHost",
                                Description = "Set the IP of the target's Exchange server.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 2,
                                Name = "AttackerHost",
                                Description = "Set the attaccker's IP.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 3,
                                Name = "AttackerPort",
                                Description = "Set the attacker's port.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 4,
                                Name = "AttackerPage",
                                Description = "Set the attacker's page.",
                                Value = "SharpPriv"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 5,
                                Name = "SSL",
                                Description = "Enable SSL.",
                                Value = "true"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 6,
                                Name = "ExchangeVersion",
                                Description = "Set the Exchange's version.",
                                Value = "2016"
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 33,
                                OptionId = 7,
                                Name = "ExchangePort",
                                Description = "Set the Exchange's target port.",
                                Value = "443"
                            }
                        }
                    },
                    new GruntTask
                    {
                        Id = 34,
                        Name = "ComHijackPersist",
                        Description = "Achieve persistence via COM hijacking",
                        ReferenceAssemblies = String.Join(",", new List<string>()),
                        ReferenceSourceLibraries = String.Join(",", new List<string> { "SharpSploit" }),
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskDirectory, "ComHijackPersist" + ".task")),
                        Options = new List<GruntTask.GruntTaskOption>
                        {
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 34,
                                OptionId = 1,
                                Name = "CLSID",
                                Description = "Set the missing CLSID.",
                                Value = ""
                            },
                            new GruntTask.GruntTaskOption
                            {
                                TaskId = 34,
                                OptionId = 2,
                                Name = "Path",
                                Description = "Set the path to the payload.",
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
