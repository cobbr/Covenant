// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Microsoft.AspNetCore.Identity;

using Covenant.Models;
using Covenant.Models.Launchers;
using Covenant.Models.Listeners;
using Covenant.Models.Grunts;

namespace Covenant.Core
{
    public static class DbInitializer
    {
        public async static Task Initialize(ICovenantService service, CovenantContext context, RoleManager<IdentityRole> roleManager, ConcurrentDictionary<int, CancellationTokenSource> ListenerCancellationTokens)
        {
            await InitializeListeners(service, context, ListenerCancellationTokens);
            await InitializeImplantTemplates(service, context);
            await InitializeLaunchers(service, context);
            await InitializeTasks(service, context);
            await InitializeRoles(roleManager);
        }

        public async static Task InitializeImplantTemplates(ICovenantService service, CovenantContext context)
        {
            if (!context.ImplantTemplates.Any())
            {
                var templates = new ImplantTemplate[]
                {
                    new ImplantTemplate
                    {
                        Name = "GruntHTTP",
                        Description = "A Windows implant written in C# that communicates over HTTP.",
                        Language = ImplantLanguage.CSharp,
                        CommType = CommunicationType.HTTP,
                        ImplantDirection = ImplantDirection.Pull,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ImplantTemplate
                    {
                        Name = "GruntSMB",
                        Description = "A Windows implant written in C# that communicates over SMB.",
                        Language = ImplantLanguage.CSharp,
                        CommType = CommunicationType.SMB,
                        ImplantDirection = ImplantDirection.Push,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ImplantTemplate
                    {
                        Name = "GruntBridge",
                        Description = "A customizable implant written in C# that communicates with a custom C2Bridge.",
                        Language = ImplantLanguage.CSharp,
                        CommType = CommunicationType.Bridge,
                        ImplantDirection = ImplantDirection.Push,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ImplantTemplate
                    {
                        Name = "Brute",
                        Description = "A cross-platform implant built on .NET Core 3.0.",
                        Language = ImplantLanguage.CSharp,
                        CommType = CommunicationType.HTTP,
                        ImplantDirection = ImplantDirection.Pull,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 }
                    }
                };
                templates.ToList().ForEach(t => t.ReadFromDisk());
                await service.CreateImplantTemplates(templates);

                await service.CreateEntities(
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await service.GetListenerTypeByName("HTTP"),
                        ImplantTemplate = await service.GetImplantTemplateByName("GruntHTTP")
                    },
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await service.GetListenerTypeByName("HTTP"),
                        ImplantTemplate = await service.GetImplantTemplateByName("GruntSMB")
                    },
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await service.GetListenerTypeByName("Bridge"),
                        ImplantTemplate = await service.GetImplantTemplateByName("GruntBridge")
                    },
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await service.GetListenerTypeByName("Bridge"),
                        ImplantTemplate = await service.GetImplantTemplateByName("GruntSMB")
                    },
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await service.GetListenerTypeByName("HTTP"),
                        ImplantTemplate = await service.GetImplantTemplateByName("Brute")
                    }
                );
            }
        }

        public async static Task InitializeListeners(ICovenantService service, CovenantContext context, ConcurrentDictionary<int, CancellationTokenSource> ListenerCancellationTokens)
        {
            if (!context.ListenerTypes.Any())
            {
                await service.CreateEntities<ListenerType>(
                    new ListenerType { Name = "HTTP", Description = "Listens on HTTP protocol." },
                    new ListenerType { Name = "Bridge", Description = "Creates a C2 Bridge for custom listeners." }
                );
            }
            if (!context.Profiles.Any())
            {
                string[] files = Directory.GetFiles(Common.CovenantProfileDirectory, "*.yaml", SearchOption.AllDirectories);
                HttpProfile[] httpProfiles = files.Where(F => F.Contains("HTTP", StringComparison.CurrentCultureIgnoreCase))
                    .Select(F => HttpProfile.Create(F))
                    .ToArray();
                BridgeProfile[] bridgeProfiles = files.Where(F => F.Contains("Bridge", StringComparison.CurrentCultureIgnoreCase))
                    .Select(F => BridgeProfile.Create(F))
                    .ToArray();
                await service.CreateProfiles(httpProfiles);
                await service.CreateProfiles(bridgeProfiles);
            }
            var listeners = (await service.GetListeners()).Where(L => L.Status == ListenerStatus.Active);

            foreach (Listener l in listeners)
            {
                l.Profile = await service.GetProfile(l.ProfileId);
                await service.StartListener(l.Id);
            }
        }

        public async static Task InitializeLaunchers(ICovenantService service, CovenantContext context)
        {
            if (!context.Launchers.Any())
            {
                var launchers = new Launcher[]
                {
                    new BinaryLauncher(),
                    new PowerShellLauncher(),
                    new MSBuildLauncher(),
                    new InstallUtilLauncher(),
                    new WmicLauncher(),
                    new Regsvr32Launcher(),
                    new MshtaLauncher(),
                    new CscriptLauncher(),
                    new WscriptLauncher()
                };
                await service.CreateEntities(launchers);
            }
        }

        public async static Task InitializeTasks(ICovenantService service, CovenantContext context)
        {
            if (!context.ReferenceAssemblies.Any())
            {
                List<ReferenceAssembly> ReferenceAssemblies = Directory.GetFiles(Common.CovenantAssemblyReferenceNet35Directory).Select(R =>
                {
                    FileInfo info = new FileInfo(R);
                    return new ReferenceAssembly
                    {
                        Name = info.Name,
                        Location = info.FullName,
                        DotNetVersion = Common.DotNetVersion.Net35
                    };
                }).ToList();
                Directory.GetFiles(Common.CovenantAssemblyReferenceNet40Directory).ToList().ForEach(R =>
                {
                    FileInfo info = new FileInfo(R);
                    ReferenceAssemblies.Add(new ReferenceAssembly
                    {
                        Name = info.Name,
                        Location = info.FullName,
                        DotNetVersion = Common.DotNetVersion.Net40
                    });
                });
                await service.CreateReferenceAssemblies(ReferenceAssemblies.ToArray());
            }
            if (!context.EmbeddedResources.Any())
            {
                EmbeddedResource[] EmbeddedResources = Directory.GetFiles(Common.CovenantEmbeddedResourcesDirectory).Select(R =>
                {
                    FileInfo info = new FileInfo(R);
                    return new EmbeddedResource
                    {
                        Name = info.Name,
                        Location = info.FullName
                    };
                }).ToArray();
                await service.CreateEmbeddedResources(EmbeddedResources);
            }

            #region ReferenceSourceLibraries
            if (!context.ReferenceSourceLibraries.Any())
            {
                var ReferenceSourceLibraries = new ReferenceSourceLibrary[]
                {
                    new ReferenceSourceLibrary
                    {
                        Name = "SharpSploit", Description = "SharpSploit is a library for C# post-exploitation modules.",
                        Location = Common.CovenantReferenceSourceLibraries + "SharpSploit" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ReferenceSourceLibrary
                    {
                        Name = "Rubeus", Description = "Rubeus is a C# toolset for raw Kerberos interaction and abuses.",
                        Location = Common.CovenantReferenceSourceLibraries + "Rubeus" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ReferenceSourceLibrary
                    {
                        Name = "Seatbelt", Description = "Seatbelt is a C# project that performs a number of security oriented host-survey \"safety checks\" relevant from both offensive and defensive security perspectives.",
                        Location = Common.CovenantReferenceSourceLibraries + "Seatbelt" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ReferenceSourceLibrary
                    {
                        Name = "SharpDPAPI", Description = "SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.",
                        Location = Common.CovenantReferenceSourceLibraries + "SharpDPAPI" + Path.DirectorySeparatorChar + "SharpDPAPI" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    // new ReferenceSourceLibrary
                    // {
                    //     Name = "SharpChrome", Description = "SharpChrome is a C# port of some Mimikatz DPAPI functionality targeting Google Chrome.",
                    //     Location = Common.CovenantReferenceSourceLibraries + "SharpDPAPI" + Path.DirectorySeparatorChar + "SharpChrome" + Path.DirectorySeparatorChar,
                    //     SupportedDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    // },
                    new ReferenceSourceLibrary
                    {
                        Name = "SharpDump", Description = "SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.",
                        Location = Common.CovenantReferenceSourceLibraries + "SharpDump" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ReferenceSourceLibrary
                    {
                        Name = "SharpUp", Description = "SharpUp is a C# port of various PowerUp functionality.",
                        Location = Common.CovenantReferenceSourceLibraries + "SharpUp" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    },
                    new ReferenceSourceLibrary
                    {
                        Name = "SharpWMI", Description = "SharpWMI is a C# implementation of various WMI functionality.",
                        Location = Common.CovenantReferenceSourceLibraries + "SharpWMI" + Path.DirectorySeparatorChar,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 }
                    }
                };
                await service.CreateReferenceSourceLibraries(ReferenceSourceLibraries);

                var ss = await service.GetReferenceSourceLibraryByName("SharpSploit");
                var ru = await service.GetReferenceSourceLibraryByName("Rubeus");
                var se = await service.GetReferenceSourceLibraryByName("Seatbelt");
                var sd = await service.GetReferenceSourceLibraryByName("SharpDPAPI");
                // var sc = await service.GetReferenceSourceLibraryByName("SharpChrome");
                var sdu = await service.GetReferenceSourceLibraryByName("SharpDump");
                var su = await service.GetReferenceSourceLibraryByName("SharpUp");
                var sw = await service.GetReferenceSourceLibraryByName("SharpWMI");
                await service.CreateEntities(
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.IdentityModel.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.IdentityModel.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.Automation.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ss, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.Automation.dll", Common.DotNetVersion.Net40) },

    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.AccountManagement.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.AccountManagement.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.IdentityModel.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = ru, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.IdentityModel.dll", Common.DotNetVersion.Net40) },

    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.DirectoryServices.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.ServiceProcess.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.ServiceProcess.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Web.Extensions.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = se, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Web.Extensions.dll", Common.DotNetVersion.Net40) },

    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Security.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sd, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Security.dll", Common.DotNetVersion.Net40) },

    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net35) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net40) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Security.dll", Common.DotNetVersion.Net35) },
    // new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sc, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Security.dll", Common.DotNetVersion.Net40) },


    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sdu, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sdu, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sdu, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sdu, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sdu, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sdu, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },

    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.ServiceProcess.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.ServiceProcess.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = su, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net40) },

    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net35) },
    new ReferenceSourceLibraryReferenceAssembly { ReferenceSourceLibrary = sw, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Management.dll", Common.DotNetVersion.Net40) }
                );
            }
            #endregion
            if (!context.GruntTasks.Any())
            {
                var GruntTasks = new GruntTask[]
                {
                    #region GruntTasks DotNetFramework
                    new GruntTask
                    {
                        Name = "Shell",
                        Aliases = new List<string>(),
                        Description = "Execute a Shell command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Shell" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 1,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ShellCmd",
                        Aliases = new List<string>(),
                        Description = "Execute a Shell command using \"cmd.exe /c\"",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ShellCmd" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 2,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ShellRunAs",
                        Aliases = new List<string>(),
                        Description = "Execute a Shell command as a specified user.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ShellRunAs" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 3,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 4,
                                Name = "Username",
                                Description = "The username to execute as.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 5,
                                Name = "Domain",
                                Description = "The domain to execute as.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 6,
                                Name = "Password",
                                Description = "The password to execute as.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ShellCmdRunAs",
                        Aliases = new List<string>(),
                        Description = "Execute a Shell command using \"cmd.exe /c\" as a specified user.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ShellCmdRunAs" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 7,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 8,
                                Name = "Username",
                                Description = "The username to execute as.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 9,
                                Name = "Domain",
                                Description = "The domain to execute as.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 10,
                                Name = "Password",
                                Description = "The password to execute as.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PowerShell",
                        Aliases = new List<string>(),
                        Description = "Execute a PowerShell command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PowerShell" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 11,
                                Name = "PowerShellCommand",
                                Description = "The PowerShellCommand to execute.",
                                Value = "Get-ChildItem Env:",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Assembly",
                        Aliases = new List<string>(),
                        Description = "Execute a dotnet Assembly EntryPoint.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Assembly" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 12,
                                Name = "AssemblyName",
                                Description = "Name of the assembly.",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 13,
                                Name = "EncodedAssembly",
                                Description = "The Base64 encoded Assembly bytes.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = false
                            },
                            new GruntTaskOption
                            {
                                Id = 14,
                                Name = "Parameters",
                                Description = "The command-line parameters to pass to the assembly's EntryPoint.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "AssemblyReflect",
                        Aliases = new List<string>(),
                        Description = "Execute a dotnet Assembly method using reflection.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "AssemblyReflect" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 15,
                                Name = "AssemblyName",
                                Description = "Name of the assembly.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 16,
                                Name = "EncodedAssembly",
                                Description = "The Base64 encoded Assembly bytes.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = false
                            },
                            new GruntTaskOption
                            {
                                Id = 17,
                                Name = "TypeName",
                                Description = "The name of the Type that contains the method to execute.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 18,
                                Name = "MethodName",
                                Description = "The name of the method to execute.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 19,
                                Name = "Parameters",
                                Description = "The parameters to pass to the method.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ListDirectory",
                        Aliases = new List<string> { "ls" },
                        Description = "Get a listing of the current directory.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ListDirectory" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 20,
                                Name = "Path",
                                Description = "Directory to list.",
                                Value = ".",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = ".",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetCurrentDirectory",
                        Aliases = new List<string>{ "pwd" },
                        Description = "Get the Grunt's Current Working Directory",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetCurrentDirectory" + ".task")),
                        Options = new List<GruntTaskOption>{ }
                    },
                    new GruntTask
                    {
                        Name = "ChangeDirectory",
                        Aliases = new List<string> { "cd" },
                        Description = "Change the current directory.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ChangeDirectory" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 21,
                                Name = "Directory",
                                Description = "Directory to change to.",
                                Value = ".",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ReadTextFile",
                        Aliases = new List<string>{"cat"},
                        Description = "Read a text file on disk.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ReadTextFile" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 22,
                                Name = "Path",
                                Description = "Path to the file.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Delete",
                        Aliases = new List<string>{ "rm", "del" },
                        Description = "Delete a file or directory.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Delete" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 23,
                                Name = "Path",
                                Description = "The path of the file or directory to delete.",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ProcessList",
                        Aliases = new List<string> { "ps" },
                        Description = "Get a list of currently running processes.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ProcessList" + ".task")),
                        Options = new List<GruntTaskOption> { }
                    },
                    new GruntTask
                    {
                        Name = "Kill",
                        Aliases = new List<string>(),
                        Description = "Kills the process of a given Process ID.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Kill" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 24,
                                Name = "ProcessID",
                                Description = "The Process ID of the process to kill.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Upload",
                        Aliases = new List<string>(),
                        Description = "Upload a file.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Upload" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 25,
                                Name = "FilePath",
                                Description = "Remote file path to write to.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 26,
                                Name = "FileContents",
                                Description = "Base64 contents of the file to be written.",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = false
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Download",
                        Aliases = new List<string>(),
                        Description = "Download a file.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Download" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 27,
                                Name = "FileName",
                                Description = "Remote file name to download.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ScreenShot",
                        Description = "Takes a screenshot of the currently active desktop, move into a targeted pid for specific desktops",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ScreenShot" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "Mimikatz",
                        Aliases = new List<string>(),
                        Description = "Execute a mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Mimikatz" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 28,
                                Name = "Command",
                                Description = "Mimikatz command to execute.",
                                Value = "sekurlsa::logonPasswords",
                                SuggestedValues = new List<string> { "sekurlsa::logonpasswords", "privilege::debug sekurlsa::logonpasswords", "lsadump::sam", "token::elevate lsadump::sam", "lsadump::secrets", "token::elevate lsadump::secrets" },
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "LogonPasswords",
                        Aliases = new List<string>(),
                        Description = "Execute the 'privilege::debug sekurlsa::logonPasswords' Mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "LogonPasswords" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "LsaSecrets",
                        Aliases = new List<string>(),
                        Description = "Execute the 'privilege::debug lsadump::secrets' Mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "LsaSecrets" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "LsaCache",
                        Aliases = new List<string>(),
                        Description = "Execute the 'privilege::debug lsadump::cache' Mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "LsaCache" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "SamDump",
                        Aliases = new List<string>(),
                        Description = "Execute the 'privilege::debug lsadump::sam' Mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SamDump" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "Wdigest",
                        Aliases = new List<string>(),
                        Description = "Execute the 'sekurlsa::wdigest' Mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Wdigest" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "DCSync",
                        Aliases = new List<string>(),
                        Description = "Execute the 'lsadump::dcsync Mimikatz command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "DCSync" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 29,
                                Name = "Username",
                                Description = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 30,
                                Name = "FQDN",
                                Description = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 31,
                                Name = "DC",
                                Description = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PortScan",
                        Aliases = new List<string>(),
                        Description = "Perform a TCP port scan.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PortScan" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 32,
                                Name = "ComputerNames",
                                Description = "ComputerName(s) to port scan. Can be a DNS name, IP address, or CIDR range.",
                                Value = "127.0.0.1",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 33,
                                Name = "Ports",
                                Description = "Ports to scan. Comma-delimited port list, use hyphens for port ranges",
                                Value = "80,443-445,3389",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 34,
                                Name = "Ping",
                                Description = "Boolean, whether to ping hosts prior to port scanning.",
                                Value = "False",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "False",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Rubeus",
                        Aliases = new List<string>(),
                        Description = "Use a rubeus command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Rubeus" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 35,
                                Name = "Command",
                                Description = "Rubeus command to execute.",
                                Value = "triage",
                                SuggestedValues = new List<string> { "triage", "dump", "asktgt", "asktgs", "renew", "s4u", "ptt", "purge", "describe", "klist", "tgtdeleg", "monitor", "harvest", "kerberoast", "asreproast", "createnetonly", "changepw", "hash", "tgssub" },
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Kerberoast",
                        Aliases = new List<string>(),
                        Description = "Perform a \"Kerberoast\" attack that retrieves crackable service tickets for Domain User's w/ an SPN set.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Kerberoast" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 36,
                                Name = "Usernames",
                                Description = "Username(s) to port scan. Comma-delimited username list.",
                                Value = "DOMAIN\\username1,DOMAIN\\username2",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 37,
                                Name = "HashFormat",
                                Description = "Format to output the hashes (\"Hashcat\" or \"John\").",
                                Value = "Hashcat",
                                SuggestedValues = new List<string> { "Hashcat", "John" },
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SafetyKatz",
                        Aliases = new List<string>(),
                        Description = "Use SafetyKatz.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SafetyKatz" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "SharpDPAPI",
                        Aliases = new List<string>(),
                        Description = "Use a SharpDPAPI command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SharpDPAPI" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 38,
                                Name = "Command",
                                Description = "SharpDPAPI command to execute.",
                                Value = "triage",
                                SuggestedValues = new List<string> { "triage", "machinetriage", "backupkey", "masterkeys", "machinemasterkeys", "credentials", "machinecredentials", "vaults", "machinevaults", "rdg" },
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    // new GruntTask
                    // {
                    //     Name = "SharpChrome",
                    //     AlternateNames = new List<string>(),
                    //     Description = "Use a SharpChrome command.",
                    //     Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SharpChrome" + ".task")),
                    //     Options = new List<GruntTaskOption>
                    //     {
                    //         new GruntTaskOption
                    //         {
                    //             Id = 39,
                    //             Name = "Command",
                    //             Description = "SharpChrome command to execute.",
                    //             Value = "logins",
                    //             SuggestedValues = new List<string> { "logins", "cookies", "backupkey" },
                    //             Optional = true,
                    //             DefaultValue = "",
                    //             DisplayInCommand = true
                    //         }
                    //     }
                    // },
                    new GruntTask
                    {
                        Name = "SharpUp",
                        Aliases = new List<string>(),
                        Description = "Use a SharpUp command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SharpUp" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 39,
                                Name = "Command",
                                Description = "SharpUp command to execute.",
                                Value = "",
                                SuggestedValues = new List<string> { "audit" },
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SharpDump",
                        Aliases = new List<string>(),
                        Description = "Use a SharpDump command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SharpDump" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 40,
                                Name = "ProcessID",
                                Description = "ProcessID of the process to createa dump file of.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Seatbelt",
                        Aliases = new List<string>(),
                        Description = "Use a Seatbelt command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "Seatbelt" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 41,
                                Name = "Command",
                                Description = "Seatbelt command to execute.",
                                Value = "",
                                SuggestedValues = new List<string> { "all", "system", "BasicOSInfo", "RebootSchedule", "TokenGroupPrivs", "UACSystemPolicies", "PowerShellSettings",
                                    "AuditSettings", "WEFSettings", "LSASettings", "UserEnvVariables", "SystemEnvVariables", "UserFolders", "NonstandardServices", "LapsSettings",
                                    "LocalGroupMembers", "MappedDrives", "RDPSessions", "WMIMappedDrives", "NetworkShares", "FirewallRules", "AntiVirusWMI", "InterestingProcesses",
                                    "RegistryAutoRuns", "RegistryAutoLogon", "DNSCache", "ARPTable", "AllTcpConnections", "AllUdpConnections", "NonstandardProcesses", "SysmonConfig",
                                    "user", "SavedRDPConnections", "TriageIE", "DumpVault", "RecentRunCommands", "PuttySessions", "PuttySSHHostKeys", "CloudCreds", "RecentFiles",
                                    "MasterKeys", "CredFiles", "RCDManFiles", "CurrentDomainGroups", "Patches", "LogonSessions", "KerberosTGTData", "InterestingFiles", "IETabs",
                                    "TriageChrome", "TriageFirefox", "RecycleBin", "4624Events", "4648Events", "KerberosTickets" },
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SharpWMI",
                        Aliases = new List<string>(),
                        Description = "Use a SharpWMI command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SharpWMI" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 42,
                                Name = "Command",
                                Description = "SharpWMI command to execute.",
                                Value = "",
                                SuggestedValues = new List<string> { "action=query", "action=create", "action=executevbs" },
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "WhoAmI",
                        Aliases = new List<string>(),
                        Description = "Gets the username of the currently used/impersonated token.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "WhoAmI" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "ImpersonateUser",
                        Aliases = new List<string>(),
                        Description = "Find a process owned by the specified user and impersonate the token. Used to execute subsequent commands as the specified user.",
                        TokenTask = true,
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ImpersonateUser" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 43,
                                Name = "Username",
                                Description = "User to impersonate. \"DOMAIN\\Username\" format expected.",
                                Value = "DOMAIN\\Username",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ImpersonateProcess",
                        Aliases = new List<string>(),
                        Description = "Impersonate the token of the specified process. Used to execute subsequent commands as the user associated with the token of the specified process.",
                        TokenTask = true,
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ImpersonateProcess" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 44,
                                Name = "ProcessID",
                                Description = "Process ID of the process to impersonate.",
                                Value = "1234",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetSystem",
                        Aliases = new List<string>(),
                        Description = "Impersonate the SYSTEM user. Equates to ImpersonateUser(\"NT AUTHORITY\\SYSTEM\").",
                        TokenTask = true,
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetSystem" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "MakeToken",
                        Aliases = new List<string>(),
                        Description = "Makes a new token with a specified username and password, and impersonates it to conduct future actions as the specified user.",
                        TokenTask = true,
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "MakeToken" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 45,
                                Name = "Username",
                                Description = "Username to authenticate as.",
                                Value = "username1",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 46,
                                Name = "Domain",
                                Description = "Domain to authenticate the user to.",
                                Value = "DOMAIN",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 47,
                                Name = "Password",
                                Description = "Password to authenticate the user.",
                                Value = "Password123",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 48,
                                Name = "LogonType",
                                Description = "LogonType to use. Defaults to LOGON32_LOGON_NEW_CREDENTIALS, which is suitable to perform actions that require remote authentication. LOGON32_LOGON_INTERACTIVE is suitable for local actions.",
                                Value = "LOGON32_LOGON_NEW_CREDENTIALS",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "LOGON32_LOGON_NEW_CREDENTIALS",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "RevertToSelf",
                        Aliases = new List<string> { "RevToSelf" },
                        Description = "Ends the impersonation of any token, reverting back to the initial token associated with the current process. Useful in conjuction with functions impersonate a token and do not automatically RevertToSelf, such as ImpersonateUser(), ImpersonateProcess(), GetSystem(), and MakeToken().",
                        TokenTask = true,
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "RevertToSelf" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "WMICommand",
                        Aliases = new List<string>(),
                        Description = "Execute a process on a remote system using Win32_Process Create, optionally with alternate credentials.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "WMI" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 49,
                                Name = "ComputerName",
                                Description = "ComputerName to create the process on.",
                                Value = "localhost",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 50,
                                Name = "Command",
                                Description = "Command line to execute on the remote system.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 51,
                                Name = "Username",
                                Description = "Username to authenticate as. Format: DOMAIN\\Username (optional)",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 52,
                                Name = "Password",
                                Description = "Password to authenticate the user. (optional)",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "WMIGrunt",
                        Aliases = new List<string>(),
                        Description = "Execute a Grunt Launcher on a remote system using Win32_Process Create, optionally with alternate credentials.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "WMI" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 53,
                                Name = "ComputerName",
                                Description = "ComputerName to launch the Grunt on.",
                                Value = "localhost",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 54,
                                Name = "Launcher",
                                Description = "Grunt Launcher to execute on the remote system.",
                                Value = "PowerShell",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 55,
                                Name = "Username",
                                Description = "Username to authenticate as. Format: DOMAIN\\Username (optional)",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 56,
                                Name = "Password",
                                Description = "Password to authenticate the user. (optional)",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "DCOMCommand",
                        Aliases = new List<string>(),
                        Description = "Execute a process on a remote system using various DCOM methods.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "DCOM" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 57,
                                Name = "ComputerName",
                                Description = "ComputerName to execute the process on.",
                                Value = "localhost",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 58,
                                Name = "Command",
                                Description = "Executable to execute on the remote system.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 59,
                                Name = "Parameters",
                                Description = "Command line parameters to pass to the Command.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 60,
                                Name = "Directory",
                                Description = "Directory on the remote system containing the Command executable.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "C:\\Windows\\System32\\",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 61,
                                Name = "Method",
                                Description = "DCOM method to use for execution.",
                                Value = "MMC20.Application",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "MMC20.Application",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "DCOMGrunt",
                        Aliases = new List<string>(),
                        Description = "Execute a Grunt Launcher on a remote system using various DCOM methods.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "DCOM" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 62,
                                Name = "ComputerName",
                                Description = "ComputerName to execute the process on.",
                                Value = "localhost",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 63,
                                Name = "Launcher",
                                Description = "Grunt Launcher to execute on the remote system.",
                                Value = "PowerShell",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 64,
                                Name = "Method",
                                Description = "DCOM method to use for execution.",
                                Value = "MMC20.Application",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "MMC20.Application",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PowerShellRemotingCommand",
                        Aliases = new List<string>(),
                        Description = "Execute a PowerShell command on a remote system using PowerShell Remoting, optionally with alternate credentials.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PowerShellRemoting" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 65,
                                Name = "ComputerName",
                                Description = "ComputerName of the remote system.",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 66,
                                Name = "Command",
                                Description = "PowerShell command to execute on the remote system.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true,
                            },
                            new GruntTaskOption
                            {
                                Id = 67,
                                Name = "Domain",
                                Description = "The domain to execute as.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true,
                            },
                            new GruntTaskOption
                            {
                                Id = 68,
                                Name = "Username",
                                Description = "The username to execute as.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true,
                            },
                            new GruntTaskOption
                            {
                                Id = 69,
                                Name = "Password",
                                Description = "The password to execute as.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true,
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PowerShellRemotingGrunt",
                        Aliases = new List<string>(),
                        Description = "Execute a Grunt Launcher on a remote system using PowerShell Remoting, optionally with alternate credentials.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PowerShellRemoting" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 70,
                                Name = "ComputerName",
                                Description = "ComputerName to launch the Grunt on.",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 71,
                                Name = "Launcher",
                                Description = "Grunt Launcher to execute on the remote system.",
                                Value = "PowerShell",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true,
                            },
                            new GruntTaskOption
                            {
                                Id = 72,
                                Name = "Domain",
                                Description = "The domain to execute as.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true,
                            },
                            new GruntTaskOption
                            {
                                Id = 73,
                                Name = "Username",
                                Description = "The username to execute as.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true,
                            },
                            new GruntTaskOption
                            {
                                Id = 74,
                                Name = "Password",
                                Description = "The password to execute as.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true,
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "BypassUACCommand",
                        Aliases = new List<string>(),
                        Description = "Bypasses UAC through token duplication and executes a command with high integrity.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "BypassUAC" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 75,
                                Name = "Command",
                                Description = "Command to execute with high integrity.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 76,
                                Name = "Parameters",
                                Description = "Command line parameters to pass to the Command.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 77,
                                Name = "Directory",
                                Description = "Directory containing the Command executable.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "C:\\Windows\\System32\\",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 78,
                                Name = "ProcessID",
                                Description = "ProcessID.",
                                Value = "0",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "0",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "BypassUACGrunt",
                        Aliases = new List<string>(),
                        Description = "Bypasses UAC through token duplication and executes a Grunt Launcher with high integrity.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "BypassUAC" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 79,
                                Name = "Launcher",
                                Description = "Launcher to execute with high integrity.",
                                Value = "PowerShell",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetDomainUser",
                        Aliases = new List<string>(),
                        Description = "Gets a list of specified (or all) user `DomainObject`s in the current Domain.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetDomainUser" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 80,
                                Name = "Identities",
                                Description = "List of comma-delimited usernames to retrieve.",
                                Value = "username",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetDomainGroup",
                        Aliases = new List<string>(),
                        Description = "Gets a list of specified (or all) group `DomainObject`s in the current Domain.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetDomainGroup" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 81,
                                Name = "Identities",
                                Description = "List of comma-delimited groups to retrieve.",
                                Value = "Domain Admins",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetDomainComputer",
                        Aliases = new List<string>(),
                        Description = "Gets a list of specified (or all) computer `DomainObject`s in the current Domain.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetDomainComputer" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 82,
                                Name = "Identities",
                                Description = "List of comma-delimited computers to retrieve.",
                                Value = "DC01",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetLocalGroup",
                        Aliases = new List<string>(),
                        Description = "Gets a list of `LocalGroup`s from specified remote computer(s).",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetNetLocalGroup" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 83,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetLocalGroupMember",
                        Aliases = new List<string>(),
                        Description = "Gets a list of `LocalGroupMember`s from specified remote computer(s).",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetNetLocalGroupMember" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 84,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 85,
                                Name = "LocalGroup",
                                Description = "LocalGroup name to query for members.",
                                Value = "Administrators",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "Administrators",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetLoggedOnUser",
                        Aliases = new List<string>(),
                        Description = "Gets a list of `LoggedOnUser`s from specified remote computer(s).",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetNetLoggedOnUser" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 86,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetNetSession",
                        Aliases = new List<string>(),
                        Description = "Gets a list of `SessionInfo`s from specified remote computer(s).",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetNetSession" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 87,
                                Name = "ComputerNames",
                                Description = "List of comma-delimited ComputerNames to query.",
                                Value = "DC01",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetRegistryKey",
                        Aliases = new List<string>(),
                        Description = "Gets a value stored in registry.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetRegistryKey" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 88,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SetRegistryKey",
                        Aliases = new List<string>(),
                        Description = "Sets a value into the registry.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SetRegistryKey" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 89,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 90,
                                Name = "Value",
                                Description = "The value to write to the registry key.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "GetRemoteRegistryKey",
                        Aliases = new List<string>(),
                        Description = "Gets a value stored in registry on a remote system.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "GetRemoteRegistryKey" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 91,
                                Name = "Hostname",
                                Description = "The Hostname of the remote system to query.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 92,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SetRemoteRegistryKey",
                        Aliases = new List<string>(),
                        Description = "Sets a value into the registry on a remote system.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "SetRemoteRegistryKey" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 93,
                                Name = "Hostname",
                                Description = "The Hostname of the remote system to write to.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 94,
                                Name = "RegPath",
                                Description = "The full path to the registry value to be read.",
                                Value = "HKEY_CURRENT_USER\\Environment\\Path",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 95,
                                Name = "Value",
                                Description = "The value to write to the registry key.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ShellCode",
                        Aliases = new List<string>(),
                        Description = "Executes a specified shellcode byte array by copying it to pinned memory, modifying the memory permissions, and executing.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "ShellCode" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 96,
                                Name = "Hex",
                                Description = "Hex string representing the Shellcode bytes to execute.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PrivExchange",
                        Aliases = new List<string>(),
                        Description = "Performs the PrivExchange attack by sending a push notification to EWS.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PrivExchange" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 97,
                                Name = "EWSUri",
                                Description = "The URI of the Exchange EWS instance to perform the relay against. For example: http(s)://<hostname>:<port>/EWS/Exchange.asmx.",
                                Value = "https://exchange.example.local:443/EWS/Exchange.asmx",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 98,
                                Name = "RelayUri",
                                Description = "The URI of the external relay of the Exchange authentication.",
                                Value = "https://relay.example.local:443/relay",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 99,
                                Name = "ExchangeVersion",
                                Description = "Microsoft Exchange version. Defaults to Exchange2010.",
                                Value = "Exchange2010",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PersistCOMHijack",
                        Aliases = new List<string>(),
                        Description = "Hijacks a CLSID key to execute a payload for persistence.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PersistCOMHijack" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 100,
                                Name = "CLSID",
                                Description = "Missing CLSID to abuse.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 101,
                                Name = "ExecutablePath",
                                Description = "Path to the executable path.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PersistStartup",
                        Aliases = new List<string>(),
                        Description = "Installs a payload into the current users startup folder.\n\n\tPayload: Payload to write to a file. E.g. \"powershell -Sta -Nop -Window Hidden -EncodedCommand <blah>\".\n\tFileName: Name of the file to write. E.g. \"startup.bat\".\n",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PersistStartup" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 102,
                                Name = "Payload",
                                Description = "Payload to write to a file.",
                                Value = "powershell -Sta -Nop -Window Hidden -EncodedCommand <blah>",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 103,
                                Name = "FileName",
                                Description = "Name of the file to write.",
                                Value = "startup.bat",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PersistAutorun",
                        Aliases = new List<string>(),
                        Description = "Installs an autorun value in HKCU or HKLM to execute a payload.\n\n\tTargetHive: Target hive to install autorun. Specify \"CurrentUser\" for HKCU and \"LocalMachine\" for HKLM.\n\tValue: Value to set in the registry. E.g. \"C:\\Example\\GruntStager.exe\"\n\tName: Name for the registy value.E.g. \"Updater\".\n",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PersistAutorun" + ".task")),
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 104,
                                Name = "TargetHive",
                                Description = "Target hive to install autorun.",
                                Value = "CurrentUser",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 105,
                                Name = "Name",
                                Description = "Name for the registy value.",
                                Value = "Updater",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 106,
                                Name = "Value",
                                Description = "Value to set in the registry.",
                                Value = "C:\\Example\\GruntStager.exe",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PersistWMI",
                        Description = "Creates a WMI Event, Consumer and Binding to execute a payload.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "PersistWMI" + ".task")),
                        Options = new List<GruntTaskOption>{
                            new GruntTaskOption
                            {
                                Id = 107,
                                Name = "EventName",
                                Description = "Creates a WMI Event, Consumer and Binding to execute a payload.\n\n\tEventName: An arbitrary name to be assigned to the new WMI Event. E.g. \"Evil Persistence\".\n\tEventFilter: Specifies the event trigger to use. The options are \"ProcessStart\".\n\tEventConsumer: Specifies the action to carry out. The options are \"CommandLine\" (OS Command) and \"ActiveScript\" (JScript or VBScript).\n\tPayload: Specifies the CommandLine or ActiveScript payload to run. E.g. \"powershell -Sta -Nop -Window Hidden -EncodedCommand <blah>\".\n\tProcessName: Specifies the process name when the \"ProcessStart\" trigger is selected. E.g. \"notepad.exe\".\n\tScriptingEngine: Specifies the scripting engine when the \"ActiveScript\" consumer is selected. The options are \"JScript\" and \"VBScript\".\n",
                                Value = "Evil Persistence",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 108,
                                Name = "EventFilter",
                                Description = "Specifies the event trigger to use.",
                                Value = "ProcessStart",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 109,
                                Name = "EventConsumer",
                                Description = "Specifies the action to carry out.",
                                Value = "CommandLine",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 110,
                                Name = "Payload",
                                Description = "Specifies the CommandLine or ActiveScript payload to run.",
                                Value = "powershell -Sta -Nop -Window Hidden -EncodedCommand <blah>",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 111,
                                Name = "ProcessName",
                                Description = "Specifies the process name when the ProcessStart trigger is selected.",
                                Value = "notepad.exe",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = false
                            },
                            new GruntTaskOption
                            {
                                Id = 112,
                                Name = "ScriptingEngine",
                                Description = "Specifies the scripting engine when the ActiveScript consumer is selected.",
                                Value = "VBScript",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "VBScript",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "BypassAmsi",
                        Aliases = new List<string>(),
                        Description = "Bypasses AMSI by patching the AmsiScanBuffer function.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpDirectory, "BypassAmsi" + ".task")),
                        Options = new List<GruntTaskOption>()
                    },
                    #endregion
                    #region GruntTask Generic
                    new GruntTask
                    {
                        Name = "Set",
                        Aliases = new List<string>(),
                        Description = "Set a Grunt setting.",
                        Code = "",
                        TaskingType = GruntTaskingType.SetOption,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40, Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 113,
                                Name = "Setting",
                                Description = "Setting to set.",
                                Value = "",
                                SuggestedValues = new List<string> { "Delay", "ConnectAttempts", "JitterPercent" },
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 114,
                                Name = "Value",
                                Description = "Value to change the option to.",
                                Value = "",
                                SuggestedValues = new List<string> { },
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Jobs",
                        Aliases = new List<string>(),
                        Description = "Get active Jobs.",
                        Code = "",
                        TaskingType = GruntTaskingType.Jobs,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40, Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "Exit",
                        Aliases = new List<string>(),
                        Description = "Exits the Grunt.",
                        Code = "",
                        TaskingType = GruntTaskingType.Exit,
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40, Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "Connect",
                        Aliases = new List<string>(),
                        Description = "Connect to a P2P Grunt.",
                        Code = "",
                        TaskingType = GruntTaskingType.Connect,
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 115,
                                Name = "ComputerName",
                                Description = "ComputerName of Grunt to connect to.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 116,
                                Name = "PipeName",
                                Description = "PipeName of Grunt to connect to.",
                                Value = "",
                                SuggestedValues = new List<string> { "gruntsvc" },
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Disconnect",
                        Aliases = new List<string>(),
                        Description = "Disconnect from a ChildGrunt.",
                        Code = "",
                        TaskingType = GruntTaskingType.Disconnect,
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 117,
                                Name = "GruntName",
                                Description = "Name of Grunt to disconnect from.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "SharpShell",
                        Aliases = new List<string>(),
                        Description = "Execute custom c# code.",
                        Code = "",
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 118,
                                Name = "Code",
                                Description = "C# code to execute.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "PowerShellImport",
                        Aliases = new List<string>(),
                        Description = "Import a PowerShell script.",
                        Code = "",
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 119,
                                Name = "Script",
                                Description = "PowerShell Script to import.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = false
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Help",
                        Aliases = new List<string>(),
                        Description = "Show the help menu.",
                        Code = "",
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40, Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 120,
                                Name = "TaskName",
                                Description = "The GruntTask name to retrieve help information for.",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    #endregion
                    #region GruntTask DotNetCore
                    new GruntTask
                    {
                        Name = "WhoAmI",
                        Aliases = new List<string>(),
                        Description = "Gets the username of the currently used/impersonated token.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "WhoAmI" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>()
                    },
                    new GruntTask
                    {
                        Name = "Shell",
                        Aliases = new List<string>(),
                        Description = "Execute a Shell command.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "Shell" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 121,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ShellCmd",
                        Aliases = new List<string>(),
                        Description = "Execute a Shell command using \"cmd.exe /c\"",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "ShellCmd" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 122,
                                Name = "ShellCommand",
                                Description = "The ShellCommand to execute.",
                                Value = "whoami",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "Assembly",
                        Aliases = new List<string>(),
                        Description = "Execute a dotnet Assembly EntryPoint.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "Assembly" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 123,
                                Name = "AssemblyName",
                                Description = "Name of the assembly.",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            },
                            new GruntTaskOption
                            {
                                Id = 124,
                                Name = "EncodedAssembly",
                                Description = "The Base64 encoded Assembly bytes.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = false
                            },
                            new GruntTaskOption
                            {
                                Id = 125,
                                Name = "Parameters",
                                Description = "The command-line parameters to pass to the assembly's EntryPoint.",
                                Value = "",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = "",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ListDirectory",
                        Aliases = new List<string> { "ls" },
                        Description = "Get a listing of the current directory.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "ListDirectory" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 126,
                                Name = "Path",
                                Description = "Directory to list.",
                                Value = ".",
                                SuggestedValues = new List<string>(),
                                Optional = true,
                                DefaultValue = ".",
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ChangeDirectory",
                        Aliases = new List<string> { "cd" },
                        Description = "Change the current directory.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "ChangeDirectory" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption>
                        {
                            new GruntTaskOption
                            {
                                Id = 127,
                                Name = "Directory",
                                Description = "Directory to change to.",
                                Value = ".",
                                SuggestedValues = new List<string>(),
                                Optional = false,
                                DisplayInCommand = true
                            }
                        }
                    },
                    new GruntTask
                    {
                        Name = "ProcessList",
                        Aliases = new List<string> { "ps" },
                        Description = "Get a list of currently running processes.",
                        Code = File.ReadAllText(Path.Combine(Common.CovenantTaskCSharpNetCoreApp30Directory, "ProcessList" + ".task")),
                        CompatibleDotNetVersions = new List<Common.DotNetVersion> { Common.DotNetVersion.NetCore30 },
                        Options = new List<GruntTaskOption> { }
                    }
                    #endregion
                };
                await service.CreateGruntTasks(GruntTasks);

                var ss = await service.GetReferenceSourceLibraryByName("SharpSploit");
                var ru = await service.GetReferenceSourceLibraryByName("Rubeus");
                var se = await service.GetReferenceSourceLibraryByName("Seatbelt");
                var sd = await service.GetReferenceSourceLibraryByName("SharpDPAPI");
                // var sc = await service.GetReferenceSourceLibraryByName("SharpChrome");
                var sdu = await service.GetReferenceSourceLibraryByName("SharpDump");
                var su = await service.GetReferenceSourceLibraryByName("SharpUp");
                var sw = await service.GetReferenceSourceLibraryByName("SharpWMI");
                await service.CreateEntities(
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("Shell") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ShellCmd") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ShellRunAs") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ShellCmdRunAs") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PowerShell") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("Assembly") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("BypassAmsi") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("AssemblyReflect") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ListDirectory") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ChangeDirectory") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ProcessList") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("Mimikatz") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("LogonPasswords") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("LsaSecrets") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("LsaCache") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("SamDump") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("Wdigest") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("DCSync") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PortScan") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ru, GruntTask = await service.GetGruntTaskByName("Rubeus") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("Kerberoast") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("SafetyKatz") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = sd, GruntTask = await service.GetGruntTaskByName("SharpDPAPI") },
    // new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = sc, GruntTask = await service.GetGruntTaskByName("SharpChrome") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = su, GruntTask = await service.GetGruntTaskByName("SharpUp") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = sdu, GruntTask = await service.GetGruntTaskByName("SharpDump") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = se, GruntTask = await service.GetGruntTaskByName("Seatbelt") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = sw, GruntTask = await service.GetGruntTaskByName("SharpWMI") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("WhoAmI") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ImpersonateUser") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ImpersonateProcess") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetSystem") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("MakeToken") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("RevertToSelf") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("WMICommand") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("WMIGrunt") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("DCOMCommand") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("DCOMGrunt") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PowerShellRemotingCommand") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PowerShellRemotingGrunt") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("BypassUACCommand") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("BypassUACGrunt") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetDomainUser") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetDomainGroup") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetDomainComputer") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetNetLocalGroup") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetNetLocalGroupMember") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetNetLoggedOnUser") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetNetSession") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetRegistryKey") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("SetRegistryKey") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("GetRemoteRegistryKey") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("SetRemoteRegistryKey") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("ShellCode") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("SharpShell") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PrivExchange") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PersistCOMHijack") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PersistStartup") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PersistAutorun") },
    new GruntTaskReferenceSourceLibrary { ReferenceSourceLibrary = ss, GruntTask = await service.GetGruntTaskByName("PersistWMI") }
                );

                var er1 = await service.GetEmbeddedResourceByName("SharpSploit.Resources.powerkatz_x64.dll");
                var er2 = await service.GetEmbeddedResourceByName("SharpSploit.Resources.powerkatz_x86.dll");
                await service.CreateEntities(
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("Mimikatz") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("LogonPasswords") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("LsaSecrets") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("LsaCache") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("SamDump") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("Wdigest") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("DCSync") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er1, GruntTask = await service.GetGruntTaskByName("SafetyKatz") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("Mimikatz") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("LogonPasswords") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("LsaSecrets") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("LsaCache") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("SamDump") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("Wdigest") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("DCSync") },
                    new GruntTaskEmbeddedResource { EmbeddedResource = er2, GruntTask = await service.GetGruntTaskByName("SafetyKatz") }
                );
                var upload = await service.GetGruntTaskByName("Upload");
                var download = await service.GetGruntTaskByName("Download");
                var privexchange = await service.GetGruntTaskByName("PrivExchange");
                var screenshot = await service.GetGruntTaskByName("ScreenShot");
                var readtextfile = await service.GetGruntTaskByName("ReadTextFile");
                var delete = await service.GetGruntTaskByName("Delete");
                var kill = await service.GetGruntTaskByName("Kill");
                var getcurrentdir = await service.GetGruntTaskByName("GetCurrentDirectory");
                await service.CreateEntities(
    new GruntTaskReferenceAssembly { GruntTask = upload, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = upload, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = upload, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = upload, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = upload, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = upload, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = download, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = download, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = download, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = download, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = download, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = download, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = readtextfile, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = readtextfile, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = readtextfile, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = readtextfile, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = readtextfile, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = readtextfile, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = delete, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = delete, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = delete, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = delete, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = delete, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = delete, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = kill, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = kill, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = kill, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = kill, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = kill, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = kill, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = getcurrentdir, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = getcurrentdir, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = getcurrentdir, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = getcurrentdir, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = getcurrentdir, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = getcurrentdir, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = privexchange, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = privexchange, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.XML.dll", Common.DotNetVersion.Net40) },

    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Drawing.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Drawing.dll", Common.DotNetVersion.Net40) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Windows.Forms.dll", Common.DotNetVersion.Net35) },
    new GruntTaskReferenceAssembly { GruntTask = screenshot, ReferenceAssembly = await service.GetReferenceAssemblyByName("System.Windows.Forms.dll", Common.DotNetVersion.Net40) }

                );
            }
        }

        public async static Task InitializeRoles(RoleManager<IdentityRole> roleManager)
        {
            List<string> roles = new List<string> { "Administrator", "User", "Listener", "SignalR" };
            foreach (string role in roles)
            {
                if (!(await roleManager.RoleExistsAsync(role)))
                {
                    IdentityResult roleResult = await roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }
    }
}
