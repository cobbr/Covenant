// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using Microsoft.CodeAnalysis;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Covenant.Core
{
    public static class Common
    {
        public static int CovenantHTTPSPort = 7443;

        public static Encoding CovenantEncoding = Encoding.UTF8;
        public static int AesIVLength = 16;
        public static CipherMode AesCipherMode = CipherMode.CBC;
        public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;

        public static string CovenantDirectory = Assembly.GetExecutingAssembly().Location.Split("bin")[0].Split("Covenant.dll")[0];
        public static string CovenantDataDirectory = CovenantDirectory + "Data" + Path.DirectorySeparatorChar;
		public static string CovenantDatabaseFile = CovenantDataDirectory + "covenant.db";
        public static string CovenantTempDirectory = CovenantDataDirectory + "Temp" + Path.DirectorySeparatorChar;

        public static string CovenantProfileDirectory = CovenantDataDirectory + "Profiles" + Path.DirectorySeparatorChar;
        public static string CovenantDefaultHttpProfile = CovenantProfileDirectory + "DefaultHttpProfile.yaml";

        public static string CovenantDownloadDirectory = CovenantDataDirectory + "Downloads" + Path.DirectorySeparatorChar;

        public static string CovenantAssemblyReferenceDirectory = CovenantDataDirectory + "AssemblyReferences" + Path.DirectorySeparatorChar;
        public static string CovenantAssemblyReferenceNet35Directory = CovenantAssemblyReferenceDirectory + "net35" + Path.DirectorySeparatorChar;
        public static string CovenantAssemblyReferenceNet40Directory = CovenantAssemblyReferenceDirectory + "net40" + Path.DirectorySeparatorChar;
        public static string CovenantEmbeddedResourcesDirectory = CovenantDataDirectory + "EmbeddedResources" + Path.DirectorySeparatorChar;
        public static string CovenantReferenceSourceLibraries = CovenantDataDirectory + "ReferenceSourceLibraries" + Path.DirectorySeparatorChar;
        public static string CovenantSharpSploitDirectory = CovenantReferenceSourceLibraries + "SharpSploit" + Path.DirectorySeparatorChar;
        public static string CovenantRubeusDirectory = CovenantReferenceSourceLibraries + "Rubeus" + Path.DirectorySeparatorChar;

        public static string CovenantTaskDirectory = CovenantDataDirectory + "Tasks" + Path.DirectorySeparatorChar;
        public static string CovenantCompiledTaskDirectory = CovenantTaskDirectory + "Compiled" + Path.DirectorySeparatorChar;
        public static string CovenantCompiledTaskNet35Directory = CovenantCompiledTaskDirectory + "net35" + Path.DirectorySeparatorChar;
        public static string CovenantCompiledTaskNet40Directory = CovenantCompiledTaskDirectory + "net40" + Path.DirectorySeparatorChar;

        public static string CovenantGruntDirectory = CovenantDataDirectory + "Grunt" + Path.DirectorySeparatorChar;
        public static string CovenantLogDirectory = CovenantDataDirectory + "Logs" + Path.DirectorySeparatorChar;
        public static string CovenantLogFile = CovenantLogDirectory + "covenant.log";
        public static string CovenantPrivateCertFile = CovenantDataDirectory + "covenant-dev-private.pfx";
        public static string CovenantPublicCertFile = CovenantDataDirectory + "covenant-dev-public.cer";
        public static string CovenantListenersDirectory = CovenantDataDirectory + "Listeners" + Path.DirectorySeparatorChar;

        public static string CovenantAppSettingsFile = CovenantDataDirectory + "appsettings.json";
        public static string CovenantJwtKeyReplaceMessage = "[KEY USED TO SIGN/VERIFY JWT TOKENS, ALWAYS REPLACE THIS VALUE]";

        public static List<Compiler.Reference> DefaultNet35References = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantAssemblyReferenceNet35Directory + "mscorlib.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet35Directory + "System.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet35Directory + "System.Core.dll", Framework = DotNetVersion.Net35, Enabled = true },
        };

        public static List<Compiler.Reference> DefaultNet40References = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantAssemblyReferenceNet40Directory + "mscorlib.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet40Directory + "System.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet40Directory + "System.Core.dll", Framework = DotNetVersion.Net40, Enabled = true }
        };

        public static List<Compiler.Reference> DefaultNetFrameworkReferences = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = CovenantAssemblyReferenceNet35Directory + "mscorlib.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet40Directory + "mscorlib.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet35Directory + "System.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet40Directory + "System.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet35Directory + "System.Core.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = CovenantAssemblyReferenceNet40Directory + "System.Core.dll", Framework = DotNetVersion.Net40, Enabled = true }
        };

        public static List<Compiler.Reference> DefaultReferencesCore21 { get; set; } = new List<Compiler.Reference>
        {
            new Compiler.Reference
            {
                File = String.Join(Path.DirectorySeparatorChar, typeof(object).GetTypeInfo().Assembly.Location.Split(Path.DirectorySeparatorChar).Take(typeof(object).GetTypeInfo().Assembly.Location.Split(Path.DirectorySeparatorChar).Count() - 1))
                + Path.DirectorySeparatorChar + "System.Private.CoreLib.dll", Framework = DotNetVersion.NetCore21, Enabled = true
            }
        };

        public enum DotNetVersion
        {
            Net40,
            Net35,
            NetCore21
        }
    }
}
