// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.IO;
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
        public static string CovenantReferenceDirectory = CovenantDataDirectory + "References" + Path.DirectorySeparatorChar;
        public static string CovenantResourceDirectory = CovenantDataDirectory + "Resources" + Path.DirectorySeparatorChar;
        public static string CovenantTaskDirectory = CovenantDataDirectory + "Tasks" + Path.DirectorySeparatorChar;
        public static string CovenantGruntDirectory = CovenantDataDirectory + "Grunt" + Path.DirectorySeparatorChar;
        public static string CovenantLogDirectory = CovenantDataDirectory + "Logs" + Path.DirectorySeparatorChar;
        public static string CovenantLogFile = CovenantLogDirectory + "covenant.log";
        public static string CovenantPrivateCertFile = CovenantDataDirectory + "covenant-dev-private.pfx";
        public static string CovenantPublicCertFile = CovenantDataDirectory + "covenant-dev-public.cer";
        public static string CovenantStaticHostDirectory = CovenantDataDirectory + "Static" + Path.DirectorySeparatorChar;
        public static string Net35Directory = CovenantReferenceDirectory + "net35" + Path.DirectorySeparatorChar;
        public static string Net40Directory = CovenantReferenceDirectory + "net40" + Path.DirectorySeparatorChar;
        public static string CovenantSrcDirectory = CovenantTaskDirectory + "src" + Path.DirectorySeparatorChar;
        public static string CovenantSharpSploitDirectory = CovenantSrcDirectory + "SharpSploit" + Path.DirectorySeparatorChar;
        public static string CovenantRubeusDirectory = CovenantSrcDirectory + "Rubeus" + Path.DirectorySeparatorChar;

        public static string CovenantAppSettingsFile = CovenantDataDirectory + "appsettings.json";
        public static string CovenantJwtKeyReplaceMessage = "[KEY USED TO SIGN/VERIFY JWT TOKENS, ALWAYS REPLACE THIS VALUE]";

        public static List<Compiler.Reference> DefaultReferences = new List<Compiler.Reference>
        {
            new Compiler.Reference { File = "mscorlib.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = "System.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = "System.Core.dll", Framework = DotNetVersion.Net35, Enabled = true },
            new Compiler.Reference { File = "mscorlib.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = "System.dll", Framework = DotNetVersion.Net40, Enabled = true },
            new Compiler.Reference { File = "System.Core.dll", Framework = DotNetVersion.Net40, Enabled = true },
        };

        public static List<Compiler.Reference> NetCore21References { get; set; } = new List<Compiler.Reference>
        {
            new Compiler.Reference
            {
                File = "System.Private.CoreLib.dll", Framework = DotNetVersion.NetCore21, Enabled = true
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
