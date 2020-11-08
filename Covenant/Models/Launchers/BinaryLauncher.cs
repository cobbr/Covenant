// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;
using Covenant.Models.Grunts;
using Covenant.Core;
using NLog;

namespace Covenant.Models.Launchers
{
    public class BinaryLauncher : Launcher, ILoggable
    {
        public BinaryLauncher()
        {
            this.Type = LauncherType.Binary;
            this.Description = "Uses a generated .NET Framework binary to launch a Grunt.";
            this.Name = "Binary";
            this.OutputKind = OutputKind.ConsoleApplication;
            this.CompressStager = false;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);
            this.LauncherString = template.Name + ".exe";
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
        //public void ToLog(LogAction action, LogLevel level)
        //{
            // NetworkIndicator|Action|ID|Name|LauncherString|OutputKind|CompressStager
        //    Common.logger.Log(level, $"BinaryLauncher|{action}|{this.Id}|{this.Name}|{this.LauncherString}|{this.OutputKind}|{this.CompressStager}");
        //}
    }
}
