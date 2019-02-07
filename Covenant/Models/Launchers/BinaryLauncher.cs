// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;
using Covenant.Models.Grunts;

namespace Covenant.Models.Launchers
{
    public class BinaryLauncher : Launcher
    {
        public BinaryLauncher()
        {
            this.Type = LauncherType.Binary;
            this.Description = "Uses a generated .NET Framework binary to launch a Grunt.";
            this.Name = "Binary";
            this.OutputKind = OutputKind.ConsoleApplication;
        }

        public override string GetLauncher(Listener listener, Grunt grunt, HttpProfile profile)
        {
            this.StagerCode = listener.GetGruntStagerCode(grunt, profile);
            this.Base64ILByteString = listener.CompileGruntStagerCode(grunt, profile, this.OutputKind);
            this.LauncherString = this.Base64ILByteString;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
				Uri hostedLocation = new Uri(httpListener.Url + hostedFile.Path);
                this.LauncherString = hostedFile.Path.Split("\\").Last().Split("/").Last();
                return hostedLocation.ToString();
            }
            else { return ""; }
        }
    }
}
