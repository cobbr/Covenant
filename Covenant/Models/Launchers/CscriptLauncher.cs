// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;
using NLog;
using Covenant.Core;

namespace Covenant.Models.Launchers
{
    public class CscriptLauncher : ScriptletLauncher, ILoggable
    {
        public CscriptLauncher()
        {
            this.Name = "Cscript";
            this.Type = LauncherType.Cscript;
            this.Description = "Uses cscript.exe to launch a Grunt using a COM activated Delegate and ActiveXObjects (ala DotNetToJScript). Please note that DotNetToJScript-based launchers may not work on Windows 10 and Windows Server 2016.";
            this.ScriptType = ScriptletType.Plain;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }

        protected override string GetLauncher()
        {
            string launcher = "cscript" + " " + "file.js";
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                string launcher = "cscript" + " " + hostedFile.Path.Split('/').Last();
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }
        //public void ToLog(LogAction action, LogLevel level)
        //{
            // CScriptLauncher|Action|ID|Name|LauncherString|ScriptType|OutputKind|CompressStager
        //    Common.logger.Log(level, $"{this.Type}|{action}|{this.Id}|{this.Name}|{this.LauncherString}|{this.ScriptType}|{this.OutputKind}|{this.CompressStager}");
        //}
    }
}
