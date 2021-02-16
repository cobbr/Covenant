using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Newtonsoft.Json;
using YamlDotNet.Serialization;

using Covenant.Core;
using Covenant.Models.Listeners;

namespace Covenant.Models.Grunts
{
    public enum CommunicationType
    {
        HTTP,
        SMB,
        Bridge
    }

    public enum ImplantLanguage
    {
        CSharp
    }

    public enum ImplantDirection
    {
        Push,
        Pull
    }

    public class ImplantTemplate : ILoggable, IYamlSerializable<ImplantTemplate>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Description { get; set; }
        public ImplantLanguage Language { get; set; }
        public CommunicationType CommType { get; set; }
        public ImplantDirection ImplantDirection { get; set; }

        public List<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<ReferenceSourceLibrary>();
        public List<ReferenceAssembly> ReferenceAssemblies { get; set; } = new List<ReferenceAssembly>();
        public List<EmbeddedResource> EmbeddedResources { get; set; } = new List<EmbeddedResource>();
        public List<ListenerType> CompatibleListenerTypes { get; set; } = new List<ListenerType>();
        public List<Common.DotNetVersion> CompatibleDotNetVersions { get; set; } = new List<Common.DotNetVersion>();

        public string StagerCode { get; set; } = "";
        public string ExecutorCode { get; set; } = "";

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<Grunt> Grunts { get; set; } = new List<Grunt>();

        private string StagerLocation
        {
            get
            {
                if (string.IsNullOrEmpty(this.Name))
                {
                    return "";
                }
                string dir = Common.CovenantDataDirectory + "Grunt" + Path.DirectorySeparatorChar + Utilities.GetSanitizedFilename(this.Name) + Path.DirectorySeparatorChar;
                string file = Utilities.GetSanitizedFilename(this.Name) + "Stager" + Utilities.GetExtensionForLanguage(this.Language);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                if (!File.Exists(dir + file))
                {
                    var fs = File.Create(dir + file);
                    fs.Close();
                }
                return dir + file;
            }
        }

        private string ExecutorLocation
        {
            get
            {
                if (string.IsNullOrEmpty(this.Name))
                {
                    return "";
                }
                string dir = Common.CovenantDataDirectory + "Grunt" + Path.DirectorySeparatorChar + Utilities.GetSanitizedFilename(this.Name) + Path.DirectorySeparatorChar;
                string file = Utilities.GetSanitizedFilename(this.Name) + Utilities.GetExtensionForLanguage(this.Language);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                if (!File.Exists(dir + file))
                {
                    var fs = File.Create(dir + file);
                    fs.Close();
                }
                return dir + file;
            }
        }

        public void ReadFromDisk()
        {
            if (!string.IsNullOrEmpty(this.StagerLocation) && File.Exists(this.StagerLocation))
            {
                this.StagerCode = File.ReadAllText(this.StagerLocation);
            }

            if (!string.IsNullOrEmpty(this.ExecutorLocation) && File.Exists(this.ExecutorLocation))
            {
                this.ExecutorCode = File.ReadAllText(this.ExecutorLocation);
            }
        }

        // ImplantTemplate|Action|ID|Name|Description|Language|CommType|ImplantDirection
        public string ToLog(LogAction action) => $"ImplantTemplate|{action}|{this.Id}|{this.Name}|{this.Description}|{this.Language}|{this.CommType}|{this.ImplantDirection}";
    }
}
