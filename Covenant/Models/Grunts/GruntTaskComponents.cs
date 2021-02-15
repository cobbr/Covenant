using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

using Covenant.Core;

namespace Covenant.Models.Grunts
{
    public class ReferenceAssembly : IYamlSerializable<ReferenceAssembly>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }
        public Common.DotNetVersion DotNetVersion { get; set; }

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<GruntTask> GruntTasks { get; set; } = new List<GruntTask>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<ImplantTemplate> ImplantTemplates { get; set; } = new List<ImplantTemplate>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<ReferenceSourceLibrary>();
    }

    public class EmbeddedResource : IYamlSerializable<EmbeddedResource>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<GruntTask> GruntTasks { get; set; } = new List<GruntTask>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<ImplantTemplate> ImplantTemplates { get; set; } = new List<ImplantTemplate>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<ReferenceSourceLibrary>();
    }

    public class ReferenceSourceLibrary : IYamlSerializable<ReferenceSourceLibrary>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;
        public List<Common.DotNetVersion> CompatibleDotNetVersions { get; set; } = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 };

        public List<ReferenceAssembly> ReferenceAssemblies { get; set; } = new List<ReferenceAssembly>();
        public List<EmbeddedResource> EmbeddedResources { get; set; } = new List<EmbeddedResource>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<GruntTask> GruntTasks { get; set; } = new List<GruntTask>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<ImplantTemplate> ImplantTemplates { get; set; } = new List<ImplantTemplate>();
    }
}
