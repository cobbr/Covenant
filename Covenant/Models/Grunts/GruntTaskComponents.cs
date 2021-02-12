using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

using Covenant.Core;

namespace Covenant.Models.Grunts
{
    public class ReferenceAssembly : ISerializable<ReferenceAssembly>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }
        public Common.DotNetVersion DotNetVersion { get; set; }

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<GruntTask> GruntTasks { get; set; } = new List<GruntTask>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ImplantTemplate> ImplantTemplates { get; set; } = new List<ImplantTemplate>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<ReferenceSourceLibrary>();

        internal SerializedReferenceAssembly ToSerializedReferenceAssembly()
        {
            return new SerializedReferenceAssembly
            {
                Name = this.Name,
                Location = this.Location,
                DotNetVersion = this.DotNetVersion
            };
        }

        internal ReferenceAssembly FromSerializedReferenceAssembly(SerializedReferenceAssembly assembly)
        {
            this.Name = assembly.Name;
            this.Location = assembly.Location;
            this.DotNetVersion = assembly.DotNetVersion;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedReferenceAssembly());
        }

        public ReferenceAssembly FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedReferenceAssembly assembly = deserializer.Deserialize<SerializedReferenceAssembly>(yaml);
            return this.FromSerializedReferenceAssembly(assembly);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedReferenceAssembly());
        }

        public ReferenceAssembly FromJson(string json)
        {
            SerializedReferenceAssembly assembly = JsonConvert.DeserializeObject<SerializedReferenceAssembly>(json);
            return this.FromSerializedReferenceAssembly(assembly);
        }
    }

    public class EmbeddedResource : ISerializable<EmbeddedResource>
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<GruntTask> GruntTasks { get; set; } = new List<GruntTask>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ImplantTemplate> ImplantTemplates { get; set; } = new List<ImplantTemplate>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<ReferenceSourceLibrary>();

        internal SerializedEmbeddedResource ToSerializedEmbeddedResource()
        {
            return new SerializedEmbeddedResource
            {
                Name = this.Name,
                Location = this.Location
            };
        }

        internal EmbeddedResource FromSerializedEmbeddedResource(SerializedEmbeddedResource resource)
        {
            this.Name = resource.Name;
            this.Location = resource.Location;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedEmbeddedResource());
        }

        public EmbeddedResource FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedEmbeddedResource resource = deserializer.Deserialize<SerializedEmbeddedResource>(yaml);
            return FromSerializedEmbeddedResource(resource);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedEmbeddedResource());
        }

        public EmbeddedResource FromJson(string json)
        {
            SerializedEmbeddedResource resource = JsonConvert.DeserializeObject<SerializedEmbeddedResource>(json);
            return FromSerializedEmbeddedResource(resource);
        }
    }

    public class ReferenceSourceLibrary : ISerializable<ReferenceSourceLibrary>
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;
        public List<Common.DotNetVersion> CompatibleDotNetVersions { get; set; } = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 };

        public List<ReferenceAssembly> ReferenceAssemblies { get; set; } = new List<ReferenceAssembly>();
        public List<EmbeddedResource> EmbeddedResources { get; set; } = new List<EmbeddedResource>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<GruntTask> GruntTasks { get; set; } = new List<GruntTask>();
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ImplantTemplate> ImplantTemplates { get; set; } = new List<ImplantTemplate>();

        internal SerializedReferenceSourceLibrary ToSerializedReferenceSourceLibrary()
        {
            return new SerializedReferenceSourceLibrary
            {
                Name = this.Name,
                Description = this.Description,
                Location = this.Location,
                Language = this.Language,
                CompatibleDotNetVersions = this.CompatibleDotNetVersions,
                ReferenceAssemblies = this.ReferenceAssemblies.Select(RA => RA.ToSerializedReferenceAssembly()).ToList(),
                EmbeddedResources = this.EmbeddedResources.Select(ER => ER.ToSerializedEmbeddedResource()).ToList()
            };
        }

        internal ReferenceSourceLibrary FromSerializedReferenceSourceLibrary(SerializedReferenceSourceLibrary library)
        {
            this.Name = library.Name;
            this.Description = library.Description;
            this.Location = library.Location;
            this.Language = library.Language;
            this.CompatibleDotNetVersions = library.CompatibleDotNetVersions;
            this.ReferenceAssemblies = library.ReferenceAssemblies.Select(RA => new ReferenceAssembly().FromSerializedReferenceAssembly(RA)).ToList();
            this.EmbeddedResources = library.EmbeddedResources.Select(ER => new EmbeddedResource().FromSerializedEmbeddedResource(ER)).ToList();
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedReferenceSourceLibrary());
        }

        public ReferenceSourceLibrary FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedReferenceSourceLibrary library = deserializer.Deserialize<SerializedReferenceSourceLibrary>(yaml);
            return this.FromSerializedReferenceSourceLibrary(library);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedReferenceSourceLibrary());
        }

        public ReferenceSourceLibrary FromJson(string json)
        {
            SerializedReferenceSourceLibrary library = JsonConvert.DeserializeObject<SerializedReferenceSourceLibrary>(json);
            return this.FromSerializedReferenceSourceLibrary(library);
        }
    }

    internal class SerializedReferenceAssembly
    {
        public string Name { get; set; }
        public string Location { get; set; }
        public Common.DotNetVersion DotNetVersion { get; set; }
    }

    internal class SerializedEmbeddedResource
    {
        public string Name { get; set; }
        public string Location { get; set; }
    }

    internal class SerializedReferenceSourceLibrary
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;
        public List<Common.DotNetVersion> CompatibleDotNetVersions { get; set; }
        public List<SerializedReferenceAssembly> ReferenceAssemblies { get; set; }
        public List<SerializedEmbeddedResource> EmbeddedResources { get; set; }
    }
}
