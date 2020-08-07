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

        private List<ReferenceSourceLibraryReferenceAssembly> ReferenceSourceLibraryReferenceAssemblies { get; set; } = new List<ReferenceSourceLibraryReferenceAssembly>();
        private List<GruntTaskReferenceAssembly> GruntTaskReferenceAssemblies { get; set; } = new List<GruntTaskReferenceAssembly>();

        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries => ReferenceSourceLibraryReferenceAssemblies.Select(e => e.ReferenceSourceLibrary).ToList();
        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<GruntTask> GruntTasks => GruntTaskReferenceAssemblies.Select(e => e.GruntTask).ToList();
        
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

        private List<ReferenceSourceLibraryEmbeddedResource> ReferenceSourceLibraryEmbeddedResources { get; set; } = new List<ReferenceSourceLibraryEmbeddedResource>();
        private List<GruntTaskEmbeddedResource> GruntTaskEmbeddedResources { get; set; } = new List<GruntTaskEmbeddedResource>();

        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries => ReferenceSourceLibraryEmbeddedResources.Select(e => e.ReferenceSourceLibrary).ToList();
        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<GruntTask> GruntTasks => GruntTaskEmbeddedResources.Select(e => e.GruntTask).ToList();

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

        private List<ReferenceSourceLibraryReferenceAssembly> ReferenceSourceLibraryReferenceAssemblies { get; set; } = new List<ReferenceSourceLibraryReferenceAssembly>();
        private List<ReferenceSourceLibraryEmbeddedResource> ReferenceSourceLibraryEmbeddedResources { get; set; } = new List<ReferenceSourceLibraryEmbeddedResource>();
        private List<GruntTaskReferenceSourceLibrary> GruntTaskReferenceSourceLibraries { get; set; } = new List<GruntTaskReferenceSourceLibrary>();

        public void Add(ReferenceAssembly assembly)
        {
            ReferenceSourceLibraryReferenceAssemblies.Add(new ReferenceSourceLibraryReferenceAssembly
            {
                ReferenceSourceLibraryId = this.Id, ReferenceSourceLibrary = this,
                ReferenceAssemblyId = assembly.Id, ReferenceAssembly = assembly
            });
        }

        public void Remove(ReferenceAssembly assembly)
        {
            ReferenceSourceLibraryReferenceAssemblies.Remove(
                ReferenceSourceLibraryReferenceAssemblies
                    .FirstOrDefault(RSLRA => RSLRA.ReferenceSourceLibraryId == this.Id && RSLRA.ReferenceAssemblyId == assembly.Id)
            );
        }

        public void Add(EmbeddedResource resource)
        {
            ReferenceSourceLibraryEmbeddedResources.Add(new ReferenceSourceLibraryEmbeddedResource
            {
                ReferenceSourceLibraryId = this.Id, ReferenceSourceLibrary = this,
                EmbeddedResourceId = resource.Id, EmbeddedResource = resource
            });
        }

        public void Remove(EmbeddedResource resource)
        {
            ReferenceSourceLibraryEmbeddedResources.Remove(
                ReferenceSourceLibraryEmbeddedResources
                    .FirstOrDefault(RSLER => RSLER.ReferenceSourceLibraryId == this.Id && RSLER.EmbeddedResourceId == resource.Id)
            );
        }

        [NotMapped]
        public List<ReferenceAssembly> ReferenceAssemblies => ReferenceSourceLibraryReferenceAssemblies.Select(e => e.ReferenceAssembly).ToList();
        [NotMapped]
        public List<EmbeddedResource> EmbeddedResources => ReferenceSourceLibraryEmbeddedResources.Select(e => e.EmbeddedResource).ToList();
        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public List<GruntTask> GruntTasks => GruntTaskReferenceSourceLibraries.Select(e => e.GruntTask).ToList();

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
            library.ReferenceAssemblies.ForEach(A => this.Add(new ReferenceAssembly().FromSerializedReferenceAssembly(A)));
            library.EmbeddedResources.ForEach(R => this.Add(new EmbeddedResource().FromSerializedEmbeddedResource(R)));
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

    public class ReferenceSourceLibraryReferenceAssembly
    {
        public int ReferenceSourceLibraryId { get; set; }
        public ReferenceSourceLibrary ReferenceSourceLibrary { get; set; }

        public int ReferenceAssemblyId { get; set; }
        public ReferenceAssembly ReferenceAssembly { get; set; }
    }

    public class ReferenceSourceLibraryEmbeddedResource
    {
        public int ReferenceSourceLibraryId { get; set; }
        public ReferenceSourceLibrary ReferenceSourceLibrary { get; set; }

        public int EmbeddedResourceId { get; set; }
        public EmbeddedResource EmbeddedResource { get; set; }
    }

    public class GruntTaskReferenceSourceLibrary
    {
        public int GruntTaskId { get; set; }
        public GruntTask GruntTask { get; set; }

        public int ReferenceSourceLibraryId { get; set; }
        public ReferenceSourceLibrary ReferenceSourceLibrary { get; set; }
    }

    public class GruntTaskReferenceAssembly
    {
        public int GruntTaskId { get; set; }
        public GruntTask GruntTask { get; set; }

        public int ReferenceAssemblyId { get; set; }
        public ReferenceAssembly ReferenceAssembly { get; set; }
    }

    public class GruntTaskEmbeddedResource
    {
        public int GruntTaskId { get; set; }
        public GruntTask GruntTask { get; set; }

        public int EmbeddedResourceId { get; set; }
        public EmbeddedResource EmbeddedResource { get; set; }
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
