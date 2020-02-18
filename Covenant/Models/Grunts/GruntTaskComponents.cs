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

        private class SimpleReferenceAssembly
        {
            public string Name { get; set; }
            public string Location { get; set; }
            public Common.DotNetVersion DotNetVersion { get; set; }
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(new SimpleReferenceAssembly
            {
                Name = this.Name,
                Location = this.Location,
                DotNetVersion = this.DotNetVersion
            });
        }

        public ReferenceAssembly FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SimpleReferenceAssembly assembly = deserializer.Deserialize<SimpleReferenceAssembly>(yaml);
            this.Name = assembly.Name;
            this.Location = assembly.Location;
            this.DotNetVersion = assembly.DotNetVersion;
            return this;
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public ReferenceAssembly FromJson(string json)
        {
            SimpleReferenceAssembly assembly = JsonConvert.DeserializeObject<SimpleReferenceAssembly>(json);
            this.Name = assembly.Name;
            this.Location = assembly.Location;
            this.DotNetVersion = assembly.DotNetVersion;
            return this;
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

        private class SimpleEmbeddedResource
        {
            public string Name { get; set; }
            public string Location { get; set; }
        }
        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(new SimpleEmbeddedResource
            {
                Name = this.Name,
                Location = this.Location
            });
        }

        public EmbeddedResource FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SimpleEmbeddedResource resource = deserializer.Deserialize<SimpleEmbeddedResource>(yaml);
            this.Name = resource.Name;
            this.Location = resource.Location;
            return this;
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public EmbeddedResource FromJson(string json)
        {
            SimpleEmbeddedResource resource = JsonConvert.DeserializeObject<SimpleEmbeddedResource>(json);
            this.Name = resource.Name;
            this.Location = resource.Location;
            return this;
        }
    }

    public class ReferenceSourceLibrary : ISerializable<ReferenceSourceLibrary>
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;
        public List<Common.DotNetVersion> CompatibleDotNetVersions { get; set; }

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

        private class SimpleReferenceSourceLibrary
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public string Location { get; set; }
            public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;
            public List<Common.DotNetVersion> CompatibleDotNetVersions { get; set; }
            public List<ReferenceAssembly> ReferenceAssemblies { get; set; }
            public List<EmbeddedResource> EmbeddedResources { get; set; }
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(new SimpleReferenceSourceLibrary
            {
                Name = this.Name,
                Description = this.Description,
                Location = this.Location,
                Language = this.Language,
                CompatibleDotNetVersions = this.CompatibleDotNetVersions,
                ReferenceAssemblies = this.ReferenceAssemblies,
                EmbeddedResources = this.EmbeddedResources
            });
        }

        public ReferenceSourceLibrary FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SimpleReferenceSourceLibrary library = deserializer.Deserialize<SimpleReferenceSourceLibrary>(yaml);
            this.Name = library.Name;
            this.Description = library.Description;
            this.Location = library.Location;
            this.Language = library.Language;
            this.CompatibleDotNetVersions = library.CompatibleDotNetVersions;
            library.ReferenceAssemblies.ForEach(A => this.Add(A));
            library.EmbeddedResources.ForEach(R => this.Add(R));
            return this;
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public ReferenceSourceLibrary FromJson(string json)
        {
            SimpleReferenceSourceLibrary library = JsonConvert.DeserializeObject<SimpleReferenceSourceLibrary>(json);
            this.Name = library.Name;
            this.Description = library.Description;
            this.Location = library.Location;
            this.Language = library.Language;
            this.CompatibleDotNetVersions = library.CompatibleDotNetVersions;
            library.ReferenceAssemblies.ForEach(A => this.Add(A));
            library.EmbeddedResources.ForEach(R => this.Add(R));
            return this;
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
}
