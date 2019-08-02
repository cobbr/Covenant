using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;

using Covenant.Core;

namespace Covenant.Models.Grunts
{
    public class ReferenceAssembly
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }
        public Common.DotNetVersion DotNetVersion { get; set; }

        private List<ReferenceSourceLibraryReferenceAssembly> ReferenceSourceLibraryReferenceAssemblies { get; set; } = new List<ReferenceSourceLibraryReferenceAssembly>();
        private List<GruntTaskReferenceAssembly> GruntTaskReferenceAssemblies { get; set; } = new List<GruntTaskReferenceAssembly>();

        [NotMapped]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries => ReferenceSourceLibraryReferenceAssemblies.Select(e => e.ReferenceSourceLibrary).ToList();
        [NotMapped]
        public List<GruntTask> GruntTasks => GruntTaskReferenceAssemblies.Select(e => e.GruntTask).ToList();
    }

    public class EmbeddedResource
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }

        private List<ReferenceSourceLibraryEmbeddedResource> ReferenceSourceLibraryEmbeddedResources { get; set; } = new List<ReferenceSourceLibraryEmbeddedResource>();
        private List<GruntTaskEmbeddedResource> GruntTaskEmbeddedResources { get; set; } = new List<GruntTaskEmbeddedResource>();

        [NotMapped]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries => ReferenceSourceLibraryEmbeddedResources.Select(e => e.ReferenceSourceLibrary).ToList();
        [NotMapped]
        public List<GruntTask> GruntTasks => GruntTaskEmbeddedResources.Select(e => e.GruntTask).ToList();
    }

    public class ReferenceSourceLibrary
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public List<Common.DotNetVersion> SupportedDotNetVersions { get; set; }

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
        [NotMapped]
        public List<GruntTask> GruntTasks => GruntTaskReferenceSourceLibraries.Select(e => e.GruntTask).ToList();
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
