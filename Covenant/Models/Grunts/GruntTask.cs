// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Microsoft.CodeAnalysis;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

using Covenant.Core;

namespace Covenant.Models.Grunts
{
    public class GruntTaskOption
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        
        public int GruntTaskId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GruntTask Task { get; set; }
    }

    public class GruntTask : ISerializable<GruntTask>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = "GenericTask";
        public IList<string> Aliases { get; set; } = new List<string>();
        public string Description { get; set; } = "A generic GruntTask.";
        public string Help { get; set; }
        public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;
        public IList<Common.DotNetVersion> CompatibleDotNetVersions { get; set; } = new List<Common.DotNetVersion> { Common.DotNetVersion.Net35, Common.DotNetVersion.Net40 };

        public string Code { get; set; } = "";
        public bool Compiled { get; set; } = false;
        public GruntTaskingType TaskingType { get; set; } = GruntTaskingType.Assembly;

        private List<GruntTaskReferenceSourceLibrary> GruntTaskReferenceSourceLibraries { get; set; } = new List<GruntTaskReferenceSourceLibrary>();
        private List<GruntTaskReferenceAssembly> GruntTaskReferenceAssemblies { get; set; } = new List<GruntTaskReferenceAssembly>();
        private List<GruntTaskEmbeddedResource> GruntTaskEmbeddedResources { get; set; } = new List<GruntTaskEmbeddedResource>();
        [NotMapped]
        public List<ReferenceSourceLibrary> ReferenceSourceLibraries => GruntTaskReferenceSourceLibraries.Select(e => e.ReferenceSourceLibrary).ToList();
        [NotMapped]
        public List<ReferenceAssembly> ReferenceAssemblies => GruntTaskReferenceAssemblies.Select(e => e.ReferenceAssembly).ToList();
        [NotMapped]
        public List<EmbeddedResource> EmbeddedResources => GruntTaskEmbeddedResources.Select(e => e.EmbeddedResource).ToList();

        public bool UnsafeCompile { get; set; } = false;
        public bool TokenTask { get; set; } = false;

        public List<GruntTaskOption> Options { get; set; } = new List<GruntTaskOption>();

        public void Add(ReferenceSourceLibrary library)
        {
            GruntTaskReferenceSourceLibraries.Add(new GruntTaskReferenceSourceLibrary
            {
                GruntTaskId = this.Id, GruntTask = this,
                ReferenceSourceLibraryId = library.Id, ReferenceSourceLibrary = library
            });
        }

        public void Remove(ReferenceSourceLibrary library)
        {
            GruntTaskReferenceSourceLibraries.Remove(
                GruntTaskReferenceSourceLibraries
                    .FirstOrDefault(GTRSL => GTRSL.GruntTaskId == this.Id && GTRSL.ReferenceSourceLibraryId == library.Id)
            );
        }

        public void Add(ReferenceAssembly assembly)
        {
            GruntTaskReferenceAssemblies.Add(new GruntTaskReferenceAssembly
            {
                GruntTaskId = this.Id, GruntTask = this,
                ReferenceAssemblyId = assembly.Id, ReferenceAssembly = assembly
            });
        }

        public void Remove(ReferenceAssembly assembly)
        {
            GruntTaskReferenceAssemblies.Remove(
                GruntTaskReferenceAssemblies
                    .FirstOrDefault(GTRA => GTRA.GruntTaskId == this.Id && GTRA.ReferenceAssemblyId == assembly.Id)
            );
        }

        public void Add(EmbeddedResource resource)
        {
            GruntTaskEmbeddedResources.Add(new GruntTaskEmbeddedResource
            {
                GruntTaskId = this.Id, GruntTask = this,
                EmbeddedResourceId = resource.Id, EmbeddedResource = resource
            });
        }

        public void Remove(EmbeddedResource resource)
        {
            GruntTaskEmbeddedResources.Remove(
                GruntTaskEmbeddedResources
                    .FirstOrDefault(GTER => GTER.GruntTaskId == this.Id && GTER.EmbeddedResourceId == resource.Id)
            );
        }

        private class SimpleGruntTask
        {
            public string Name { get; set; } = "";
            public IList<string> Aliases { get; set; } = new List<string>();
            public string Description { get; set; } = "";
            public string Help { get; set; } = "";
            public ImplantLanguage Language { get; set; }
            public IList<Common.DotNetVersion> CompatibleDotNetVersions { get; set; } = new List<Common.DotNetVersion>();
            public string Code { get; set; } = "";
            public bool Compiled { get; set; } = false;
            public GruntTaskingType TaskingType { get; set; } = GruntTaskingType.Assembly;
            public bool UnsafeCompile { get; set; } = false;
            public bool TokenTask { get; set; } = false;
            public List<GruntTaskOption> Options { get; set; } = new List<GruntTaskOption>();
            public List<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<ReferenceSourceLibrary>();
            public List<ReferenceAssembly> ReferenceAssemblies { get; set; } = new List<ReferenceAssembly>();
            public List<EmbeddedResource> EmbeddedResources { get; set; } = new List<EmbeddedResource>();
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(new SimpleGruntTask
            {
                Name = this.Name,
                Aliases = this.Aliases,
                Description = this.Description,
                Help = this.Help,
                Language = this.Language,
                CompatibleDotNetVersions = this.CompatibleDotNetVersions,
                Code = this.Code,
                Compiled = this.Compiled,
                TaskingType = this.TaskingType,
                UnsafeCompile = this.UnsafeCompile,
                TokenTask = this.TokenTask,
                Options = this.Options,
                ReferenceSourceLibraries = this.ReferenceSourceLibraries,
                ReferenceAssemblies = this.ReferenceAssemblies,
                EmbeddedResources = this.EmbeddedResources
            });
        }

        public GruntTask FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SimpleGruntTask task = deserializer.Deserialize<SimpleGruntTask>(yaml);
            this.Name = task.Name;
            this.Aliases = task.Aliases;
            this.Description = task.Description;
            this.Help = task.Help;
            this.Language = task.Language;
            this.CompatibleDotNetVersions = task.CompatibleDotNetVersions;
            this.Code = task.Code;
            this.Compiled = task.Compiled;
            this.TaskingType = task.TaskingType;
            this.UnsafeCompile = task.UnsafeCompile;
            this.TokenTask = task.TokenTask;
            this.Options = task.Options;
            task.ReferenceSourceLibraries.ForEach(RSL => this.Add(RSL));
            task.ReferenceAssemblies.ForEach(A => this.Add(A));
            task.EmbeddedResources.ForEach(R => this.Add(R));
            return this;
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public GruntTask FromJson(string json)
        {
            SimpleGruntTask task = JsonConvert.DeserializeObject<SimpleGruntTask>(json);
            this.Name = task.Name;
            this.Aliases = task.Aliases;
            this.Description = task.Description;
            this.Help = task.Help;
            this.Language = task.Language;
            this.CompatibleDotNetVersions = task.CompatibleDotNetVersions;
            this.Code = task.Code;
            this.Compiled = task.Compiled;
            this.TaskingType = task.TaskingType;
            this.UnsafeCompile = task.UnsafeCompile;
            this.TokenTask = task.TokenTask;
            this.Options = task.Options;
            task.ReferenceSourceLibraries.ForEach(RSL => this.Add(RSL));
            task.ReferenceAssemblies.ForEach(A => this.Add(A));
            task.EmbeddedResources.ForEach(R => this.Add(R));
            return this;
        }

        public byte[] GetCompressedILAssembly35()
        {
            return File.ReadAllBytes(Common.CovenantTaskCSharpCompiledNet35Directory + this.Name + ".compiled");
        }

        public byte[] GetCompressedILAssembly40()
        {
            return File.ReadAllBytes(Common.CovenantTaskCSharpCompiledNet40Directory + this.Name + ".compiled");
        }

        public void Compile(ImplantTemplate template, Compiler.RuntimeIdentifier runtimeIdentifier = Compiler.RuntimeIdentifier.win_x64)
        {
            if (!this.Compiled)
            {
                foreach (Common.DotNetVersion version in this.CompatibleDotNetVersions)
                {
                    if (version == Common.DotNetVersion.Net35)
                    {
                        this.CompileDotNet35();
                    }
                    else if (version == Common.DotNetVersion.Net40)
                    {
                        this.CompileDotNet40();
                    }
                    else if (version == Common.DotNetVersion.NetCore30)
                    {
                        this.CompileDotNetCore30(template, runtimeIdentifier);
                    }
                }

            }
        }

        private void CompileDotNet35()
        {
            List<Compiler.EmbeddedResource> resources = this.EmbeddedResources.Select(ER =>
            {
                return new Compiler.EmbeddedResource
                {
                    Name = ER.Name,
                    File = ER.Location,
                    Platform = Platform.X64,
                    Enabled = true
                };
            }).ToList();
            this.ReferenceSourceLibraries.ToList().ForEach(RSL =>
            {
                resources.AddRange(
                    RSL.EmbeddedResources.Select(ER =>
                    {
                        return new Compiler.EmbeddedResource
                        {
                            Name = ER.Name,
                            File = ER.Location,
                            Platform = Platform.X64,
                            Enabled = true
                        };
                    })
                );
            });
            List<Compiler.Reference> references35 = new List<Compiler.Reference>();
            this.ReferenceSourceLibraries.ToList().ForEach(RSL =>
            {
                references35.AddRange(
                    RSL.ReferenceAssemblies.Where(RA => RA.DotNetVersion == Common.DotNetVersion.Net35).Select(RA =>
                    {
                        return new Compiler.Reference { File = RA.Location, Framework = Common.DotNetVersion.Net35, Enabled = true };
                    })
                );
            });
            references35.AddRange(
                this.ReferenceAssemblies.Where(RA => RA.DotNetVersion == Common.DotNetVersion.Net35).Select(RA =>
                {
                    return new Compiler.Reference { File = RA.Location, Framework = Common.DotNetVersion.Net35, Enabled = true };
                })
            );

            File.WriteAllBytes(Common.CovenantTaskCSharpCompiledNet35Directory + this.Name + ".compiled",
                Utilities.Compress(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = this.Language,
                    Source = this.Code,
                    SourceDirectories = this.ReferenceSourceLibraries.Select(RSL => RSL.Location).ToList(),
                    TargetDotNetVersion = Common.DotNetVersion.Net35,
                    References = references35,
                    EmbeddedResources = resources,
                    UnsafeCompile = this.UnsafeCompile,
                    Confuse = true,
                    // TODO: Fix optimization to work with GhostPack
                    Optimize = !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("Rubeus") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("Seatbelt") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpDPAPI") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpDump") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpUp") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpWMI")
                }))
            );
        }

        private void CompileDotNet40()
        {
            List<Compiler.EmbeddedResource> resources = this.EmbeddedResources.Select(ER =>
            {
                return new Compiler.EmbeddedResource
                {
                    Name = ER.Name,
                    File = ER.Location,
                    Platform = Platform.X64,
                    Enabled = true
                };
            }).ToList();
            this.ReferenceSourceLibraries.ToList().ForEach(RSL =>
            {
                resources.AddRange(
                    RSL.EmbeddedResources.Select(ER =>
                    {
                        return new Compiler.EmbeddedResource
                        {
                            Name = ER.Name,
                            File = ER.Location,
                            Platform = Platform.X64,
                            Enabled = true
                        };
                    })
                );
            });
            List<Compiler.Reference> references40 = new List<Compiler.Reference>();
            this.ReferenceSourceLibraries.ToList().ForEach(RSL =>
            {
                references40.AddRange(
                    RSL.ReferenceAssemblies.Where(RA => RA.DotNetVersion == Common.DotNetVersion.Net40).Select(RA =>
                    {
                        return new Compiler.Reference { File = RA.Location, Framework = Common.DotNetVersion.Net40, Enabled = true };
                    })
                );
            });
            references40.AddRange(
                this.ReferenceAssemblies.Where(RA => RA.DotNetVersion == Common.DotNetVersion.Net40).Select(RA =>
                {
                    return new Compiler.Reference { File = RA.Location, Framework = Common.DotNetVersion.Net40, Enabled = true };
                })
            );
            File.WriteAllBytes(Common.CovenantTaskCSharpCompiledNet40Directory + this.Name + ".compiled",
                Utilities.Compress(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = this.Language,
                    Source = this.Code,
                    SourceDirectories = this.ReferenceSourceLibraries.Select(RSL => RSL.Location).ToList(),
                    TargetDotNetVersion = Common.DotNetVersion.Net40,
                    References = references40,
                    EmbeddedResources = resources,
                    UnsafeCompile = this.UnsafeCompile,
                    Confuse = true,
                    // TODO: Fix optimization to work with GhostPack
                    Optimize = !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("Rubeus") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("Seatbelt") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpDPAPI") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpDump") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpUp") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpWMI")
                }))
            );
        }

        private void CompileDotNetCore30(ImplantTemplate template, Compiler.RuntimeIdentifier runtimeIdentifier)
        {
            string cspprojformat =
@"<Project Sdk=""Microsoft.NET.Sdk"">

  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFramework>netcoreapp3.0</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
  </PropertyGroup>

  {0}
</Project>";
            string referencegroupformat =
@"<ItemGroup>
    {0}
  </ItemGroup>";
            string referenceformat =
@"<Reference Include=""{0}"">
      <HintPath>{1}</HintPath>
    </Reference>";

            IEnumerable<string> references = this.ReferenceAssemblies.Select(RA =>
            {
                string name = RA.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? RA.Name.Substring(0, RA.Name.Length - 4) : RA.Name;
                return string.Format(referenceformat, name, RA.Location);
            });
            string csproj = string.Format(cspprojformat, string.Format(referencegroupformat, string.Join(Environment.NewLine + "    ", references)));
            string sanitizedName = Utilities.GetSanitizedFilename(template.Name);
            string dir = Common.CovenantDataDirectory + "Grunt" + Path.DirectorySeparatorChar + sanitizedName + Path.DirectorySeparatorChar + "Task" + Path.DirectorySeparatorChar;
            string file = "Task" + Utilities.GetExtensionForLanguage(this.Language);
            File.WriteAllText(dir + "Task" + ".csproj", csproj);
            File.WriteAllText(dir + file, this.Code);
            File.WriteAllBytes(Common.CovenantTaskCSharpCompiledNetCoreApp30Directory + this.Name + ".compiled",
                Utilities.Compress(Compiler.Compile(new Compiler.CsharpCoreCompilationRequest
                {
                    ResultName = "Task",
                    Language = this.Language,
                    TargetDotNetVersion = Common.DotNetVersion.NetCore30,
                    SourceDirectory = dir,
                    OutputKind = OutputKind.DynamicallyLinkedLibrary,
                    RuntimeIdentifier = runtimeIdentifier
                }))
            );
        }
    }
}
