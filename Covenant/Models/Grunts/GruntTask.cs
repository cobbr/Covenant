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
    public class GruntTask : ISerializable<GruntTask>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        public int AuthorId { get; set; }
        public GruntTaskAuthor Author { get; set; } = new GruntTaskAuthor();

        [Required]
        public string Name { get; set; } = "GenericTask";
        public List<string> Aliases { get; set; } = new List<string>();
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

        public string GetVerboseCommand(bool includeNotForDisplay = false)
        {
            string command = this.Name;
            for (int i = 0; i < this.Options.Count; i++)
            {
                if (this.Options[i].DisplayInCommand || includeNotForDisplay)
                {
                    command += " /" + this.Options[i].Name.ToLower() + ":\"" + this.Options[i].Value.Replace("\"", "\\\"") + "\"";
                }
            }
            return command;
        }

        internal SerializedGruntTask ToSerializedGruntTask()
        {
            return new SerializedGruntTask
            {
                Name = this.Name,
                Author = this.Author.ToSerializedGruntTaskAuthor(),
                Aliases = this.Aliases,
                Description = this.Description,
                Help = this.Help,
                Language = this.Language,
                CompatibleDotNetVersions = this.CompatibleDotNetVersions,
                Code = this.Code,
                TaskingType = this.TaskingType,
                UnsafeCompile = this.UnsafeCompile,
                TokenTask = this.TokenTask,
                Options = this.Options.OrderBy(O => O.Id).Select(O => O.ToSerializedGruntTaskOption()).ToList(),
                ReferenceSourceLibraries = this.ReferenceSourceLibraries.Select(RSL => RSL.ToSerializedReferenceSourceLibrary()).ToList(),
                ReferenceAssemblies = this.ReferenceAssemblies.Select(RA => RA.ToSerializedReferenceAssembly()).ToList(),
                EmbeddedResources = this.EmbeddedResources.Select(ER => ER.ToSerializedEmbeddedResource()).ToList()
            };
        }

        internal GruntTask FromSerializedGruntTask(SerializedGruntTask task)
        {
            this.Name = task.Name;
            this.Author = new GruntTaskAuthor().FromSerializedGruntTaskAuthor(task.Author);
            this.Aliases = task.Aliases;
            this.Description = task.Description;
            this.Help = task.Help;
            this.Language = task.Language;
            this.CompatibleDotNetVersions = task.CompatibleDotNetVersions;
            this.Code = task.Code;
            this.Compiled = false;
            this.TaskingType = task.TaskingType;
            this.UnsafeCompile = task.UnsafeCompile;
            this.TokenTask = task.TokenTask;
            this.Options = task.Options.Select(O => new GruntTaskOption().FromSerializedGruntTaskOption(O)).ToList();
            this.Options.ForEach(O => O.GruntTaskId = this.Id);
            task.ReferenceSourceLibraries.ForEach(RSL => this.Add(new ReferenceSourceLibrary().FromSerializedReferenceSourceLibrary(RSL)));
            task.ReferenceAssemblies.ForEach(RA => this.Add(new ReferenceAssembly().FromSerializedReferenceAssembly(RA)));
            task.EmbeddedResources.ForEach(ER => this.Add(new EmbeddedResource().FromSerializedEmbeddedResource(ER)));
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(new List<SerializedGruntTask> { this.ToSerializedGruntTask() });
        }

        public GruntTask FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedGruntTask task = deserializer.Deserialize<SerializedGruntTask>(yaml);
            return this.FromSerializedGruntTask(task);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedGruntTask());
        }

        public GruntTask FromJson(string json)
        {
            SerializedGruntTask task = JsonConvert.DeserializeObject<SerializedGruntTask>(json);
            return this.FromSerializedGruntTask(task);
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
                foreach (Common.DotNetVersion version in template.CompatibleDotNetVersions.Intersect(this.CompatibleDotNetVersions))
                {
                    if (version == Common.DotNetVersion.Net35)
                    {
                        this.CompileDotNet35();
                    }
                    else if (version == Common.DotNetVersion.Net40)
                    {
                        this.CompileDotNet40();
                    }
                    else if (version == Common.DotNetVersion.NetCore31)
                    {
                        this.CompileDotNetCore(template, runtimeIdentifier);
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
                    File = Common.CovenantEmbeddedResourcesDirectory + ER.Location,
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
                            File = Common.CovenantEmbeddedResourcesDirectory + ER.Location,
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
                        return new Compiler.Reference { File = Common.CovenantAssemblyReferenceDirectory + RA.Location, Framework = Common.DotNetVersion.Net35, Enabled = true };
                    })
                );
            });
            references35.AddRange(
                this.ReferenceAssemblies.Where(RA => RA.DotNetVersion == Common.DotNetVersion.Net35).Select(RA =>
                {
                    return new Compiler.Reference { File = Common.CovenantAssemblyReferenceDirectory + RA.Location, Framework = Common.DotNetVersion.Net35, Enabled = true };
                })
            );
            
            File.WriteAllBytes(Common.CovenantTaskCSharpCompiledNet35Directory + this.Name + ".compiled",
                Utilities.Compress(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = this.Language,
                    Source = this.Code,
                    SourceDirectories = this.ReferenceSourceLibraries.Select(RSL => Common.CovenantReferenceSourceLibraries + RSL.Location).ToList(),
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
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpWMI") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpSC") &&
                           !this.Name.Contains("inject", StringComparison.CurrentCultureIgnoreCase)
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
                    File = Common.CovenantEmbeddedResourcesDirectory + ER.Location,
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
                            File = Common.CovenantEmbeddedResourcesDirectory + ER.Location,
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
                        return new Compiler.Reference { File = Common.CovenantAssemblyReferenceDirectory + RA.Location, Framework = Common.DotNetVersion.Net40, Enabled = true };
                    })
                );
            });
            references40.AddRange(
                this.ReferenceAssemblies.Where(RA => RA.DotNetVersion == Common.DotNetVersion.Net40).Select(RA =>
                {
                    return new Compiler.Reference { File = Common.CovenantAssemblyReferenceDirectory + RA.Location, Framework = Common.DotNetVersion.Net40, Enabled = true };
                })
            );
            File.WriteAllBytes(Common.CovenantTaskCSharpCompiledNet40Directory + this.Name + ".compiled",
                Utilities.Compress(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = this.Language,
                    Source = this.Code,
                    SourceDirectories = this.ReferenceSourceLibraries.Select(RSL => Common.CovenantReferenceSourceLibraries + RSL.Location).ToList(),
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
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpWMI") &&
                           !this.ReferenceSourceLibraries.Select(RSL => RSL.Name).Contains("SharpSC") &&
                           !this.Name.Contains("inject", StringComparison.CurrentCultureIgnoreCase)
                }))
            );
        }

        private void CompileDotNetCore(ImplantTemplate template, Compiler.RuntimeIdentifier runtimeIdentifier)
        {
            string cspprojformat =
@"<Project Sdk=""Microsoft.NET.Sdk"">

  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFramework>netcoreapp3.1</TargetFramework>
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
                    TargetDotNetVersion = Common.DotNetVersion.NetCore31,
                    SourceDirectory = dir,
                    OutputKind = OutputKind.DynamicallyLinkedLibrary,
                    RuntimeIdentifier = runtimeIdentifier,
                    UseSubprocess = true
                }))
            );
        }
    }

    internal class SerializedGruntTask
    {
        public string Name { get; set; } = "";
        public List<string> Aliases { get; set; } = new List<string>();
        public SerializedGruntTaskAuthor Author { get; set; }
        public string Description { get; set; } = "";
        public string Help { get; set; } = "";
        public ImplantLanguage Language { get; set; }
        public IList<Common.DotNetVersion> CompatibleDotNetVersions { get; set; } = new List<Common.DotNetVersion>();
        public string Code { get; set; } = "";
        public GruntTaskingType TaskingType { get; set; } = GruntTaskingType.Assembly;
        public bool UnsafeCompile { get; set; } = false;
        public bool TokenTask { get; set; } = false;
        public List<SerializedGruntTaskOption> Options { get; set; } = new List<SerializedGruntTaskOption>();
        public List<SerializedReferenceSourceLibrary> ReferenceSourceLibraries { get; set; } = new List<SerializedReferenceSourceLibrary>();
        public List<SerializedReferenceAssembly> ReferenceAssemblies { get; set; } = new List<SerializedReferenceAssembly>();
        public List<SerializedEmbeddedResource> EmbeddedResources { get; set; } = new List<SerializedEmbeddedResource>();
    }
}
