// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using Microsoft.CodeAnalysis;

using Covenant.Core;

namespace Covenant.Models.Grunts
{
    public class GruntTaskOption
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public string DefaultValue { get; set; }
        public string Description { get; set; }
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        
        public int GruntTaskId { get; set; }
        public GruntTask Task { get; set; }
    }

    public class GruntTask
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = "GenericTask";
        public List<string> AlternateNames { get; set; } = new List<string>();
        public string Description { get; set; } = "A generic GruntTask.";
        public string Help { get; set; }
        public ImplantLanguage Language { get; set; } = ImplantLanguage.CSharp;

        public string Code { get; set; } = "";
        public bool Compiled { get; set; } = false;

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

        public byte[] GetCompressedILAssembly35()
        {
            return File.ReadAllBytes(Common.CovenantTaskCSharpCompiledNet35Directory + this.Name + ".compiled");
        }

        public byte[] GetCompressedILAssembly40()
        {
            return File.ReadAllBytes(Common.CovenantTaskCSharpCompiledNet40Directory + this.Name + ".compiled");
        }

        public void Compile()
        {
            if (!this.Compiled)
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
                    Utilities.Compress(Compiler.Compile(new Compiler.CompilationRequest
                    {
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
                    Utilities.Compress(Compiler.Compile(new Compiler.CompilationRequest
                    {
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
        }
    }
}
