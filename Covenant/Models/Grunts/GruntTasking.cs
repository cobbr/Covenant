// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Covenant;

namespace Covenant.Models.Grunts
{
    public enum GruntTaskingStatus
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed
    }

    public enum GruntTaskingType
    {
        Assembly,
        SetDelay,
        SetJitter,
        SetConnectAttempts,
        Kill,
        Connect,
        Disconnect,
        Jobs
    }

    public class GruntTaskingMessage
    {
        public GruntTaskingType Type { get; set; }
        public string Name { get; set; }
        public string Message { get; set; }
        public bool Token { get; set; }
    }

    public class GruntTasking
    {
        public int Id { get; set; }
        public string Name { get; set; } = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);

        public int GruntId { get; set; }
        public int TaskId { get; set; }

        public GruntTaskingType Type { get; set; } = GruntTaskingType.Assembly;
        public string TaskingMessage { get; set; } = "";
        public bool TokenTask { get; set; } = false;

        public string TaskingCommand { get; set; } = "";
        public string TaskingUser { get; set; }

        public GruntTaskingStatus Status { get; set; } = GruntTaskingStatus.Uninitialized;
        public string GruntTaskOutput { get; set; } = "";

        public DateTime TaskingTime { get; set; } = DateTime.MinValue;
        public DateTime CompletionTime { get; set; } = DateTime.MinValue;

        public GruntTaskingMessage GruntTaskingMessage
        {
            get
            {
                return new GruntTaskingMessage
                {
                    Type = this.Type,
                    Name = this.Name,
                    Message = this.TaskingMessage,
                    Token = this.TokenTask
                };
            }
        }

        public string Compile(GruntTask task, Grunt grunt, List<string> Parameters)
        {
            this.TokenTask = task.TokenTask;
            List<Compiler.Reference> references = Common.DefaultReferences;
            task.ReferenceAssemblies.ForEach(RA =>
            {
                references.AddRange(
                    new List<Compiler.Reference> {
                        new Compiler.Reference { File = RA, Framework = Common.DotNetVersion.Net35, Enabled = true },
                        new Compiler.Reference { File = RA, Framework = Common.DotNetVersion.Net40, Enabled = true }
                    }
                );
            });
            List<Compiler.EmbeddedResource> resources = task.EmbeddedResources.Select(ER =>
            {
                return new Compiler.EmbeddedResource
                {
                    Name = ER,
                    File = ER,
                    Platform = Platform.X64,
                    Enabled = true
                };
            }).ToList();
            byte[] compiled = Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = task.Code,
                SourceDirectory = task.ReferenceSourceLibraries == null || task.ReferenceSourceLibraries.Count == 0 ? null : Common.CovenantSrcDirectory + Path.DirectorySeparatorChar + task.ReferenceSourceLibraries[0],
                ResourceDirectory = Common.CovenantResourceDirectory,
                ReferenceDirectory = Common.CovenantReferenceDirectory,
                TargetDotNetVersion = grunt.DotNetFrameworkVersion,
                References = references,
                EmbeddedResources = resources,
                UnsafeCompile = task.UnsafeCompile,
                Confuse = true,
                // TODO: Fix optimization to work with GhostPack
                Optimize = !task.ReferenceSourceLibraries.Contains("Rubeus") &&
                           !task.ReferenceSourceLibraries.Contains("SharpDPAPI") &&
                           !task.ReferenceSourceLibraries.Contains("SharpUp") &&
                           !task.ReferenceSourceLibraries.Contains("Seatbelt")
            });

            this.TaskingMessage = Convert.ToBase64String(Utilities.Compress(compiled));
            foreach(string Parameter in Parameters)
            {
                this.TaskingMessage += "," + Convert.ToBase64String(Common.CovenantEncoding.GetBytes(Parameter));
            }
            return this.TaskingMessage;
        }
    }
}
