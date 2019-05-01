// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;

namespace Covenant.Models.Grunts
{
    public class GruntTask
    {
        public int Id { get; set; }

        public string Name { get; set; } = "GenericTask";
        public string Description { get; set; } = "A generic GruntTask.";
        public string Help { get; set; }
        public bool TokenTask { get; set; } = false;

        public string Code { get; set; } = "";
        public List<string> ReferenceAssemblies { get; set; } = new List<string>();
        public List<string> ReferenceSourceLibraries { get; set; } = new List<string>();
        public List<string> EmbeddedResources { get; set; } = new List<string>();
        public bool UnsafeCompile { get; set; } = false;

        public List<GruntTaskOption> Options { get; set; } = new List<GruntTaskOption>();

        public class GruntTaskOption
        {
            public int Id { get; set; }
            public string Name { get; set; }
            public string Value { get; set; }
            public string Description { get; set; }
        }
    }
}
