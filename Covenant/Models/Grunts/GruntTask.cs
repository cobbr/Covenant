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

        private List<String> _referenceAssemblies = new List<String> { };
        // Split into comma-delimited list to easily save as text in the Database
        public String ReferenceAssemblies {
            get { return String.Join(',', _referenceAssemblies); }
            set { _referenceAssemblies = value.Split(',').Where(V => V.Length > 0).ToList(); }
        }

        private List<String> _referenceSourceLibraries = new List<String> { };
        // Split into comma-delimited list to easily save as text in the Database
        public String ReferenceSourceLibraries
        {
            get { return String.Join(',', _referenceSourceLibraries); }
            set { _referenceSourceLibraries = value.Split(',').Where(V => V.Length > 0).ToList(); }
        }

        private List<String> _embeddedResources = new List<String> { };
        // Split into comma-delimited list to easily save as text in the Database
        public String EmbeddedResources
        {
            get { return String.Join(',', _embeddedResources); }
            set { _embeddedResources = value.Split(',').Where(V => V.Length > 0).ToList(); }
        }

        public class GruntTaskOption
        {
            public int Id { get; set; }
            public int TaskId { get; set; }
            public int OptionId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public string Value { get; set; }
        }

        public List<GruntTaskOption> Options { get; set; } = new List<GruntTaskOption> { };

        public string Code { get; set; } = "";

        public List<String> GetReferenceAssemblies()
        {
            return _referenceAssemblies;
        }

        public List<String> GetReferenceSourceLibraries()
        {
            return _referenceSourceLibraries;
        }

        public List<String> GetEmbeddedResources()
        {
            return _embeddedResources;
        }
    }
}
