using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

namespace Covenant.Models.Grunts
{
    public class GruntTaskOption : IYamlSerializable<GruntTaskOption>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        public bool FileOption { get; set; } = false;

        public int GruntTaskId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public GruntTask Task { get; set; }
    }
}
