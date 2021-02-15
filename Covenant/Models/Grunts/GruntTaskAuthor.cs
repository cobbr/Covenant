using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

namespace Covenant.Models.Grunts
{
    public class GruntTaskAuthor : IYamlSerializable<GruntTaskAuthor>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Handle { get; set; } = "";
        public string Link { get; set; } = "";

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore, YamlIgnore]
        public List<GruntTask> GruntTasks { get; set; }
    }
}
