using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

namespace Covenant.Models.Grunts
{
    public class GruntTaskOption : ISerializable<GruntTaskOption>
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
        public bool FileOption { get; set; } = false;

        public int GruntTaskId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GruntTask Task { get; set; }

        internal SerializedGruntTaskOption ToSerializedGruntTaskOption()
        {
            return new SerializedGruntTaskOption
            {
                Name = this.Name,
                Value = "",
                DefaultValue = this.DefaultValue,
                Description = this.Description,
                SuggestedValues = this.SuggestedValues,
                Optional = this.Optional,
                DisplayInCommand = this.DisplayInCommand,
                FileOption = this.FileOption
            };
        }

        internal GruntTaskOption FromSerializedGruntTaskOption(SerializedGruntTaskOption option)
        {
            this.Name = option.Name;
            this.Value = option.Value;
            this.DefaultValue = option.DefaultValue;
            this.Description = option.Description;
            this.SuggestedValues = option.SuggestedValues;
            this.Optional = option.Optional;
            this.DisplayInCommand = option.DisplayInCommand;
            this.FileOption = option.FileOption;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedGruntTaskOption());
        }

        public GruntTaskOption FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedGruntTaskOption option = deserializer.Deserialize<SerializedGruntTaskOption>(yaml);
            return this.FromSerializedGruntTaskOption(option);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedGruntTaskOption());
        }

        public GruntTaskOption FromJson(string json)
        {
            SerializedGruntTaskOption option = JsonConvert.DeserializeObject<SerializedGruntTaskOption>(json);
            return this.FromSerializedGruntTaskOption(option);
        }
    }

    internal class SerializedGruntTaskOption
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        public bool FileOption { get; set; } = false;
    }
}
