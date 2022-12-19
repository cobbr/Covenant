// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.IO;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using YamlDotNet.Serialization;
using YamlDotNet.RepresentationModel;

namespace Covenant.Models.Listeners
{
    public enum ProfileType
    {
        HTTP,
        Bridge
    }

    public class Profile : ILoggable, IYamlSerializable<Profile>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity), YamlIgnore]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ProfileType Type { get; set; }
        public string MessageTransform { get; set; } =
@"public static class MessageTransform
{
    public static string Transform(byte[] bytes)
    {
        return System.Convert.ToBase64String(bytes);
    }
    public static byte[] Invert(string str)
    {
        return System.Convert.FromBase64String(str);
    }
}";

        // Profile|Action|ID|Name|Description|Type
        public string ToLog(LogAction action) => $"Listener|{action}|{this.Id}|{this.Name}|{this.Description}|{this.Type}";

        public string ToYaml()
        {
            if (this.Type == ProfileType.HTTP)
            {
                return ((HttpProfile)this).ToYaml();
            }
            else if (this.Type == ProfileType.Bridge)
            {
                return ((BridgeProfile)this).ToYaml();
            }
            return "";
        }

        public static Profile FromYaml(string yaml)
        {
            Profile p = new DeserializerBuilder()
                .IgnoreUnmatchedProperties()
                .Build()
                .Deserialize<Profile>(yaml);
            if (p.Type == ProfileType.HTTP)
            {
                return HttpProfile.FromYaml(yaml);
            }
            else if (p.Type == ProfileType.Bridge)
            {
                return BridgeProfile.FromYaml(yaml);
            }
            return null;
        }

        public static IEnumerable<Profile> FromYamlEnumerable(string yaml)
        {
            List<Profile> profiles = new List<Profile>();
            YamlStream stream = new YamlStream();
            stream.Load(new StringReader(yaml));
            YamlSequenceNode list = (YamlSequenceNode)stream.Documents[0].RootNode;
            foreach (YamlMappingNode entry in list)
            {
                var type = entry.Children[new YamlScalarNode("Type")];
                var str = entry.ToString();
                var test = entry.ToYaml();
                ProfileType profType = System.Enum.Parse<ProfileType>(type.ToString());
                if (profType == ProfileType.HTTP)
                {
                    HttpProfile profile = new DeserializerBuilder()
                        .Build()
                        .Deserialize<HttpProfile>(test);
                    profiles.Add(profile);
                }
                else if (profType == ProfileType.Bridge)
                {
                    BridgeProfile profile = new DeserializerBuilder()
                        .Build()
                        .Deserialize<BridgeProfile>(test);
                    profiles.Add(profile);
                }
            }
            return profiles;
        }
    }

    public class BridgeProfile : Profile, IYamlSerializable<BridgeProfile>
    {
        public string ReadFormat { get; set; } = @"{DATA},{GUID}";
        public string WriteFormat { get; set; } = @"{DATA},{GUID}";
        public string BridgeMessengerCode { get; set; } =
@"public interface IMessenger
{
    string Hostname { get; }
    string Identifier { get; set; }
    string Authenticator { get; set; }
    string Read();
    void Write(string Message);
    void Close();
}

public class BridgeMessenger : IMessenger
{
    public string Hostname { get; } = """";
    public string Identifier { get; set; } = """";
    public string Authenticator { get; set; } = """";

    public BridgeMessenger(string CovenantURI, string Identifier, string WriteFormat)
    {
        this.CovenantURI = CovenantURI;
        this.Identifier = Identifier;
        // TODO
    }

    public string Read()
    {
        // TODO
        return null;
    }

    public void Write(string Message)
    {
        // TODO
    }

    public void Close()
    {
        // TODO
    }
}";

        public BridgeProfile()
        {
            this.Type = ProfileType.Bridge;
        }
    }

    public class HttpProfileHeader
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
    }

    public class HttpProfile : Profile, IYamlSerializable<HttpProfile>
    {
        public List<string> HttpUrls { get; set; } = new List<string> { };
        public virtual List<HttpProfileHeader> HttpRequestHeaders { get; set; } = new List<HttpProfileHeader> { };
        public virtual List<HttpProfileHeader> HttpResponseHeaders { get; set; } = new List<HttpProfileHeader> { };

        public string HttpPostRequest { get; set; } = @"{DATA}";
        public string HttpGetResponse { get; set; } = @"{DATA}";
        public string HttpPostResponse { get; set; } = @"{DATA}";

        public HttpProfile()
        {
            this.Type = ProfileType.HTTP;
        }
    }
}
