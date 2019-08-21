// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Collections.Generic;

using YamlDotNet.Serialization;

namespace Covenant.Models.Listeners
{
    public enum ProfileType
    {
        HTTP,
        Bridge
    }

    public class Profile
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ProfileType Type { get; set; }
        public string MessageTransform { get; set; }
    }

    public class BridgeProfile : Profile
    {
        public string ReadFormat { get; set; }
        public string WriteFormat { get; set; }

        public BridgeProfile()
        {
            this.Type = ProfileType.Bridge;
        }

        public static BridgeProfile Create(string ProfileFilePath)
        {
            Console.WriteLine("Create bridge profile: " + ProfileFilePath);
            using (TextReader reader = File.OpenText(ProfileFilePath))
            {
                var deserializer = new DeserializerBuilder().Build();
                BridgeProfileYaml yaml = deserializer.Deserialize<BridgeProfileYaml>(reader);
                return CreateFromBridgeProfileYaml(yaml);
            }
        }

        private class BridgeProfileYaml
        {
            public string Name { get; set; } = "";
            public string Description { get; set; } = "";
            public string MessageTransform { get; set; } = "";
            public string ReadFormat { get; set; } = "";
            public string WriteFormat { get; set; } = "";
        }

        private static BridgeProfile CreateFromBridgeProfileYaml(BridgeProfileYaml yaml)
        {
            return new BridgeProfile
            {
                Name = yaml.Name,
                Description = yaml.Description,
                MessageTransform = yaml.MessageTransform,
                ReadFormat = yaml.ReadFormat.TrimEnd('\n'),
                WriteFormat = yaml.WriteFormat.TrimEnd('\n')
            };
        }
    }

    public class HttpProfileHeader
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
    }

    public class HttpProfile : Profile
    {
        public List<string> HttpUrls { get; set; } = new List<string> { "" };
        public virtual List<HttpProfileHeader> HttpRequestHeaders { get; set; } = new List<HttpProfileHeader> { new HttpProfileHeader { Name = "", Value = "" } };
        public virtual List<HttpProfileHeader> HttpResponseHeaders { get; set; } = new List<HttpProfileHeader> { new HttpProfileHeader { Name = "", Value = "" } };

        public string HttpPostRequest { get; set; } = "";
        public string HttpGetResponse { get; set; } = "";
        public string HttpPostResponse { get; set; } = "";

        public HttpProfile()
        {
            this.Type = ProfileType.HTTP;
        }

        public static HttpProfile Create(string ProfileFilePath)
        {
            using (TextReader reader = File.OpenText(ProfileFilePath))
            {
                var deserializer = new DeserializerBuilder().Build();
                HttpProfileYaml yaml = deserializer.Deserialize<HttpProfileYaml>(reader);
                return CreateFromHttpProfileYaml(yaml);
            }
        }

        private class HttpProfileYaml
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public string MessageTransform { get; set; } = "";

            public List<string> HttpUrls { get; set; } = new List<string>();
            public List<HttpProfileHeader> HttpRequestHeaders { get; set; } = new List<HttpProfileHeader>();
            public List<HttpProfileHeader> HttpResponseHeaders { get; set; } = new List<HttpProfileHeader>();
            public string HttpPostRequest { get; set; } = "";
            public string HttpGetResponse { get; set; } = "";
            public string HttpPostResponse { get; set; } = "";
        }

        private static HttpProfile CreateFromHttpProfileYaml(HttpProfileYaml yaml)
        {
            return new HttpProfile
            {
                Name = yaml.Name,
                Description = yaml.Description,
                HttpUrls = yaml.HttpUrls,
                MessageTransform = yaml.MessageTransform,
                HttpRequestHeaders = yaml.HttpRequestHeaders,
                HttpPostRequest = yaml.HttpPostRequest.TrimEnd('\n'),
                HttpResponseHeaders = yaml.HttpResponseHeaders,
                HttpGetResponse = yaml.HttpGetResponse.TrimEnd('\n'),
                HttpPostResponse = yaml.HttpPostResponse.TrimEnd('\n')
            };
        }
    }
}
