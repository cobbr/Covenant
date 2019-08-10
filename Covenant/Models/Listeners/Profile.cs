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
        HTTP
    }

    public class Profile
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ProfileType Type { get; set; }
    }

    public class HttpProfileHeader
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
    }

    public class HttpProfile : Profile
    {
        public List<string> HttpUrls { get; set; } = new List<string> { "" };
        public string HttpMessageTransform { get; set; } = "";
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
            public List<string> HttpUrls { get; set; } = new List<string>();
            public List<string> HttpCookies { get; set; } = new List<string>();
            public string HttpMessageTransform { get; set; } = "";
            public List<HttpProfileHeader> HttpRequestHeaders { get; set; } = new List<HttpProfileHeader>();
            public string HttpPostRequest { get; set; } = "";
            public List<HttpProfileHeader> HttpResponseHeaders { get; set; } = new List<HttpProfileHeader>();
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
                HttpMessageTransform = yaml.HttpMessageTransform,
                HttpRequestHeaders = yaml.HttpRequestHeaders,
                HttpPostRequest = yaml.HttpPostRequest.TrimEnd('\n'),
                HttpResponseHeaders = yaml.HttpResponseHeaders,
                HttpGetResponse = yaml.HttpGetResponse.TrimEnd('\n'),
                HttpPostResponse = yaml.HttpPostResponse.TrimEnd('\n')
            };
        }
    }
}