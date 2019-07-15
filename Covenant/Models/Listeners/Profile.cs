// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;

using YamlDotNet.Serialization;

using APIModels = Covenant.API.Models;
using Covenant.Core;

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
        public static HttpProfileHeader CreateHeader(APIModels.HttpProfileHeader httpHeaderModel)
        {
            return new HttpProfileHeader
            {
                Name = httpHeaderModel.Name,
                Value = httpHeaderModel.Value
            };
        }
    }

    public class HttpProfile : Profile
    {
        public List<string> HttpUrls { get; set; } = new List<string>();
        public List<string> HttpCookies { get; set; } = new List<string>();
        public string HttpMessageTransform { get; set; } = "";
        public virtual List<HttpProfileHeader> HttpRequestHeaders { get; set; } = new List<HttpProfileHeader>();
        public virtual List<HttpProfileHeader> HttpResponseHeaders { get; set; } = new List<HttpProfileHeader>();

        public string HttpPostRequest { get; set; } = "";
        public string HttpGetResponse { get; set; } = "";
        public string HttpPostResponse { get; set; } = "";

        public HttpProfile()
        {
            this.Type = ProfileType.HTTP;
        }

        private byte[] TransformCoreAssemblyBytes { get; set; }
        private Assembly TransformCoreAssembly { get; set; }

        private Assembly GetTransformCoreAssembly()
        {
            if (this.TransformCoreAssembly == null)
            {
                if (this.TransformCoreAssemblyBytes == null)
                {
                    string[] refLocationPieces = typeof(object).GetTypeInfo().Assembly.Location.Split(Path.DirectorySeparatorChar);
                    this.TransformCoreAssemblyBytes = Compiler.Compile(new Compiler.CompilationRequest
                    {
                        Source = this.HttpMessageTransform,
                        TargetDotNetVersion = Common.DotNetVersion.NetCore21,
                        References = Common.DefaultReferencesCore21
                    });
                }
                this.TransformCoreAssembly = Assembly.Load(this.TransformCoreAssemblyBytes);
            }
            return this.TransformCoreAssembly;
        }

        public string Transform(byte[] bytes)
        {
            Type t = this.GetTransformCoreAssembly().GetType("HttpMessageTransform");
            return (string)t.GetMethod("Transform").Invoke(null, new object[] { bytes });
        }

        public byte[] Invert(string str)
        {
            Type t = this.GetTransformCoreAssembly().GetType("HttpMessageTransform");
            return (byte[])t.GetMethod("Invert").Invoke(null, new object[] { str });
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
                HttpUrls = yaml.HttpUrls,
                HttpCookies = yaml.HttpCookies,
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