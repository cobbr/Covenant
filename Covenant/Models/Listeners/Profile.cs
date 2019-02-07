// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

using APIModels = Covenant.API.Models;
using Covenant.Core;

namespace Covenant.Models.Listeners
{
    public class Profile
    {
        public int Id { get; set; }
    }

    public class HttpProfile : Profile
    {
        public class HttpProfileHeader
        {
            public string Name { get; set; } = "";
            public string Value { get; set; } = "";
        }

        private List<string> _HttpUrls { get; set; } = new List<string>();
        private List<string> _HttpCookies { get; set; } = new List<string>();
        private List<HttpProfileHeader> _HttpHeaders { get; set; } = new List<HttpProfileHeader>();

        public string Name { get; set; }
        public string HttpUrls
        {
            get { return JsonConvert.SerializeObject(this._HttpUrls); }
            set { this._HttpUrls = JsonConvert.DeserializeObject<List<string>>(value); }
        }
        public string HttpCookies
        {
            get { return JsonConvert.SerializeObject(this._HttpCookies); }
            set { this._HttpCookies = JsonConvert.DeserializeObject<List<string>>(value); }
        }
        public string HttpMessageTransform { get; set; } = "";
        public string HttpRequestHeaders
        {
            get { return JsonConvert.SerializeObject(this._HttpHeaders); }
            set { this._HttpHeaders = JsonConvert.DeserializeObject<List<HttpProfileHeader>>(value); }
        }
        public string HttpPostRequest { get; set; } = "";

        public string HttpResponseHeaders
        {
            get { return JsonConvert.SerializeObject(this._HttpHeaders); }
            set { this._HttpHeaders = JsonConvert.DeserializeObject<List<HttpProfileHeader>>(value); }
        }
        public string HttpGetResponse { get; set; } = "";
        public string HttpPostResponse { get; set; } = "";

        public List<string> GetUrls()
        {
            return this._HttpUrls;
        }
        public List<string> GetCookies()
        {
            return this._HttpCookies;
        }
        public List<HttpProfileHeader> GetHeaders()
        {
            return this._HttpHeaders;
        }

        private byte[] _TransformCoreAssemblyBytes { get; set; } = null;
        private Assembly _TransformCoreAssembly { get; set; } = null;

        private Assembly GetTransformCoreAssembly()
        {
            if (this._TransformCoreAssembly == null)
            {
                if (this._TransformCoreAssemblyBytes == null)
                {
                    string[] refLocationPieces = typeof(object).GetTypeInfo().Assembly.Location.Split(Path.DirectorySeparatorChar);
                    this._TransformCoreAssemblyBytes = Compiler.Compile(new Compiler.CompilationRequest
                    {
                        Source = this.HttpMessageTransform,
                        ReferenceDirectory = String.Join(Path.DirectorySeparatorChar, refLocationPieces.Take(refLocationPieces.Count() - 1)),
                        TargetDotNetVersion = Common.DotNetVersion.NetCore21,
                        References = Common.NetCore21References
                    });
                }
                this._TransformCoreAssembly = Assembly.Load(this._TransformCoreAssemblyBytes);
            }
            return this._TransformCoreAssembly;
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

        public static HttpProfile Create(APIModels.HttpProfile httpProfileModel)
        {
            return new HttpProfile
            {
                Id = httpProfileModel.Id ?? default,
                Name = httpProfileModel.Name,
                HttpUrls = httpProfileModel.HttpUrls,
                HttpCookies = httpProfileModel.HttpCookies,
                HttpMessageTransform = httpProfileModel.HttpMessageTransform,
                HttpRequestHeaders = httpProfileModel.HttpRequestHeaders,
                HttpPostRequest = httpProfileModel.HttpPostRequest,
                HttpResponseHeaders = httpProfileModel.HttpResponseHeaders,
                HttpGetResponse = httpProfileModel.HttpGetResponse,
                HttpPostResponse = httpProfileModel.HttpPostResponse
            };
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

        private static HttpProfile CreateFromHttpProfileYaml(HttpProfileYaml yaml)
        {
            return new HttpProfile
            {
                Name = yaml.Name,
                HttpUrls = JsonConvert.SerializeObject(yaml.HttpUrls),
                HttpCookies = JsonConvert.SerializeObject(yaml.HttpCookies),
                HttpMessageTransform = yaml.HttpMessageTransform,
                HttpRequestHeaders = JsonConvert.SerializeObject(yaml.HttpRequestHeaders),
                HttpPostRequest = yaml.HttpPostRequest,
                HttpResponseHeaders = JsonConvert.SerializeObject(yaml.HttpResponseHeaders),
                HttpGetResponse = yaml.HttpGetResponse,
                HttpPostResponse = yaml.HttpPostResponse
            };
        }
    }
}