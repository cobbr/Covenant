// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;

using Covenant.Core;
using Encrypt = Covenant.Core.Encryption;

namespace Covenant.Models.Grunts
{
    public class Grunt
    {
        public enum GruntStatus
        {
            Uninitialized,
            Stage0,
            Stage1,
            Stage2,
            Active,
            Lost,
            Killed
        }

        public enum IntegrityLevel
        {
            Untrusted,
            Low,
            Medium,
            High,
            System
        }

        public int Id { get; set; }
        public string Name { get; set; } = GenerateName();
        public string OriginalServerGuid { get; set; } = GenerateName();
        public string GUID { get; set; }
        public Common.DotNetVersion DotNetFrameworkVersion { get; set; } = Common.DotNetVersion.Net35;

        public int ListenerId { get; set; }
        public string CovenantIPAddress { get; set; }

        private List<string> _ChildGrunts = new List<string>();
        // Split into comma-delimited list to easily save as text in the Database
        public string ChildGrunts
        {
            get { return String.Join(',', this._ChildGrunts); }
            set { this._ChildGrunts = value.Split(',').Where(V => V.Length > 0).ToList(); }
        }
        public bool UsePipes { get; set; } = false;
        public string PipeName { get; set; } = "gruntsvc";

        public int Delay { get; set; } = 5;
        public int Jitter { get; set; } = 3;
        public int ConnectAttempts { get; set; } = 1000;

        public string LastCheckIn { get; set; } = DateTime.MinValue.ToString();
        public GruntStatus Status { get; set; } = GruntStatus.Uninitialized;
        public IntegrityLevel Integrity { get; set; } = IntegrityLevel.Untrusted;
        public string Process { get; set; } = "";
        public string UserDomainName { get; set; } = "";
        public string UserName { get; set; } = "";
        public string IPAddress { get; set; } = "";
        public string OperatingSystem { get; set; } = "";

        public string GruntSharedSecretPassword { get; set; } = Utilities.CreateSecretPassword();
        public string GruntRSAPublicKey { get; set; } = "";
        public string GruntNegotiatedSessionKey { get; set; } = "";
        public string GruntChallenge { get; set; } = "";
        public string CookieAuthKey { get; set; } = Utilities.CreateSecretPassword();

        public static Grunt Create(API.Models.Grunt gruntModel)
        {
            return new Grunt
            {
                Id = gruntModel.Id ?? default,
                ListenerId = gruntModel.ListenerId ?? default,
                Name = gruntModel.Name ?? default,
                GUID = gruntModel.Guid ?? default,
                OriginalServerGuid = gruntModel.OriginalServerGuid ?? default,
                DotNetFrameworkVersion = (Common.DotNetVersion)Enum.Parse(typeof(Common.DotNetVersion), gruntModel.DotNetFrameworkVersion.ToString()),
                CovenantIPAddress = gruntModel.CovenantIPAddress ?? default,
                ChildGrunts = gruntModel.ChildGrunts,
                UsePipes = gruntModel.UsePipes ?? default,
                PipeName = gruntModel.PipeName,
                Delay = gruntModel.Delay ?? default,
                Jitter = gruntModel.Jitter ?? default,
                ConnectAttempts = gruntModel.ConnectAttempts ?? default,
                LastCheckIn = gruntModel.LastCheckIn ?? default,
                Status = (GruntStatus)Enum.Parse(typeof(GruntStatus), gruntModel.Status.ToString()),
                Integrity = (IntegrityLevel)Enum.Parse(typeof(IntegrityLevel), gruntModel.Integrity.ToString()),
                Process = gruntModel.Process,
                UserDomainName = gruntModel.UserDomainName,
                UserName = gruntModel.UserName,
                GruntSharedSecretPassword = gruntModel.GruntSharedSecretPassword,
                GruntRSAPublicKey = gruntModel.GruntRSAPublicKey,
                GruntNegotiatedSessionKey = gruntModel.GruntNegotiatedSessionKey,
                GruntChallenge = gruntModel.GruntChallenge,
                IPAddress = gruntModel.IpAddress,
                OperatingSystem = gruntModel.OperatingSystem,
                CookieAuthKey = gruntModel.CookieAuthKey
            };
        }

        public API.Models.Grunt ToModel()
        {
            return new API.Models.Grunt
            {
                Id = this.Id,
                ListenerId = this.ListenerId,
                Name = this.Name,
                Guid = this.GUID,
                OriginalServerGuid = this.OriginalServerGuid,
                DotNetFrameworkVersion = (API.Models.DotNetVersion)Enum.Parse(typeof(API.Models.DotNetVersion), this.DotNetFrameworkVersion.ToString()),
                CovenantIPAddress = this.CovenantIPAddress,
                ChildGrunts = this.ChildGrunts,
                UsePipes = this.UsePipes,
                PipeName = this.PipeName,
                Delay = this.Delay,
                Jitter = this.Jitter,
                ConnectAttempts = this.ConnectAttempts,
                LastCheckIn = this.LastCheckIn,
                Status = (API.Models.GruntStatus)Enum.Parse(typeof(API.Models.GruntStatus), this.Status.ToString()),
                Integrity = (API.Models.IntegrityLevel)Enum.Parse(typeof(API.Models.IntegrityLevel), this.Integrity.ToString()),
                Process = this.Process,
                UserDomainName = this.UserDomainName,
                UserName = this.UserName,
                GruntSharedSecretPassword = this.GruntSharedSecretPassword,
                GruntRSAPublicKey = this.GruntRSAPublicKey,
                GruntNegotiatedSessionKey = this.GruntNegotiatedSessionKey,
                GruntChallenge = this.GruntChallenge,
                IpAddress = this.IPAddress,
                OperatingSystem = this.OperatingSystem,
                CookieAuthKey = this.CookieAuthKey
            };
        }

        public List<string> GetChildren()
        {
            return this._ChildGrunts;
        }

        public byte[] RSAEncrypt(byte[] toEncrypt)
        {
            return Encrypt.Utilities.RSAEncrypt(toEncrypt, Common.CovenantEncoding.GetString(Convert.FromBase64String(this.GruntRSAPublicKey)));
        }

        // Returns IV (16 bytes) + EncryptedData byte array
        public byte[] SessionEncrypt(byte[] data)
        {
            return Encrypt.Utilities.AesEncrypt(data, Convert.FromBase64String(this.GruntNegotiatedSessionKey));
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public byte[] SessionDecrypt(byte[] data)
        {
            return Encrypt.Utilities.AesDecrypt(data, Convert.FromBase64String(this.GruntNegotiatedSessionKey));
        }
        // Convenience method for decrypting a GruntEncryptedMessage
        public byte[] SessionDecrypt(GruntEncryptedMessage gruntEncryptedMessage)
        {
            return this.SessionDecrypt(Convert.FromBase64String(gruntEncryptedMessage.IV)
                .Concat(Convert.FromBase64String(gruntEncryptedMessage.EncryptedMessage)).ToArray());
        }

        public byte[] SessionHash(byte[] data)
        {
            return Encrypt.Utilities.ComputeHMAC(data, Convert.FromBase64String(this.GruntNegotiatedSessionKey));
        }

        private static string GenerateName()
        {
            return Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
        }
    }

    public class GruntEncryptedMessage
    {
        public enum GruntEncryptedMessageType
        {
            Routing,
            Tasking
        }

        public string GUID { get; set; }
        public GruntEncryptedMessageType Type { get; set; }
        public string Meta { get; set; } = "";

        public string IV { get; set; }
        public string EncryptedMessage { get; set; }
        public string HMAC { get; set; }

        private static GruntEncryptedMessage Create(string GUID, byte[] message, byte[] key, GruntEncryptedMessageType Type = GruntEncryptedMessageType.Tasking)
        {
            byte[] encryptedMessagePacket = Encrypt.Utilities.AesEncrypt(message, key);
            byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
            byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
            byte[] hmac = Encrypt.Utilities.ComputeHMAC(encryptedMessage, key);
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
            if (grunt.Status == Grunt.GruntStatus.Uninitialized || grunt.Status == Grunt.GruntStatus.Stage0)
            {
                return Create(grunt.GUID, message, Convert.FromBase64String(grunt.GruntSharedSecretPassword), Type);
            }
            return Create(grunt.GUID, message, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey), Type);
        }

        public bool VerifyHMAC(byte[] Key)
        {
            if (IV == "" || EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
            try
            {
                var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                return Encrypt.Utilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
            }
            catch
            {
                return false;
            }
        }

    }
}
