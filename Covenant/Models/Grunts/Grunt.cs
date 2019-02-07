// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;

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
        public Common.DotNetVersion DotNetFrameworkVersion { get; set; } = Common.DotNetVersion.Net35;

        public int ListenerId { get; set; }
        public string CovenantIPAddress { get; set; }

        public int Delay { get; set; } = 5;
        public int Jitter { get; set; } = 0;
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
                DotNetFrameworkVersion = (Common.DotNetVersion)Enum.Parse(typeof(Common.DotNetVersion), gruntModel.DotNetFrameworkVersion.ToString()),
                CovenantIPAddress = gruntModel.CovenantIPAddress ?? default,
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
                DotNetFrameworkVersion = (API.Models.DotNetVersion)Enum.Parse(typeof(API.Models.DotNetVersion), this.DotNetFrameworkVersion.ToString()),
                CovenantIPAddress = this.CovenantIPAddress,
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

    public class GruntEncryptedMessage : Encrypt.EncryptedMessagePacket
    {
		public enum GruntEncryptedMessageType
		{
			Stage0,
            Stage1,
            Stage2,
            Register,
            GetTask,
            PostTask,
            Deliver
		}

        public int Id { get; set; }
        public string Name { get; set; }
		public GruntEncryptedMessageType Type { get; set; } = GruntEncryptedMessageType.GetTask;
        public string Meta { get; set; } = "";

		private static GruntEncryptedMessage Create(int gruntId, string gruntName, byte[] message, byte[] key)
        {
            byte[] encryptedMessagePacket = Encrypt.Utilities.AesEncrypt(message, key);
            byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
            byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
            byte[] hmac = Encrypt.Utilities.ComputeHMAC(encryptedMessage, key);
            return new GruntEncryptedMessage
            {
                Id = gruntId,
                Name = gruntName,
				Type = GruntEncryptedMessageType.Deliver,
                EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                IV = Convert.ToBase64String(encryptionIV),
                HMAC = Convert.ToBase64String(hmac)
            };
        }

        public static GruntEncryptedMessage Create(Grunt grunt, byte[] message, byte[] key)
        {
            return Create(grunt.Id, grunt.Name, message, key);
        }

        public static GruntEncryptedMessage Create(Grunt grunt, byte[] message)
        {
            return Create(grunt, message, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey));
        }

    }
}
