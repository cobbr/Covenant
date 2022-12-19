// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.IO.Compression;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Covenant.Core
{
    public static class Utilities
    {
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

		public static string GenerateJwtToken(string UserName, string UserId, string[] Roles,
                                              string JwtKey, string JwtIssuer, string JwtAudience, string JwtExpireDays)
        {
			List<Claim> claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.Sub, UserName),
				new Claim(JwtRegisteredClaimNames.Jti, CreateSecureGuid().ToString()),
				new Claim(ClaimTypes.NameIdentifier, UserId)
			};
            foreach (string role in Roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

            SymmetricSecurityKey key = new SymmetricSecurityKey(Common.CovenantEncoding.GetBytes(JwtKey));
            SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            DateTime expireTime = DateTime.Now.AddDays(Convert.ToDouble(JwtExpireDays));

            JwtSecurityToken token = new JwtSecurityToken(
                JwtIssuer, JwtAudience, claims, expires: expireTime, signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static string GenerateJwtKey()
        {
            char[] printablechars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%^&*()_+{}|:<>?~-=[];',./`".ToCharArray();
            using (var provider = RandomNumberGenerator.Create())
            {
                // Random length between 50 and 100 characters
                int min = 50; int max = 100;
                byte[] lengthBytes = new byte[4];
                provider.GetBytes(lengthBytes);
                int length = (int)(min + (max - min) * (BitConverter.ToUInt32(lengthBytes, 0) / (double)uint.MaxValue));

                byte[] keyBytes = new byte[length];
                provider.GetBytes(keyBytes);
                StringBuilder result = new StringBuilder(length);
                foreach (byte b in keyBytes)
                {
                    result.Append(printablechars[b % (printablechars.Length)]);
                }
                return result.ToString();
            }
        }

        public static string CreateShortGuid()
        {
            return Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
        }

        public static Guid CreateSecureGuid()
        {
            using (var provider = RandomNumberGenerator.Create())
            {
                var bytes = new byte[16];
                provider.GetBytes(bytes);
                return new Guid(bytes);
            }
        }

        public static String CreateSecretPassword(int length = 32)
        {
            using (var provider = RandomNumberGenerator.Create())
            {
                var bytes = new byte[length];
                provider.GetBytes(bytes);
                return Convert.ToBase64String(bytes);
            }
        }

        public static X509Certificate2 CreateSelfSignedCertificate(IPAddress address, string DistinguishedName = "")
        {
            if (DistinguishedName == "") { DistinguishedName = "CN=" + address; }
            using (RSA rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(new X500DistinguishedName(DistinguishedName), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                SubjectAlternativeNameBuilder subjectAlternativeName = new SubjectAlternativeNameBuilder();
                subjectAlternativeName.AddIpAddress(address);

                request.CertificateExtensions.Add(subjectAlternativeName.Build());
                return request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));
            }
        }

        public static bool IsIPAddress(string ComputerName)
        {
            return IPAddress.TryParse(ComputerName, out IPAddress address);
        }

        public static string GetSanitizedFilename(string filename)
        {
            foreach (char invalid in Path.GetInvalidFileNameChars())
            {
                filename = filename.Replace(invalid, '_');
            }
            return filename;
        }

        public static string GetExtensionForLanguage(Models.Grunts.ImplantLanguage language)
        {
            switch (language)
            {
                case Models.Grunts.ImplantLanguage.CSharp:
                    return ".cs";
                default:
                    return ".cs";
            }
        }
    }

    public static class TaskExtensions
    {
        public static T WaitResult<T>(this Task<T> Task)
        {
            return TaskExtensions.WaitTask(Task).Result;
        }

        public static Task<T> WaitTask<T>(this Task<T> Task)
        {
            Task.Wait();
            return Task;
        }

        public static T WaitResult<T>(this ValueTask<T> Task)
        {
            return TaskExtensions.WaitTask(Task).Result;
        }

        public static ValueTask<T> WaitTask<T>(this ValueTask<T> Task)
        {
            Task.AsTask().Wait();
            return Task;
        }
    }

    // http://www.mikeobrien.net/blog/parseexact-for-strings
    public static class StringExtensions
    {
        public static string[] ParseExact(this string data, string format)
        {
            return ParseExact(data, format, false);
        }

        public static string[] ParseExact(this string data, string format, bool ignoreCase)
        {
            string[] values;
            if (TryParseExact(data, format, out values, ignoreCase))
            {
                return values;
            }
            else
            {
                throw new ArgumentException("Format not compatible with value.");
            }
        }

        public static bool TryExtract(this string data, string format, out string[] values)
        {
            return TryParseExact(data, format, out values, false);
        }

        public static bool TryParseExact(this string data, string format, out string[] values, bool ignoreCase)
        {
            int tokenCount = 0;
            format = Regex.Escape(format).Replace("\\{", "{");

            for (tokenCount = 0; ; tokenCount++)
            {
                string token = string.Format("{{{0}}}", tokenCount);
                if (!format.Contains(token)) break;
                format = format.Replace(token, string.Format("(?'group{0}'.*)", tokenCount));
            }

            RegexOptions options = ignoreCase ? RegexOptions.IgnoreCase : RegexOptions.None;
            Match match = new Regex(format, options).Match(data);

            if (tokenCount != (match.Groups.Count - 1))
            {
                values = new string[] { };
                return false;
            }
            else
            {
                values = new string[tokenCount];
                for (int index = 0; index < tokenCount; index++)
                {
                    values[index] = match.Groups[string.Format("group{0}", index)].Value;
                }
                return true;
            }
        }

        public static string TrimOnceSymmetric(this string str, char c)
        {
            string ch = c.ToString();
            if (str.StartsWith(ch, StringComparison.Ordinal) && str.EndsWith(ch, StringComparison.Ordinal))
            {
                if (str.Length > 1)
                {
                    str = str.Substring(1, str.Length - 1);
                }
                if (str.Length > 1)
                {
                    str = str.Substring(0, str.Length - 1);
                }
            }
            return str;
        }
    }
}
