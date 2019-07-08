// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

using Covenant.Core;
using Covenant.Models.Listeners;

namespace Covenant.Models.Grunts
{
    public enum CommunicationType
    {
        HTTP,
        SMB
    }

    public enum GruntStatus
    {
        Uninitialized,
        Stage0,
        Stage1,
        Stage2,
        Active,
        Lost,
        Killed,
        Disconnected
    }

    public enum IntegrityLevel
    {
        Untrusted,
        Low,
        Medium,
        High,
        System
    }

    public class Grunt
    {
        // Information to uniquely identify this Grunt
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = GenerateName();
        [Required]
        public string OriginalServerGuid { get; set; } = GenerateName();
        [DisplayName("GUID")]
        public string GUID { get; set; }

        // Downstream Grunt GUIDs
        public List<string> Children { get; set; } = new List<string>();

        // Communication information
        [Required]
        public CommunicationType CommType { get; set; } = CommunicationType.HTTP;
        [Required]
        public bool ValidateCert { get; set; } = true;
        [Required]
        public bool UseCertPinning { get; set; } = true;
        [Required]
        [DisplayName("SMBPipeName")]
        public string SMBPipeName { get; set; } = "gruntsvc";

        // Information about the Listener
        public int ListenerId { get; set; }
        public Listener Listener { get; set; }

        // Settings that can be configured
        public string Note { get; set; } = "";
        [Required]
        [Range(0, int.MaxValue)]
        public int Delay { get; set; } = 10;
        [Required]
        [Range(0, 100)]
        public int JitterPercent { get; set; } = 10;
        [Required]
        [Range(0, int.MaxValue)]
        public int ConnectAttempts { get; set; } = 5000;
        [Required]
        public DateTime KillDate { get; set; } = DateTime.MaxValue;

        // Attributes of the remote Grunt
        [Required]
        public Common.DotNetVersion DotNetFrameworkVersion { get; set; } = Common.DotNetVersion.Net35;
        [Required]
        public GruntStatus Status { get; set; } = GruntStatus.Uninitialized;
        [Required]
        public IntegrityLevel Integrity { get; set; } = IntegrityLevel.Untrusted;
        public string Process { get; set; } = "";
        public string UserDomainName { get; set; } = "";
        public string UserName { get; set; } = "";
        [DisplayName("IPAddress")]
        public string IPAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string OperatingSystem { get; set; } = "";

        // Information used for authentication or encrypted key exchange
        public string GruntSharedSecretPassword { get; set; } = Utilities.CreateSecretPassword();
        public string GruntRSAPublicKey { get; set; } = "";
        public string GruntNegotiatedSessionKey { get; set; } = "";
        public string GruntChallenge { get; set; } = "";
        public string CookieAuthKey { get; set; } = Utilities.CreateSecretPassword();

        // Time information
        public DateTime ActivationTime { get; set; } = DateTime.MinValue;
        public DateTime LastCheckIn { get; set; } = DateTime.MinValue;

        public List<GruntCommand> GruntCommands { get; set; } = new List<GruntCommand>();

        public void AddChild(Grunt grunt)
        {
            if (!string.IsNullOrWhiteSpace(grunt.GUID))
            {
                this.Children.Add(grunt.GUID);
            }
        }

        public bool RemoveChild(Grunt grunt)
        {
            return this.Children.Remove(grunt.GUID);
        }

        private static string GenerateName()
        {
            return Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
        }
    }
}
