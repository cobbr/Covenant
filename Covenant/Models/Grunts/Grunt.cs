// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Covenant.Core;
using Covenant.Models.Listeners;

namespace Covenant.Models.Grunts
{
    public enum GruntStatus
    {
        Uninitialized,
        Stage0,
        Stage1,
        Stage2,
        Active,
        Lost,
        Exited,
        Disconnected,
        Hidden
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
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public string OriginalServerGuid { get; set; } = Utilities.CreateShortGuid();
        [DisplayName("GUID")]
        public string GUID { get; set; }

        // Downstream Grunt GUIDs
        public List<string> Children { get; set; } = new List<string>();

        // Communication information
        [Required]
        public int ImplantTemplateId { get; set; }
        public ImplantTemplate ImplantTemplate { get; set; }
        [Required]
        public bool ValidateCert { get; set; } = true;
        [Required]
        public bool UseCertPinning { get; set; } = true;
        [Required, DisplayName("SMBPipeName")]
        public string SMBPipeName { get; set; } = "gruntsvc";

        // Information about the Listener
        public int ListenerId { get; set; }
        public Listener Listener { get; set; }

        // Settings that can be configured
        public string Note { get; set; } = "";
        [Required, Range(0, int.MaxValue)]
        public int Delay { get; set; } = 10;
        [Required, Range(0, 100)]
        public int JitterPercent { get; set; } = 10;
        [Required, Range(0, int.MaxValue)]
        public int ConnectAttempts { get; set; } = 5000;
        [Required]
        public DateTime KillDate { get; set; } = DateTime.MaxValue;

        // Attributes of the remote Grunt
        [Required]
        public Common.DotNetVersion DotNetVersion { get; set; } = Common.DotNetVersion.Net35;
        [Required]
        public Compiler.RuntimeIdentifier RuntimeIdentifier { get; set; } = Compiler.RuntimeIdentifier.win_x64;
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

        // Time information
        public DateTime ActivationTime { get; set; } = DateTime.MinValue;
        public DateTime LastCheckIn { get; set; } = DateTime.MinValue;

        public string PowerShellImport { get; set; } = "";
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
    }
}
