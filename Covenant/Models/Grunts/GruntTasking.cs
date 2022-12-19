// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;

using Covenant.Core;
using Covenant.Models.Covenant;
using NLog;
using System.Threading.Tasks;

namespace Covenant.Models.Grunts
{
    public class CommandOutput : ILoggable
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        public string Output { get; set; } = "";

        [Required]
        public int GruntCommandId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GruntCommand GruntCommand { get; set; }

        // GruntTask|Action|ID|Name|Author|Aliases|Description|TaskingType|UnsafeCompile
        public string ToLog(LogAction action) => $"CommandOutput|{action}|{this.Id}|{this.GruntCommandId}|{this.Output}";
    }

    public class GruntCommand : ILoggable
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Command { get; set; }
        [Required]
        public DateTime CommandTime { get; set; } = DateTime.MinValue;
        [Required]
        public int CommandOutputId { get; set; }
        public CommandOutput CommandOutput { get; set; }

        [Required]
        public string UserId { get; set; }
        public CovenantUser User { get; set; }

        public int? GruntTaskingId { get; set; } = null;
        public GruntTasking GruntTasking { get; set; }

        public int GruntId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Grunt Grunt { get; set; }

        // GruntCommand|Action|User|UserId|GruntId|Id|Command
        public string ToLog(LogAction action) => $"GruntCommand|{action}|{this.User}|{this.UserId}|{this.GruntId}|{this.Id}|{this.Command}";
    }

    public enum GruntTaskingStatus
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed,
        Aborted
    }

    public enum GruntTaskingType
    {
        Assembly,
        SetDelay,
        SetJitter,
        SetConnectAttempts,
        SetKillDate,
        Exit,
        Connect,
        Disconnect,
        Tasks,
        TaskKill
    }

    public class GruntTasking : ILoggable
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public int GruntId { get; set; }
        public Grunt Grunt { get; set; }
        [Required]
        public int GruntTaskId { get; set; }
        public GruntTask GruntTask { get; set; }

        public GruntTaskingType Type { get; set; } = GruntTaskingType.Assembly;
        public List<string> Parameters { get; set; } = new List<string>();

        public GruntTaskingStatus Status { get; set; } = GruntTaskingStatus.Uninitialized;
        public DateTime TaskingTime { get; set; } = DateTime.MinValue;
        public DateTime CompletionTime { get; set; } = DateTime.MinValue;

        public int GruntCommandId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GruntCommand GruntCommand { get; set; }

        // GruntTasking|Action|Id|Name|GruntId|GruntTaskId|GruntCommand|Status
        public string ToLog(LogAction action) => $"GruntTasking|{action}|{this.Id}|{this.Name}|{this.GruntId}|{this.GruntTaskId}|{this.Status}";
    }
}
