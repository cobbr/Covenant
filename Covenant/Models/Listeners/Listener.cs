// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Threading;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Grunts;

namespace Covenant.Models.Listeners
{
    public class ListenerType
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }

        public static ListenerType HttpListenerType { get; set; } = new ListenerType
        {
            Name = "HTTP",
            Description = "Listens on HTTP protocol."
        };

        [JsonIgnore]
        public List<Listener> Listeners { get; set; }
    }

    public enum ListenerStatus
    {
        Uninitialized,
        Active,
        Stopped
    }

    public class Listener
    {
        [Key]
        public int Id { get; set; }
        [Required, StringLength(100)]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required, StringLength(100), RegularExpression("^[a-zA-Z0-9]*$")]
        public string GUID { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public string Description { get; set; } = "A generic listener.";
        [Required, RegularExpression(@"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ErrorMessage = "The field BindAddress must be an IPv4 Address.")]
        public string BindAddress { get; set; } = "0.0.0.0";
        [Required, Range(1, 65535)]
        public int BindPort { get; set; } = 80;
        [Required]
        public string ConnectAddress { get; set; }
        [Required]
        public int ProfileId { get; set; }
        public Profile Profile { get; set; }

        [Required]
        public int ListenerTypeId { get; set; }
        public ListenerType ListenerType { get; set; }

        [Required]
        public ListenerStatus Status { get; set; } = ListenerStatus.Uninitialized;
        public string CovenantToken { get; set; }

        public DateTime StartTime { get; set; } = DateTime.MinValue;

        public virtual CancellationTokenSource Start() { return null; }
        public virtual void Stop(CancellationTokenSource cancellationTokenSource) { }
        public virtual string GetGruntStagerCode(Grunt grunt, HttpProfile profile) { return ""; }

        protected string ListenerDirectory { get { return Common.CovenantListenersDirectory + this.GUID + Path.DirectorySeparatorChar; } }

        public string CompileGruntStagerCode(Grunt grunt, HttpProfile profile, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            byte[] ILBytes = Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = this.GetGruntStagerCode(grunt, profile),
                TargetDotNetVersion = grunt.DotNetFrameworkVersion,
                OutputKind = outputKind,
                References = grunt.DotNetFrameworkVersion == Common.DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References
            });
            if (ILBytes == null || ILBytes.Length == 0)
            {
                throw new CovenantCompileGruntStagerFailedException("Compiling Grunt code failed");
            }
            if (Compress) {
                ILBytes = Utilities.Compress(ILBytes);
            }
            return Convert.ToBase64String(ILBytes);
        }
    }
}
