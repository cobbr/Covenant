// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;

using Covenant.Models.Grunts;
using Covenant.Core;

namespace Covenant.Models.Listeners
{
    public class ListenerType
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }

        public static ListenerType HttpListenerType { get; set; } = new ListenerType
        {
            Name = "HTTP",
            Description = "Listens on HTTP protocol."
        };
    }

    public class Listener
    {
        public enum ListenerStatus
        {
            Uninitialized,
            Active,
            Stopped
        }

        public int Id { get; set; }
        public int ProfileId { get; set; } = 1;
        public string Name { get; set; } = GenerateName();
        public string Description { get; set; } = "A generic listener.";
        public string BindAddress { get; set; } = "0.0.0.0";
        public int BindPort { get; set; } = 80;
        public string ConnectAddress { get; set; } = System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName()).FirstOrDefault(
            A => A.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToString();

        public int ListenerTypeId { get; set; }
        public ListenerStatus Status { get; set; } = ListenerStatus.Uninitialized;

        public string CovenantToken { get; set; }
        
        public virtual CancellationTokenSource Start(HttpProfile profile) { return null; }
        public virtual void Stop(CancellationTokenSource cancellationTokenSource) { }
        public virtual string GetGruntStagerCode(Grunt grunt, HttpProfile profile) { return ""; }
        public virtual string GetGruntExecutorCode(Grunt grunt, HttpProfile profile) { return ""; }

        public string CompileGruntStagerCode(Grunt grunt, HttpProfile profile, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            byte[] ILBytes = Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = this.GetGruntStagerCode(grunt, profile),
                ResourceDirectory = Common.CovenantResourceDirectory,
                ReferenceDirectory = Common.CovenantReferenceDirectory,
                TargetDotNetVersion = grunt.DotNetFrameworkVersion,
                OutputKind = outputKind,
                References = Common.DefaultReferences
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

        public string CompileGruntExecutorCode(Grunt grunt, HttpProfile profile, bool Compress = false)
        {
            byte[] ILBytes = Compiler.Compile(new Compiler.CompilationRequest
            {
                Source = this.GetGruntExecutorCode(grunt, profile),
                ResourceDirectory = Common.CovenantResourceDirectory,
                ReferenceDirectory = Common.CovenantReferenceDirectory,
                TargetDotNetVersion = grunt.DotNetFrameworkVersion,
                OutputKind = OutputKind.DynamicallyLinkedLibrary,
                References = Common.DefaultReferences
            });
            if (ILBytes == null || ILBytes.Length == 0)
            {
                throw new CovenantCompileGruntStagerFailedException("Compiling Grunt code failed");
            }

            if (Compress)
            {
                ILBytes = Utilities.Compress(ILBytes);
            }
            return Convert.ToBase64String(ILBytes);
        }

        private static string GenerateName()
        {
            return Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
        }
    }
}
