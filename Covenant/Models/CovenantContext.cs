// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

using Newtonsoft.Json;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

using Covenant.Core;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;
using Covenant.Models.Launchers;
using Covenant.Models.Grunts;
using Covenant.Models.Indicators;
using System.Text;

namespace Covenant.Models
{
    public class CovenantContext : IdentityDbContext<CovenantUser>
    {
        public DbSet<Listener> Listeners { get; set; }
        public DbSet<ListenerType> ListenerTypes { get; set; }
        public DbSet<Profile> Profiles { get; set; }
        public DbSet<HostedFile> HostedFiles { get; set; }

        public DbSet<Launcher> Launchers { get; set; }
        public DbSet<ImplantTemplate> ImplantTemplates { get; set; }
        public DbSet<Grunt> Grunts { get; set; }
        public DbSet<GruntTask> GruntTasks { get; set; }
        public DbSet<GruntTaskAuthor> GruntTaskAuthors { get; set; }
        public DbSet<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; }
        public DbSet<ReferenceAssembly> ReferenceAssemblies { get; set; }
        public DbSet<EmbeddedResource> EmbeddedResources { get; set; }
        public DbSet<GruntCommand> GruntCommands { get; set; }
        public DbSet<CommandOutput> CommandOutputs { get; set; }
        public DbSet<GruntTasking> GruntTaskings { get; set; }

        public DbSet<Event> Events { get; set; }
        public DbSet<CapturedCredential> Credentials { get; set; }
        public DbSet<Indicator> Indicators { get; set; }
        public DbSet<Theme> Themes { get; set; }

        public CovenantContext(DbContextOptions<CovenantContext> options) : base(options)
        {
            // this.ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
            // this.ChangeTracker.CascadeDeleteTiming = Microsoft.EntityFrameworkCore.ChangeTracking.CascadeTiming.Never;
            // this.ChangeTracker.DeleteOrphansTiming = Microsoft.EntityFrameworkCore.ChangeTracking.CascadeTiming.Never;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            => optionsBuilder
                .UseSqlite("Data Source=" + Common.CovenantDatabaseFile);

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<GruntTaskOption>().ToTable("GruntTaskOption");

            builder.Entity<HttpListener>();
            builder.Entity<HttpProfile>().HasBaseType<Profile>();
            builder.Entity<BridgeListener>();
            builder.Entity<BridgeProfile>().HasBaseType<Profile>();

            builder.Entity<WmicLauncher>();
            builder.Entity<Regsvr32Launcher>();
            builder.Entity<MshtaLauncher>();
            builder.Entity<CscriptLauncher>();
            builder.Entity<WscriptLauncher>();
            builder.Entity<InstallUtilLauncher>();
            builder.Entity<MSBuildLauncher>();
            builder.Entity<PowerShellLauncher>();
            builder.Entity<BinaryLauncher>();
            builder.Entity<ShellCodeLauncher>();

            builder.Entity<CapturedPasswordCredential>();
            builder.Entity<CapturedHashCredential>();
            builder.Entity<CapturedTicketCredential>();

            builder.Entity<DownloadEvent>();
            builder.Entity<ScreenshotEvent>();

            builder.Entity<FileIndicator>();
            builder.Entity<NetworkIndicator>();
            builder.Entity<TargetIndicator>();

            builder.Entity<Theme>();

            builder.Entity<Grunt>()
                .HasOne(G => G.ImplantTemplate)
                .WithMany(IT => IT.Grunts)
                .HasForeignKey(G => G.ImplantTemplateId);

            builder.Entity<GruntTask>()
                .HasOne(GT => GT.Author)
                .WithMany(GTA => GTA.GruntTasks)
                .HasForeignKey(GT => GT.AuthorId);

            builder.Entity<GruntCommand>()
                .HasOne(GC => GC.GruntTasking)
                .WithOne(GT => GT.GruntCommand)
                .HasForeignKey<GruntCommand>(GC => GC.GruntTaskingId)
                .IsRequired(false);

            builder.Entity<GruntCommand>()
                .HasOne(GC => GC.CommandOutput)
                .WithOne(CO => CO.GruntCommand)
                .HasForeignKey<GruntCommand>(GC => GC.CommandOutputId);

            builder.Entity<ListenerTypeImplantTemplate>()
                .HasKey(ltit => new { ltit.ListenerTypeId, ltit.ImplantTemplateId });
            builder.Entity<ListenerTypeImplantTemplate>()
                .HasOne(ltit => ltit.ImplantTemplate)
                .WithMany("ListenerTypeImplantTemplates");
            builder.Entity<ListenerTypeImplantTemplate>()
                .HasOne(ltit => ltit.ListenerType);

            builder.Entity<ReferenceSourceLibraryReferenceAssembly>()
                .HasKey(t => new { t.ReferenceSourceLibraryId, t.ReferenceAssemblyId });
            builder.Entity<ReferenceSourceLibraryReferenceAssembly>()
                .HasOne(rslra => rslra.ReferenceSourceLibrary)
                .WithMany("ReferenceSourceLibraryReferenceAssemblies");
            builder.Entity<ReferenceSourceLibraryReferenceAssembly>()
                .HasOne(rslra => rslra.ReferenceAssembly)
                .WithMany("ReferenceSourceLibraryReferenceAssemblies");
                
            builder.Entity<ReferenceSourceLibraryEmbeddedResource>()
                .HasKey(t => new { t.ReferenceSourceLibraryId, t.EmbeddedResourceId });
            builder.Entity<ReferenceSourceLibraryEmbeddedResource>()
                .HasOne(rslra => rslra.ReferenceSourceLibrary)
                .WithMany("ReferenceSourceLibraryEmbeddedResources");
            builder.Entity<ReferenceSourceLibraryEmbeddedResource>()
                .HasOne(rslra => rslra.EmbeddedResource)
                .WithMany("ReferenceSourceLibraryEmbeddedResources");


            builder.Entity<GruntTaskReferenceAssembly>()
                .HasKey(t => new { t.GruntTaskId, t.ReferenceAssemblyId });
            builder.Entity<GruntTaskReferenceAssembly>()
                .HasOne(gtra => gtra.GruntTask)
                .WithMany("GruntTaskReferenceAssemblies");
            builder.Entity<GruntTaskReferenceAssembly>()
                .HasOne(gtra => gtra.ReferenceAssembly)
                .WithMany("GruntTaskReferenceAssemblies");

            builder.Entity<GruntTaskEmbeddedResource>()
                .HasKey(t => new { t.GruntTaskId, t.EmbeddedResourceId });
            builder.Entity<GruntTaskEmbeddedResource>()
                .HasOne(gter => gter.GruntTask)
                .WithMany("GruntTaskEmbeddedResources");
            builder.Entity<GruntTaskEmbeddedResource>()
                .HasOne(gter => gter.EmbeddedResource)
                .WithMany("GruntTaskEmbeddedResources");

            builder.Entity<GruntTaskReferenceSourceLibrary>()
                .HasKey(t => new { t.GruntTaskId, t.ReferenceSourceLibraryId });
            builder.Entity<GruntTaskReferenceSourceLibrary>()
                .HasOne(gtrsl => gtrsl.GruntTask)
                .WithMany("GruntTaskReferenceSourceLibraries");
            builder.Entity<GruntTaskReferenceSourceLibrary>()
                .HasOne(gtrsl => gtrsl.ReferenceSourceLibrary)
                .WithMany("GruntTaskReferenceSourceLibraries");

            ValueComparer<List<string>> stringListComparer = new ValueComparer<List<string>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c.ToList()
            );
            ValueComparer<IList<string>> stringIListComparer = new ValueComparer<IList<string>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c
            );
            ValueComparer<List<Common.DotNetVersion>> dotnetversionListComparer = new ValueComparer<List<Common.DotNetVersion>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c
            );
            ValueComparer<IList<Common.DotNetVersion>> dotnetversionIListComparer = new ValueComparer<IList<Common.DotNetVersion>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c
            );
            ValueComparer<List<HttpProfileHeader>> httpProfileHeaderListComparer = new ValueComparer<List<HttpProfileHeader>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c
            );

            builder.Entity<Listener>().Property(L => L.ConnectAddresses).HasConversion(
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);
            builder.Entity<HttpListener>().Property(L => L.Urls).HasConversion(
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);

            builder.Entity<ImplantTemplate>().Property(IT => IT.CompatibleDotNetVersions).HasConversion(
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<Common.DotNetVersion>() : JsonConvert.DeserializeObject<List<Common.DotNetVersion>>(v)
            ).Metadata.SetValueComparer(dotnetversionListComparer);

            builder.Entity<Grunt>().Property(G => G.Children).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);

            builder.Entity<GruntTask>().Property(GT => GT.Aliases).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);

            builder.Entity<GruntTask>().Property(GT => GT.CompatibleDotNetVersions).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<Common.DotNetVersion>() : JsonConvert.DeserializeObject<List<Common.DotNetVersion>>(v)
            ).Metadata.SetValueComparer(dotnetversionIListComparer);

            builder.Entity<GruntTaskOption>().Property(GTO => GTO.SuggestedValues).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);

            builder.Entity<GruntTasking>().Property(GT => GT.Parameters).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);

            builder.Entity<ReferenceSourceLibrary>().Property(RSL => RSL.CompatibleDotNetVersions).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<Common.DotNetVersion>() : JsonConvert.DeserializeObject<List<Common.DotNetVersion>>(v)
            ).Metadata.SetValueComparer(dotnetversionListComparer);

            builder.Entity<HttpProfile>().Property(HP => HP.HttpUrls).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringListComparer);
            builder.Entity<HttpProfile>().Property(HP => HP.HttpRequestHeaders).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<HttpProfileHeader>() : JsonConvert.DeserializeObject<List<HttpProfileHeader>>(v)
            ).Metadata.SetValueComparer(httpProfileHeaderListComparer);
            builder.Entity<HttpProfile>().Property(HP => HP.HttpResponseHeaders).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<HttpProfileHeader>() : JsonConvert.DeserializeObject<List<HttpProfileHeader>>(v)
            ).Metadata.SetValueComparer(httpProfileHeaderListComparer);
            base.OnModelCreating(builder);
        }
    }
}
