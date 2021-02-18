// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

using Newtonsoft.Json;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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
                .UseSqlite(
                    "Data Source=" + Common.CovenantDatabaseFile,
                    o => o.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery)
                );

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<GruntTaskOption>().ToTable("GruntTaskOption");

            builder.Entity<HttpListener>().HasBaseType<Listener>();
            builder.Entity<HttpProfile>().HasBaseType<Profile>();
            builder.Entity<BridgeListener>().HasBaseType<Listener>();
            builder.Entity<BridgeProfile>().HasBaseType<Profile>();

            builder.Entity<Regsvr32Launcher>().HasBaseType<Launcher>();
            builder.Entity<MshtaLauncher>().HasBaseType<Launcher>();
            builder.Entity<InstallUtilLauncher>().HasBaseType<Launcher>();
            builder.Entity<MSBuildLauncher>().HasBaseType<Launcher>();
            builder.Entity<PowerShellLauncher>().HasBaseType<Launcher>();
            builder.Entity<BinaryLauncher>().HasBaseType<Launcher>();
            builder.Entity<ServiceBinaryLauncher>().HasBaseType<Launcher>();
            builder.Entity<ShellCodeLauncher>().HasBaseType<Launcher>();

            builder.Entity<CapturedPasswordCredential>().HasBaseType<CapturedCredential>();
            builder.Entity<CapturedHashCredential>().HasBaseType<CapturedCredential>();
            builder.Entity<CapturedTicketCredential>().HasBaseType<CapturedCredential>();

            builder.Entity<DownloadEvent>().HasBaseType<Event>();
            builder.Entity<ScreenshotEvent>().HasBaseType<DownloadEvent>();

            builder.Entity<FileIndicator>().HasBaseType<Indicator>();
            builder.Entity<NetworkIndicator>().HasBaseType<Indicator>();
            builder.Entity<TargetIndicator>().HasBaseType<Indicator>();

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
