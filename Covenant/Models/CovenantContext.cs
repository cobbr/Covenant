// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

using Covenant.Models.Covenant;
using Covenant.Models.Listeners;
using Covenant.Models.Launchers;
using Covenant.Models.Grunts;
using Covenant.Models.Indicators;

namespace Covenant.Models
{
    public class CovenantContext : IdentityDbContext<CovenantUser>
    {
        public DbSet<Listener> Listeners { get; set; }
        public DbSet<ListenerType> ListenerTypes { get; set; }
        public DbSet<Profile> Profiles { get; set; }

        public DbSet<Launcher> Launchers { get; set; }
        public DbSet<Grunt> Grunts { get; set; }
        public DbSet<GruntTask> GruntTasks { get; set; }
        public DbSet<GruntTask.GruntTaskOption> GruntTaskOptions { get; set; }
        public DbSet<HostedFile> HostedFiles { get; set; }

        public DbSet<CapturedCredential> Credentials { get; set; }
        public DbSet<GruntTasking> GruntTaskings { get; set; }
        public DbSet<Event> Events { get; set; }

        public DbSet<Indicator> Indicators { get; set; }

        public CovenantContext(DbContextOptions<CovenantContext> options) : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
			builder.Entity<HttpListener>().ToTable("HttpListener");
            builder.Entity<HttpProfile>().ToTable("HttpProfile");

            builder.Entity<WmicLauncher>().ToTable("WmicLauncher");
            builder.Entity<Regsvr32Launcher>().ToTable("Regsvr32Launcher");
            builder.Entity<MshtaLauncher>().ToTable("MshtaLauncher");
            builder.Entity<CscriptLauncher>().ToTable("CscriptLauncher");
            builder.Entity<WscriptLauncher>().ToTable("WscriptLauncher");
            builder.Entity<InstallUtilLauncher>().ToTable("InstallUtilLauncher");
            builder.Entity<MSBuildLauncher>().ToTable("MSBuildLauncher");
            builder.Entity<PowerShellLauncher>().ToTable("PowerShellLauncher");
            builder.Entity<BinaryLauncher>().ToTable("BinaryLauncher");

            builder.Entity<CapturedPasswordCredential>().ToTable("CapturedPasswordCredential");
            builder.Entity<CapturedHashCredential>().ToTable("CapturedHashCredential");
            builder.Entity<CapturedTicketCredential>().ToTable("CapturedTicketCredential");

            builder.Entity<DownloadEvent>().ToTable("DownloadEvent");

            builder.Entity<FileIndicator>().ToTable("FileIndicator");
            builder.Entity<NetworkIndicator>().ToTable("FileIndicator");
            builder.Entity<TargetIndicator>().ToTable("FileIndicator");

            // modelBuilder.Entity<Task>().HasMany(T => T.Options).WithOne().OnDelete(DeleteBehavior.Cascade);
            // builder.Entity<GruntTask.GruntTaskOption>().HasKey(T => new { T.Id, T.TaskId});
        }
    }
}
