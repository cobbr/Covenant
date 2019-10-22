// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Newtonsoft.Json;

using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.CodeAnalysis;

using Covenant.Hubs;
using Covenant.Core;
using Encrypt = Covenant.Core.Encryption;
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
        public DbSet<HostedFile> HostedFiles { get; set; }

        public DbSet<Launcher> Launchers { get; set; }
        public DbSet<ImplantTemplate> ImplantTemplates { get; set; }
        public DbSet<Grunt> Grunts { get; set; }
        public DbSet<GruntTask> GruntTasks { get; set; }
        public DbSet<ReferenceSourceLibrary> ReferenceSourceLibraries { get; set; }
        public DbSet<ReferenceAssembly> ReferenceAssemblies { get; set; }
        public DbSet<EmbeddedResource> EmbeddedResources { get; set; }
        public DbSet<GruntCommand> GruntCommands { get; set; }
        public DbSet<CommandOutput> CommandOutputs { get; set; }
        public DbSet<GruntTasking> GruntTaskings { get; set; }

        public DbSet<Event> Events { get; set; }

        public DbSet<CapturedCredential> Credentials { get; set; }
        public DbSet<Indicator> Indicators { get; set; }

        public CovenantContext(DbContextOptions<CovenantContext> options) : base(options)
        {
            
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            => optionsBuilder.UseSqlite("Data Source=" + Common.CovenantDatabaseFile);

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<GruntTaskOption>().ToTable("GruntTaskOption");

            builder.Entity<HttpListener>().ToTable("HttpListener");
            builder.Entity<HttpProfile>().HasBaseType<Profile>().ToTable("HttpProfile");
            builder.Entity<BridgeListener>().ToTable("BridgeListener");
            builder.Entity<BridgeProfile>().HasBaseType<Profile>().ToTable("BridgeProfile");

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
            builder.Entity<ScreenshotEvent>().ToTable("ScreenshotEvent");

            builder.Entity<FileIndicator>().ToTable("FileIndicator");
            builder.Entity<NetworkIndicator>().ToTable("NetworkIndicator");
            builder.Entity<TargetIndicator>().ToTable("TargetIndicator");

            builder.Entity<Grunt>()
                .HasOne(G => G.ImplantTemplate)
                .WithMany(IT => IT.Grunts)
                .HasForeignKey(G => G.ImplantTemplateId);

            builder.Entity<GruntTasking>()
                .HasOne(GT => GT.GruntCommand)
                .WithOne(GC => GC.GruntTasking)
                .HasForeignKey<GruntCommand>(GC => GC.GruntTaskingId);

            builder.Entity<GruntCommand>()
                .HasOne(GC => GC.CommandOutput)
                .WithOne(CO => CO.GruntCommand)
                .HasForeignKey<GruntCommand>(GC => GC.CommandOutputId);

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

            builder.Entity<Listener>().Property(L => L.ConnectAddresses).HasConversion(
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );
            builder.Entity<HttpListener>().Property(L => L.Urls).HasConversion(
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<Grunt>().Property(G => G.Children).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<GruntTask>().Property(GT => GT.AlternateNames).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<GruntTaskOption>().Property(GTO => GTO.SuggestedValues).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<GruntTasking>().Property(GT => GT.Parameters).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );

            builder.Entity<ReferenceSourceLibrary>().Property(RA => RA.SupportedDotNetVersions).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<Common.DotNetVersion>() : JsonConvert.DeserializeObject<List<Common.DotNetVersion>>(v)
            );

            builder.Entity<HttpProfile>().Property(HP => HP.HttpUrls).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            );
            builder.Entity<HttpProfile>().Property(HP => HP.HttpRequestHeaders).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<HttpProfileHeader>() : JsonConvert.DeserializeObject<List<HttpProfileHeader>>(v)
            );
            builder.Entity<HttpProfile>().Property(HP => HP.HttpResponseHeaders).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<HttpProfileHeader>() : JsonConvert.DeserializeObject<List<HttpProfileHeader>>(v)
            );
            base.OnModelCreating(builder);
        }

        #region CovenantUser Actions
        public async Task<IEnumerable<CovenantUser>> GetUsers()
        {
            return await this.Users.ToListAsync();
        }

        public async Task<CovenantUser> GetUser(string userId)
        {
            CovenantUser user = await this.Users.FindAsync(userId);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with id: {userId}");
            }
            return user;
        }

        public async Task<CovenantUser> GetUserByUsername(string username)
        {
            CovenantUser user = await this.Users.FirstOrDefaultAsync(U => U.UserName == username);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with Username: {username}");
            }
            return user;
        }

        public async Task<CovenantUser> GetCurrentUser(UserManager<CovenantUser> userManager, ClaimsPrincipal principal)
        {
            CovenantUser user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not identify current username");
            }
            return await this.GetUser(user.Id);
        }

        public async Task<CovenantUserLoginResult> Login(SignInManager<CovenantUser> signInManager, IConfiguration configuration, CovenantUserLogin login)
        {
            SignInResult result = await signInManager.PasswordSignInAsync(login.UserName, login.Password, false, false);
            if (!result.Succeeded)
            {
                return new CovenantUserLoginResult { Success = false, CovenantToken = "" };
            }
            CovenantUser user = await this.Users.FirstOrDefaultAsync(U => U.UserName == login.UserName);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - User with username: {login.UserName}");
            }
            List<string> userRoles = await this.UserRoles.Where(UR => UR.UserId == user.Id).Select(UR => UR.RoleId).ToListAsync();
            List<string> roles = await this.Roles.Where(R => userRoles.Contains(R.Id)).Select(R => R.Name).ToListAsync();

            string token = Utilities.GenerateJwtToken(
                login.UserName, user.Id, roles.ToArray(),
                configuration["JwtKey"], configuration["JwtIssuer"],
                configuration["JwtAudience"], configuration["JwtExpireDays"]
            );
            return new CovenantUserLoginResult { Success = true, CovenantToken = token };
        }

        public async Task<CovenantUser> CreateUser(UserManager<CovenantUser> userManager, CovenantUserLogin login, IHubContext<EventHub> _eventhub)
        {
            CovenantUser user = new CovenantUser { UserName = login.UserName };
            IdentityResult result = await userManager.CreateAsync(user, login.Password);
            if (!result.Succeeded)
            {
                List<IdentityError> errors = result.Errors.ToList();
                string ErrorMessage = $"BadRequest - Could not create CovenantUser: {login.UserName}";
                foreach (IdentityError error in result.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                throw new ControllerBadRequestException(ErrorMessage);
            }

            CovenantUser savedUser = await this.Users.FirstOrDefaultAsync(U => U.UserName == user.UserName);
            if (savedUser == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find CovenantUser with username: {login.UserName}");
            }
            string savedRoles = String.Join(",", await this.GetUserRoles(savedUser.Id));

            DateTime eventTime = DateTime.UtcNow;
            Event userEvent = new Event
            {
                Time = eventTime,
                MessageHeader = "[" + eventTime + " UTC] User: " + savedUser.UserName + " with roles: " + savedRoles + " has been created!",
                Level = EventLevel.Highlight,
                Context = "Users"
            };
            await this.Events.AddAsync(userEvent);
            await EventHubProxy.SendEvent(_eventhub, userEvent);
            return savedUser;
        }

        public async Task<CovenantUser> EditUser(UserManager<CovenantUser> userManager, CovenantUser currentUser, CovenantUserLogin user)
        {
            CovenantUser matching_user = await this.GetUserByUsername(user.UserName);
            var admins = from users in this.Users
                         join userroles in this.UserRoles on users.Id equals userroles.UserId
                         join roles in this.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select users.UserName;
            if (currentUser.UserName != matching_user.UserName && !admins.Contains(currentUser.UserName))
            {
                throw new ControllerBadRequestException($"BadRequest - Current user: {currentUser.UserName} is not an Administrator and cannot change password of user: {user.Password}");
            }
            matching_user.PasswordHash = userManager.PasswordHasher.HashPassword(matching_user, user.Password);
            IdentityResult result = await userManager.UpdateAsync(matching_user);
            if (!result.Succeeded)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not set new password for CovenantUser with username: {user.UserName}");
            }
            this.Users.Update(matching_user);
            await this.SaveChangesAsync();
            return matching_user;
        }

        public async Task<CovenantUser> EditUser(UserManager<CovenantUser> userManager, ClaimsPrincipal principal, CovenantUserLogin user)
        {
            return await this.EditUser(userManager, await GetCurrentUser(userManager, principal), user);
        }

        public async Task DeleteUser(string userId)
        {
            CovenantUser user = await this.GetUser(userId);
            if (await this.IsAdmin(user) && this.GetAdminCount() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not delete CovenantUser with id: {userId}";
                ErrorMessage += "Can't delete the last Administrative user.";
                throw new ControllerBadRequestException(ErrorMessage);
            }
            this.Users.Remove(user);
            await this.SaveChangesAsync();
        }

        private IQueryable<CovenantUser> GetAdminUsers()
        {
            return from users in this.Users
                         join userroles in this.UserRoles on users.Id equals userroles.UserId
                         join roles in this.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select users;
        }

        private async Task<bool> IsAdmin(CovenantUser user)
        {
            return await GetAdminUsers().Select(U => U.UserName).ContainsAsync(user.UserName);
        }

        private int GetAdminCount()
        {
            return GetAdminUsers().Count();
        }
        #endregion

        #region Role Actions
        public async Task<IEnumerable<IdentityRole>> GetRoles()
        {
            return await this.Roles.ToListAsync();
        }

        public async Task<IdentityRole> GetRole(string roleId)
        {
            IdentityRole role = await this.Roles.FindAsync(roleId);
            if (role == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find Role with id: {roleId}");
            }
            return role;
        }

        public async Task<IdentityRole> GetRoleByName(string rolename)
        {
            IdentityRole role = await this.Roles.FirstOrDefaultAsync(R => R.Name == rolename);
            if (role == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find Role with name: {rolename}");
            }
            return role;
        }
        #endregion

        #region UserRole Actions
        public async Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles()
        {
            return await this.UserRoles.ToListAsync();
        }

        public async Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles(string userId)
        {
            return await this.UserRoles.Where(UR => UR.UserId == userId).ToListAsync();
        }

        public async Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId)
        {
            IdentityUserRole<string> userRole = await this.UserRoles.FirstOrDefaultAsync(UR => UR.UserId == userId && UR.RoleId == roleId);
            if (userRole == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find UserRole with user id: {userId} and role id: {roleId}");
            }
            return userRole;
        }

        public async Task<IdentityUserRole<string>> CreateUserRole(UserManager<CovenantUser> userManager, string userId, string roleId)
        {
            CovenantUser user = await this.GetUser(userId);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find CovenantUser with id: {userId}");
            }
            IdentityRole role = await this.GetRole(roleId);
            if (role == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find UserRole with id: {roleId}");
            }
            IdentityResult result = await userManager.AddToRoleAsync(user, role.Name);
            if (!result.Succeeded)
            {
                string ErrorMessage = $"BadRequest - Could not add CovenantUser: {user.UserName} to role: {role.Name}";
                foreach (IdentityError error in result.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                throw new ControllerBadRequestException(ErrorMessage);
            }
            IdentityUserRole<string> userRole = await this.GetUserRole(userId, roleId);
            if (userRole == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find UserRole with user id: {userId} and role id: {roleId}");
            }
            return userRole;
        }

        public async Task DeleteUserRole(UserManager<CovenantUser> userManager, string userId, string roleId)
        {
            CovenantUser user = await this.GetUser(userId);
            IdentityRole role = await this.GetRole(roleId);
            IdentityUserRole<string> userRole = await this.GetUserRole(user.Id, role.Id);
            var adminUserRoles = from users in this.Users
                                 join userroles in this.UserRoles on users.Id equals userroles.UserId
                                 join roles in this.Roles on userroles.RoleId equals roles.Id
                                 where roles.Name == "Administrator"
                                 select userroles;
            if (adminUserRoles.Contains(userRole) && adminUserRoles.Count() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not remove CovenantUser with id: {userId} from Administrative role";
                ErrorMessage += "Can't remove the last Administrative user.";
                throw new ControllerBadRequestException(ErrorMessage);
            }
            IdentityResult result = await userManager.RemoveFromRoleAsync(user, role.Name);
            if (!result.Succeeded)
            {
                string ErrorMessage = $"BadRequest - Could not remove role: {role.Name} from CovenantUser: {user.UserName}";
                foreach (IdentityError error in result.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                throw new ControllerBadRequestException(ErrorMessage);
            }
            await this.SaveChangesAsync();
        }
        #endregion

        #region Event Actions
        public async Task<IEnumerable<Event>> GetEvents()
        {
            return await this.Events.ToListAsync();
        }

        public async Task<Event> GetEvent(int eventId)
        {
            Event anEvent = await this.Events.FindAsync(eventId);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - Event with id: {eventId}");
            }
            return anEvent;
        }

        public long GetEventTime()
        {
            return DateTime.UtcNow.ToBinary();
        }

        public async Task<IEnumerable<Event>> GetEventsAfter(long fromdate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            return await this.Events.Where(E => E.Time.CompareTo(start) >= 0).ToListAsync();
        }

        public async Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            DateTime end = DateTime.FromBinary(todate);
            return await this.Events.Where(E => E.Time.CompareTo(start) >= 0 && E.Time.CompareTo(end) <= 0).ToListAsync();
        }

        public async Task<Event> CreateEvent(Event anEvent)
        {
            anEvent.Time = DateTime.UtcNow;
            await this.Events.AddAsync(anEvent);
            await this.SaveChangesAsync();
            return await this.GetEvent(anEvent.Id);
        }

        public async Task<IEnumerable<DownloadEvent>> GetDownloadEvents()
        {
            return await this.Events.Where(E => E.Type == EventType.Download).Select(E => (DownloadEvent)E).ToListAsync();
        }

        public async Task<DownloadEvent> GetDownloadEvent(int eventId)
        {
            DownloadEvent anEvent = (DownloadEvent)await this.Events.FirstOrDefaultAsync(E => E.Id == eventId && E.Type == EventType.Download);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - DownloadEvent with id: {eventId}");
            }
            return anEvent;
        }

        public async Task<string> GetDownloadContent(int eventId)
        {
            DownloadEvent theEvent = await this.GetDownloadEvent(eventId);
            string filename = System.IO.Path.Combine(Common.CovenantDownloadDirectory, theEvent.FileName);
            if (!System.IO.File.Exists(filename))
            {
                throw new ControllerBadRequestException($"BadRequest - Path does not exist on disk: {filename}");
            }
            try
            {
                return Convert.ToBase64String(System.IO.File.ReadAllBytes(filename));
            }
            catch (Exception e)
            {
                throw new ControllerBadRequestException($"BadRequest - Unable to read download content from: {filename}{Environment.NewLine}{e.Message}");
            }
        }

        public async Task<DownloadEvent> CreateDownloadEvent(DownloadEvent downloadEvent)
        {
            downloadEvent.Time = DateTime.UtcNow;
            downloadEvent.WriteToDisk();
            await this.Events.AddAsync(downloadEvent);
            await this.SaveChangesAsync();
            return await this.GetDownloadEvent(downloadEvent.Id);
        }

        public async Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents()
        {
            return await this.Events.Where(E => E.Type == EventType.Screenshot).Select(E => (ScreenshotEvent)E).ToListAsync();
        }

        public async Task<ScreenshotEvent> GetScreenshotEvent(int eventId)
        {
            ScreenshotEvent anEvent = (ScreenshotEvent)await this.Events.FirstOrDefaultAsync(E => E.Id == eventId && E.Type == EventType.Screenshot);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - ScreenshotEvent with id: {eventId}");
            }
            return anEvent;
        }

        public async Task<string> GetScreenshotContent(int eventId)
        {
            ScreenshotEvent theEvent = await this.GetScreenshotEvent(eventId);
            string filename = System.IO.Path.Combine(Common.CovenantDownloadDirectory, Utilities.GetSanitizedFilename(theEvent.FileName));
            if (!System.IO.File.Exists(filename))
            {
                throw new ControllerBadRequestException($"BadRequest - Path does not exist on disk: {filename}");
            }
            try
            {
                return Convert.ToBase64String(System.IO.File.ReadAllBytes(filename));
            }
            catch (Exception e)
            {
                throw new ControllerBadRequestException($"BadRequest - Unable to read download content from: {filename}{Environment.NewLine}{e.Message}");
            }
        }

        public async Task<ScreenshotEvent> CreateScreenshotEvent(ScreenshotEvent screenshotEvent)
        {
            screenshotEvent.Time = DateTime.UtcNow;
            screenshotEvent.WriteToDisk();
            await this.Events.AddAsync(screenshotEvent);
            await this.SaveChangesAsync();
            return await this.GetScreenshotEvent(screenshotEvent.Id);
        }
        #endregion

        #region ImplantTemplate Actions

        public async Task<IEnumerable<ImplantTemplate>> GetImplantTemplates()
        {
            return await this.ImplantTemplates.ToListAsync();
        }

        public async Task<ImplantTemplate> GetImplantTemplate(int id)
        {
            ImplantTemplate template = await this.ImplantTemplates.FindAsync(id);
            if (template == null)
            {
                throw new ControllerNotFoundException($"NotFound - ImplantTemplate with id: {id}");
            }
            return template;
        }

        public async Task<ImplantTemplate> GetImplantTemplateByName(string name)
        {
            ImplantTemplate template = await this.ImplantTemplates
                .Where(IT => IT.Name == name)
                .FirstOrDefaultAsync();
            if (template == null)
            {
                throw new ControllerNotFoundException($"NotFound - ImplantTemplate with Name: {name}");
            }
            return template;
        }

        public async Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template)
        {
            await this.ImplantTemplates.AddAsync(template);
            await this.SaveChangesAsync();
            return await this.GetImplantTemplate(template.Id);
        }

        public async Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template)
        {
            ImplantTemplate matchingTemplate = await this.GetImplantTemplate(template.Id);
            matchingTemplate.Name = template.Name;
            matchingTemplate.Description = template.Description;
            matchingTemplate.Language = template.Language;
            matchingTemplate.StagerCode = template.StagerCode;
            matchingTemplate.ExecutorCode = template.ExecutorCode;

            this.ImplantTemplates.Update(matchingTemplate);
            await this.SaveChangesAsync();
            return await this.GetImplantTemplate(matchingTemplate.Id);
        }

        public async Task DeleteImplantTemplate(int id)
        {
            ImplantTemplate matchingTemplate = await this.GetImplantTemplate(id);
            this.ImplantTemplates.Remove(matchingTemplate);
            await this.SaveChangesAsync();
        }
        #endregion

        #region Grunt Actions
        public async Task<IEnumerable<Grunt>> GetGrunts()
        {
            List<Grunt> grunts = await this.Grunts.Include(G => G.ImplantTemplate).ToListAsync();
            grunts.ForEach(async G =>
            {
                if (G.Status == GruntStatus.Active || G.Status == GruntStatus.Lost)
                {
                    bool lost = await this.IsGruntLost(G);
                    if (G.Status == GruntStatus.Active && lost)
                    {
                        G.Status = GruntStatus.Lost;
                        this.Grunts.Update(G);
                        this.SaveChanges();
                    }
                    else if (G.Status == GruntStatus.Lost && !lost)
                    {
                        G.Status = GruntStatus.Active;
                        this.Grunts.Update(G);
                        this.SaveChanges();
                    }
                }
            });
            return await this.Grunts.ToListAsync();
        }

        public async Task<Grunt> GetGrunt(int gruntId)
        {
            Grunt grunt = await this.Grunts.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(G => G.Id == gruntId);
            if (grunt == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grunt with id: {gruntId}");
            }
            if (grunt.Status == GruntStatus.Active || grunt.Status == GruntStatus.Lost)
            {
                bool lost = await this.IsGruntLost(grunt);
                if (grunt.Status == GruntStatus.Active && lost)
                {
                    grunt.Status = GruntStatus.Lost;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
            }
            return grunt;
        }

        public async Task<Grunt> GetGruntByName(string name)
        {
            Grunt grunt = await this.Grunts.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(g => g.Name == name);
            if (grunt == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grunt with name: {name}");
            }
            if (grunt.Status == GruntStatus.Active || grunt.Status == GruntStatus.Lost)
            {
                bool lost = await this.IsGruntLost(grunt);
                if (grunt.Status == GruntStatus.Active && lost)
                {
                    grunt.Status = GruntStatus.Lost;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
            }
            return grunt;
        }

        public async Task<Grunt> GetGruntByGUID(string guid)
        {
            Grunt grunt = await this.Grunts.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(g => g.GUID == guid);
            if (grunt == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grunt with GUID: {guid}");
            }
            if (grunt.Status == GruntStatus.Active || grunt.Status == GruntStatus.Lost)
            {
                bool lost = await this.IsGruntLost(grunt);
                if (grunt.Status == GruntStatus.Active && lost)
                {
                    grunt.Status = GruntStatus.Lost;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
            }
            return grunt;
        }

        public async Task<Grunt> GetGruntByOriginalServerGUID(string serverguid)
        {
            Grunt grunt = await this.Grunts.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(g => g.OriginalServerGuid == serverguid);
            if (grunt == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grunt with OriginalServerGUID: {serverguid}");
            }
            if (grunt.Status == GruntStatus.Active || grunt.Status == GruntStatus.Lost)
            {
                bool lost = await this.IsGruntLost(grunt);
                if (grunt.Status == GruntStatus.Active && lost)
                {
                    grunt.Status = GruntStatus.Lost;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    this.Grunts.Update(grunt);
                    this.SaveChanges();
                }
            }
            return grunt;
        }

        public async Task<bool> IsGruntLost(Grunt g)
        {
            DateTime lostTime = g.LastCheckIn;
            int Drift = 10;
            lostTime = lostTime.AddSeconds(g.Delay + (g.Delay * (g.JitterPercent / 100.0)) + Drift);
            if (g.ImplantTemplate.CommType != CommunicationType.SMB)
            {
                return DateTime.UtcNow >= lostTime;
            }
            Grunt sg = await this.Grunts
                    .Where(GR => GR.Id == g.Id)
                    .Include(GR => GR.GruntCommands)
                    .ThenInclude(GC => GC.GruntTasking)
                    .FirstOrDefaultAsync();
            
            if(DateTime.UtcNow >= lostTime &&
                sg != null &&
                sg.GruntCommands != null &&
                sg.GruntCommands.Count > 0 &&
                sg.GruntCommands.Any(
                    GC => GC.GruntTasking != null &&
                    (GC.GruntTasking.Status == GruntTaskingStatus.Uninitialized || GC.GruntTasking.Status == GruntTaskingStatus.Tasked)))
            {
                lostTime = sg.GruntCommands.Where(GC => GC.GruntTasking != null &&
                    (GC.GruntTasking.Status == GruntTaskingStatus.Uninitialized || GC.GruntTasking.Status == GruntTaskingStatus.Tasked)).Select(GC => GC.CommandTime).OrderBy(CT => CT).FirstOrDefault();
                lostTime = lostTime.AddSeconds(g.Delay + (g.Delay * (g.JitterPercent / 100.0)) + Drift);
                return DateTime.UtcNow >= lostTime;
            }
            return false;
        }

        public async Task<List<string>> GetPathToChildGrunt(int gruntId, int childId)
        {
            Grunt grunt = await this.GetGrunt(gruntId);
            if (grunt == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grunt with id: {gruntId}");
            }
            List<string> path = new List<string>();
            bool found = GetPathToChildGrunt(gruntId, childId, ref path);
            if (!found)
            {
                throw new ControllerNotFoundException($"NotFound - Path from Grunt with id: {gruntId} to Grunt with id: {childId}");
            }
            path.Add(grunt.GUID);
            path.Reverse();
            return path;
        }

        public async Task<Grunt> CreateGrunt(Grunt grunt)
        {
            TargetIndicator indicator = await this.Indicators.Where(I => I.Type == IndicatorType.TargetIndicator)
                .Select(T => (TargetIndicator)T)
                .FirstOrDefaultAsync(T => T.ComputerName == grunt.Hostname && T.UserName == grunt.UserDomainName + "\\" + grunt.UserName);
            if (indicator == null && !string.IsNullOrWhiteSpace(grunt.Hostname))
            {
                await this.Indicators.AddAsync(new TargetIndicator
                {
                    ComputerName = grunt.Hostname,
                    UserName = grunt.UserName,
                });
            }
            grunt.ImplantTemplate = null;
            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();
            return await this.GetGrunt(grunt.Id);
        }

        public async Task<Grunt> EditGrunt(Grunt grunt, CovenantUser user, IHubContext<GruntHub> grunthub, IHubContext<EventHub> _eventhub)
        {
            Grunt matching_grunt = await this.GetGrunt(grunt.Id);
            if (matching_grunt.Status != GruntStatus.Active && grunt.Status == GruntStatus.Active)
            {
                grunt.ActivationTime = DateTime.UtcNow;
                Event gruntEvent = new Event
                {
                    Time = DateTime.UtcNow,
                    MessageHeader = "[" + grunt.ActivationTime + " UTC] Grunt: " + grunt.Name + " from: " + grunt.Hostname + " has been activated!",
                    Level = EventLevel.Highlight,
                    Context = "*"
                };
                await this.Events.AddAsync(gruntEvent);
                await EventHubProxy.SendEvent(_eventhub, gruntEvent);
            }
            matching_grunt.Name = grunt.Name;
            matching_grunt.GUID = grunt.GUID;
            matching_grunt.OriginalServerGuid = grunt.OriginalServerGuid;

            matching_grunt.ListenerId = grunt.ListenerId;
            matching_grunt.Listener = await this.GetListener(grunt.ListenerId);

            matching_grunt.ImplantTemplateId = grunt.ImplantTemplateId;
            matching_grunt.ImplantTemplate = await this.GetImplantTemplate(grunt.ImplantTemplateId);

            matching_grunt.UserDomainName = grunt.UserDomainName;
            matching_grunt.UserName = grunt.UserName;
            matching_grunt.Status = grunt.Status;
            matching_grunt.Integrity = grunt.Integrity;
            matching_grunt.Process = grunt.Process;
            matching_grunt.LastCheckIn = grunt.LastCheckIn;
            matching_grunt.ActivationTime = grunt.ActivationTime;
            matching_grunt.IPAddress = grunt.IPAddress;
            matching_grunt.Hostname = grunt.Hostname;
            matching_grunt.OperatingSystem = grunt.OperatingSystem;

            matching_grunt.Children = grunt.Children;
            matching_grunt.ValidateCert = grunt.ValidateCert;
            matching_grunt.UseCertPinning = grunt.UseCertPinning;
            matching_grunt.SMBPipeName = grunt.SMBPipeName;
            matching_grunt.Note = grunt.Note;

            if (matching_grunt.Status == grunt.Status && (matching_grunt.Status == GruntStatus.Active || matching_grunt.Status == GruntStatus.Lost))
            {
                if (matching_grunt.ConnectAttempts != grunt.ConnectAttempts)
                {
                    GruntTask setTask = await this.GetGruntTaskByName("Set");
                    matching_grunt.ConnectAttempts = grunt.ConnectAttempts;
                    setTask.Options[0].Value = "ConnectAttempts";
                    setTask.Options[1].Value = grunt.ConnectAttempts.ToString();
                    GruntCommand createdGruntCommand = await this.CreateGruntCommand(new GruntCommand
                    {
                        Command = "Set ConnectAttempts " + grunt.ConnectAttempts.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    }, grunthub, _eventhub);
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetOption,
                        Parameters = new List<string> { "ConnectAttempts", grunt.ConnectAttempts.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    }, grunthub);
                }
                if (matching_grunt.Delay != grunt.Delay)
                {
                    GruntTask setTask = await this.GetGruntTaskByName("Set");
                    matching_grunt.Delay = grunt.Delay;
                    setTask.Options[0].Value = "Delay";
                    setTask.Options[1].Value = grunt.Delay.ToString();
                    GruntCommand createdGruntCommand = await this.CreateGruntCommand(new GruntCommand
                    {
                        Command = "Set Delay " + grunt.Delay.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    }, grunthub, _eventhub);
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetOption,
                        Parameters = new List<string> { "Delay", grunt.Delay.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    }, grunthub);
                }
                if (matching_grunt.JitterPercent != grunt.JitterPercent)
                {
                    GruntTask setTask = await this.GetGruntTaskByName("Set");
                    matching_grunt.JitterPercent = grunt.JitterPercent;
                    setTask.Options[0].Value = "JitterPercent";
                    setTask.Options[1].Value = grunt.JitterPercent.ToString();
                    GruntCommand createdGruntCommand = await this.CreateGruntCommand(new GruntCommand
                    {
                        Command = "Set JitterPercent " + grunt.JitterPercent.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    }, grunthub, _eventhub);
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetOption,
                        Parameters = new List<string> { "JitterPercent", grunt.JitterPercent.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    }, grunthub);
                }
                if (matching_grunt.KillDate != grunt.KillDate)
                {
                    matching_grunt.KillDate = grunt.KillDate;
                }
            }

            matching_grunt.DotNetFrameworkVersion = grunt.DotNetFrameworkVersion;

            matching_grunt.GruntChallenge = grunt.GruntChallenge;
            matching_grunt.GruntNegotiatedSessionKey = grunt.GruntNegotiatedSessionKey;
            matching_grunt.GruntRSAPublicKey = grunt.GruntRSAPublicKey;
            matching_grunt.GruntSharedSecretPassword = grunt.GruntSharedSecretPassword;
            matching_grunt.PowerShellImport = grunt.PowerShellImport;
            this.Grunts.Update(matching_grunt);

            TargetIndicator indicator = (await this.GetTargetIndicators())
                .FirstOrDefault(T => T.ComputerName == grunt.Hostname && T.UserName == grunt.UserDomainName + "\\" + grunt.UserName);

            if (indicator == null && !string.IsNullOrWhiteSpace(grunt.Hostname))
            {
                await this.Indicators.AddAsync(new TargetIndicator
                {
                    ComputerName = grunt.Hostname,
                    UserName = grunt.UserDomainName + "\\" + grunt.UserName
                });
            }
            await this.SaveChangesAsync();
            return await this.GetGrunt(matching_grunt.Id);
        }

        public async Task<Grunt> EditGrunt(Grunt grunt, UserManager<CovenantUser> userManager, ClaimsPrincipal userPrincipal, IHubContext<GruntHub> grunthub, IHubContext<EventHub> _eventhub)
        {
            return await this.EditGrunt(grunt, await this.GetCurrentUser(userManager, userPrincipal), grunthub, _eventhub);
        }

        public async Task DeleteGrunt(int gruntId)
        {
            Grunt grunt = await this.GetGrunt(gruntId);
            if (grunt == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grunt with id: {gruntId}");
            }
            this.Grunts.Remove(grunt);
            await this.SaveChangesAsync();
        }

        public async Task<byte[]> CompileGruntStagerCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            Grunt grunt = await this.GetGrunt(id);
            ImplantTemplate template = await this.GetImplantTemplate(grunt.ImplantTemplateId);
            Listener listener = await this.GetListener(grunt.ListenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            return CompileGruntCode(template.StagerCode, template, grunt, listener, profile, outputKind, Compress);
        }

        public async Task<byte[]> CompileGruntExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            Grunt grunt = await this.GetGrunt(id);
            ImplantTemplate template = await this.GetImplantTemplate(grunt.ImplantTemplateId);
            Listener listener = await this.GetListener(grunt.ListenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            return CompileGruntCode(template.ExecutorCode, template, grunt, listener, profile, outputKind, Compress);
        }

        private byte[] CompileGruntCode(string CodeTemplate, ImplantTemplate template, Grunt grunt, Listener listener, Profile profile, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            byte[] ILBytes = Compiler.Compile(new Compiler.CompilationRequest
            {
                Language = template.Language,
                Source = this.GruntTemplateReplace(CodeTemplate, grunt, listener, profile),
                TargetDotNetVersion = grunt.DotNetFrameworkVersion,
                OutputKind = outputKind,
                References = grunt.DotNetFrameworkVersion == Common.DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References
            });
            if (ILBytes == null || ILBytes.Length == 0)
            {
                throw new CovenantCompileGruntStagerFailedException("Compiling Grunt code failed");
            }
            if (Compress)
            {
                ILBytes = Utilities.Compress(ILBytes);
            }
            return ILBytes;
        }

        private string GruntTemplateReplace(string CodeTemplate, Grunt grunt, Listener listener, Profile profile)
        {
            switch (profile.Type)
            {
                case ProfileType.HTTP:
                    HttpProfile httpProfile = (HttpProfile)profile;
                    HttpListener httpListener = (HttpListener)listener;
                    return CodeTemplate
                        .Replace("// {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}", profile.MessageTransform)
                        .Replace("{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpRequestHeaders.Select(H => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(H.Name.Replace("{GUID}", grunt.GUID)))))))
                        .Replace("{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpRequestHeaders.Select(H => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(H.Value.Replace("{GUID}", grunt.GUID)))))))
                        .Replace("{{REPLACE_PROFILE_HTTP_URLS}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpUrls.Select(H => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(H.Replace("{GUID}", grunt.GUID)))))))
                        .Replace("{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}", this.FormatForVerbatimString(httpProfile.HttpGetResponse))
                        .Replace("{{REPLACE_PROFILE_HTTP_POST_REQUEST}}", this.FormatForVerbatimString(httpProfile.HttpPostRequest))
                        .Replace("{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}", this.FormatForVerbatimString(httpProfile.HttpPostResponse))
                        .Replace("{{REPLACE_VALIDATE_CERT}}", grunt.ValidateCert ? "true" : "false")
                        .Replace("{{REPLACE_USE_CERT_PINNING}}", grunt.UseCertPinning ? "true" : "false")
                        .Replace("{{REPLACE_PIPE_NAME}}", grunt.SMBPipeName)
                        .Replace("{{REPLACE_COVENANT_URIS}}", this.FormatForVerbatimString(string.Join(",", httpListener.Urls)))
                        .Replace("{{REPLACE_COVENANT_CERT_HASH}}", this.FormatForVerbatimString(httpListener.UseSSL ? httpListener.SSLCertHash : ""))
                        .Replace("{{REPLACE_GRUNT_GUID}}", this.FormatForVerbatimString(grunt.OriginalServerGuid))
                        .Replace("{{REPLACE_DELAY}}", this.FormatForVerbatimString(grunt.Delay.ToString()))
                        .Replace("{{REPLACE_JITTER_PERCENT}}", this.FormatForVerbatimString(grunt.JitterPercent.ToString()))
                        .Replace("{{REPLACE_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grunt.ConnectAttempts.ToString()))
                        .Replace("{{REPLACE_KILL_DATE}}", this.FormatForVerbatimString(grunt.KillDate.ToBinary().ToString()))
                        .Replace("{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grunt.GruntSharedSecretPassword));
                case ProfileType.Bridge:
                    BridgeProfile bridgeProfile = (BridgeProfile)profile;
                    BridgeListener bridgeListener = (BridgeListener)listener;
                    return CodeTemplate
                        .Replace("// {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}", bridgeProfile.MessageTransform)
                        .Replace("{{REPLACE_PROFILE_WRITE_FORMAT}}", bridgeProfile.WriteFormat.Replace("{GUID}", "{0}").Replace("{DATA}", "{1}"))
                        .Replace("{{REPLACE_PROFILE_READ_FORMAT}}", bridgeProfile.ReadFormat.Replace("{GUID}", "{0}").Replace("{DATA}", "{1}"))
                        .Replace("{{REPLACE_PIPE_NAME}}", grunt.SMBPipeName)
                        .Replace("{{REPLACE_COVENANT_URI}}", this.FormatForVerbatimString(bridgeListener.ConnectAddresses[0] + ":" + bridgeListener.ConnectPort))
                        .Replace("{{REPLACE_GRUNT_GUID}}", this.FormatForVerbatimString(grunt.OriginalServerGuid))
                        .Replace("{{REPLACE_DELAY}}", this.FormatForVerbatimString(grunt.Delay.ToString()))
                        .Replace("{{REPLACE_JITTER_PERCENT}}", this.FormatForVerbatimString(grunt.JitterPercent.ToString()))
                        .Replace("{{REPLACE_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grunt.ConnectAttempts.ToString()))
                        .Replace("{{REPLACE_KILL_DATE}}", this.FormatForVerbatimString(grunt.KillDate.ToBinary().ToString()))
                        .Replace("{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grunt.GruntSharedSecretPassword));
                default:
                    return CodeTemplate;
            }
        }

        private string FormatForVerbatimString(string replacement)
        {
            return replacement.Replace("\"", "\"\"").Replace("{", "{{").Replace("}", "}}").Replace("{{0}}", "{0}");
        }

        private bool GetPathToChildGrunt(int ParentId, int ChildId, ref List<string> GruntPath)
        {
            if (ParentId == ChildId)
            {
                return true;
            }

            Grunt parentGrunt = this.Grunts.Find(ParentId);
            Grunt childGrunt = this.Grunts.Find(ChildId);
            if (parentGrunt == null || childGrunt == null)
            {
                return false;
            }
            if (parentGrunt.Children.Contains(childGrunt.GUID))
            {
                GruntPath.Add(childGrunt.GUID);
                return true;
            }
            foreach (string child in parentGrunt.Children)
            {
                Grunt directChild = this.Grunts.FirstOrDefault(G => G.GUID == child);
                if (directChild == null)
                {
                    return false;
                }
                if (GetPathToChildGrunt(directChild.Id, ChildId, ref GruntPath))
                {
                    GruntPath.Add(directChild.GUID);
                    return true;
                }
            }
            return false;
        }
        #endregion

        #region GruntTaskComponent ReferenceAssembly Actions
        public async Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies()
        {
            return await this.ReferenceAssemblies.ToListAsync();
        }

        public async Task<IEnumerable<ReferenceAssembly>> GetDefaultNet35ReferenceAssemblies()
        {
            return new List<ReferenceAssembly>
            {
                await this.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35),
                await this.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35),
                await this.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35)
            };
        }

        public async Task<IEnumerable<ReferenceAssembly>> GetDefaultNet40ReferenceAssemblies()
        {
            return new List<ReferenceAssembly>
            {
                await this.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40),
                await this.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40),
                await this.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40)
            };
        }

        public async Task<ReferenceAssembly> GetReferenceAssembly(int id)
        {
            ReferenceAssembly assembly = await this.ReferenceAssemblies.FindAsync(id);
            if (assembly == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceAssembly with id: {id}");
            }
            return assembly;
        }

        public async Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version)
        {
            ReferenceAssembly assembly = await this.ReferenceAssemblies
                .Where(RA => RA.Name == name && RA.DotNetVersion == version)
                .FirstOrDefaultAsync();
            if (assembly == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceAssembly with Name: {name} and DotNetVersion: {version}");
            }
            return assembly;
        }

        public async Task<ReferenceAssembly> CreateReferenceAssembly(ReferenceAssembly assembly)
        {
            await this.ReferenceAssemblies.AddAsync(assembly);
            await this.SaveChangesAsync();
            return await this.GetReferenceAssembly(assembly.Id);
        }

        public async Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly)
        {
            ReferenceAssembly matchingAssembly = await this.GetReferenceAssembly(assembly.Id);
            matchingAssembly.Name = assembly.Name;
            matchingAssembly.Location = assembly.Location;
            matchingAssembly.DotNetVersion = assembly.DotNetVersion;
            this.ReferenceAssemblies.Update(matchingAssembly);
            await this.SaveChangesAsync();
            return await this.GetReferenceAssembly(matchingAssembly.Id);
        }

        public async Task DeleteReferenceAssembly(int id)
        {
            ReferenceAssembly matchingAssembly = await this.GetReferenceAssembly(id);
            this.ReferenceAssemblies.Remove(matchingAssembly);
            await this.SaveChangesAsync();
        }
        #endregion

        #region GruntTaskComponents EmbeddedResource Actions
        public async Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources()
        {
            return await this.EmbeddedResources.ToListAsync();
        }

        public async Task<EmbeddedResource> GetEmbeddedResource(int id)
        {
            EmbeddedResource resource = await this.EmbeddedResources.FindAsync(id);
            if (resource == null)
            {
                throw new ControllerNotFoundException($"NotFound - EmbeddedResource with id: {id}");
            }
            return resource;
        }

        public async Task<EmbeddedResource> GetEmbeddedResourceByName(string name)
        {
            EmbeddedResource resource = await this.EmbeddedResources
                .Where(ER => ER.Name == name)
                .FirstOrDefaultAsync();
            if (resource == null)
            {
                throw new ControllerNotFoundException($"NotFound - EmbeddedResource with Name: {name}");
            }
            return resource;
        }

        public async Task<EmbeddedResource> CreateEmbeddedResource(EmbeddedResource resource)
        {
            await this.EmbeddedResources.AddAsync(resource);
            await this.SaveChangesAsync();
            return await this.GetEmbeddedResource(resource.Id);
        }

        public async Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource)
        {
            EmbeddedResource matchingResource = await this.GetEmbeddedResource(resource.Id);
            matchingResource.Name = resource.Name;
            matchingResource.Location = resource.Location;
            this.EmbeddedResources.Update(matchingResource);
            await this.SaveChangesAsync();
            return await this.GetEmbeddedResource(matchingResource.Id);
        }

        public async Task DeleteEmbeddedResource(int id)
        {
            EmbeddedResource matchingResource = await this.GetEmbeddedResource(id);
            this.EmbeddedResources.Remove(matchingResource);
            await this.SaveChangesAsync();
        }
        #endregion

        #region GruntTaskComponents ReferenceSourceLibrary Actions
        public async Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries()
        {
            return await this.ReferenceSourceLibraries
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .ToListAsync();
        }

        public async Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id)
        {
            ReferenceSourceLibrary library = await this.ReferenceSourceLibraries
                .Where(RSL => RSL.Id == id)
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (library == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceSourceLibrary with id: {id}");
            }
            return library;
        }

        public async Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name)
        {
            ReferenceSourceLibrary library = await this.ReferenceSourceLibraries
                .Where(RSL => RSL.Name == name)
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (library == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceSourceLibrary with Name: {name}");
            }
            return library;
        }

        public async Task<ReferenceSourceLibrary> CreateReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            await this.ReferenceSourceLibraries.AddAsync(library);
            await this.SaveChangesAsync();
            return await this.GetReferenceSourceLibrary(library.Id);
        }

        public async Task<ReferenceSourceLibrary> EditReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            ReferenceSourceLibrary matchingLibrary = await this.GetReferenceSourceLibrary(library.Id);
            matchingLibrary.Name = library.Name;
            matchingLibrary.Description = library.Description;
            matchingLibrary.Location = library.Location;

            var removeAssemblies = matchingLibrary.ReferenceAssemblies.Select(MRA => MRA.Id).Except(library.ReferenceAssemblies.Select(RA => RA.Id));
            var addAssemblies = library.ReferenceAssemblies.Select(MRA => MRA.Id).Except(matchingLibrary.ReferenceAssemblies.Select(MRA => MRA.Id));
            removeAssemblies.ToList().ForEach(async RA => matchingLibrary.Remove(await this.GetReferenceAssembly(RA)));
            addAssemblies.ToList().ForEach(async AA => matchingLibrary.Add(await this.GetReferenceAssembly(AA)));

            var removeResources = matchingLibrary.EmbeddedResources.Select(MER => MER.Id).Except(library.EmbeddedResources.Select(ER => ER.Id));
            var addResources = library.EmbeddedResources.Select(MER => MER.Id).Except(matchingLibrary.EmbeddedResources.Select(MER => MER.Id));
            removeResources.ToList().ForEach(async RR => matchingLibrary.Remove(await this.GetEmbeddedResource(RR)));
            addResources.ToList().ForEach(async AR => matchingLibrary.Add(await this.GetEmbeddedResource(AR)));

            this.ReferenceSourceLibraries.Update(matchingLibrary);
            await this.SaveChangesAsync();
            return await this.GetReferenceSourceLibrary(matchingLibrary.Id);
        }

        public async Task DeleteReferenceSourceLibrary(int id)
        {
            ReferenceSourceLibrary referenceSourceLibrary = await this.GetReferenceSourceLibrary(id);
            this.ReferenceSourceLibraries.Remove(referenceSourceLibrary);
            await this.SaveChangesAsync();
        }
        #endregion

        #region GruntTaskOption Actions
        public async Task<GruntTaskOption> EditGruntTaskOption(GruntTaskOption option)
        {
            this.Entry(option).State = EntityState.Modified;
            await this.SaveChangesAsync();
            return option;
        }

        public async Task<GruntTaskOption> CreateGruntTaskOption(GruntTaskOption option)
        {
            await this.AddAsync(option);
            await this.SaveChangesAsync();
            return option;
        }
        #endregion

        #region GruntTask Actions
        public async Task<IEnumerable<GruntTask>> GetGruntTasks()
        {
            return await this.GruntTasks
                .Include(T => T.Options)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .ToListAsync();
        }

        public async Task<GruntTask> GetGruntTask(int id)
        {
            GruntTask task = await this.GruntTasks
                .Where(T => T.Id == id)
                .Include(T => T.Options)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (task == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTask with id: {id}");
            }
            return task;
        }

        public async Task<GruntTask> GetGruntTaskByName(string name)
        {
            GruntTask task = await this.GruntTasks
                .Where(T => T.Name.Equals(name, StringComparison.OrdinalIgnoreCase) || T.AlternateNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                .Include(T => T.Options)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (task == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTask with Name: {name}");
            }
            return task;
        }

        public async Task<GruntTask> CreateGruntTask(GruntTask task)
        {
            await this.GruntTasks.AddAsync(task);
            await this.SaveChangesAsync();
            return await this.GetGruntTask(task.Id);
        }

        public async Task<GruntTask> EditGruntTask(GruntTask task)
        {
            GruntTask updatingTask = await this.GetGruntTask(task.Id);
            updatingTask.Name = task.Name;
            updatingTask.Description = task.Description;
            updatingTask.Help = task.Help;
            if (updatingTask.Code != task.Code)
            {
                updatingTask.Code = task.Code;
                updatingTask.Compiled = false;
            }
            else
            {
                updatingTask.Compiled = task.Compiled;
            }
            updatingTask.UnsafeCompile = task.UnsafeCompile;
            updatingTask.TokenTask = task.TokenTask;
            updatingTask.TaskingType = task.TaskingType;
            task.Options.Where(O => O.Id == 0).ToList().ForEach(async O => await this.CreateGruntTaskOption(O));
            var removeOptions = updatingTask.Options.Select(UT => UT.Id).Except(task.Options.Select(O => O.Id));
            removeOptions.ToList().ForEach(RO => updatingTask.Options.Remove(updatingTask.Options.FirstOrDefault(UO => UO.Id == RO)));
            foreach (var option in updatingTask.Options)
            {
                var newOption = task.Options.FirstOrDefault(T => T.Id == option.Id);
                if (newOption != null)
                {
                    option.Name = newOption.Name;
                    option.Description = newOption.Description;
                    option.Value = newOption.Value;
                    option.SuggestedValues = newOption.SuggestedValues;
                    option.Optional = newOption.Optional;
                    option.DisplayInCommand = newOption.DisplayInCommand;
                }
            }

            var removeAssemblies = updatingTask.ReferenceAssemblies.Select(MRA => MRA.Id).Except(task.ReferenceAssemblies.Select(RA => RA.Id));
            var addAssemblies = task.ReferenceAssemblies.Select(MRA => MRA.Id).Except(updatingTask.ReferenceAssemblies.Select(MRA => MRA.Id));
            removeAssemblies.ToList().ForEach(async RA => updatingTask.Remove(await this.GetReferenceAssembly(RA)));
            addAssemblies.ToList().ForEach(async AA => updatingTask.Add(await this.GetReferenceAssembly(AA)));

            var removeResources = updatingTask.EmbeddedResources.Select(MER => MER.Id).Except(task.EmbeddedResources.Select(ER => ER.Id));
            var addResources = task.EmbeddedResources.Select(MER => MER.Id).Except(updatingTask.EmbeddedResources.Select(MER => MER.Id));
            removeResources.ToList().ForEach(async RR => updatingTask.Remove(await this.GetEmbeddedResource(RR)));
            addResources.ToList().ForEach(async AR => updatingTask.Add(await this.GetEmbeddedResource(AR)));

            var removeLibraries = updatingTask.ReferenceSourceLibraries.Select(MRSL => MRSL.Id).Except(task.ReferenceSourceLibraries.Select(RSL => RSL.Id));
            var addLibraries = task.ReferenceSourceLibraries.Select(RSL => RSL.Id).Except(updatingTask.ReferenceSourceLibraries.Select(MRSL => MRSL.Id));
            removeLibraries.ToList().ForEach(async RL => updatingTask.Remove(await this.GetReferenceSourceLibrary(RL)));
            addLibraries.ToList().ForEach(async AL => updatingTask.Add(await this.GetReferenceSourceLibrary(AL)));

            this.GruntTasks.Update(updatingTask);
            await this.SaveChangesAsync();
            return updatingTask;
        }

        public async Task DeleteGruntTask(int taskId)
        {
            GruntTask removingTask = await this.GetGruntTask(taskId);
            if (removingTask == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTask with id: {taskId}");
            }
            this.GruntTasks.Remove(removingTask);
            await this.SaveChangesAsync();
        }
        #endregion

        #region GruntCommand Actions
        public async Task<IEnumerable<GruntCommand>> GetGruntCommands()
        {
            return await this.GruntCommands
                .Include(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntCommand>> GetGruntCommandsForGrunt(int gruntId)
        {
            return await this.GruntCommands
                .Where(GC => GC.GruntId == gruntId)
                .Include(GC => GC.User)
                .ToListAsync();
        }

        public async Task<GruntCommand> GetGruntCommand(int id)
        {
            GruntCommand command = await this.GruntCommands
                .Where(GC => GC.Id == id)
                .Include(GC => GC.User)
                .FirstOrDefaultAsync();
            if (command == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntCommand with Id: {id}");
            }
            return command;
        }

        public async Task<GruntCommand> CreateGruntCommand(GruntCommand command, IHubContext<GruntHub> _grunthub, IHubContext<EventHub> _eventhub)
        {
            this.GruntCommands.Add(command);
            await this.SaveChangesAsync();
            GruntCommand createdCommand = await this.GruntCommands
                .Where(GC => GC.Id == command.Id)
                .Include(GC => GC.User)
                .Include(GC => GC.CommandOutput)
                .Include(GC => GC.GruntTasking)
                    .ThenInclude(GC => GC.GruntTask)
                .FirstOrDefaultAsync();
            Event ev = new Event
            {
                Time = createdCommand.CommandTime,
                MessageHeader = "[" + createdCommand.CommandTime + " UTC] Command assigned",
                MessageBody = "(" + createdCommand.User.UserName + ") > " + createdCommand.Command,
                Level = EventLevel.Highlight,
                Context = createdCommand.Grunt.Name
            };
            await this.Events.AddAsync(ev);
            await this.SaveChangesAsync();
            await GruntHubProxy.SendCommandEvent(_grunthub, ev, createdCommand);
            await EventHubProxy.SendEvent(_eventhub, ev);
            return createdCommand;
        }

        public async Task<GruntCommand> EditGruntCommand(GruntCommand command, IHubContext<GruntHub> _grunthub, IHubContext<EventHub> _eventhub)
        {
            GruntCommand updatingCommand = await this.GruntCommands
                .Where(GC => GC.Id == command.Id)
                .Include(GC => GC.User)
                .Include(GC => GC.CommandOutput)
                .Include(GC => GC.GruntTasking)
                    .ThenInclude(GC => GC.GruntTask)
                .FirstOrDefaultAsync();
            updatingCommand.Command = command.Command;
            updatingCommand.CommandTime = command.CommandTime;

            if (updatingCommand.CommandOutput.Output != command.CommandOutput.Output)
            {
                updatingCommand.CommandOutputId = command.CommandOutputId;
                updatingCommand.CommandOutput = command.CommandOutput;
                Grunt g = await this.GetGrunt(updatingCommand.GruntId);
                if(updatingCommand.GruntTasking.GruntTask.Name == "PowerShell" && !string.IsNullOrWhiteSpace(g.PowerShellImport))
                {
                    updatingCommand.Command = updatingCommand.Command.Replace(Common.CovenantEncoding.GetString(Convert.FromBase64String(g.PowerShellImport)) + "\r\n", "");
                }
                Event ev = new Event
                {
                    Time = updatingCommand.CommandTime,
                    MessageHeader = "[" + updatingCommand.CommandTime + " UTC] Command completed",
                    MessageBody = "(" + updatingCommand.User.UserName + ") > " + updatingCommand.Command + Environment.NewLine + updatingCommand.CommandOutput,
                    Level = EventLevel.Highlight,
                    Context = g.Name
                };
                await this.Events.AddAsync(ev);
                this.GruntCommands.Update(updatingCommand);
                await this.SaveChangesAsync();
                await GruntHubProxy.SendCommandEvent(_grunthub, ev, updatingCommand);
                await EventHubProxy.SendEvent(_eventhub, ev);
            }
            else
            {
                this.GruntCommands.Update(updatingCommand);
                await this.SaveChangesAsync();
            }
            return updatingCommand;
        }

        public async Task DeleteGruntCommand(int id)
        {
            GruntCommand command = await this.GetGruntCommand(id);
            this.GruntCommands.Remove(command);
            await this.SaveChangesAsync();
        }
        #endregion

        #region CommandOutput Actions
        public async Task<IEnumerable<CommandOutput>> GetCommandOutputs()
        {
            return await this.CommandOutputs
                .ToListAsync();
        }

        public async Task<CommandOutput> GetCommandOutput(int commandOutputId)
        {
            CommandOutput output = await this.CommandOutputs
                .Where(CO => CO.Id == commandOutputId)
                .FirstOrDefaultAsync();
            if (output == null)
            {
                throw new ControllerNotFoundException($"NotFound - CommandOutput with Id: {commandOutputId}");
            }
            return output;
        }

        public async Task<CommandOutput> CreateCommandOutput(CommandOutput output)
        {
            await this.CommandOutputs.AddAsync(output);
            await this.SaveChangesAsync();
            return output;
        }

        public async Task<CommandOutput> EditCommandOutput(CommandOutput output, IHubContext<GruntHub> _grunthub, IHubContext<EventHub> _eventhub)
        {
            CommandOutput updatingOutput = await this.GetCommandOutput(output.Id);

            if (updatingOutput.Output != output.Output)
            {
                updatingOutput.Output = output.Output;
                GruntCommand command = await this.GruntCommands
                    .Where(GC => GC.Id == updatingOutput.GruntCommandId)
                    .Include(GC => GC.User)
                    .Include(GC => GC.CommandOutput)
                    .Include(GC => GC.GruntTasking)
                        .ThenInclude(GC => GC.GruntTask)
                    .FirstOrDefaultAsync();
                command.CommandOutput = updatingOutput;
                Grunt g = await this.GetGrunt(command.GruntId);
                Event ev = new Event
                {
                    Time = command.CommandTime,
                    MessageHeader = "[" + command.CommandTime + " UTC] Command completed",
                    MessageBody = "(" + command.User.UserName + ") > " + command.Command + Environment.NewLine + command.CommandOutput,
                    Level = EventLevel.Highlight,
                    Context = g.Name
                };
                await this.Events.AddAsync(ev);
                this.CommandOutputs.Update(updatingOutput);
                await this.SaveChangesAsync();
                await GruntHubProxy.SendCommandEvent(_grunthub, ev, command);
                await EventHubProxy.SendEvent(_eventhub, ev);
            }
            return updatingOutput;
        }

        public async Task DeleteCommandOutput(int id)
        {
            CommandOutput output = await this.GetCommandOutput(id);
            this.CommandOutputs.Remove(output);
            await this.SaveChangesAsync();
        }
        #endregion

        #region GruntTasking Actions
        public async Task<IEnumerable<GruntTasking>> GetGruntTaskings()
        {
            return await this.GruntTaskings
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntTasking>> GetGruntTaskingsForGrunt(int gruntId)
        {
            return await this.GruntTaskings
                .Where(GT => GT.GruntId == gruntId)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntTasking>> GetUninitializedGruntTaskingsForGrunt(int gruntId)
        {
            return await this.GruntTaskings
                .Where(GT => GT.GruntId == gruntId && GT.Status == GruntTaskingStatus.Uninitialized)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntTasking>> GetGruntTaskingsSearch(int gruntId)
        {
            List<GruntTasking> search = new List<GruntTasking>();
            foreach (GruntTasking task in await this.GetGruntTaskings())
            {
                if (await this.IsChildGrunt(gruntId, task.GruntId))
                {
                    search.Add(task);
                }
            }
            return search;
        }

        public async Task<GruntTasking> GetGruntTasking(int taskingId)
        {
            GruntTasking tasking = await this.GruntTaskings
                .Where(GT => GT.Id == taskingId)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .FirstOrDefaultAsync();
            if (tasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTasking with id: {taskingId}");
            }
            return tasking;
        }

        public async Task<GruntTasking> GetGruntTaskingByName(string taskingName)
        {
            GruntTasking tasking = await this.GruntTaskings
                .Where(GT => GT.Name == taskingName)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .FirstOrDefaultAsync();
            if (tasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTasking with Name: {taskingName}");
            }
            return tasking;
        }

        public async Task<GruntTasking> CreateGruntTasking(GruntTasking tasking, IHubContext<GruntHub> _grunthub)
        {
            tasking.Grunt = await this.GetGrunt(tasking.GruntId);
            tasking.Grunt.Listener = await this.GetListener(tasking.Grunt.ListenerId);
            tasking.GruntTask = await this.GetGruntTask(tasking.GruntTaskId);
            tasking.GruntCommand = await this.GetGruntCommand(tasking.GruntCommandId);
            List<string> parameters = tasking.GruntTask.Options.OrderBy(O => O.Id).Select(O => string.IsNullOrEmpty(O.Value) ? O.DefaultValue : O.Value).ToList();
            if (tasking.GruntTask.Name.Equals("powershell", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(tasking.Grunt.PowerShellImport))
            {
                parameters[0] = Common.CovenantEncoding.GetString(Convert.FromBase64String(tasking.Grunt.PowerShellImport)) + "\r\n" + parameters[0];
            }
            else if (tasking.GruntTask.Name.Equals("powershellimport", StringComparison.OrdinalIgnoreCase))
            {
                if (parameters.Count >= 1)
                {
                    string import = parameters[0];
                    byte[] importBytes = Convert.FromBase64String(import);
                    if (importBytes.Length >= 3 && importBytes[0] == 0xEF && importBytes[1] == 0xBB && importBytes[2] == 0xBF)
                    {
                        import = Convert.ToBase64String(importBytes.Skip(3).ToArray());
                    }
                    tasking.Grunt.PowerShellImport = import;
                }
                else
                {
                    tasking.Grunt.PowerShellImport = "";
                }
                this.Grunts.Update(tasking.Grunt);
                tasking.GruntCommand.CommandOutput.Output = "PowerShell Imported";

                Event ev = new Event
                {
                    Time = tasking.GruntCommand.CommandTime,
                    MessageHeader = "[" + tasking.GruntCommand.CommandTime + " UTC] Command completed",
                    MessageBody = "(" + tasking.GruntCommand.User.UserName + ") > " + tasking.GruntCommand.Command + Environment.NewLine + tasking.GruntCommand.CommandOutput,
                    Level = EventLevel.Highlight,
                    Context = tasking.Grunt.Name
                };
                await this.Events.AddAsync(ev);
                this.GruntCommands.Update(tasking.GruntCommand);
                await this.SaveChangesAsync();
                await GruntHubProxy.SendCommandEvent(_grunthub, ev, tasking.GruntCommand);
                tasking.Status = GruntTaskingStatus.Completed;
            }
            else if (tasking.GruntTask.Name.Equals("wmigrunt", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await this.Launchers.FirstOrDefaultAsync(L => L.Name.Equals(parameters[1], StringComparison.OrdinalIgnoreCase));
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[1]}");
                }
                
                // Add .exe extension if needed
                List<string> split = l.LauncherString.Split(" ").ToList();
                parameters[1] = split.FirstOrDefault();
                if (!parameters[1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[1] += ".exe"; }

                // Add Directory
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[1].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[1].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }
                if (!parameters[1].StartsWith("C:\\", StringComparison.OrdinalIgnoreCase)) { parameters[1] = Directory + parameters[1]; }
                if (split.Count > 1) { parameters[1] += " " + String.Join(" ", split.Skip(1).ToArray()); }
            }
            else if (tasking.GruntTask.Name.Equals("dcomgrunt", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await this.Launchers.FirstOrDefaultAsync(L => L.Name.Equals(parameters[1], StringComparison.OrdinalIgnoreCase));
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[1]}");
                }
                // Add .exe extension if needed
                List<string> split = l.LauncherString.Split(" ").ToList();
                parameters[1] = split.FirstOrDefault();
                if (!parameters[1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[1] += ".exe"; }

                // Add command parameters
                split.RemoveAt(0);
                parameters.Insert(2, String.Join(" ", split.ToArray()));

                // Add Directory
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[1].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[1].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }
                if (!parameters[1].StartsWith("C:\\", StringComparison.OrdinalIgnoreCase)) { parameters[1] = Directory + parameters[1]; }

                parameters.Insert(3, Directory);
            }
            else if (tasking.GruntTask.Name.Equals("powershellremotinggrunt", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await this.Launchers.FirstOrDefaultAsync(L => L.Name.Equals(parameters[1], StringComparison.OrdinalIgnoreCase));
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[1]}");
                }
                // Add .exe extension if needed
                List<string> split = l.LauncherString.Split(" ").ToList();
                parameters[1] = split.FirstOrDefault();
                if (!parameters[1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[1] += ".exe"; }
                // Add Directory
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[1].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[1].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }
                if (!parameters[1].StartsWith("C:\\", StringComparison.OrdinalIgnoreCase)) { parameters[1] = Directory + parameters[1]; }
                parameters[1] = parameters[1] + " " + string.Join(" ", split.Skip(1).ToList());
            }
            else if (tasking.GruntTask.Name.Equals("bypassuacgrunt", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await this.Launchers.FirstOrDefaultAsync(L => L.Name.Equals(parameters[0], StringComparison.OrdinalIgnoreCase));
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[0]}");
                }
                // Add .exe extension if needed
                string[] split = l.LauncherString.Split(" ");
                parameters[0] = split.FirstOrDefault();
                if (!parameters[0].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[0] += ".exe"; }
                        
                // Add parameters need for BypassUAC Task
                string ArgParams = String.Join(" ", split.ToList().GetRange(1, split.Count() - 1));
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[0].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[0].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }

                parameters.Add(ArgParams);
                parameters.Add(Directory);
                parameters.Add("0");
            }
            else if (tasking.GruntTask.Name.Equals("SharpShell", StringComparison.CurrentCultureIgnoreCase))
            {
                string WrapperFunctionFormat =
    @"using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security;
using System.Security.Principal;
using System.Collections.Generic;
using SharpSploit.Credentials;
using SharpSploit.Enumeration;
using SharpSploit.Execution;
using SharpSploit.Generic;
using SharpSploit.Misc;
public static class Task
{{
    public static string Execute()
    {{
        {0}
    }}
}}";
                string csharpcode = string.Join(" ", parameters);
                tasking.GruntTask.Code = string.Format(WrapperFunctionFormat, csharpcode);
                tasking.GruntTask.Compiled = false;
                this.GruntTasks.Update(tasking.GruntTask);
                await this.SaveChangesAsync();
                parameters = new List<string> { };
            }
            else if (tasking.GruntTask.Name.Equals("Disconnect", StringComparison.CurrentCultureIgnoreCase))
            {
                Grunt g = await this.GetGruntByName(parameters[0]);
                parameters[0] = g.GUID;
            }
            tasking.Parameters = parameters;
            try
            {
                tasking.GruntTask.Compile();
            }
            catch (CompilerException e)
            {
                tasking.GruntCommand.CommandOutput.Output = "CompilerException: " + e.Message;
                tasking.Status = GruntTaskingStatus.Aborted;
                Event ev = new Event
                {
                    Time = tasking.GruntCommand.CommandTime,
                    MessageHeader = "[" + tasking.GruntCommand.CommandTime + " UTC] Command aborted",
                    MessageBody = "(" + tasking.GruntCommand.User.UserName + ") > " + tasking.GruntCommand.Command + Environment.NewLine + tasking.GruntCommand.CommandOutput,
                    Level = EventLevel.Highlight,
                    Context = tasking.Grunt.Name
                };
                await this.Events.AddAsync(ev);
                this.GruntCommands.Update(tasking.GruntCommand);
                await this.SaveChangesAsync();
                await GruntHubProxy.SendCommandEvent(_grunthub, ev, tasking.GruntCommand);
            }
            await this.GruntTaskings.AddAsync(tasking);
            await this.SaveChangesAsync();
            Grunt parent = await this.GetParentGrunt(tasking.Grunt);
            parent.Listener = await this.GetListener(parent.ListenerId);
            await GruntHubProxy.NotifyListener(_grunthub, parent);
            return tasking;
        }

        public async Task<GruntTasking> CreateGruntTasking(UserManager<CovenantUser> userManager, ClaimsPrincipal principal, GruntTasking tasking, IHubContext<GruntHub> _grunthub)
        {
            CovenantUser user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser");
            }
            return await this.CreateGruntTasking(tasking, _grunthub);
        }

        public async Task<GruntTasking> EditGruntTasking(GruntTasking tasking, IHubContext<GruntHub> _grunthub, IHubContext<EventHub> _eventhub)
        {
            Grunt grunt = await this.GetGrunt(tasking.GruntId);
            GruntTasking updatingGruntTasking = await this.GruntTaskings
                .Where(GT => GT.Id == tasking.Id)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.CommandOutput)
                .FirstOrDefaultAsync();
            if (updatingGruntTasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTasking with id: {tasking.Id}");
            }
            tasking.GruntTask = await this.GetGruntTask(tasking.GruntTaskId);
            tasking.GruntCommand =  await this.GruntCommands
                .Include(GC => GC.User)
                .Include(GC => GC.CommandOutput)
                .FirstOrDefaultAsync(GC => GC.Id == tasking.GruntCommandId);
            List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(tasking.GruntCommand.CommandOutput.Output);
            foreach (CapturedCredential cred in capturedCredentials)
            {
                if (!await this.ContainsCredentials(cred))
                {
                    await this.Credentials.AddAsync(cred);
                    await this.SaveChangesAsync();
                }
            }

            GruntTaskingStatus newStatus = tasking.Status;
            GruntTaskingStatus originalStatus = updatingGruntTasking.Status;
            if ((originalStatus == GruntTaskingStatus.Tasked || originalStatus == GruntTaskingStatus.Progressed) &&
                newStatus == GruntTaskingStatus.Completed)
            {
                if (tasking.Type == GruntTaskingType.Exit)
                {
                    grunt.Status = GruntStatus.Exited;
                }
                else if (tasking.Type == GruntTaskingType.SetOption && tasking.Parameters.Count >= 2)
                {
                    bool parsed = int.TryParse(tasking.Parameters[1], out int n);
                    if (parsed)
                    {
                        if (tasking.Parameters[0].Equals("Delay", StringComparison.CurrentCultureIgnoreCase))
                        {
                            grunt.Delay = n;
                        }
                        else if (tasking.Parameters[0].Equals("JitterPercent", StringComparison.CurrentCultureIgnoreCase))
                        {
                            grunt.JitterPercent = n;
                        }
                        else if (tasking.Parameters[0].Equals("ConnectAttempts", StringComparison.CurrentCultureIgnoreCase))
                        {
                            grunt.ConnectAttempts = n;
                        }
                        this.Grunts.Update(grunt);
                    }
                }
                else if (tasking.Type == GruntTaskingType.Connect)
                {
                    if (originalStatus == GruntTaskingStatus.Tasked)
                    {
                        // Check if this Grunt was already connected
                        string hostname = tasking.Parameters[0];
                        string pipename = tasking.Parameters[1];
                        Grunt previouslyConnectedGrunt = await this.Grunts.FirstOrDefaultAsync(G =>
                            G.ImplantTemplate.CommType == CommunicationType.SMB &&
                            (G.IPAddress == hostname || G.Hostname == hostname) &&
                            G.SMBPipeName == pipename &&
                            (G.Status == GruntStatus.Disconnected || G.Status == GruntStatus.Lost || G.Status == GruntStatus.Active)
                        );
                        if (previouslyConnectedGrunt != null)
                        {
                            if (previouslyConnectedGrunt.Status != GruntStatus.Disconnected)
                            {
                                // If already connected, disconnect to avoid cycles
                                Grunt previouslyConnectedGruntPrevParent = await this.Grunts.FirstOrDefaultAsync(G => G.Children.Contains(previouslyConnectedGrunt.GUID));
                                if (previouslyConnectedGruntPrevParent != null)
                                {
                                    previouslyConnectedGruntPrevParent.RemoveChild(previouslyConnectedGrunt);
                                    this.Grunts.Update(previouslyConnectedGruntPrevParent);
                                }
                            }

                            // Connect to tasked Grunt, no need to "Progress", as Grunt is already staged
                            grunt.AddChild(previouslyConnectedGrunt);
                            previouslyConnectedGrunt.Status = GruntStatus.Active;
                            this.Grunts.Update(previouslyConnectedGrunt);
                        }
                        else
                        {
                            // If not already connected, the Grunt is going to stage, set status to Progressed
                            newStatus = GruntTaskingStatus.Progressed;
                        }
                    }
                    else if (originalStatus == GruntTaskingStatus.Progressed)
                    {
                        // Connecting Grunt has staged, add as Child
                        string hostname = tasking.Parameters[0];
                        string pipename = tasking.Parameters[1];
                        Grunt stagingGrunt = await this.Grunts.FirstOrDefaultAsync(G =>
                            G.ImplantTemplate.CommType == CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename &&
                            G.Status == GruntStatus.Stage0
                        );
                        if (stagingGrunt == null)
                        {
                            throw new ControllerNotFoundException($"NotFound - Grunt staging from {hostname}:{pipename}");
                        }
                        grunt.AddChild(stagingGrunt);
                    }
                }
                else if (tasking.Type == GruntTaskingType.Disconnect)
                {
                    Grunt disconnectFromGrunt = await this.GetGruntByGUID(tasking.Parameters[0]);
                    disconnectFromGrunt.Status = GruntStatus.Disconnected;
                    this.Grunts.Update(disconnectFromGrunt);
                    grunt.RemoveChild(disconnectFromGrunt);
                }
            }
            Event ev = null;
            if ((newStatus == GruntTaskingStatus.Completed || newStatus == GruntTaskingStatus.Progressed) && originalStatus != newStatus)
            {
                if (newStatus == GruntTaskingStatus.Completed)
                {
                    updatingGruntTasking.CompletionTime = DateTime.UtcNow;
                }
                string verb = newStatus == GruntTaskingStatus.Completed ? "completed" : "progressed";
                GruntTask DownloadTask = await this.GetGruntTaskByName("Download");
                GruntTask ScreenshotTask = await this.GetGruntTaskByName("ScreenShot");

                if (tasking.GruntTaskId == DownloadTask.Id)
                {
                    ev = new Event
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "[" + updatingGruntTasking.CompletionTime + " UTC] " + tasking.GruntTask.Name + " " + verb,
                        Level = EventLevel.Highlight,
                        Context = grunt.Name
                    };
                    await this.Events.AddAsync(ev);
                    string FileName = tasking.Parameters[0];
                    DownloadEvent downloadEvent = new DownloadEvent
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "Downloaded: " + FileName,
                        Level = EventLevel.Highlight,
                        Context = grunt.Name,
                        FileName = FileName,
                        FileContents = tasking.GruntCommand.CommandOutput.Output,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    downloadEvent.WriteToDisk();
                    await this.Events.AddAsync(downloadEvent);
                }
                else if (tasking.GruntTaskId == ScreenshotTask.Id)
                {
                    ev = new Event
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "[" + updatingGruntTasking.CompletionTime + " UTC] " + tasking.GruntTask.Name + " " + verb,
                        Level = EventLevel.Highlight,
                        Context = grunt.Name
                    };
                    await this.Events.AddAsync(ev);
                    string FileName = tasking.Name + ".png";
                    ScreenshotEvent screenshotEvent = new ScreenshotEvent
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "Downloaded: " + FileName,
                        Level = EventLevel.Highlight,
                        Context = grunt.Name,
                        FileName = FileName,
                        FileContents = tasking.GruntCommand.CommandOutput.Output,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    screenshotEvent.WriteToDisk();
                    await this.Events.AddAsync(screenshotEvent);
                }
                else
                {
                    ev = new Event
                    {
                        Time = tasking.CompletionTime,
                        MessageHeader = "[" + tasking.CompletionTime + " UTC] " + tasking.GruntTask.Name + " " + verb,
                        MessageBody = "(" + tasking.GruntCommand.User.UserName + ") > " + tasking.GruntCommand.Command + Environment.NewLine + tasking.GruntCommand.CommandOutput.Output,
                        Level = EventLevel.Highlight,
                        Context = grunt.Name
                    };
                    await this.Events.AddAsync(ev);
                }
            }
            updatingGruntTasking.TaskingTime = tasking.TaskingTime;
            updatingGruntTasking.Status = newStatus;
            updatingGruntTasking.GruntCommand.CommandOutput.Output = tasking.GruntCommand.CommandOutput.Output;
            this.GruntTaskings.Update(updatingGruntTasking);
            this.Grunts.Update(grunt);
            await this.SaveChangesAsync();
            if (ev != null)
            {
                tasking.GruntCommand = await this.GruntCommands
                    .Where(GC => GC.Id == tasking.GruntCommandId)
                    .Include(GC => GC.User)
                    .Include(GC => GC.CommandOutput)
                    .Include(GC => GC.GruntTasking)
                        .ThenInclude(GC => GC.GruntTask)
                    .FirstOrDefaultAsync();
                await GruntHubProxy.SendCommandEvent(_grunthub, ev, tasking.GruntCommand);
                await EventHubProxy.SendEvent(_eventhub, ev);
            }
            return updatingGruntTasking;
        }

        public async Task DeleteGruntTasking(int taskingId)
        {
            GruntTasking removingGruntTasking = await this.GruntTaskings.FindAsync(taskingId);
            if (removingGruntTasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTasking with id: {taskingId}");
            }
            this.GruntTaskings.Remove(removingGruntTasking);
            await this.SaveChangesAsync();
        }

        private async Task<Grunt> GetParentGrunt(Grunt child)
        {
            var parent = child.ImplantTemplate.CommType != CommunicationType.SMB ? child : await this.Grunts.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(G => G.Children.Contains(child.GUID));
            if (parent != null && parent.ImplantTemplate.CommType == CommunicationType.SMB)
            {
                return await GetParentGrunt(parent);
            }
            return parent;
        }

        private async Task<bool> IsChildGrunt(int ParentId, int ChildId)
        {
            if (ParentId == ChildId)
            {
                return true;
            }
            Grunt parentGrunt = await this.Grunts.FindAsync(ParentId);
            Grunt childGrunt = await this.Grunts.FindAsync(ChildId);
            if (parentGrunt == null || childGrunt == null)
            {
                return false;
            }
            if (parentGrunt.Children.Contains(childGrunt.GUID))
            {
                return true;
            }
            foreach (string child in parentGrunt.Children)
            {
                Grunt directChild = await this.Grunts.FirstOrDefaultAsync(G => G.GUID == child);
                if (directChild != null && await IsChildGrunt(directChild.Id, ChildId))
                {
                    return true;
                }
            }
            return false;
        }

        private async Task<bool> ContainsCredentials(CapturedCredential cred)
        {
            switch (cred.Type)
            {
                case CredentialType.Password:
                    CapturedPasswordCredential passcred = (CapturedPasswordCredential)cred;
                    return (await this.Credentials.Where(C => C.Type == CredentialType.Password)
                                   .Select(C => (CapturedPasswordCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == passcred.Type &&
                                       PC.Domain == passcred.Domain &&
                                       PC.Username == passcred.Username &&
                                       PC.Password == passcred.Password
                           )) != null;
                case CredentialType.Hash:
                    CapturedHashCredential hashcred = (CapturedHashCredential)cred;
                    return (await this.Credentials.Where(C => C.Type == CredentialType.Hash)
                                   .Select(C => (CapturedHashCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == hashcred.Type &&
                                       PC.Domain == hashcred.Domain &&
                                       PC.Username == hashcred.Username &&
                                       PC.Hash == hashcred.Hash &&
                                       PC.HashCredentialType == hashcred.HashCredentialType
                           )) != null;
                case CredentialType.Ticket:
                    CapturedTicketCredential ticketcred = (CapturedTicketCredential)cred;
                    return (await this.Credentials.Where(C => C.Type == CredentialType.Ticket)
                                   .Select(C => (CapturedTicketCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == ticketcred.Type &&
                                       PC.Domain == ticketcred.Domain &&
                                       PC.Username == ticketcred.Username &&
                                       PC.Ticket == ticketcred.Ticket &&
                                       PC.TicketCredentialType == ticketcred.TicketCredentialType
                           )) != null;
                default:
                    return (await this.Credentials.FirstOrDefaultAsync(P =>
                                       P.Type == cred.Type &&
                                       P.Domain == cred.Domain &&
                                       P.Username == cred.Username
                           )) != null;
            }
        }
        #endregion

        #region Credentials Actions
        public async Task<IEnumerable<CapturedCredential>> GetCredentials()
        {
            return await this.Credentials.ToListAsync();
        }

        public async Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials()
        {
            return await this.Credentials.Where(P => P.Type == CredentialType.Password).Select(P => (CapturedPasswordCredential)P).ToListAsync();
        }

        public async Task<IEnumerable<CapturedHashCredential>> GetHashCredentials()
        {
            return await this.Credentials.Where(P => P.Type == CredentialType.Hash).Select(H => (CapturedHashCredential)H).ToListAsync();
        }

        public async Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials()
        {
            return await this.Credentials.Where(P => P.Type == CredentialType.Ticket).Select(T => (CapturedTicketCredential)T).ToListAsync();
        }

        public async Task<CapturedCredential> GetCredential(int credentialId)
        {
            CapturedCredential credential = await this.Credentials.FindAsync(credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedPasswordCredential> GetPasswordCredential(int credentialId)
        {
            CapturedPasswordCredential credential = (await this.GetPasswordCredentials()).FirstOrDefault(c => c.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedPasswordCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedHashCredential> GetHashCredential(int credentialId)
        {
            CapturedHashCredential credential = (await this.GetHashCredentials()).FirstOrDefault(c => c.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedHashCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedTicketCredential> GetTicketCredential(int credentialId)
        {
            CapturedTicketCredential credential = (await this.GetTicketCredentials()).FirstOrDefault(c => c.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedTicketCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedPasswordCredential> CreatePasswordCredential(CapturedPasswordCredential credential)
        {
            await this.Credentials.AddAsync(credential);
            await this.SaveChangesAsync();
            return await GetPasswordCredential(credential.Id);
        }

        public async Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential)
        {
            await this.Credentials.AddAsync(credential);
            await this.SaveChangesAsync();
            return await GetHashCredential(credential.Id);
        }

        public async Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential)
        {
            await this.Credentials.AddAsync(credential);
            await this.SaveChangesAsync();
            return await GetTicketCredential(credential.Id);
        }

        public async Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential)
        {
            CapturedPasswordCredential matchingCredential = await this.GetPasswordCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Password = credential.Password;
            matchingCredential.Type = credential.Type;

            this.Credentials.Update(matchingCredential);
            await this.SaveChangesAsync();
            return await GetPasswordCredential(matchingCredential.Id);
        }

        public async Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential)
        {
            CapturedHashCredential matchingCredential = await this.GetHashCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Hash = credential.Hash;
            matchingCredential.HashCredentialType = credential.HashCredentialType;
            matchingCredential.Type = credential.Type;

            this.Credentials.Update(matchingCredential);
            await this.SaveChangesAsync();
            return await GetHashCredential(matchingCredential.Id);
        }

        public async Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential)
        {
            CapturedTicketCredential matchingCredential = await this.GetTicketCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Ticket = credential.Ticket;
            matchingCredential.TicketCredentialType = credential.TicketCredentialType;
            matchingCredential.Type = credential.Type;

            this.Credentials.Update(matchingCredential);
            await this.SaveChangesAsync();
            return await GetTicketCredential(matchingCredential.Id);
        }

        public async Task DeleteCredential(int credentialId)
        {
            CapturedCredential credential = await this.GetCredential(credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedCredential with id: {credentialId}");
            }
            this.Credentials.Remove(credential);
            await this.SaveChangesAsync();
        }
        #endregion

        #region Indicator Actions
        public async Task<IEnumerable<Indicator>> GetIndicators()
        {
            return await this.Indicators.ToListAsync();
        }

        public async Task<IEnumerable<FileIndicator>> GetFileIndicators()
        {
            return await this.Indicators.Where(I => I.Type == IndicatorType.FileIndicator)
                .Select(I => (FileIndicator)I).ToListAsync();
        }

        public async Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators()
        {
            return await this.Indicators.Where(I => I.Type == IndicatorType.NetworkIndicator)
                .Select(I => (NetworkIndicator)I).ToListAsync();
        }

        public async Task<IEnumerable<TargetIndicator>> GetTargetIndicators()
        {
            return await this.Indicators.Where(I => I.Type == IndicatorType.TargetIndicator)
                .Select(I => (TargetIndicator)I).ToListAsync();
        }

        public async Task<Indicator> GetIndicator(int indicatorId)
        {
            Indicator indicator = await this.Indicators.FindAsync(indicatorId);
            if (indicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicatorId}");
            }
            return indicator;
        }

        public async Task<FileIndicator> GetFileIndicator(int indicatorId)
        {
            Indicator indicator = await this.Indicators.FindAsync(indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.FileIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - FileIndicator with id: {indicatorId}");
            }
            return (FileIndicator)indicator;
        }

        public async Task<NetworkIndicator> GetNetworkIndicator(int indicatorId)
        {
            Indicator indicator = await this.Indicators.FindAsync(indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.NetworkIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - NetworkIndicator with id: {indicatorId}");
            }
            return (NetworkIndicator)indicator;
        }

        public async Task<TargetIndicator> GetTargetIndicator(int indicatorId)
        {
            Indicator indicator = await this.Indicators.FindAsync(indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.TargetIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - TargetIndicator with id: {indicatorId}");
            }
            return (TargetIndicator)indicator;
        }

        public async Task<Indicator> CreateIndicator(Indicator indicator)
        {
            await this.Indicators.AddAsync(indicator);
            await this.SaveChangesAsync();
            return await GetIndicator(indicator.Id);
        }

        public async Task<Indicator> EditIndicator(Indicator indicator)
        {
            Indicator matchingIndicator = await this.GetIndicator(indicator.Id);
            if (matchingIndicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicator.Id}");
            }
            matchingIndicator.Type = indicator.Type;
            switch (indicator.Type)
            {
                case IndicatorType.FileIndicator:
                    FileIndicator matchingFileIndicator = (FileIndicator)matchingIndicator;
                    FileIndicator fileIndicator = (FileIndicator)indicator;
                    matchingFileIndicator.FileName = fileIndicator.FileName;
                    matchingFileIndicator.FilePath = fileIndicator.FilePath;
                    matchingFileIndicator.SHA2 = fileIndicator.SHA2;
                    matchingFileIndicator.SHA1 = fileIndicator.SHA1;
                    matchingFileIndicator.MD5 = fileIndicator.MD5;
                    this.Indicators.Update(matchingFileIndicator);
                    break;
                case IndicatorType.NetworkIndicator:
                    NetworkIndicator matchingNetworkIndicator = (NetworkIndicator)matchingIndicator;
                    NetworkIndicator networkIndicator = (NetworkIndicator)indicator;
                    matchingNetworkIndicator.Protocol = networkIndicator.Protocol;
                    matchingNetworkIndicator.Domain = networkIndicator.Domain;
                    matchingNetworkIndicator.IPAddress = networkIndicator.IPAddress;
                    matchingNetworkIndicator.Port = networkIndicator.Port;
                    matchingNetworkIndicator.URI = networkIndicator.URI;
                    this.Indicators.Update(matchingNetworkIndicator);
                    break;
                case IndicatorType.TargetIndicator:
                    TargetIndicator matchingTargetIndicator = (TargetIndicator)matchingIndicator;
                    TargetIndicator targetIndicator = (TargetIndicator)indicator;
                    matchingTargetIndicator.ComputerName = targetIndicator.ComputerName;
                    matchingTargetIndicator.UserName = targetIndicator.UserName;
                    this.Indicators.Update(matchingTargetIndicator);
                    break;
            }
            await this.SaveChangesAsync();
            return await this.GetIndicator(indicator.Id);
        }

        public async Task DeleteIndicator(int indicatorId)
        {
            Indicator indicator = await this.GetIndicator(indicatorId);
            if (indicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicatorId}");
            }
            this.Indicators.Remove(indicator);
            await this.SaveChangesAsync();
        }
        #endregion

        #region ListenerType Actions
        public async Task<IEnumerable<ListenerType>> GetListenerTypes()
        {
            return await this.ListenerTypes.ToListAsync();
        }

        public async Task<ListenerType> GetListenerType(int listenerTypeId)
        {
            ListenerType type = await this.ListenerTypes.FindAsync(listenerTypeId);
            if (type == null)
            {
                throw new ControllerNotFoundException($"NotFound - ListenerType with id: {listenerTypeId}");
            }
            return type;
        }
        #endregion

        #region Profile Actions
        public async Task<IEnumerable<Profile>> GetProfiles()
        {
            return await this.Profiles.ToListAsync();
        }

        public async Task<Profile> GetProfile(int profileId)
        {
            Profile profile = await this.Profiles.FindAsync(profileId);
            if (profile == null)
            {
                throw new ControllerNotFoundException($"NotFound - Profile with id: {profileId}");
            }
            return profile;
        }

        public async Task<Profile> CreateProfile(Profile profile, CovenantUser currentUser)
        {
            if (! await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await this.Profiles.AddAsync(profile);
            await this.SaveChangesAsync();
            return await this.GetProfile(profile.Id);
        }

        public async Task<Profile> EditProfile(Profile profile, CovenantUser currentUser)
        {
            Profile matchingProfile = await this.GetProfile(profile.Id);
            matchingProfile.Description = profile.Description;
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            this.Profiles.Update(matchingProfile);
            await this.SaveChangesAsync();
            return await this.GetProfile(profile.Id);
        }

        public async Task DeleteProfile(int id)
        {
            Profile profile = await this.GetProfile(id);
            this.Profiles.Remove(profile);
            await this.SaveChangesAsync();
        }

        public async Task<IEnumerable<HttpProfile>> GetHttpProfiles()
        {
            return await this.Profiles.Where(P => P.Type == ProfileType.HTTP).Select(P => (HttpProfile)P).ToListAsync();
        }

        public async Task<IEnumerable<BridgeProfile>> GetBridgeProfiles()
        {
            return await this.Profiles.Where(P => P.Type == ProfileType.Bridge).Select(P => (BridgeProfile)P).ToListAsync();
        }

        public async Task<HttpProfile> GetHttpProfile(int profileId)
        {
            Profile profile = await this.Profiles.FindAsync(profileId);
            if (profile == null || profile.Type != ProfileType.HTTP)
            {
                throw new ControllerNotFoundException($"NotFound - HttpProfile with id: {profileId}");
            }
            return (HttpProfile)profile;
        }

        public async Task<BridgeProfile> GetBridgeProfile(int profileId)
        {
            Profile profile = await this.Profiles.FindAsync(profileId);
            if (profile == null || profile.Type != ProfileType.Bridge)
            {
                throw new ControllerNotFoundException($"NotFound - BridgeProfile with id: {profileId}");
            }
            return (BridgeProfile)profile;
        }

        public async Task<HttpProfile> CreateHttpProfile(HttpProfile profile, CovenantUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await this.Profiles.AddAsync(profile);
            await this.SaveChangesAsync();
            return await this.GetHttpProfile(profile.Id);
        }

        public async Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, CovenantUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await this.Profiles.AddAsync(profile);
            await this.SaveChangesAsync();
            return await this.GetBridgeProfile(profile.Id);
        }

        public async Task<HttpProfile> EditHttpProfile(HttpProfile profile, CovenantUser currentUser)
        {
            HttpProfile matchingProfile = await this.GetHttpProfile(profile.Id);
            Listener l = await this.Listeners.FirstOrDefaultAsync(L => L.ProfileId == matchingProfile.Id && L.Status == ListenerStatus.Active);
            if (l != null)
            {
                throw new ControllerBadRequestException($"BadRequest - Cannot edit a profile assigned to an Active Listener");
            }
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            matchingProfile.Description = profile.Description;
            matchingProfile.HttpRequestHeaders = profile.HttpRequestHeaders;
            matchingProfile.HttpResponseHeaders = profile.HttpResponseHeaders;
            matchingProfile.HttpUrls = profile.HttpUrls;
            matchingProfile.HttpGetResponse = profile.HttpGetResponse.Replace("\r\n", "\n");
            matchingProfile.HttpPostRequest = profile.HttpPostRequest.Replace("\r\n", "\n");
            matchingProfile.HttpPostResponse = profile.HttpPostResponse.Replace("\r\n", "\n");
            if (matchingProfile.MessageTransform != profile.MessageTransform)
            {
                if (!await this.IsAdmin(currentUser))
                {
                    throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
                }
                matchingProfile.MessageTransform = profile.MessageTransform;
            }
            this.Update(matchingProfile);
            await this.SaveChangesAsync();
            return await this.GetHttpProfile(profile.Id);
        }

        public async Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, CovenantUser currentUser)
        {
            BridgeProfile matchingProfile = await this.GetBridgeProfile(profile.Id);
            Listener l = await this.Listeners.FirstOrDefaultAsync(L => L.ProfileId == matchingProfile.Id && L.Status == ListenerStatus.Active);
            if (l != null)
            {
                throw new ControllerBadRequestException($"BadRequest - Cannot edit a profile assigned to an Active Listener");
            }
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            matchingProfile.Description = profile.Description;
            matchingProfile.ReadFormat = profile.ReadFormat;
            matchingProfile.WriteFormat = profile.WriteFormat;
            if (matchingProfile.MessageTransform != profile.MessageTransform)
            {
                if (!await this.IsAdmin(currentUser))
                {
                    throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
                }
                matchingProfile.MessageTransform = profile.MessageTransform;
            }
            this.Update(matchingProfile);
            await this.SaveChangesAsync();
            return await this.GetBridgeProfile(profile.Id);
        }
        #endregion

        #region Listener Actions
        public async Task<IEnumerable<Listener>> GetListeners()
        {
            return await this.Listeners
                .Include(L => L.ListenerType)
                .ToListAsync();
        }

        public async Task<Listener> GetListener(int listenerId)
        {
            Listener listener = await this.Listeners
                .Include(L => L.ListenerType)
                .FirstOrDefaultAsync(L => L.Id == listenerId);
            if (listener == null)
            {
                throw new ControllerNotFoundException($"NotFound - Listener with id: {listenerId}");
            }
            return listener;
        }

        public async Task<Listener> EditListener(Listener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            Listener matchingListener = await this.GetListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.GUID = listener.GUID;
            matchingListener.Description = listener.Description;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.CovenantToken = listener.CovenantToken;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_ListenerCancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "[" + eventTime + " UTC] Stopped Listener: " + matchingListener.Name,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await EventHubProxy.SendEvent(_eventhub, listenerEvent);
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.StartTime = DateTime.UtcNow;
                HttpProfile profile = await this.GetHttpProfile(matchingListener.ProfileId);
                if (profile == null)
                {
                    throw new ControllerNotFoundException($"NotFound - HttpProfile with id: {matchingListener.ProfileId}");
                }
                CancellationTokenSource listenerCancellationToken = null;
                try
                {
                    listenerCancellationToken = matchingListener.Start();
                }
                catch(ListenerStartException e)
                {
                    throw new ControllerBadRequestException($"BadRequest - Listener with id: {matchingListener.Id} did not start due to exception: {e.Message}");
                }
                _ListenerCancellationTokens[matchingListener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {matchingListener.Id} did not start properly");
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = matchingListener.StartTime,
                    MessageHeader = "[" + matchingListener.StartTime + " UTC] Started Listener: " + matchingListener.Name,
                    Level = EventLevel.Highlight,
                    Context = "*"
                });
                await EventHubProxy.SendEvent(_eventhub, listenerEvent);
            }

            this.Listeners.Update(matchingListener);
            await this.SaveChangesAsync();
            return await this.GetListener(matchingListener.Id);
        }

        public async Task StartListener(int listenerId, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens)
        {
            Listener listener = await this.GetListener(listenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            CancellationTokenSource listenerCancellationToken = null;
            try
            {
                listenerCancellationToken = listener.Start();
            }
            catch (ListenerStartException e)
            {
                throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start due to exception: {e.Message}");
            }
            _ListenerCancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");
        }

        public async Task DeleteListener(int listenerId, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens)
        {
            Listener listener = await this.GetListener(listenerId);
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Stop(_ListenerCancellationTokens[listener.Id]);
            }
			this.Launchers.Where(L => L.ListenerId == listener.Id).ToList().ForEach(L =>
			{
				L.LauncherString = "";
				L.StagerCode = "";
				L.Base64ILByteString = "";
				this.Launchers.Update(L);
			});
            this.Listeners.Remove(listener);
            await this.SaveChangesAsync();
        }

        public async Task<IEnumerable<HttpListener>> GetHttpListeners()
        {
            return await this.Listeners
                .Include(L => L.ListenerType)
                .Where(L => L.ListenerType.Name == "HTTP")
                .Select(L => (HttpListener)L)
                .ToListAsync();
        }

        public async Task<IEnumerable<BridgeListener>> GetBridgeListeners()
        {
            return await this.Listeners
                .Include(L => L.ListenerType)
                .Where(L => L.ListenerType.Name == "Bridge")
                .Select(L => (BridgeListener)L)
                .ToListAsync();
        }

        public async Task<HttpListener> GetHttpListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            ListenerType listenerType = await this.GetListenerType(listener.ListenerTypeId);
            if (listenerType.Name != "HTTP")
            {
                throw new ControllerNotFoundException($"NotFound - HttpListener with id: {listener.ListenerTypeId}");
            }
            return (HttpListener)listener;
        }

        public async Task<BridgeListener> GetBridgeListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            ListenerType listenerType = await this.GetListenerType(listener.ListenerTypeId);
            if (listenerType.Name != "Bridge")
            {
                throw new ControllerNotFoundException($"NotFound - BridgeListener with id: {listener.ListenerTypeId}");
            }
            return (BridgeListener)listener;
        }

        private async Task<HttpListener> StartInitialHttpListener(HttpListener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            listener.StartTime = DateTime.UtcNow;
            if (listener.UseSSL && string.IsNullOrWhiteSpace(listener.SSLCertificate))
            {
                throw new ControllerBadRequestException($"HttpListener: {listener.Name} missing SSLCertificate");
            }
            if (this.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
            {
                throw new ControllerBadRequestException($"Listener already listening on port: {listener.BindPort}");
            }
            CancellationTokenSource listenerCancellationToken = null;
            try
            {
                listenerCancellationToken = listener.Start();
            }
            catch (ListenerStartException e)
            {
                throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start due to exception: {e.Message}");
            }
            _ListenerCancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");

            for (int i = 0; i < listener.ConnectAddresses.Count; i++)
            {
                NetworkIndicator httpIndicator = new NetworkIndicator
                {
                    Protocol = "http",
                    Domain = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? "" : listener.ConnectAddresses[i],
                    IPAddress = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? listener.ConnectAddresses[i] : "",
                    Port = listener.BindPort,
                    URI = listener.Urls[i]
                };
                IEnumerable<NetworkIndicator> indicators = await this.GetNetworkIndicators();
                if (indicators.FirstOrDefault(I => I.IPAddress == httpIndicator.IPAddress && I.Domain == httpIndicator.Domain) == null)
                {
                    await this.Indicators.AddAsync(httpIndicator);
                }
            }
            
            _ListenerCancellationTokens[listener.Id] = listenerCancellationToken;
            Event listenerEvent = await this.CreateEvent(new Event
            {
                Time = listener.StartTime,
                MessageHeader = "[" + listener.StartTime + " UTC] Started Listener: " + listener.Name + " at: " + listener.Urls,
                Level = EventLevel.Highlight,
                Context = "*"
            });
            await EventHubProxy.SendEvent(_eventhub, listenerEvent);
            return listener;
        }

        private async Task<BridgeListener> StartInitialBridgeListener(BridgeListener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            listener.StartTime = DateTime.UtcNow;
            if (this.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
            {
                throw new ControllerBadRequestException($"Listener already listening on port: {listener.BindPort}");
            }
            CancellationTokenSource listenerCancellationToken = null;
            try
            {
                listenerCancellationToken = listener.Start();
            }
            catch (ListenerStartException e)
            {
                throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start due to exception: {e.Message}");
            }
            _ListenerCancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");

            for (int i = 0; i < listener.ConnectAddresses.Count; i++)
            {
                NetworkIndicator bridgeIndicator = new NetworkIndicator
                {
                    Protocol = "bridge",
                    Domain = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? "" : listener.ConnectAddresses[i],
                    IPAddress = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? listener.ConnectAddresses[i] : "",
                    Port = listener.BindPort
                };
                IEnumerable<NetworkIndicator> indicators = await this.GetNetworkIndicators();
                if (indicators.FirstOrDefault(I => I.IPAddress == bridgeIndicator.IPAddress && I.Domain == bridgeIndicator.Domain) == null)
                {
                    await this.Indicators.AddAsync(bridgeIndicator);
                }
            }

            _ListenerCancellationTokens[listener.Id] = listenerCancellationToken;
            Event listenerEvent = await this.CreateEvent(new Event
            {
                Time = listener.StartTime,
                MessageHeader = "[" + listener.StartTime + " UTC] Started Listener: " + listener.Name + " at: " + listener.ConnectAddresses,
                Level = EventLevel.Highlight,
                Context = "*"
            });
            await EventHubProxy.SendEvent(_eventhub, listenerEvent);
            return listener;
        }

        public async Task<HttpListener> CreateHttpListener(UserManager<CovenantUser> userManager, IConfiguration configuration, HttpListener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            listener.Profile = await this.GetHttpProfile(listener.ProfileId);
            // Append capital letter to appease Password complexity requirements, get rid of warning output
            string password = Utilities.CreateSecureGuid().ToString() + "A";
            CovenantUser listenerUser = await this.CreateUser(userManager, new CovenantUserLogin {
                UserName = Utilities.CreateSecureGuid().ToString(),
                Password = password
            }, _eventhub);
            IdentityRole listenerRole = await this.Roles.FirstOrDefaultAsync(R => R.Name == "Listener");
            IdentityUserRole<string> userrole = await this.CreateUserRole(userManager, listenerUser.Id, listenerRole.Id);
            listener.CovenantToken = Utilities.GenerateJwtToken(
                listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
                configuration["JwtKey"], configuration["JwtIssuer"],
                configuration["JwtAudience"], "2000"
            );
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Status = ListenerStatus.Uninitialized;
                await this.Listeners.AddAsync(listener);
                await this.SaveChangesAsync();
                listener.Status = ListenerStatus.Active;
                listener = await this.StartInitialHttpListener(listener, _ListenerCancellationTokens, _eventhub);
                this.Listeners.Update(listener);
                await this.SaveChangesAsync();
            }
            else
            {
                await this.Listeners.AddAsync(listener);
                await this.SaveChangesAsync();
            }
            return await this.GetHttpListener(listener.Id);
        }

        public async Task<BridgeListener> CreateBridgeListener(UserManager<CovenantUser> userManager, IConfiguration configuration, BridgeListener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            listener.Profile = await this.GetBridgeProfile(listener.ProfileId);
            // Append capital letter to appease Password complexity requirements, get rid of warning output
            string password = Utilities.CreateSecureGuid().ToString() + "A";
            CovenantUser listenerUser = await this.CreateUser(userManager, new CovenantUserLogin
            {
                UserName = Utilities.CreateSecureGuid().ToString(),
                Password = password
            }, _eventhub);
            IdentityRole listenerRole = await this.Roles.FirstOrDefaultAsync(R => R.Name == "Listener");
            IdentityUserRole<string> userrole = await this.CreateUserRole(userManager, listenerUser.Id, listenerRole.Id);
            listener.CovenantToken = Utilities.GenerateJwtToken(
                listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
                configuration["JwtKey"], configuration["JwtIssuer"],
                configuration["JwtAudience"], "2000"
            );
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Status = ListenerStatus.Uninitialized;
                await this.Listeners.AddAsync(listener);
                await this.SaveChangesAsync();
                listener.Status = ListenerStatus.Active;
                listener = await this.StartInitialBridgeListener(listener, _ListenerCancellationTokens, _eventhub);
                this.Listeners.Update(listener);
                await this.SaveChangesAsync();
            }
            else
            {
                await this.Listeners.AddAsync(listener);
                await this.SaveChangesAsync();
            }
            return await this.GetBridgeListener(listener.Id);
        }

        public async Task<HttpListener> EditHttpListener(HttpListener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            HttpListener matchingListener = await this.GetHttpListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.GUID = listener.GUID;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.ConnectPort = listener.ConnectPort;
            matchingListener.UseSSL = listener.UseSSL;
            matchingListener.SSLCertificatePassword = listener.SSLCertificatePassword;
            matchingListener.SSLCertificate = listener.SSLCertificate;

            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            matchingListener.ProfileId = profile.Id;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_ListenerCancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "[" + eventTime + " UTC] Stopped Listener: " + matchingListener.Name + " at: " + matchingListener.Urls,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await EventHubProxy.SendEvent(_eventhub, listenerEvent);
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.Status = ListenerStatus.Active;
                matchingListener = await this.StartInitialHttpListener(matchingListener, _ListenerCancellationTokens, _eventhub);
            }

            this.Listeners.Update(matchingListener);
            await this.SaveChangesAsync();
            return await this.GetHttpListener(matchingListener.Id);
        }

        public async Task<BridgeListener> EditBridgeListener(BridgeListener listener, ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens, IHubContext<EventHub> _eventhub)
        {
            BridgeListener matchingListener = await this.GetBridgeListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.GUID = listener.GUID;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.ConnectPort = listener.ConnectPort;

            BridgeProfile profile = await this.GetBridgeProfile(listener.ProfileId);
            matchingListener.ProfileId = profile.Id;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_ListenerCancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "[" + eventTime + " UTC] Stopped Listener: " + matchingListener.Name + " at: " + matchingListener.ConnectAddresses,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await EventHubProxy.SendEvent(_eventhub, listenerEvent);
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.Status = ListenerStatus.Active;
                matchingListener = await this.StartInitialBridgeListener(matchingListener, _ListenerCancellationTokens, _eventhub);
            }

            this.Listeners.Update(matchingListener);
            await this.SaveChangesAsync();
            return await this.GetBridgeListener(matchingListener.Id);
        }
        #endregion

        #region HostedFile Actions
        public async Task<IEnumerable<HostedFile>> GetHostedFiles()
        {
            return await this.HostedFiles.ToListAsync();
        }

        public async Task<HostedFile> GetHostedFile(int hostedFileId)
        {
            HostedFile file = await this.HostedFiles.FindAsync(hostedFileId);
            if (file == null)
            {
                throw new ControllerNotFoundException($"NotFound - HostedFile with id: {hostedFileId}");
            }
            return file;
        }

        public async Task<IEnumerable<HostedFile>> GetHostedFiles(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            return await this.HostedFiles.Where(HF => HF.ListenerId == listener.Id).ToListAsync();
        }

        public async Task<HostedFile> GetHostedFile(int listenerId, int hostedFileId)
        {
            Listener listener = await this.GetListener(listenerId);
            HostedFile file = await this.GetHostedFile(hostedFileId);
            if (file.ListenerId != listener.Id)
            {
                throw new ControllerBadRequestException($"BadRequest - HostedFile with id: {hostedFileId} is not hosted on Listener with id: {listenerId}");
            }
            return file;
        }

        public async Task<HostedFile> CreateHostedFile(HostedFile file)
        {
            HttpListener listener = await this.GetHttpListener(file.ListenerId);
            if (file.ListenerId != listener.Id)
            {
                throw new ControllerBadRequestException($"BadRequest - HostedFile with listener id: {file.ListenerId} does not match listener with id: {listener.Id}");
            }
            HostedFile existing = await this.HostedFiles.FirstOrDefaultAsync(HF => HF.Path == file.Path && HF.ListenerId == file.ListenerId);
            if (existing != null)
            {
                // If file already exists and is being hosted, BadRequest
                throw new ControllerBadRequestException($"BadRequest - HostedFile already exists at path: {file.Path}");
            }
            try
            {
                HostedFile hostedFile = listener.HostFile(file);
                // Check if it already exists again, path could have changed
                existing = await this.HostedFiles.FirstOrDefaultAsync(HF => HF.Path == file.Path && HF.ListenerId == file.ListenerId);
                if (existing != null)
                {
                    throw new ControllerBadRequestException($"BadRequest - HostedFile already exists at: {hostedFile.Path}");
                }
                await this.Indicators.AddAsync(new FileIndicator
                {
                    FileName = hostedFile.Path.Split("/").Last(),
                    FilePath = listener.Urls + hostedFile.Path,
                    MD5 = Encrypt.Utilities.GetMD5(Convert.FromBase64String(hostedFile.Content)),
                    SHA1 = Encrypt.Utilities.GetSHA1(Convert.FromBase64String(hostedFile.Content)),
                    SHA2 = Encrypt.Utilities.GetSHA256(Convert.FromBase64String(hostedFile.Content))
                });
                await this.HostedFiles.AddAsync(hostedFile);
                await this.SaveChangesAsync();
                return await this.GetHostedFile(hostedFile.Id);
            }
            catch (Exception)
            {
                throw new ControllerBadRequestException($"BadRequest - Error hosting file at path: {file.Path}");
            }
        }

        public async Task<HostedFile> EditHostedFile(int listenerId, HostedFile file)
        {
            HttpListener listener = await this.GetHttpListener(listenerId);
            HostedFile matchingFile = await this.GetHostedFile(listenerId, file.Id);
            matchingFile.Path = file.Path;
            matchingFile.Content = file.Content;
            try
            {
                HostedFile updatedFile = listener.HostFile(matchingFile);
                this.HostedFiles.Update(updatedFile);
                await this.SaveChangesAsync();
                return await this.GetHostedFile(updatedFile.Id);
            }
            catch
            {
                throw new ControllerBadRequestException($"BadRequest - Error hosting file at: {matchingFile.Path}");
            }
        }

        public async Task DeleteHostedFile(int listenerId, int hostedFileId)
        {
            HttpListener listener = await this.GetHttpListener(listenerId);
            HostedFile file = await this.GetHostedFile(listenerId, hostedFileId);
            this.HostedFiles.Remove(file);
            await this.SaveChangesAsync();
        }
        #endregion

        #region Launcher Actions
        public async Task<IEnumerable<Launcher>> GetLaunchers()
        {
            return await this.Launchers.ToListAsync();
        }

        public async Task<BinaryLauncher> GetBinaryLauncher()
        {
            BinaryLauncher launcher = (BinaryLauncher) await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Binary);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - BinaryLauncher");
            }
            return launcher;
        }

        public async Task<BinaryLauncher> GenerateBinaryLauncher()
        {
            BinaryLauncher launcher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetBinaryLauncher();
        }

        public async Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file)
        {
            BinaryLauncher launcher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetBinaryLauncher();
        }

        public async Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher)
        {
            BinaryLauncher matchingLauncher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetBinaryLauncher();
        }

        public async Task<PowerShellLauncher> GetPowerShellLauncher()
        {
            PowerShellLauncher launcher = (PowerShellLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.PowerShell);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - PowerShellLauncher");
            }
            return launcher;
        }

        public async Task<PowerShellLauncher> GeneratePowerShellLauncher()
        {
            PowerShellLauncher launcher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetPowerShellLauncher();
        }

        public async Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file)
        {
            PowerShellLauncher launcher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetPowerShellLauncher();
        }

        public async Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher)
        {
            PowerShellLauncher matchingLauncher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetPowerShellLauncher();
        }

        public async Task<MSBuildLauncher> GetMSBuildLauncher()
        {
            MSBuildLauncher launcher = (MSBuildLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.MSBuild);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - MSBuildLauncher");
            }
            return launcher;
        }

        public async Task<MSBuildLauncher> GenerateMSBuildLauncher()
        {
            MSBuildLauncher launcher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetMSBuildLauncher();
        }

        public async Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file)
        {
            MSBuildLauncher launcher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetMSBuildLauncher();
        }

        public async Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher)
        {
            MSBuildLauncher matchingLauncher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetMSBuildLauncher();
        }

        public async Task<InstallUtilLauncher> GetInstallUtilLauncher()
        {
            InstallUtilLauncher launcher = (InstallUtilLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.InstallUtil);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - InstallUtilLauncher");
            }
            return launcher;
        }

        public async Task<InstallUtilLauncher> GenerateInstallUtilLauncher()
        {
            InstallUtilLauncher launcher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetInstallUtilLauncher();
        }

        public async Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file)
        {
            InstallUtilLauncher launcher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetInstallUtilLauncher();
        }

        public async Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher)
        {
            InstallUtilLauncher matchingLauncher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetInstallUtilLauncher();
        }

        public async Task<WmicLauncher> GetWmicLauncher()
        {
            WmicLauncher launcher = (WmicLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Wmic);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - WmicLauncher");
            }
            return launcher;
        }

        public async Task<WmicLauncher> GenerateWmicLauncher()
        {
            WmicLauncher launcher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetWmicLauncher();
        }

        public async Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file)
        {
            WmicLauncher launcher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetWmicLauncher();
        }

        public async Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher)
        {
            WmicLauncher matchingLauncher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetWmicLauncher();
        }

        public async Task<Regsvr32Launcher> GetRegsvr32Launcher()
        {
            Regsvr32Launcher launcher = (Regsvr32Launcher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Regsvr32);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - Regsvr32Launcher");
            }
            return launcher;
        }

        public async Task<Regsvr32Launcher> GenerateRegsvr32Launcher()
        {
            Regsvr32Launcher launcher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetRegsvr32Launcher();
        }

        public async Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file)
        {
            Regsvr32Launcher launcher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetRegsvr32Launcher();
        }

        public async Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher)
        {
            Regsvr32Launcher matchingLauncher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ParameterString = launcher.ParameterString;
            matchingLauncher.DllName = launcher.DllName;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetRegsvr32Launcher();
        }

        public async Task<MshtaLauncher> GetMshtaLauncher()
        {
            MshtaLauncher launcher = (MshtaLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Mshta);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - MshtaLauncher");
            }
            return launcher;
        }

        public async Task<MshtaLauncher> GenerateMshtaLauncher()
        {
            MshtaLauncher launcher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetMshtaLauncher();
        }

        public async Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file)
        {
            MshtaLauncher launcher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetMshtaLauncher();
        }

        public async Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher)
        {
            MshtaLauncher matchingLauncher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetMshtaLauncher();
        }

        public async Task<CscriptLauncher> GetCscriptLauncher()
        {
            CscriptLauncher launcher = (CscriptLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Cscript);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - CscriptLauncher");
            }
            return launcher;
        }

        public async Task<CscriptLauncher> GenerateCscriptLauncher()
        {
            CscriptLauncher launcher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetCscriptLauncher();
        }

        public async Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file)
        {
            CscriptLauncher launcher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetCscriptLauncher();
        }

        public async Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher)
        {
            CscriptLauncher matchingLauncher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetCscriptLauncher();
        }

        public async Task<WscriptLauncher> GetWscriptLauncher()
        {
            WscriptLauncher launcher = (WscriptLauncher)await this.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Wscript);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - WscriptLauncher");
            }
            return launcher;
        }

        public async Task<WscriptLauncher> GenerateWscriptLauncher()
        {
            WscriptLauncher launcher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            Grunt grunt = new Grunt
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValidateCert = launcher.ValidateCert,
                UseCertPinning = launcher.UseCertPinning,
                Delay = launcher.Delay,
                JitterPercent = launcher.JitterPercent,
                ConnectAttempts = launcher.ConnectAttempts,
                KillDate = launcher.KillDate,
                DotNetFrameworkVersion = launcher.DotNetFrameworkVersion
            };

            await this.Grunts.AddAsync(grunt);
            await this.SaveChangesAsync();

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager),
                grunt,
                template
            );
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetWscriptLauncher();
        }

        public async Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file)
        {
            WscriptLauncher launcher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            this.Launchers.Update(launcher);
            await this.SaveChangesAsync();
            return await this.GetWscriptLauncher();
        }

        public async Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher)
        {
            WscriptLauncher matchingLauncher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.DotNetFrameworkVersion = launcher.DotNetFrameworkVersion;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            this.Launchers.Update(matchingLauncher);
            await this.SaveChangesAsync();
            return await this.GetWscriptLauncher();
        }
        #endregion
    }
}
