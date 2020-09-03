using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR;

using Covenant.Hubs;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;
using Covenant.Models.Launchers;
using Covenant.Models.Grunts;
using Covenant.Models.Indicators;
using NLog;

namespace Covenant.Core
{
    public interface ICovenantUserLoggingService
    {
        event EventHandler<CovenantUser> OnCreateCovenantUser;
        event EventHandler<CovenantUser> OnEditCovenantUser;
        event EventHandler<CovenantUser> OnDeleteCovenantUser;
        Task LogCreateCovenantUser(object sender, CovenantUser user);
        Task LogEditCovenantUser(object sender, CovenantUser user);
        Task LogDeleteCovenantUser(object sender, CovenantUser user);
    }

    public interface IIdentityRoleLoggingService
    {
        event EventHandler<IdentityRole> OnCreateIdentityRole;
        event EventHandler<IdentityRole> OnEditIdentityRole;
        event EventHandler<IdentityRole> OnDeleteIdentityRole;

        Task LogCreateIdentityRole(object sender, IdentityRole role);
        Task LogEditIdentityRole(object sender, IdentityRole role);
        Task LogDeleteIdentityRole(object sender, IdentityRole role);
    }

    public interface IIdentityUserRoleLoggingService
    {
        event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole;
        event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole;
        event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole;
    }

    public interface IThemeLoggingService
    {
        event EventHandler<Theme> OnCreateTheme;
        event EventHandler<Theme> OnEditTheme;
        event EventHandler<int> OnDeleteTheme;
    }

    public interface IEventLoggingService
    {
        event EventHandler<Event> OnCreateEvent;
        event EventHandler<Event> OnEditEvent;
        event EventHandler<int> OnDeleteEvent;
        Task LogCreateEvent(object sender, Event anEvent);
    }

    public interface IImplantTemplateLoggingService
    {
        event EventHandler<ImplantTemplate> OnCreateImplantTemplate;
        event EventHandler<ImplantTemplate> OnEditImplantTemplate;
        event EventHandler<int> OnDeleteImplantTemplate;
    }

    public interface IGruntLoggingService
    {
        event EventHandler<Grunt> OnCreateGrunt;
        event EventHandler<Grunt> OnEditGrunt;
        event EventHandler<Grunt> OnDeleteGrunt;
        Task LogCreateGrunt(object sender, Grunt grunt);
        Task LogEditGrunt(object sender, Grunt grunt);
        Task LogDeleteGrunt(object sender, Grunt grunt);
    }

    public interface IReferenceAssemblyLoggingService
    {
        event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly;
        event EventHandler<ReferenceAssembly> OnEditReferenceAssembly;
        event EventHandler<int> OnDeleteReferenceAssembly;
    }

    public interface IEmbeddedResourceLoggingService
    {
        event EventHandler<EmbeddedResource> OnCreateEmbeddedResource;
        event EventHandler<EmbeddedResource> OnEditEmbeddedResource;
        event EventHandler<int> OnDeleteEmbeddedResource;
    }

    public interface IReferenceSourceLibraryLoggingService
    {
        event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary;
        event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary;
        event EventHandler<int> OnDeleteReferenceSourceLibrary;
    }

    public interface IGruntTaskOptionLoggingService
    {
        event EventHandler<GruntTaskOption> OnCreateGruntTaskOption;
        event EventHandler<GruntTaskOption> OnEditGruntTaskOption;
        event EventHandler<int> OnDeleteGruntTaskOption;
    }

    public interface IGruntTaskLoggingService : IReferenceAssemblyLoggingService, IEmbeddedResourceLoggingService,
        IReferenceSourceLibraryLoggingService, IGruntTaskOptionLoggingService
    {
        event EventHandler<GruntTask> OnCreateGruntTask;
        event EventHandler<GruntTask> OnEditGruntTask;
        event EventHandler<int> OnDeleteGruntTask;
    }

    public interface IGruntCommandLoggingService
    {
        event EventHandler<GruntCommand> OnCreateGruntCommand;
        event EventHandler<GruntCommand> OnEditGruntCommand;
        event EventHandler<int> OnDeleteGruntCommand;
        Task LogCreateGruntCommand(object sender, GruntCommand command);
        Task LogEditGruntCommand(object sender, GruntCommand command);
    }

    public interface ICommandOutputLoggingService
    {
        event EventHandler<CommandOutput> OnCreateCommandOutput;
        event EventHandler<CommandOutput> OnEditCommandOutput;
        event EventHandler<int> OnDeleteCommandOutput;
        //Task LogEditCommandOutput(object sender, CommandOutput output);
        Task LogCreateCommandOutput(object sender, CommandOutput output);
        Task LogEditCommandOutput(object sender, CommandOutput output);

    }

    public interface IGruntTaskingLoggingService
    {
        event EventHandler<GruntTasking> OnCreateGruntTasking;
        event EventHandler<GruntTasking> OnEditGruntTasking;
        event EventHandler<GruntTasking> OnDeleteGruntTasking;
        Task LogCreateGruntTasking(object sender, GruntTasking tasking);
        Task LogEditGruntTasking(object sender, GruntTasking tasking);

        Task LogDeleteGruntTasking(object sender, GruntTasking tasking);
    }

    public interface ICredentialLoggingService
    {
        event EventHandler<CapturedCredential> OnCreateCapturedCredential;
        event EventHandler<CapturedCredential> OnEditCapturedCredential;
        event EventHandler<CapturedCredential> OnDeleteCapturedCredential;
        Task LogCreateCapturedCredential(object sender, CapturedCredential credential);
        Task LogEditCapturedCredential(object sender, CapturedCredential credential);
        Task LogDeleteCapturedCredential(object sender, CapturedCredential credential);
    }

    public interface IIndicatorLoggingService
    {
        event EventHandler<Indicator> OnCreateIndicator;
        event EventHandler<Indicator> OnEditIndicator;
        event EventHandler<int> OnDeleteIndicator;
    }

    public interface IListenerTypeLoggingService
    {
        event EventHandler<ListenerType> OnCreateListenerType;
        event EventHandler<ListenerType> OnEditListenerType;
        event EventHandler<int> OnDeleteListenerType;
    }

    public interface IListenerLoggingService : IListenerTypeLoggingService
    {
        event EventHandler<Listener> OnCreateListener;
        event EventHandler<Listener> OnEditListener;
        event EventHandler<Listener> OnDeleteListener;
        event EventHandler<Grunt> OnLogListener;
        Task LogCreateListener(object sender, Listener listener);
        Task LogEditListener(object sender, Listener listener);
        Task LogDeleteListener(object sender, Listener listener);
    }

    public interface IProfileLoggingService
    {
        event EventHandler<Profile> OnCreateProfile;
        event EventHandler<Profile> OnEditProfile;
        event EventHandler<int> OnDeleteProfile;
    }

    public interface IHostedFileLoggingService
    {
        event EventHandler<HostedFile> OnCreateHostedFile;
        event EventHandler<HostedFile> OnEditHostedFile;
        event EventHandler<HostedFile> OnDeleteHostedFile;
        Task LogCreateHostedFile(object sender, HostedFile file);
        Task LogEditHostedFile(object sender, HostedFile file);
        Task LogDeleteHostedFile(object sender, HostedFile file);
    }

    public interface ILauncherLoggingService
    {
        event EventHandler<Launcher> OnCreateLauncher;
        event EventHandler<Launcher> OnEditLauncher;
        event EventHandler<int> OnDeleteLauncher;
    }
    public interface ILoggingService : ICovenantUserLoggingService, IIdentityRoleLoggingService, IIdentityUserRoleLoggingService, IThemeLoggingService,
   IEventLoggingService, IImplantTemplateLoggingService, IGruntLoggingService, IGruntTaskLoggingService,
   IGruntCommandLoggingService, ICommandOutputLoggingService, IGruntTaskingLoggingService,
   ICredentialLoggingService, IIndicatorLoggingService, IListenerLoggingService, IProfileLoggingService,
   IHostedFileLoggingService, ILauncherLoggingService
    {

    }

    public class LoggingService : ILoggingService
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        public LoggingService()
        {
            this.OnCreateCovenantUser += (sender, covenantUser) =>
            {
                _logger.Info($"[OnCreateCovenantUser] {covenantUser.Id} - {covenantUser.NormalizedUserName} ");
            };
            this.OnEditCovenantUser += (sender, covenantUser) =>
            {
                _logger.Info($"[OnEditCovenantUser] {covenantUser.Id} - {covenantUser.NormalizedUserName}");
            };
            this.OnDeleteCovenantUser += (sender, covenantUser) =>
            {
                _logger.Info($"[OnDeleteCovenantUser] {covenantUser.Id} - {covenantUser.NormalizedUserName}");
            };


            this.OnCreateIdentityRole += (sender, role) =>
            {
                _logger.Info($"[OnCreateIdentityRole] {role.Id} - {role.Name} ");
            };
            this.OnEditIdentityRole += (sender, role) =>
            {
                _logger.Info($"[OnEditIdentityRole] {role.Id} - {role.Name} ");
            };
            this.OnDeleteIdentityRole += (sender, role) =>
            {
                _logger.Info($"[OnDeleteIdentityRole] {role.Id} - {role.Name} ");
            };


            this.OnCreateGrunt += (sender, grunt) =>
            {
                _logger.Info($"[OnCreateGrunt] {grunt.Id} \r\n\t{grunt.Name}\r\n\t{grunt.Hostname}\r\n\t{grunt.Integrity}\r\n\t{grunt.IPAddress}\r\n\t{grunt.UserDomainName}");
            };
            this.OnEditGrunt += (sender, grunt) =>
            {
                _logger.Info($"[OnEditGrunt] {grunt.Id} \r\n\t{grunt.Name}\r\n\t{grunt.Hostname}\r\n\t{grunt.Integrity}\r\n\t{grunt.IPAddress}\r\n\t{grunt.UserDomainName}");
            };
            this.OnDeleteGrunt += (sender, grunt) =>
            {
                _logger.Info($"[OnDeleteGrunt] {grunt.Id} \r\n\t{grunt.Name}\r\n\t{grunt.Hostname}\r\n\t{grunt.Integrity}\r\n\t{grunt.IPAddress}\r\n\t{grunt.UserDomainName}");
            };
            
            this.OnCreateGruntCommand += (sender, command) =>
            {
                _logger.Info($"[OnCreateGruntCommand] Grunt:{command.Grunt.Name}\r\n\tCommandID:{command.Id}\r\n\tCommand:{command.Command}");
            };
            this.OnEditGruntCommand += (sender, command) =>
            {
                _logger.Info($"[OnEditGruntCommand] Grunt:{command.Grunt.Name}\r\n\tCommandID:{command.Id}\r\n\tCommand:{command.Command}");
            };
            /**
            this.OnCreateCommandOutput += (sender, command) =>
            {
                _logger.Info($"[OnCreateCommandOutput] CommandID:{command.GruntCommandId}\r\n\Output:{command.Output}");
            };
            **/
            /**
             this.OnEditCommandOutput += (sender, command) =>
             {
                 _logger.Info($"[OnCreateCommandOutput] CommandID:{command.GruntCommandId}\r\n\Output:{command.Output}");
             };
             **/


            this.OnCreateGruntTasking += (sender, task) =>
            {
                _logger.Info($"[OnCreateGruntCommand] Grunt:{task.Grunt.Name}\r\n\tCommandID:{task.Id}\r\n\tCommand:{task.Name}\r\n\tCommand:{String.Join(",",task.Parameters)}");
            };
            this.OnEditGruntTasking += (sender, task) =>
            {
                _logger.Info($"[OnEditGruntCommand] Grunt:{task.Grunt.Name}\r\n\tCommandID:{task.Id}\r\n\tCommand:{task.Name}\r\n\tCommand:{String.Join(",", task.Parameters)}");
            };
            this.OnDeleteGruntTasking += (sender, task) =>
            {
                _logger.Info($"[OnEditGruntCommand] Grunt:{task.Grunt.Name}\r\n\tCommandID:{task.Id}\r\n\tCommand:{task.Name}\r\n\tCommand:{String.Join(",", task.Parameters)}");
            };

            this.OnCreateCapturedCredential += (sender, credential) =>
            {
                _logger.Info($"[OnCreateCapturedCredential] {credential.Domain}\\{credential.Username}");
            };
            this.OnEditCapturedCredential += (sender, credential) =>
            {
                _logger.Info($"[OnEditCapturedCredential] {credential.Domain}\\{credential.Username}");
            };
            this.OnDeleteCapturedCredential += (sender, credential) =>
            {
                _logger.Info($"[OnDeleteCapturedCredential] {credential.Domain}\\{credential.Username}");
            };

            this.OnCreateListener += (sender, listener) =>
            {
                _logger.Info($"[OnDeleteCapturedCredential] ListenerID: {listener.Id}\r\n\tBindAddress: {listener.BindAddress}\r\n\tBindPort: {listener.BindPort}\r\n\tConnectAddresses: {String.Join(",",listener.ConnectAddresses)}\r\n\tConnectPort: {listener.ConnectPort}");
            };
            this.OnEditListener += (sender, listener) =>
            {
                _logger.Info($"[OnEditListener] ListenerID: {listener.Id}\r\n\tBindAddress: {listener.BindAddress}\r\n\tBindPort: {listener.BindPort}\r\n\tConnectAddresses: {String.Join(",", listener.ConnectAddresses)}\r\n\tConnectPort: {listener.ConnectPort}");
            };
            this.OnDeleteListener += (sender, listener) =>
            {
                _logger.Info($"[OnDeleteListener] ListenerID: {listener.Id}\r\n\tBindAddress: {listener.BindAddress}\r\n\tBindPort: {listener.BindPort}\r\n\tConnectAddresses: {String.Join(",", listener.ConnectAddresses)}\r\n\tConnectPort: {listener.ConnectPort}");
            };

            this.OnCreateHostedFile += (sender, file) =>
            {
                _logger.Info($"[OnCreateHostedFile] ID: {file.Id}\r\n\tPath: {file.Path}");
            };
            this.OnEditHostedFile += (sender, file) =>
            {
                _logger.Info($"[OnEditHostedFile] ID: {file.Id}\r\n\tPath: {file.Path}");
            };
            this.OnDeleteHostedFile += (sender, file) =>
            {
                _logger.Info($"[OnDeleteHostedFile] ID: {file.Id}\r\n\tPath: {file.Path}");
            };

        }

        public event EventHandler<CovenantUser> OnCreateCovenantUser = delegate { };
        public event EventHandler<CovenantUser> OnEditCovenantUser = delegate { };
        public event EventHandler<CovenantUser> OnDeleteCovenantUser = delegate { };
        public event EventHandler<IdentityRole> OnCreateIdentityRole = delegate { };
        public event EventHandler<IdentityRole> OnEditIdentityRole = delegate { };
        public event EventHandler<IdentityRole> OnDeleteIdentityRole = delegate { };
        public event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole = delegate { };
        public event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole = delegate { };
        public event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole = delegate { };
        public event EventHandler<Theme> OnCreateTheme = delegate { };
        public event EventHandler<Theme> OnEditTheme = delegate { };
        public event EventHandler<int> OnDeleteTheme = delegate { };
        public event EventHandler<Event> OnCreateEvent = delegate { };
        public event EventHandler<Event> OnEditEvent = delegate { };
        public event EventHandler<int> OnDeleteEvent = delegate { };
        public event EventHandler<ImplantTemplate> OnCreateImplantTemplate = delegate { };
        public event EventHandler<ImplantTemplate> OnEditImplantTemplate = delegate { };
        public event EventHandler<int> OnDeleteImplantTemplate = delegate { };
        public event EventHandler<Grunt> OnCreateGrunt = delegate { };
        public event EventHandler<Grunt> OnEditGrunt = delegate { };
        public event EventHandler<Grunt> OnDeleteGrunt = delegate { };
        public event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly = delegate { };
        public event EventHandler<ReferenceAssembly> OnEditReferenceAssembly = delegate { };
        public event EventHandler<int> OnDeleteReferenceAssembly = delegate { };
        public event EventHandler<EmbeddedResource> OnCreateEmbeddedResource = delegate { };
        public event EventHandler<EmbeddedResource> OnEditEmbeddedResource = delegate { };
        public event EventHandler<int> OnDeleteEmbeddedResource = delegate { };
        public event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary = delegate { };
        public event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary = delegate { };
        public event EventHandler<int> OnDeleteReferenceSourceLibrary = delegate { };
        public event EventHandler<GruntTaskOption> OnCreateGruntTaskOption = delegate { };
        public event EventHandler<GruntTaskOption> OnEditGruntTaskOption = delegate { };
        public event EventHandler<int> OnDeleteGruntTaskOption = delegate { };
        public event EventHandler<GruntTask> OnCreateGruntTask = delegate { };
        public event EventHandler<GruntTask> OnEditGruntTask = delegate { };
        public event EventHandler<int> OnDeleteGruntTask = delegate { };
        public event EventHandler<GruntCommand> OnCreateGruntCommand = delegate { };
        public event EventHandler<GruntCommand> OnEditGruntCommand = delegate { };
        public event EventHandler<int> OnDeleteGruntCommand = delegate { };
        public event EventHandler<CommandOutput> OnCreateCommandOutput = delegate { };
        public event EventHandler<CommandOutput> OnEditCommandOutput = delegate { };
        public event EventHandler<int> OnDeleteCommandOutput = delegate { };
        public event EventHandler<GruntTasking> OnCreateGruntTasking = delegate { };
        public event EventHandler<GruntTasking> OnEditGruntTasking = delegate { };
        public event EventHandler<GruntTasking> OnDeleteGruntTasking = delegate { };
        public event EventHandler<CapturedCredential> OnCreateCapturedCredential = delegate { };
        public event EventHandler<CapturedCredential> OnEditCapturedCredential = delegate { };
        public event EventHandler<CapturedCredential> OnDeleteCapturedCredential = delegate { };
        public event EventHandler<Indicator> OnCreateIndicator = delegate { };
        public event EventHandler<Indicator> OnEditIndicator = delegate { };
        public event EventHandler<int> OnDeleteIndicator = delegate { };
        public event EventHandler<ListenerType> OnCreateListenerType = delegate { };
        public event EventHandler<ListenerType> OnEditListenerType = delegate { };
        public event EventHandler<int> OnDeleteListenerType = delegate { };
        public event EventHandler<Listener> OnCreateListener = delegate { };
        public event EventHandler<Listener> OnEditListener = delegate { };
        public event EventHandler<Listener> OnDeleteListener = delegate { };
        public event EventHandler<Grunt> OnLogListener = delegate { };
        public event EventHandler<Profile> OnCreateProfile = delegate { };
        public event EventHandler<Profile> OnEditProfile = delegate { };
        public event EventHandler<int> OnDeleteProfile = delegate { };
        public event EventHandler<HostedFile> OnCreateHostedFile = delegate { };
        public event EventHandler<HostedFile> OnEditHostedFile = delegate { };
        public event EventHandler<HostedFile> OnDeleteHostedFile = delegate { };
        public event EventHandler<Launcher> OnCreateLauncher = delegate { };
        public event EventHandler<Launcher> OnEditLauncher = delegate { };
        public event EventHandler<int> OnDeleteLauncher = delegate { };
        public async Task LogCreateCovenantUser(object sender, CovenantUser user) { await Task.Run(() => this.OnCreateCovenantUser(sender, user)); }
        public async Task LogEditCovenantUser(object sender, CovenantUser user) { await Task.Run(() => this.OnEditCovenantUser(sender, user)); }
        public async Task LogDeleteCovenantUser(object sender, CovenantUser id) { await Task.Run(() => this.OnDeleteCovenantUser(sender, id)); }
        public async Task LogCreateIdentityRole(object sender, IdentityRole role) { await Task.Run(() => this.OnCreateIdentityRole(sender, role)); }
        public async Task LogEditIdentityRole(object sender, IdentityRole role) { await Task.Run(() => this.OnEditIdentityRole(sender, role)); }
        public async Task LogDeleteIdentityRole(object sender, IdentityRole role) { await Task.Run(() => this.OnDeleteIdentityRole(sender, role)); }
        public async Task LogCreateEvent(object sender, Event anEvent) { await Task.Run(() => this.OnCreateEvent(sender, anEvent)); }
        public async Task LogCreateGrunt(object sender, Grunt grunt) { await Task.Run(() => this.OnCreateGrunt(sender, grunt)); }
        public async Task LogEditGrunt(object sender, Grunt grunt) { await Task.Run(() => this.OnEditGrunt(sender, grunt)); }
        public async Task LogDeleteGrunt(object sender, Grunt grunt) { await Task.Run(() => this.OnDeleteGrunt(sender, grunt)); }
        public async Task LogCreateGruntCommand(object sender, GruntCommand command) { await Task.Run(() => this.OnCreateGruntCommand(sender, command)); }
        public async Task LogEditGruntCommand(object sender, GruntCommand command) { await Task.Run(() => this.OnEditGruntCommand(sender, command)); }
        public async Task LogCreateCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnCreateCommandOutput(sender, output)); }
        public async Task LogEditCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnCreateCommandOutput(sender, output)); }
        public async Task LogCreateGruntTasking(object sender, GruntTasking tasking) { await Task.Run(() => this.OnCreateGruntTasking(sender, tasking)); }
        public async Task LogEditGruntTasking(object sender, GruntTasking tasking) { await Task.Run(() => this.OnEditGruntTasking(sender, tasking)); }
        public async Task LogDeleteGruntTasking(object sender, GruntTasking tasking) { await Task.Run(() => this.OnDeleteGruntTasking(sender, tasking)); }

        public async Task LogCreateCapturedCredential(object sender, CapturedCredential credential) { await Task.Run(() => this.OnCreateCapturedCredential(sender, credential)); }
        public async Task LogEditCapturedCredential(object sender, CapturedCredential credential) { await Task.Run(() => this.OnEditCapturedCredential(sender, credential)); }
        public async Task LogDeleteCapturedCredential(object sender, CapturedCredential credential) { await Task.Run(() => this.OnDeleteCapturedCredential(sender, credential)); }
        public async Task LogListener(object sender, Grunt grunt) { await Task.Run(() => this.OnLogListener(sender, grunt)); }
        public async Task LogCreateListener(object sender, Listener listener) { await Task.Run(() => this.OnCreateListener(sender, listener)); }
        public async Task LogEditListener(object sender, Listener listener) { await Task.Run(() => this.OnEditListener(sender, listener)); }
        public async Task LogDeleteListener(object sender, Listener listener) { await Task.Run(() => this.OnEditListener(sender, listener)); }
        public async Task LogCreateHostedFile(object sender, HostedFile file) { await Task.Run(() => this.OnCreateHostedFile(sender, file)); }
        public async Task LogEditHostedFile(object sender, HostedFile file) { await Task.Run(() => this.OnEditHostedFile(sender, file)); }
        public async Task LogDeleteHostedFile(object sender, HostedFile file) { await Task.Run(() => this.OnDeleteHostedFile(sender, file)); }

    }
}
