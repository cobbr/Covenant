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

namespace Covenant.Core
{
    public interface ICovenantUserNotificationService
    {
        event EventHandler<CovenantUser> OnCreateCovenantUser;
        event EventHandler<CovenantUser> OnEditCovenantUser;
        event EventHandler<string> OnDeleteCovenantUser;
        Task NotifyCreateCovenantUser(object sender, CovenantUser user);
        Task NotifyEditCovenantUser(object sender, CovenantUser user);
        Task NotifyDeleteCovenantUser(object sender, string id);
    }

    public interface IIdentityRoleNotificationService
    {
        event EventHandler<IdentityRole> OnCreateIdentityRole;
        event EventHandler<IdentityRole> OnEditIdentityRole;
        event EventHandler<string> OnDeleteIdentityRole;
    }

    public interface IIdentityUserRoleNotificationService
    {
        event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole;
        event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole;
        event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole;
    }

    public interface IThemeNotificationService
    {
        event EventHandler<Theme> OnCreateTheme;
        event EventHandler<Theme> OnEditTheme;
        event EventHandler<int> OnDeleteTheme;
        Task NotifyCreateTheme(object sender, Theme theme);
        Task NotifyEditTheme(object sender, Theme theme);
        Task NotifyDeleteTheme(object sender, int id);
    }

    public interface IEventNotificationService
    {
        event EventHandler<Event> OnCreateEvent;
        event EventHandler<Event> OnEditEvent;
        event EventHandler<int> OnDeleteEvent;
        Task NotifyCreateEvent(object sender, Event anEvent);
    }

    public interface IImplantTemplateNotificationService
    {
        event EventHandler<ImplantTemplate> OnCreateImplantTemplate;
        event EventHandler<ImplantTemplate> OnEditImplantTemplate;
        event EventHandler<int> OnDeleteImplantTemplate;
    }

    public interface IGruntNotificationService
    {
        event EventHandler<Grunt> OnCreateGrunt;
        event EventHandler<Grunt> OnEditGrunt;
        event EventHandler<int> OnDeleteGrunt;
        Task NotifyCreateGrunt(object sender, Grunt grunt);
        Task NotifyEditGrunt(object sender, Grunt grunt);
    }

    public interface IReferenceAssemblyNotificationService
    {
        event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly;
        event EventHandler<ReferenceAssembly> OnEditReferenceAssembly;
        event EventHandler<int> OnDeleteReferenceAssembly;
    }

    public interface IEmbeddedResourceNotificationService
    {
        event EventHandler<EmbeddedResource> OnCreateEmbeddedResource;
        event EventHandler<EmbeddedResource> OnEditEmbeddedResource;
        event EventHandler<int> OnDeleteEmbeddedResource;
    }

    public interface IReferenceSourceLibraryNotificationService
    {
        event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary;
        event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary;
        event EventHandler<int> OnDeleteReferenceSourceLibrary;
    }

    public interface IGruntTaskOptionNotificationService
    {
        event EventHandler<GruntTaskOption> OnCreateGruntTaskOption;
        event EventHandler<GruntTaskOption> OnEditGruntTaskOption;
        event EventHandler<int> OnDeleteGruntTaskOption;
    }

    public interface IGruntTaskNotificationService : IReferenceAssemblyNotificationService, IEmbeddedResourceNotificationService,
        IReferenceSourceLibraryNotificationService, IGruntTaskOptionNotificationService
    {
        event EventHandler<GruntTask> OnCreateGruntTask;
        event EventHandler<GruntTask> OnEditGruntTask;
        event EventHandler<int> OnDeleteGruntTask;
    }

    public interface IGruntCommandNotificationService
    {
        event EventHandler<GruntCommand> OnCreateGruntCommand;
        event EventHandler<GruntCommand> OnEditGruntCommand;
        event EventHandler<int> OnDeleteGruntCommand;
        Task NotifyCreateGruntCommand(object sender, GruntCommand command);
        Task NotifyEditGruntCommand(object sender, GruntCommand command);
    }

    public interface ICommandOutputNotificationService
    {
        event EventHandler<CommandOutput> OnCreateCommandOutput;
        event EventHandler<CommandOutput> OnEditCommandOutput;
        event EventHandler<int> OnDeleteCommandOutput;
        Task NotifyEditCommandOutput(object sender, CommandOutput output);
        Task NotifyCreateCommandOutput(object sender, CommandOutput output);
    }

    public interface IGruntTaskingNotificationService
    {
        event EventHandler<GruntTasking> OnCreateGruntTasking;
        event EventHandler<GruntTasking> OnEditGruntTasking;
        event EventHandler<int> OnDeleteGruntTasking;
        Task NotifyCreateGruntTasking(object sender, GruntTasking tasking);
        Task NotifyEditGruntTasking(object sender, GruntTasking tasking);
    }

    public interface ICredentialNotificationService
    {
        event EventHandler<CapturedCredential> OnCreateCapturedCredential;
        event EventHandler<CapturedCredential> OnEditCapturedCredential;
        event EventHandler<int> OnDeleteCapturedCredential;
    }

    public interface IIndicatorNotificationService
    {
        event EventHandler<Indicator> OnCreateIndicator;
        event EventHandler<Indicator> OnEditIndicator;
        event EventHandler<int> OnDeleteIndicator;
    }

    public interface IListenerTypeNotificationService
    {
        event EventHandler<ListenerType> OnCreateListenerType;
        event EventHandler<ListenerType> OnEditListenerType;
        event EventHandler<int> OnDeleteListenerType;
    }

    public interface IListenerNotificationService : IListenerTypeNotificationService
    {
        event EventHandler<Listener> OnCreateListener;
        event EventHandler<Listener> OnEditListener;
        event EventHandler<int> OnDeleteListener;
        event EventHandler<Grunt> OnNotifyListener;
        Task NotifyNotifyListener(object sender, Grunt grunt);
        Task NotifyCreateListener(object sender, Listener listener);
        Task NotifyEditListener(object sender, Listener listener);
    }

    public interface IProfileNotificationService
    {
        event EventHandler<Profile> OnCreateProfile;
        event EventHandler<Profile> OnEditProfile;
        event EventHandler<int> OnDeleteProfile;
    }

    public interface IHostedFileNotificationService
    {
        event EventHandler<HostedFile> OnCreateHostedFile;
        event EventHandler<HostedFile> OnEditHostedFile;
        event EventHandler<int> OnDeleteHostedFile;
    }

    public interface ILauncherNotificationService
    {
        event EventHandler<Launcher> OnCreateLauncher;
        event EventHandler<Launcher> OnEditLauncher;
        event EventHandler<int> OnDeleteLauncher;
    }

    public interface INotificationService : ICovenantUserNotificationService, IIdentityRoleNotificationService, IIdentityUserRoleNotificationService, IThemeNotificationService,
        IEventNotificationService, IImplantTemplateNotificationService, IGruntNotificationService, IGruntTaskNotificationService,
        IGruntCommandNotificationService, ICommandOutputNotificationService, IGruntTaskingNotificationService,
        ICredentialNotificationService, IIndicatorNotificationService, IListenerNotificationService, IProfileNotificationService,
        IHostedFileNotificationService, ILauncherNotificationService
    {
        
    }

    public class NotificationService : INotificationService
    {
        private readonly IHubContext<GruntHub> _gruntHub;
        private readonly IHubContext<EventHub> _eventHub;
        public NotificationService(IHubContext<GruntHub> grunthub, IHubContext<EventHub> eventhub)
        {
            _gruntHub = grunthub;
            _eventHub = eventhub;
            this.OnNotifyListener += async (sender, egressGrunt) =>
            {
                await _gruntHub.Clients.Group(egressGrunt.Listener.GUID).SendAsync("NotifyListener", egressGrunt.GUID);
            };
            this.OnCreateEvent += async (sender, theEvent) => {
                await _eventHub.Clients.Group(theEvent.Context).SendAsync("ReceiveEvent", theEvent);
            };
        }

        public event EventHandler<CovenantUser> OnCreateCovenantUser = delegate { };
        public event EventHandler<CovenantUser> OnEditCovenantUser = delegate { };
        public event EventHandler<string> OnDeleteCovenantUser = delegate { };
        public event EventHandler<IdentityRole> OnCreateIdentityRole = delegate { };
        public event EventHandler<IdentityRole> OnEditIdentityRole = delegate { };
        public event EventHandler<string> OnDeleteIdentityRole = delegate { };
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
        public event EventHandler<int> OnDeleteGrunt = delegate { };
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
        public event EventHandler<int> OnDeleteGruntTasking = delegate { };
        public event EventHandler<CapturedCredential> OnCreateCapturedCredential = delegate { };
        public event EventHandler<CapturedCredential> OnEditCapturedCredential = delegate { };
        public event EventHandler<int> OnDeleteCapturedCredential = delegate { };
        public event EventHandler<Indicator> OnCreateIndicator = delegate { };
        public event EventHandler<Indicator> OnEditIndicator = delegate { };
        public event EventHandler<int> OnDeleteIndicator = delegate { };
        public event EventHandler<ListenerType> OnCreateListenerType = delegate { };
        public event EventHandler<ListenerType> OnEditListenerType = delegate { };
        public event EventHandler<int> OnDeleteListenerType = delegate { };
        public event EventHandler<Listener> OnCreateListener = delegate { };
        public event EventHandler<Listener> OnEditListener = delegate { };
        public event EventHandler<int> OnDeleteListener = delegate { };
        public event EventHandler<Grunt> OnNotifyListener = delegate { };
        public event EventHandler<Profile> OnCreateProfile = delegate { };
        public event EventHandler<Profile> OnEditProfile = delegate { };
        public event EventHandler<int> OnDeleteProfile = delegate { };
        public event EventHandler<HostedFile> OnCreateHostedFile = delegate { };
        public event EventHandler<HostedFile> OnEditHostedFile = delegate { };
        public event EventHandler<int> OnDeleteHostedFile = delegate { };
        public event EventHandler<Launcher> OnCreateLauncher = delegate { };
        public event EventHandler<Launcher> OnEditLauncher = delegate { };
        public event EventHandler<int> OnDeleteLauncher = delegate { };
        public async Task NotifyCreateCovenantUser(object sender, CovenantUser user) { await Task.Run(() => this.OnCreateCovenantUser(sender, user)); }
        public async Task NotifyEditCovenantUser(object sender, CovenantUser user) { await Task.Run(() => this.OnEditCovenantUser(sender, user)); }
        public async Task NotifyDeleteCovenantUser(object sender, string id) { await Task.Run(() => this.OnDeleteCovenantUser(sender, id)); }

        public async Task NotifyCreateTheme(object sender, Theme theme) { await Task.Run(() => this.OnCreateTheme(sender, theme)); }
        public async Task NotifyEditTheme(object sender, Theme theme) { await Task.Run(() => this.OnEditTheme(sender, theme)); }
        public async Task NotifyDeleteTheme(object sender, int id) { await Task.Run(() => this.OnDeleteTheme(sender, id)); }

        public async Task NotifyCreateEvent(object sender, Event anEvent) { await Task.Run(() => this.OnCreateEvent(sender, anEvent)); }

        public async Task NotifyCreateGrunt(object sender, Grunt grunt) { await Task.Run(() => this.OnCreateGrunt(sender, grunt)); }
        public async Task NotifyEditGrunt(object sender, Grunt grunt) { await Task.Run(() => this.OnEditGrunt(sender, grunt)); }

        public async Task NotifyCreateGruntCommand(object sender, GruntCommand command) { await Task.Run(() => this.OnCreateGruntCommand(sender, command)); }
        public async Task NotifyEditGruntCommand(object sender, GruntCommand command) { await Task.Run(() => this.OnEditGruntCommand(sender, command)); }

        public async Task NotifyCreateCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnCreateCommandOutput(sender, output)); }
        public async Task NotifyEditCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnEditCommandOutput(sender, output)); }

        public async Task NotifyCreateGruntTasking(object sender, GruntTasking tasking) { await Task.Run(() => this.OnCreateGruntTasking(sender, tasking)); }
        public async Task NotifyEditGruntTasking(object sender, GruntTasking tasking) { await Task.Run(() => this.OnEditGruntTasking(sender, tasking)); }

        public async Task NotifyNotifyListener(object sender, Grunt grunt) { await Task.Run(() => this.OnNotifyListener(sender, grunt)); }

        public async Task NotifyCreateListener(object sender, Listener listener) { await Task.Run(() => this.OnCreateListener(sender, listener)); }
        public async Task NotifyEditListener(object sender, Listener listener) { await Task.Run(() => this.OnEditListener(sender, listener)); }
    }
}