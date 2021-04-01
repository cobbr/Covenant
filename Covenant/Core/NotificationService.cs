using System;
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
        Task NotifyCreateIdentityRole(object sender, IdentityRole role);
        Task NotifyEditIdentityRole(object sender, IdentityRole role);
        Task NotifyDeleteIdentityRole(object sender, string id);
    }

    public interface IIdentityUserRoleNotificationService
    {
        event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole;
        event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole;
        event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole;
        Task NotifyCreateIdentityUserRole(object sender, IdentityUserRole<string> userRole);
        Task NotifyEditIdentityUserRole(object sender, IdentityUserRole<string> userRole);
        Task NotifyDeleteIdentityUserRole(object sender, Tuple<string, string> ids);
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
        Task NotifyEditEvent(object sender, Event anEvent);
        Task NotifyDeleteEvent(object sender, int id);
    }

    public interface IImplantTemplateNotificationService
    {
        event EventHandler<ImplantTemplate> OnCreateImplantTemplate;
        event EventHandler<ImplantTemplate> OnEditImplantTemplate;
        event EventHandler<int> OnDeleteImplantTemplate;
        Task NotifyCreateImplantTemplate(object sender, ImplantTemplate template);
        Task NotifyEditImplantTemplate(object sender, ImplantTemplate template);
        Task NotifyDeleteImplantTemplate(object sender, int id);
    }

    public interface IGruntNotificationService
    {
        event EventHandler<Grunt> OnCreateGrunt;
        event EventHandler<Grunt> OnEditGrunt;
        event EventHandler<int> OnDeleteGrunt;
        Task NotifyCreateGrunt(object sender, Grunt grunt);
        Task NotifyEditGrunt(object sender, Grunt grunt);
        Task NotifyDeleteGrunt(object sender, int id);
    }

    public interface IReferenceAssemblyNotificationService
    {
        event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly;
        event EventHandler<ReferenceAssembly> OnEditReferenceAssembly;
        event EventHandler<int> OnDeleteReferenceAssembly;
        Task NotifyCreateReferenceAssembly(object sender, ReferenceAssembly assembly);
        Task NotifyEditReferenceAssembly(object sender, ReferenceAssembly assembly);
        Task NotifyDeleteReferenceAssembly(object sender, int id);
    }

    public interface IEmbeddedResourceNotificationService
    {
        event EventHandler<EmbeddedResource> OnCreateEmbeddedResource;
        event EventHandler<EmbeddedResource> OnEditEmbeddedResource;
        event EventHandler<int> OnDeleteEmbeddedResource;
        Task NotifyCreateEmbeddedResource(object sender, EmbeddedResource resource);
        Task NotifyEditEmbeddedResource(object sender, EmbeddedResource resource);
        Task NotifyDeleteEmbeddedResource(object sender, int id);
    }

    public interface IReferenceSourceLibraryNotificationService
    {
        event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary;
        event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary;
        event EventHandler<int> OnDeleteReferenceSourceLibrary;
        Task NotifyCreateReferenceSourceLibrary(object sender, ReferenceSourceLibrary library);
        Task NotifyEditReferenceSourceLibrary(object sender, ReferenceSourceLibrary library);
        Task NotifyDeleteReferenceSourceLibrary(object sender, int id);
    }

    public interface IGruntTaskOptionNotificationService
    {
        event EventHandler<GruntTaskOption> OnCreateGruntTaskOption;
        event EventHandler<GruntTaskOption> OnEditGruntTaskOption;
        event EventHandler<int> OnDeleteGruntTaskOption;
        Task NotifyCreateGruntTaskOption(object sender, GruntTaskOption option);
        Task NotifyEditGruntTaskOption(object sender, GruntTaskOption option);
        Task NotifyDeleteGruntTaskOption(object sender, int id);
    }

    public interface IGruntTaskAuthorNotificationService
    {
        event EventHandler<GruntTaskAuthor> OnCreateGruntTaskAuthor;
        event EventHandler<GruntTaskAuthor> OnEditGruntTaskAuthor;
        event EventHandler<int> OnDeleteGruntTaskAuthor;
        Task NotifyCreateGruntTaskAuthor(object sender, GruntTaskAuthor author);
        Task NotifyEditGruntTaskAuthor(object sender, GruntTaskAuthor author);
        Task NotifyDeleteGruntTaskAuthor(object sender, int id);
    }

    public interface IGruntTaskNotificationService : IReferenceAssemblyNotificationService, IEmbeddedResourceNotificationService,
        IReferenceSourceLibraryNotificationService, IGruntTaskOptionNotificationService, IGruntTaskAuthorNotificationService
    {
        event EventHandler<GruntTask> OnCreateGruntTask;
        event EventHandler<GruntTask> OnEditGruntTask;
        event EventHandler<int> OnDeleteGruntTask;
        Task NotifyCreateGruntTask(object sender, GruntTask gruntTask);
        Task NotifyEditGruntTask(object sender, GruntTask gruntTask);
        Task NotifyDeleteGruntTask(object sender, int id);
    }

    public interface IGruntCommandNotificationService
    {
        event EventHandler<GruntCommand> OnCreateGruntCommand;
        event EventHandler<GruntCommand> OnEditGruntCommand;
        event EventHandler<int> OnDeleteGruntCommand;
        Task NotifyCreateGruntCommand(object sender, GruntCommand command);
        Task NotifyEditGruntCommand(object sender, GruntCommand command);
        Task NotifyDeleteGruntCommand(object sender, int id);
    }

    public interface ICommandOutputNotificationService
    {
        event EventHandler<CommandOutput> OnCreateCommandOutput;
        event EventHandler<CommandOutput> OnEditCommandOutput;
        event EventHandler<int> OnDeleteCommandOutput;
        Task NotifyEditCommandOutput(object sender, CommandOutput output);
        Task NotifyCreateCommandOutput(object sender, CommandOutput output);
        Task NotifyDeleteCommandOutput(object sender, int id);
    }

    public interface IGruntTaskingNotificationService
    {
        event EventHandler<GruntTasking> OnCreateGruntTasking;
        event EventHandler<GruntTasking> OnEditGruntTasking;
        event EventHandler<int> OnDeleteGruntTasking;
        Task NotifyCreateGruntTasking(object sender, GruntTasking tasking);
        Task NotifyEditGruntTasking(object sender, GruntTasking tasking);
        Task NotifyDeleteGruntTasking(object sender, int id);
    }

    public interface IFolderFilerNotificationService
    {
        event EventHandler<Folder> OnCreateFolder;
        event EventHandler<Folder> OnEditFolder;
        event EventHandler<int> OnDeleteFolder;
        Task NotifyCreateFolder(object sender, Folder folder);
        Task NotifyEditFolder(object sender, Folder folder);
        Task NotifyDeleteFolder(object sender, int id);
        event EventHandler<FolderFile> OnCreateFolderFile;
        event EventHandler<FolderFile> OnEditFolderFile;
        event EventHandler<int> OnDeleteFolderFile;
        Task NotifyCreateFolderFile(object sender, FolderFile file);
        Task NotifyEditFolderFile(object sender, FolderFile file);
        Task NotifyDeleteFolderFile(object sender, int id);
    }

    public interface ICredentialNotificationService
    {
        event EventHandler<CapturedCredential> OnCreateCapturedCredential;
        event EventHandler<CapturedCredential> OnEditCapturedCredential;
        event EventHandler<int> OnDeleteCapturedCredential;
        Task NotifyCreateCapturedCredential(object sender, CapturedCredential credential);
        Task NotifyEditCapturedCredential(object sender, CapturedCredential credential);
        Task NotifyDeleteCapturedCredential(object sender, int id);
    }

    public interface IIndicatorNotificationService
    {
        event EventHandler<Indicator> OnCreateIndicator;
        event EventHandler<Indicator> OnEditIndicator;
        event EventHandler<int> OnDeleteIndicator;
        Task NotifyCreateIndicator(object sender, Indicator indicator);
        Task NotifyEditIndicator(object sender, Indicator indicator);
        Task NotifyDeleteIndicator(object sender, int id);
    }

    public interface IListenerTypeNotificationService
    {
        event EventHandler<ListenerType> OnCreateListenerType;
        event EventHandler<ListenerType> OnEditListenerType;
        event EventHandler<int> OnDeleteListenerType;
        Task NotifyCreateListenerType(object sender, ListenerType type);
        Task NotifyEditListenerType(object sender, ListenerType type);
        Task NotifyDeleteListenerType(object sender, int id);
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
        Task NotifyDeleteListener(object sender, int id);
    }

    public interface IProfileNotificationService
    {
        event EventHandler<Profile> OnCreateProfile;
        event EventHandler<Profile> OnEditProfile;
        event EventHandler<int> OnDeleteProfile;
        Task NotifyCreateProfile(object sender, Profile profile);
        Task NotifyEditProfile(object sender, Profile profile);
        Task NotifyDeleteProfile(object sender, int id);
    }

    public interface IHostedFileNotificationService
    {
        event EventHandler<HostedFile> OnCreateHostedFile;
        event EventHandler<HostedFile> OnEditHostedFile;
        event EventHandler<int> OnDeleteHostedFile;
        Task NotifyCreateHostedFile(object sender, HostedFile file);
        Task NotifyEditHostedFile(object sender, HostedFile file);
        Task NotifyDeleteHostedFile(object sender, int id);
    }

    public interface ILauncherNotificationService
    {
        event EventHandler<Launcher> OnCreateLauncher;
        event EventHandler<Launcher> OnEditLauncher;
        event EventHandler<int> OnDeleteLauncher;
        Task NotifyCreateLauncher(object sender, Launcher launcher);
        Task NotifyEditLauncher(object sender, Launcher launcher);
        Task NotifyDeleteLauncher(object sender, int id);
    }

    public interface INotificationService : ICovenantUserNotificationService, IIdentityRoleNotificationService, IIdentityUserRoleNotificationService, IThemeNotificationService,
        IEventNotificationService, IImplantTemplateNotificationService, IGruntNotificationService, IGruntTaskNotificationService,
        IGruntCommandNotificationService, ICommandOutputNotificationService, IGruntTaskingNotificationService, IFolderFilerNotificationService,
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
        public event EventHandler<GruntTaskAuthor> OnCreateGruntTaskAuthor;
        public event EventHandler<GruntTaskAuthor> OnEditGruntTaskAuthor;
        public event EventHandler<int> OnDeleteGruntTaskAuthor;
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
        public event EventHandler<Folder> OnCreateFolder = delegate { };
        public event EventHandler<Folder> OnEditFolder = delegate { };
        public event EventHandler<int> OnDeleteFolder = delegate { };
        public event EventHandler<FolderFile> OnCreateFolderFile = delegate { };
        public event EventHandler<FolderFile> OnEditFolderFile = delegate { };
        public event EventHandler<int> OnDeleteFolderFile = delegate { };
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

        public async Task NotifyCreateCovenantUser(object sender, CovenantUser user) => await Task.Run(() => this.OnCreateCovenantUser(sender, user));
        public async Task NotifyEditCovenantUser(object sender, CovenantUser user) => await Task.Run(() => this.OnEditCovenantUser(sender, user));
        public async Task NotifyDeleteCovenantUser(object sender, string id) => await Task.Run(() => this.OnDeleteCovenantUser(sender, id));

        public async Task NotifyCreateIdentityRole(object sender, IdentityRole role) => await Task.Run(() => this.OnCreateIdentityRole(sender, role));
        public async Task NotifyEditIdentityRole(object sender, IdentityRole role) => await Task.Run(() => this.OnEditIdentityRole(sender, role));
        public async Task NotifyDeleteIdentityRole(object sender, string id) => await Task.Run(() => this.OnDeleteCovenantUser(sender, id));

        public async Task NotifyCreateIdentityUserRole(object sender, IdentityUserRole<string> userRole) => await Task.Run(() => this.OnCreateIdentityUserRole(sender, userRole));
        public async Task NotifyEditIdentityUserRole(object sender, IdentityUserRole<string> userRole) => await Task.Run(() => this.OnEditIdentityUserRole(sender, userRole));
        public async Task NotifyDeleteIdentityUserRole(object sender, Tuple<string, string> ids) => await Task.Run(() => this.OnDeleteIdentityUserRole(sender, ids));

        public async Task NotifyCreateTheme(object sender, Theme theme) => await Task.Run(() => this.OnCreateTheme(sender, theme));
        public async Task NotifyEditTheme(object sender, Theme theme) => await Task.Run(() => this.OnEditTheme(sender, theme));
        public async Task NotifyDeleteTheme(object sender, int id) => await Task.Run(() => this.OnDeleteTheme(sender, id));

        public async Task NotifyCreateEvent(object sender, Event anEvent) => await Task.Run(() => this.OnCreateEvent(sender, anEvent));
        public async Task NotifyEditEvent(object sender, Event anEvent) => await Task.Run(() => this.OnEditEvent(sender, anEvent));
        public async Task NotifyDeleteEvent(object sender, int id) => await Task.Run(() => this.OnDeleteEvent(sender, id));

        public async Task NotifyCreateImplantTemplate(object sender, ImplantTemplate template) => await Task.Run(() => this.OnCreateImplantTemplate(sender, template));
        public async Task NotifyEditImplantTemplate(object sender, ImplantTemplate template) => await Task.Run(() => this.OnEditImplantTemplate(sender, template));
        public async Task NotifyDeleteImplantTemplate(object sender, int id) => await Task.Run(() => this.OnDeleteImplantTemplate(sender, id));

        public async Task NotifyCreateGrunt(object sender, Grunt grunt) => await Task.Run(() => this.OnCreateGrunt(sender, grunt));
        public async Task NotifyEditGrunt(object sender, Grunt grunt) => await Task.Run(() => this.OnEditGrunt(sender, grunt));
        public async Task NotifyDeleteGrunt(object sender, int id) => await Task.Run(() => this.OnDeleteGrunt(sender, id));

        public async Task NotifyCreateReferenceAssembly(object sender, ReferenceAssembly assembly) => await Task.Run(() => this.OnCreateReferenceAssembly(sender, assembly));
        public async Task NotifyEditReferenceAssembly(object sender, ReferenceAssembly assembly) => await Task.Run(() => this.OnEditReferenceAssembly(sender, assembly));
        public async Task NotifyDeleteReferenceAssembly(object sender, int id) => await Task.Run(() => this.OnDeleteReferenceAssembly(sender, id));

        public async Task NotifyCreateEmbeddedResource(object sender, EmbeddedResource resource) => await Task.Run(() => this.OnCreateEmbeddedResource(sender, resource));
        public async Task NotifyEditEmbeddedResource(object sender, EmbeddedResource resource) => await Task.Run(() => this.OnEditEmbeddedResource(sender, resource));
        public async Task NotifyDeleteEmbeddedResource(object sender, int id) => await Task.Run(() => this.OnDeleteEmbeddedResource(sender, id));

        public async Task NotifyCreateReferenceSourceLibrary(object sender, ReferenceSourceLibrary library) => await Task.Run(() => this.OnCreateReferenceSourceLibrary(sender, library));
        public async Task NotifyEditReferenceSourceLibrary(object sender, ReferenceSourceLibrary library) => await Task.Run(() => this.OnEditReferenceSourceLibrary(sender, library));
        public async Task NotifyDeleteReferenceSourceLibrary(object sender, int id) => await Task.Run(() => this.OnDeleteReferenceSourceLibrary(sender, id));

        public async Task NotifyCreateGruntTaskOption(object sender, GruntTaskOption option) => await Task.Run(() => this.OnCreateGruntTaskOption(sender, option));
        public async Task NotifyEditGruntTaskOption(object sender, GruntTaskOption option) => await Task.Run(() => this.OnEditGruntTaskOption(sender, option));
        public async Task NotifyDeleteGruntTaskOption(object sender, int id) => await Task.Run(() => this.OnDeleteGruntTaskOption(sender, id));

        public async Task NotifyCreateGruntTaskAuthor(object sender, GruntTaskAuthor author) => await Task.Run(() => this.OnCreateGruntTaskAuthor(sender, author));
        public async Task NotifyEditGruntTaskAuthor(object sender, GruntTaskAuthor author) => await Task.Run(() => this.OnEditGruntTaskAuthor(sender, author));
        public async Task NotifyDeleteGruntTaskAuthor(object sender, int id) => await Task.Run(() => this.OnDeleteGruntTaskAuthor(sender, id));

        public async Task NotifyCreateGruntTask(object sender, GruntTask gruntTask) => await Task.Run(() => this.OnCreateGruntTask(sender, gruntTask));
        public async Task NotifyEditGruntTask(object sender, GruntTask gruntTask) => await Task.Run(() => this.OnEditGruntTask(sender, gruntTask));
        public async Task NotifyDeleteGruntTask(object sender, int id) => await Task.Run(() => this.OnDeleteGruntTask(sender, id)); 

        public async Task NotifyCreateGruntCommand(object sender, GruntCommand command) => await Task.Run(() => this.OnCreateGruntCommand(sender, command));
        public async Task NotifyEditGruntCommand(object sender, GruntCommand command) => await Task.Run(() => this.OnEditGruntCommand(sender, command));
        public async Task NotifyDeleteGruntCommand(object sender, int id) => await Task.Run(() => this.OnDeleteGruntCommand(sender, id));

        public async Task NotifyCreateCommandOutput(object sender, CommandOutput output) => await Task.Run(() => this.OnCreateCommandOutput(sender, output));
        public async Task NotifyEditCommandOutput(object sender, CommandOutput output) => await Task.Run(() => this.OnEditCommandOutput(sender, output));
        public async Task NotifyDeleteCommandOutput(object sender, int id) => await Task.Run(() => this.OnDeleteCommandOutput(sender, id));

        public async Task NotifyCreateGruntTasking(object sender, GruntTasking tasking) => await Task.Run(() => this.OnCreateGruntTasking(sender, tasking));
        public async Task NotifyEditGruntTasking(object sender, GruntTasking tasking) => await Task.Run(() => this.OnEditGruntTasking(sender, tasking));
        public async Task NotifyDeleteGruntTasking(object sender, int id) => await Task.Run(() => this.OnDeleteGruntTasking(sender, id));

        public async Task NotifyCreateFolder(object sender, Folder folder) => await Task.Run(() => this.OnCreateFolder(sender, folder));
        public async Task NotifyEditFolder(object sender, Folder folder) => await Task.Run(() => this.OnEditFolder(sender, folder));
        public async Task NotifyDeleteFolder(object sender, int id) => await Task.Run(() => this.OnDeleteFolder(sender, id));
        public async Task NotifyCreateFolderFile(object sender, FolderFile file) => await Task.Run(() => this.OnCreateFolderFile(sender, file));
        public async Task NotifyEditFolderFile(object sender, FolderFile file) => await Task.Run(() => this.OnEditFolderFile(sender, file));
        public async Task NotifyDeleteFolderFile(object sender, int id) => await Task.Run(() => this.OnDeleteFolderFile(sender, id));

        public async Task NotifyCreateCapturedCredential(object sender, CapturedCredential credential) => await Task.Run(() => this.OnCreateCapturedCredential(sender, credential));
        public async Task NotifyEditCapturedCredential(object sender, CapturedCredential credential) => await Task.Run(() => this.OnEditCapturedCredential(sender, credential));
        public async Task NotifyDeleteCapturedCredential(object sender, int id) => await Task.Run(() => this.OnDeleteCapturedCredential(sender, id));

        public async Task NotifyCreateIndicator(object sender, Indicator indicator) => await Task.Run(() => this.OnCreateIndicator(sender, indicator));
        public async Task NotifyEditIndicator(object sender, Indicator indicator) => await Task.Run(() => this.OnEditIndicator(sender, indicator));
        public async Task NotifyDeleteIndicator(object sender, int id) => await Task.Run(() => this.OnDeleteIndicator(sender, id));

        public async Task NotifyCreateListenerType(object sender, ListenerType type) => await Task.Run(() => this.OnCreateListenerType(sender, type));
        public async Task NotifyEditListenerType(object sender, ListenerType type) => await Task.Run(() => this.OnEditListenerType(sender, type));
        public async Task NotifyDeleteListenerType(object sender, int id) => await Task.Run(() => this.OnDeleteListenerType(sender, id));

        public async Task NotifyNotifyListener(object sender, Grunt grunt) => await Task.Run(() => this.OnNotifyListener(sender, grunt));
        public async Task NotifyCreateListener(object sender, Listener listener) => await Task.Run(() => this.OnCreateListener(sender, listener));
        public async Task NotifyEditListener(object sender, Listener listener) => await Task.Run(() => this.OnEditListener(sender, listener));
        public async Task NotifyDeleteListener(object sender, int id) => await Task.Run(() => this.OnDeleteListener(sender, id));

        public async Task NotifyCreateProfile(object sender, Profile profile) => await Task.Run(() => this.OnCreateProfile(sender, profile));
        public async Task NotifyEditProfile(object sender, Profile profile) => await Task.Run(() => this.OnEditProfile(sender, profile));
        public async Task NotifyDeleteProfile(object sender, int id) => await Task.Run(() => this.OnDeleteProfile(sender, id));

        public async Task NotifyCreateHostedFile(object sender, HostedFile file) => await Task.Run(() => this.OnCreateHostedFile(sender, file));
        public async Task NotifyEditHostedFile(object sender, HostedFile file) => await Task.Run(() => this.OnEditHostedFile(sender, file));
        public async Task NotifyDeleteHostedFile(object sender, int id) => await Task.Run(() => this.OnDeleteHostedFile(sender, id));

        public async Task NotifyCreateLauncher(object sender, Launcher launcher) => await Task.Run(() => this.OnCreateLauncher(sender, launcher));
        public async Task NotifyEditLauncher(object sender, Launcher launcher) => await Task.Run(() => this.OnEditLauncher(sender, launcher));
        public async Task NotifyDeleteLauncher(object sender, int id) => await Task.Run(() => this.OnDeleteLauncher(sender, id));
    }
}