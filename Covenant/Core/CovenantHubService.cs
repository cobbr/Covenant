using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.CodeAnalysis;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Configuration;

using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;
using Covenant.Models.Launchers;
using Covenant.Models.Indicators;

namespace Covenant.Core
{
    public class CovenantHubService : IRemoteCovenantService
    {
        private HubConnection _connection;
        public CovenantHubService(IConfiguration configuration)
        {
            X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return true;
                }
            };
            _connection = new HubConnectionBuilder()
                .WithUrl("https://localhost:" + configuration["CovenantPort"] + "/covenantHub", options =>
                {
                    options.AccessTokenProvider = () => { return Task.FromResult(configuration["ServiceUserToken"]); };
                    options.HttpMessageHandlerFactory = inner =>
                    {
                        var HttpClientHandler = (HttpClientHandler)inner;
                        HttpClientHandler.ServerCertificateCustomValidationCallback = clientHandler.ServerCertificateCustomValidationCallback;
                        return HttpClientHandler;
                    };
                })
                .Build();
            _connection.Closed += async (error) =>
            {
                await Task.Delay(new Random().Next(0, 5) * 1000);
                await _connection.StartAsync();
            };
            _connection.HandshakeTimeout = TimeSpan.FromSeconds(8);
            try
            {
                _connection.StartAsync().Wait();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("InternalListener SignalRConnection Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        public Task<byte[]> CompileGruntExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            return _connection.InvokeAsync<byte[]>("CompileGruntExecutorCode", id, outputKind, Compress);
        }

        public Task<byte[]> CompileGruntStagerCode(int id, Launcher launcher)
        {
            return _connection.InvokeAsync<byte[]>("CompileGruntStagerCode", id, launcher);
        }

        public Task<BridgeListener> CreateBridgeListener(BridgeListener listener)
        {
            return _connection.InvokeAsync<BridgeListener>("CreateBridgeListener", listener);
        }

        public Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, CovenantUser currentUser)
        {
            return _connection.InvokeAsync<BridgeProfile>("CreateBridgeProfile", profile, currentUser);
        }

        public Task<CommandOutput> CreateCommandOutput(CommandOutput output)
        {
            return _connection.InvokeAsync<CommandOutput>("CreateCommandOutput", output);
        }

        public Task<IEnumerable<CommandOutput>> CreateCommandOutputs(params CommandOutput[] outputs)
        {
            return _connection.InvokeAsync<IEnumerable<CommandOutput>>("CreateCommandOutputs", outputs);
        }

        public Task<IEnumerable<CapturedCredential>> CreateCredentials(params CapturedCredential[] credentials)
        {
            return _connection.InvokeAsync<IEnumerable<CapturedCredential>>("CreateCredentials", credentials);
        }

        public Task<DownloadEvent> CreateDownloadEvent(DownloadEvent downloadEvent)
        {
            return _connection.InvokeAsync<DownloadEvent>("CreateDownloadEvent", downloadEvent);
        }

        public Task<EmbeddedResource> CreateEmbeddedResource(EmbeddedResource resource)
        {
            return _connection.InvokeAsync<EmbeddedResource>("CreateEmbeddedResource", resource);
        }

        public Task<IEnumerable<EmbeddedResource>> CreateEmbeddedResources(params EmbeddedResource[] resources)
        {
            return _connection.InvokeAsync<IEnumerable<EmbeddedResource>>("CreateEmbeddedResources", resources);
        }

        public Task<Event> CreateEvent(Event anEvent)
        {
            return _connection.InvokeAsync<Event>("CreateEvent", anEvent);
        }

        public Task<IEnumerable<Event>> CreateEvents(params Event[] events)
        {
            return _connection.InvokeAsync<IEnumerable<Event>>("CreateEvents", events);
        }

        public Task<Grunt> CreateGrunt(Grunt grunt)
        {
            return _connection.InvokeAsync<Grunt>("CreateGrunt", grunt);
        }

        public Task<GruntCommand> CreateGruntCommand(GruntCommand command)
        {
            return _connection.InvokeAsync<GruntCommand>("CreateGruntCommand", command);
        }

        public Task<IEnumerable<GruntCommand>> CreateGruntCommands(params GruntCommand[] commands)
        {
            return _connection.InvokeAsync<IEnumerable<GruntCommand>>("CreateGruntCommands", commands);
        }

        public Task<IEnumerable<Grunt>> CreateGrunts(params Grunt[] grunts)
        {
            return _connection.InvokeAsync<IEnumerable<Grunt>>("CreateGrunts", grunts);
        }

        public Task<GruntTask> CreateGruntTask(GruntTask task)
        {
            return _connection.InvokeAsync<GruntTask>("CreateGruntTask", task);
        }

        public Task<GruntTasking> CreateGruntTasking(GruntTasking tasking)
        {
            return _connection.InvokeAsync<GruntTasking>("CreateGruntTasking", tasking);
        }

        public Task<IEnumerable<GruntTasking>> CreateGruntTaskings(params GruntTasking[] taskings)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTasking>>("CreateGruntTaskings", taskings);
        }

        public Task<GruntTaskOption> CreateGruntTaskOption(GruntTaskOption option)
        {
            return _connection.InvokeAsync<GruntTaskOption>("CreateGruntTaskOption", option);
        }

        public Task<IEnumerable<GruntTaskOption>> CreateGruntTaskOptions(params GruntTaskOption[] options)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTaskOption>>("CreateGruntTaskOptions", options);
        }

        public Task<IEnumerable<GruntTask>> CreateGruntTasks(params GruntTask[] tasks)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTask>>("CreateGruntTasks", tasks);
        }

        public Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential)
        {
            return _connection.InvokeAsync<CapturedHashCredential>("CreateHashCredential", credential);
        }

        public Task<HostedFile> CreateHostedFile(HostedFile file)
        {
            return _connection.InvokeAsync<HostedFile>("CreateHostedFile", file);
        }

        public Task<IEnumerable<HostedFile>> CreateHostedFiles(params HostedFile[] files)
        {
            return _connection.InvokeAsync<IEnumerable<HostedFile>>("CreateHostedFiles", files);
        }

        public Task<HttpListener> CreateHttpListener(HttpListener listener)
        {
            return _connection.InvokeAsync<HttpListener>("CreateHttpListener", listener);
        }

        public Task<HttpProfile> CreateHttpProfile(HttpProfile profile, CovenantUser currentUser)
        {
            return _connection.InvokeAsync<HttpProfile>("CreateHttpProfile", profile, currentUser);
        }

        public Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template)
        {
            return _connection.InvokeAsync<ImplantTemplate>("CreateImplantTemplate", template);
        }

        public Task<IEnumerable<ImplantTemplate>> CreateImplantTemplates(params ImplantTemplate[] templates)
        {
            return _connection.InvokeAsync<IEnumerable<ImplantTemplate>>("CreateImplantTemplates", templates);
        }

        public Task<Indicator> CreateIndicator(Indicator indicator)
        {
            return _connection.InvokeAsync<Indicator>("CreateIndicator", indicator);
        }

        public Task<IEnumerable<Indicator>> CreateIndicators(params Indicator[] indicators)
        {
            return _connection.InvokeAsync<IEnumerable<Indicator>>("CreateIndicators", indicators);
        }

        public Task<IEnumerable<Listener>> CreateListeners(params Listener[] entities)
        {
            return _connection.InvokeAsync<IEnumerable<Listener>>("CreateListeners", entities);
        }

        public Task<CapturedPasswordCredential> CreatePasswordCredential(CapturedPasswordCredential credential)
        {
            return _connection.InvokeAsync<CapturedPasswordCredential>("CreatePasswordCredential", credential);
        }

        public Task<Profile> CreateProfile(Profile profile, CovenantUser currentUser)
        {
            return _connection.InvokeAsync<Profile>("CreateProfile", profile, currentUser);
        }

        public Task<IEnumerable<Profile>> CreateProfiles(params Profile[] profiles)
        {
            return _connection.InvokeAsync<IEnumerable<Profile>>("CreateProfiles", profiles);
        }

        public Task<IEnumerable<ReferenceAssembly>> CreateReferenceAssemblies(params ReferenceAssembly[] assemblies)
        {
            return _connection.InvokeAsync<IEnumerable<ReferenceAssembly>>("CreateReferenceAssemblies", assemblies);
        }

        public Task<ReferenceAssembly> CreateReferenceAssembly(ReferenceAssembly assembly)
        {
            return _connection.InvokeAsync<ReferenceAssembly>("CreateReferenceAssembly", assembly);
        }

        public Task<IEnumerable<ReferenceSourceLibrary>> CreateReferenceSourceLibraries(params ReferenceSourceLibrary[] libraries)
        {
            return _connection.InvokeAsync<IEnumerable<ReferenceSourceLibrary>>("CreateReferenceSourceLibraries", libraries);
        }

        public Task<ReferenceSourceLibrary> CreateReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            return _connection.InvokeAsync<ReferenceSourceLibrary>("CreateReferenceSourceLibrary", library);
        }

        public Task<ScreenshotEvent> CreateScreenshotEvent(ScreenshotEvent screenshotEvent)
        {
            return _connection.InvokeAsync<ScreenshotEvent>("CreateScreenshotEvent", screenshotEvent);
        }

        public Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential)
        {
            return _connection.InvokeAsync<CapturedTicketCredential>("CreateTicketCredential", credential);
        }

        public Task<Theme> CreateTheme(Theme theme)
        {
            return _connection.InvokeAsync<Theme>("CreateTheme", theme);
        }

        public Task<CovenantUser> CreateUser(CovenantUserLogin login)
        {
            return _connection.InvokeAsync<CovenantUser>("CreateUser", login);
        }

        public Task<IdentityUserRole<string>> CreateUserRole(string userId, string roleId)
        {
            return _connection.InvokeAsync<IdentityUserRole<string>>("CreateUserRole", userId, roleId);
        }

        public Task<CovenantUser> CreateUserVerify(ClaimsPrincipal principal, CovenantUserRegister register)
        {
            return _connection.InvokeAsync<CovenantUser>("CreateUserVerify", principal, register);
        }

        public Task DeleteCommandOutput(int id)
        {
            return _connection.InvokeAsync("DeleteCommandOutput", id);
        }

        public Task DeleteCredential(int credentialId)
        {
            return _connection.InvokeAsync("DeleteCredential", credentialId);
        }

        public Task DeleteEmbeddedResource(int id)
        {
            return _connection.InvokeAsync("DeleteEmbeddedResource", id);
        }

        public Task DeleteGrunt(int gruntId)
        {
            return _connection.InvokeAsync("DeleteGrunt", gruntId);
        }

        public Task DeleteGruntCommand(int id)
        {
            return _connection.InvokeAsync("DeleteGruntCommand", id);
        }

        public Task DeleteGruntTask(int taskId)
        {
            return _connection.InvokeAsync("DeleteGruntTask", taskId);
        }

        public Task DeleteGruntTasking(int taskingId)
        {
            return _connection.InvokeAsync("DeleteGruntTasking", taskingId);
        }

        public Task DeleteHostedFile(int listenerId, int hostedFileId)
        {
            return _connection.InvokeAsync("DeleteHostedFile", listenerId, hostedFileId);
        }

        public Task DeleteImplantTemplate(int id)
        {
            return _connection.InvokeAsync("DeleteImplantTemplate", id);
        }

        public Task DeleteIndicator(int indicatorId)
        {
            return _connection.InvokeAsync("DeleteIndicator", indicatorId);
        }

        public Task DeleteListener(int listenerId)
        {
            return _connection.InvokeAsync("DeleteListener", listenerId);
        }

        public Task DeleteProfile(int id)
        {
            return _connection.InvokeAsync("DeleteProfile", id);
        }

        public Task DeleteReferenceAssembly(int id)
        {
            return _connection.InvokeAsync("DeleteReferenceAssembly", id);
        }

        public Task DeleteReferenceSourceLibrary(int id)
        {
            return _connection.InvokeAsync("DeleteReferenceSourceLibrary", id);
        }

        public Task DeleteTheme(int id)
        {
            return _connection.InvokeAsync("DeleteTheme", id);
        }

        public Task DeleteUser(string userId)
        {
            return _connection.InvokeAsync("DeleteUser", userId);
        }

        public Task DeleteUserRole(string userId, string roleId)
        {
            return _connection.InvokeAsync("DeleteUserRole", userId, roleId);
        }

        public Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher)
        {
            return _connection.InvokeAsync<BinaryLauncher>("EditBinaryLauncher", launcher);
        }

        public Task<BridgeListener> EditBridgeListener(BridgeListener listener)
        {
            return _connection.InvokeAsync<BridgeListener>("EditBridgeListener", listener);
        }

        public Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, CovenantUser currentUser)
        {
            return _connection.InvokeAsync<BridgeProfile>("EditBridgeProfile", profile, currentUser);
        }

        public Task<CommandOutput> EditCommandOutput(CommandOutput output)
        {
            return _connection.InvokeAsync<CommandOutput>("EditCommandOutput", output);
        }

        public Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher)
        {
            return _connection.InvokeAsync<CscriptLauncher>("EditCscriptLauncher", launcher);
        }

        public Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource)
        {
            return _connection.InvokeAsync<EmbeddedResource>("EditEmbeddedResource", resource);
        }

        public Task<Grunt> EditGrunt(Grunt grunt, CovenantUser user)
        {
            return _connection.InvokeAsync<Grunt>("EditGrunt", grunt, user);
        }

        public Task<GruntCommand> EditGruntCommand(GruntCommand command)
        {
            return _connection.InvokeAsync<GruntCommand>("EditGruntCommand", command);
        }

        public Task<GruntTask> EditGruntTask(GruntTask task)
        {
            return _connection.InvokeAsync<GruntTask>("EditGruntTask", task);
        }

        public Task<GruntTasking> EditGruntTasking(GruntTasking tasking)
        {
            return _connection.InvokeAsync<GruntTasking>("EditGruntTasking", tasking);
        }

        public Task<GruntTaskOption> EditGruntTaskOption(GruntTaskOption option)
        {
            return _connection.InvokeAsync<GruntTaskOption>("EditGruntTaskOption", option);
        }

        public Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential)
        {
            return _connection.InvokeAsync<CapturedHashCredential>("EditHashCredential", credential);
        }

        public Task<HostedFile> EditHostedFile(int listenerId, HostedFile file)
        {
            return _connection.InvokeAsync<HostedFile>("EditHostedFile", listenerId, file);
        }

        public Task<HttpListener> EditHttpListener(HttpListener listener)
        {
            return _connection.InvokeAsync<HttpListener>("EditHttpListener", listener);
        }

        public Task<HttpProfile> EditHttpProfile(HttpProfile profile, CovenantUser currentUser)
        {
            return _connection.InvokeAsync<HttpProfile>("EditHttpProfile", profile, currentUser);
        }

        public Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template)
        {
            return _connection.InvokeAsync<ImplantTemplate>("EditImplantTemplate", template);
        }

        public Task<Indicator> EditIndicator(Indicator indicator)
        {
            return _connection.InvokeAsync<Indicator>("EditIndicator", indicator);
        }

        public Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher)
        {
            return _connection.InvokeAsync<InstallUtilLauncher>("EditInstallUtilLauncher", launcher);
        }

        public Task<Listener> EditListener(Listener listener)
        {
            return _connection.InvokeAsync<Listener>("EditListener", listener);
        }

        public Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher)
        {
            return _connection.InvokeAsync<MSBuildLauncher>("EditMSBuildLauncher", launcher);
        }

        public Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher)
        {
            return _connection.InvokeAsync<MshtaLauncher>("EditMshtaLauncher", launcher);
        }

        public Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential)
        {
            return _connection.InvokeAsync<CapturedPasswordCredential>("EditPasswordCredential", credential);
        }

        public Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher)
        {
            return _connection.InvokeAsync<PowerShellLauncher>("EditPowerShellLauncher", launcher);
        }

        public Task<Profile> EditProfile(Profile profile, CovenantUser currentUser)
        {
            return _connection.InvokeAsync<Profile>("EditProfile", profile, currentUser);
        }

        public Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly)
        {
            return _connection.InvokeAsync<ReferenceAssembly>("EditReferenceAssembly", assembly);
        }

        public Task<ReferenceSourceLibrary> EditReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            return _connection.InvokeAsync<ReferenceSourceLibrary>("EditReferenceSourceLibrary", library);
        }

        public Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher)
        {
            return _connection.InvokeAsync<Regsvr32Launcher>("EditRegsvr32Launcher", launcher);
        }

        public Task<ShellCodeLauncher> EditShellCodeLauncher(ShellCodeLauncher launcher)
        {
            return _connection.InvokeAsync<ShellCodeLauncher>("EditShellCodeLauncher", launcher);
        }

        public Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential)
        {
            return _connection.InvokeAsync<CapturedTicketCredential>("EditTicketCredential", credential);
        }

        public Task<Theme> EditTheme(Theme theme)
        {
            return _connection.InvokeAsync<Theme>("EditTheme", theme);
        }

        public Task<CovenantUser> EditUser(CovenantUser currentUser)
        {
            return _connection.InvokeAsync<CovenantUser>("EditUser", currentUser);
        }

        public Task<CovenantUser> EditUserPassword(CovenantUser currentUser, CovenantUserLogin user)
        {
            return _connection.InvokeAsync<CovenantUser>("EditUserPassword", currentUser, user);
        }

        public Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher)
        {
            return _connection.InvokeAsync<WmicLauncher>("EditWmicLauncher", launcher);
        }

        public Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher)
        {
            return _connection.InvokeAsync<WscriptLauncher>("EditWscriptLauncher", launcher);
        }

        public Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<BinaryLauncher>("GenerateBinaryHostedLauncher", file);
        }

        public Task<BinaryLauncher> GenerateBinaryLauncher()
        {
            return _connection.InvokeAsync<BinaryLauncher>("GenerateBinaryLauncher");
        }

        public Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<CscriptLauncher>("GenerateCscriptHostedLauncher", file);
        }

        public Task<CscriptLauncher> GenerateCscriptLauncher()
        {
            return _connection.InvokeAsync<CscriptLauncher>("GenerateCscriptLauncher");
        }

        public Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<InstallUtilLauncher>("GenerateInstallUtilHostedLauncher", file);
        }

        public Task<InstallUtilLauncher> GenerateInstallUtilLauncher()
        {
            return _connection.InvokeAsync<InstallUtilLauncher>("GenerateInstallUtilLauncher");
        }

        public Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<MSBuildLauncher>("GenerateMSBuildHostedLauncher", file);
        }

        public Task<MSBuildLauncher> GenerateMSBuildLauncher()
        {
            return _connection.InvokeAsync<MSBuildLauncher>("GenerateMSBuildLauncher");
        }

        public Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<MshtaLauncher>("GenerateMshtaHostedLauncher", file);
        }

        public Task<MshtaLauncher> GenerateMshtaLauncher()
        {
            return _connection.InvokeAsync<MshtaLauncher>("GenerateMshtaLauncher");
        }

        public Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<PowerShellLauncher>("GeneratePowerShellHostedLauncher", file);
        }

        public Task<PowerShellLauncher> GeneratePowerShellLauncher()
        {
            return _connection.InvokeAsync<PowerShellLauncher>("GeneratePowerShellLauncher");
        }

        public Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<Regsvr32Launcher>("GenerateRegsvr32HostedLauncher", file);
        }

        public Task<Regsvr32Launcher> GenerateRegsvr32Launcher()
        {
            return _connection.InvokeAsync<Regsvr32Launcher>("GenerateRegsvr32Launcher");
        }

        public Task<ShellCodeLauncher> GenerateShellCodeHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<ShellCodeLauncher>("GenerateShellCodeHostedLauncher", file);
        }

        public Task<ShellCodeLauncher> GenerateShellCodeLauncher()
        {
            return _connection.InvokeAsync<ShellCodeLauncher>("GenerateShellCodeLauncher");
        }

        public Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<WmicLauncher>("GenerateWmicHostedLauncher", file);
        }

        public Task<WmicLauncher> GenerateWmicLauncher()
        {
            return _connection.InvokeAsync<WmicLauncher>("GenerateWmicLauncher");
        }

        public Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file)
        {
            return _connection.InvokeAsync<WscriptLauncher>("GenerateWscriptHostedLauncher", file);
        }

        public Task<WscriptLauncher> GenerateWscriptLauncher()
        {
            return _connection.InvokeAsync<WscriptLauncher>("GenerateWscriptLauncher");
        }

        public Task<BinaryLauncher> GetBinaryLauncher()
        {
            return _connection.InvokeAsync<BinaryLauncher>("GetBinaryLauncher");
        }

        public Task<BridgeListener> GetBridgeListener(int listenerId)
        {
            return _connection.InvokeAsync<BridgeListener>("GetBridgeListener", listenerId);
        }

        public Task<IEnumerable<BridgeListener>> GetBridgeListeners()
        {
            return _connection.InvokeAsync<IEnumerable<BridgeListener>>("GetBridgeListeners");
        }

        public Task<BridgeProfile> GetBridgeProfile(int profileId)
        {
            return _connection.InvokeAsync<BridgeProfile>("GetBridgeProfile", profileId);
        }

        public Task<IEnumerable<BridgeProfile>> GetBridgeProfiles()
        {
            return _connection.InvokeAsync<IEnumerable<BridgeProfile>>("GetBridgeProfiles");
        }

        public Task<CommandOutput> GetCommandOutput(int commandOutputId)
        {
            return _connection.InvokeAsync<CommandOutput>("GetCommandOutput", commandOutputId);
        }

        public Task<IEnumerable<CommandOutput>> GetCommandOutputs()
        {
            return _connection.InvokeAsync<IEnumerable<CommandOutput>>("GetCommandOutputs");
        }

        public Task<List<string>> GetCommandSuggestionsForGrunt(Grunt grunt)
        {
            return _connection.InvokeAsync<List<string>>("GetCommandSuggestionsForGrunt", grunt);
        }

        public Task<CapturedCredential> GetCredential(int credentialId)
        {
            return _connection.InvokeAsync<CapturedCredential>("GetCredential", credentialId);
        }

        public Task<IEnumerable<CapturedCredential>> GetCredentials()
        {
            return _connection.InvokeAsync<IEnumerable<CapturedCredential>>("GetCredentials");
        }

        public Task<CscriptLauncher> GetCscriptLauncher()
        {
            return _connection.InvokeAsync<CscriptLauncher>("GetCscriptLauncher");
        }

        public Task<CovenantUser> GetCurrentUser(ClaimsPrincipal principal)
        {
            return _connection.InvokeAsync<CovenantUser>("GetCurrentUser", principal);
        }

        public Task<IEnumerable<ReferenceAssembly>> GetDefaultNet35ReferenceAssemblies()
        {
            return _connection.InvokeAsync<IEnumerable<ReferenceAssembly>>("GetDefaultNet35ReferenceAssemblies");
        }

        public Task<IEnumerable<ReferenceAssembly>> GetDefaultNet40ReferenceAssemblies()
        {
            return _connection.InvokeAsync<IEnumerable<ReferenceAssembly>>("GetDefaultNet40ReferenceAssemblies");
        }

        public Task<string> GetDownloadContent(int eventId)
        {
            return _connection.InvokeAsync<string>("GetDownloadContent", eventId);
        }

        public Task<DownloadEvent> GetDownloadEvent(int eventId)
        {
            return _connection.InvokeAsync<DownloadEvent>("GetDownloadEvent", eventId);
        }

        public Task<IEnumerable<DownloadEvent>> GetDownloadEvents()
        {
            return _connection.InvokeAsync<IEnumerable<DownloadEvent>>("GetDownloadEvents");
        }

        public Task<EmbeddedResource> GetEmbeddedResource(int id)
        {
            return _connection.InvokeAsync<EmbeddedResource>("GetEmbeddedResource", id);
        }

        public Task<EmbeddedResource> GetEmbeddedResourceByName(string name)
        {
            return _connection.InvokeAsync<EmbeddedResource>("GetEmbeddedResourceByName", name);
        }

        public Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources()
        {
            return _connection.InvokeAsync<IEnumerable<EmbeddedResource>>("GetEmbeddedResources");
        }

        public Task<Event> GetEvent(int eventId)
        {
            return _connection.InvokeAsync<Event>("GetEvent", eventId);
        }

        public Task<IEnumerable<Event>> GetEvents()
        {
            return _connection.InvokeAsync<IEnumerable<Event>>("GetEvents");
        }

        public Task<IEnumerable<Event>> GetEventsAfter(long fromdate)
        {
            return _connection.InvokeAsync<IEnumerable<Event>>("GetEventsAfter", fromdate);
        }

        public Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate)
        {
            return _connection.InvokeAsync<IEnumerable<Event>>("GetEventsRange", fromdate, todate);
        }

        public Task<long> GetEventTime()
        {
            return _connection.InvokeAsync<long>("GetEventTime");
        }

        public Task<FileIndicator> GetFileIndicator(int indicatorId)
        {
            return _connection.InvokeAsync<FileIndicator>("GetFileIndicator", indicatorId);
        }

        public Task<IEnumerable<FileIndicator>> GetFileIndicators()
        {
            return _connection.InvokeAsync<IEnumerable<FileIndicator>>("GetFileIndicators");
        }

        public Task<Grunt> GetGrunt(int gruntId)
        {
            return _connection.InvokeAsync<Grunt>("GetGrunt", gruntId);
        }

        public Task<Grunt> GetGruntByGUID(string guid)
        {
            return _connection.InvokeAsync<Grunt>("GetGruntByGUID", guid);
        }

        public Task<Grunt> GetGruntByName(string name)
        {
            return _connection.InvokeAsync<Grunt>("GetGruntByName", name);
        }

        public Task<Grunt> GetGruntByOriginalServerGUID(string serverguid)
        {
            return _connection.InvokeAsync<Grunt>("GetGruntByOriginalServerGUID", serverguid);
        }

        public Task<GruntCommand> GetGruntCommand(int id)
        {
            return _connection.InvokeAsync<GruntCommand>("GetGruntCommand", id);
        }

        public Task<IEnumerable<GruntCommand>> GetGruntCommands()
        {
            return _connection.InvokeAsync<IEnumerable<GruntCommand>>("GetGruntCommands");
        }

        public Task<IEnumerable<GruntCommand>> GetGruntCommandsForGrunt(int gruntId)
        {
            return _connection.InvokeAsync<IEnumerable<GruntCommand>>("GetGruntCommandsForGrunt", gruntId);
        }

        public Task<IEnumerable<Grunt>> GetGrunts()
        {
            return _connection.InvokeAsync<IEnumerable<Grunt>>("GetGrunts");
        }

        public Task<GruntTask> GetGruntTask(int id)
        {
            return _connection.InvokeAsync<GruntTask>("GetGruntTask", id);
        }

        public Task<GruntTask> GetGruntTaskByName(string name, Common.DotNetVersion version = Common.DotNetVersion.Net35)
        {
            return _connection.InvokeAsync<GruntTask>("GetGruntTaskByName", name, version);
        }

        public Task<GruntTasking> GetGruntTasking(int taskingId)
        {
            return _connection.InvokeAsync<GruntTasking>("GetGruntTasking", taskingId);
        }

        public Task<GruntTasking> GetGruntTaskingByName(string taskingName)
        {
            return _connection.InvokeAsync<GruntTasking>("GetGruntTaskingByName", taskingName);
        }

        public Task<IEnumerable<GruntTasking>> GetGruntTaskings()
        {
            return _connection.InvokeAsync<IEnumerable<GruntTasking>>("GetGruntTaskings");
        }

        public Task<IEnumerable<GruntTasking>> GetGruntTaskingsForGrunt(int gruntId)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTasking>>("GetGruntTaskingsForGrunt", gruntId);
        }

        public Task<IEnumerable<GruntTasking>> GetGruntTaskingsSearch(int gruntId)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTasking>>("GetGruntTaskingsSearch", gruntId);
        }

        public Task<IEnumerable<GruntTask>> GetGruntTasks()
        {
            return _connection.InvokeAsync<IEnumerable<GruntTask>>("GetGruntTasks");
        }

        public Task<IEnumerable<GruntTask>> GetGruntTasksForGrunt(int gruntId)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTask>>("GetGruntTasks", gruntId);
        }

        public Task<CapturedHashCredential> GetHashCredential(int credentialId)
        {
            return _connection.InvokeAsync<CapturedHashCredential>("GetHashCredential", credentialId);
        }

        public Task<IEnumerable<CapturedHashCredential>> GetHashCredentials()
        {
            return _connection.InvokeAsync<IEnumerable<CapturedHashCredential>>("GetHashCredentials");
        }

        public Task<HostedFile> GetHostedFile(int hostedFileId)
        {
            return _connection.InvokeAsync<HostedFile>("GetHostedFile", hostedFileId);
        }

        public Task<HostedFile> GetHostedFileForListener(int listenerId, int hostedFileId)
        {
            return _connection.InvokeAsync<HostedFile>("GetHostedFileForListener", listenerId, hostedFileId);
        }

        public Task<IEnumerable<HostedFile>> GetHostedFiles()
        {
            return _connection.InvokeAsync<IEnumerable<HostedFile>>("GetHostedFiles");
        }

        public Task<IEnumerable<HostedFile>> GetHostedFilesForListener(int listenerId)
        {
            return _connection.InvokeAsync<IEnumerable<HostedFile>>("GetHostedFilesForListener", listenerId);
        }

        public Task<HttpListener> GetHttpListener(int listenerId)
        {
            return _connection.InvokeAsync<HttpListener>("GetHttpListener", listenerId);
        }

        public Task<IEnumerable<HttpListener>> GetHttpListeners()
        {
            return _connection.InvokeAsync<IEnumerable<HttpListener>>("GetHttpListeners");
        }

        public Task<HttpProfile> GetHttpProfile(int profileId)
        {
            return _connection.InvokeAsync<HttpProfile>("GetHttpProfile", profileId);
        }

        public Task<IEnumerable<HttpProfile>> GetHttpProfiles()
        {
            return _connection.InvokeAsync<IEnumerable<HttpProfile>>("GetHttpProfiles");
        }

        public Task<ImplantTemplate> GetImplantTemplate(int id)
        {
            return _connection.InvokeAsync<ImplantTemplate>("GetImplantTemplate", id);
        }

        public Task<ImplantTemplate> GetImplantTemplateByName(string name)
        {
            return _connection.InvokeAsync<ImplantTemplate>("GetImplantTemplateByName", name);
        }

        public Task<IEnumerable<ImplantTemplate>> GetImplantTemplates()
        {
            return _connection.InvokeAsync<IEnumerable<ImplantTemplate>>("GetImplantTemplates");
        }

        public Task<Indicator> GetIndicator(int indicatorId)
        {
            return _connection.InvokeAsync<Indicator>("GetIndicator", indicatorId);
        }

        public Task<IEnumerable<Indicator>> GetIndicators()
        {
            return _connection.InvokeAsync<IEnumerable<Indicator>>("GetIndicators");
        }

        public Task<InstallUtilLauncher> GetInstallUtilLauncher()
        {
            return _connection.InvokeAsync<InstallUtilLauncher>("GetInstallUtilLauncher");
        }

        public Task<Launcher> GetLauncher(int id)
        {
            return _connection.InvokeAsync<Launcher>("GetLauncher", id);
        }

        public Task<IEnumerable<Launcher>> GetLaunchers()
        {
            return _connection.InvokeAsync<IEnumerable<Launcher>>("GetLaunchers");
        }

        public Task<Listener> GetListener(int listenerId)
        {
            return _connection.InvokeAsync<Listener>("GetListener", listenerId);
        }

        public Task<IEnumerable<Listener>> GetListeners()
        {
            return _connection.InvokeAsync<IEnumerable<Listener>>("GetListeners");
        }

        public Task<ListenerType> GetListenerType(int listenerTypeId)
        {
            return _connection.InvokeAsync<ListenerType>("GetListenerType", listenerTypeId);
        }

        public Task<ListenerType> GetListenerTypeByName(string name)
        {
            return _connection.InvokeAsync<ListenerType>("GetListenerTypeByName", name);
        }

        public Task<IEnumerable<ListenerType>> GetListenerTypes()
        {
            return _connection.InvokeAsync<IEnumerable<ListenerType>>("GetListenerTypes");
        }

        public Task<MSBuildLauncher> GetMSBuildLauncher()
        {
            return _connection.InvokeAsync<MSBuildLauncher>("GetMSBuildLauncher");
        }

        public Task<MshtaLauncher> GetMshtaLauncher()
        {
            return _connection.InvokeAsync<MshtaLauncher>("GetMshtaLauncher");
        }

        public Task<NetworkIndicator> GetNetworkIndicator(int indicatorId)
        {
            return _connection.InvokeAsync<NetworkIndicator>("GetNetworkIndicator", indicatorId);
        }

        public Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators()
        {
            return _connection.InvokeAsync<IEnumerable<NetworkIndicator>>("GetNetworkIndicators");
        }

        public Task<Grunt> GetOutboundGrunt(int gruntId)
        {
            return _connection.InvokeAsync<Grunt>("GetOutboundGrunt", gruntId);
        }

        public Task<CapturedPasswordCredential> GetPasswordCredential(int credentialId)
        {
            return _connection.InvokeAsync<CapturedPasswordCredential>("GetPasswordCredential", credentialId);
        }

        public Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials()
        {
            return _connection.InvokeAsync<IEnumerable<CapturedPasswordCredential>>("GetPasswordCredentials");
        }

        public Task<List<string>> GetPathToChildGrunt(int gruntId, int childId)
        {
            return _connection.InvokeAsync<List<string>>("GetPathToChildGrunt", gruntId, childId);
        }

        public Task<PowerShellLauncher> GetPowerShellLauncher()
        {
            return _connection.InvokeAsync<PowerShellLauncher>("GetPowerShellLauncher");
        }

        public Task<Profile> GetProfile(int profileId)
        {
            return _connection.InvokeAsync<Profile>("GetProfile", profileId);
        }

        public Task<IEnumerable<Profile>> GetProfiles()
        {
            return _connection.InvokeAsync<IEnumerable<Profile>>("GetProfiles");
        }

        public Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies()
        {
            return _connection.InvokeAsync<IEnumerable<ReferenceAssembly>>("GetReferenceAssemblies");
        }

        public Task<ReferenceAssembly> GetReferenceAssembly(int id)
        {
            return _connection.InvokeAsync<ReferenceAssembly>("GetReferenceAssembly", id);
        }

        public Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version)
        {
            return _connection.InvokeAsync<ReferenceAssembly>("GetReferenceAssemblyByName", name, version);
        }

        public Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries()
        {
            return _connection.InvokeAsync<IEnumerable<ReferenceSourceLibrary>>("GetReferenceSourceLibraries");
        }

        public Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id)
        {
            return _connection.InvokeAsync<ReferenceSourceLibrary>("GetReferenceSourceLibrary", id);
        }

        public Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name)
        {
            return _connection.InvokeAsync<ReferenceSourceLibrary>("GetReferenceSourceLibraryByName", name);
        }

        public Task<Regsvr32Launcher> GetRegsvr32Launcher()
        {
            return _connection.InvokeAsync<Regsvr32Launcher>("GetRegsvr32Launcher");
        }

        public Task<IdentityRole> GetRole(string roleId)
        {
            return _connection.InvokeAsync<IdentityRole>("GetRole", roleId);
        }

        public Task<IdentityRole> GetRoleByName(string rolename)
        {
            return _connection.InvokeAsync<IdentityRole>("GetRoleByName", rolename);
        }

        public Task<IEnumerable<IdentityRole>> GetRoles()
        {
            return _connection.InvokeAsync<IEnumerable<IdentityRole>>("GetRoles");
        }

        public Task<string> GetScreenshotContent(int eventId)
        {
            return _connection.InvokeAsync<string>("GetScreenshotContent", eventId);
        }

        public Task<ScreenshotEvent> GetScreenshotEvent(int eventId)
        {
            return _connection.InvokeAsync<ScreenshotEvent>("GetScreenshotEvent", eventId);
        }

        public Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents()
        {
            return _connection.InvokeAsync<IEnumerable<ScreenshotEvent>>("GetScreenshotEvents");
        }

        public Task<ShellCodeLauncher> GetShellCodeLauncher()
        {
            return _connection.InvokeAsync<ShellCodeLauncher>("GetShellCodeLauncher");
        }

        public Task<TargetIndicator> GetTargetIndicator(int indicatorId)
        {
            return _connection.InvokeAsync<TargetIndicator>("GetTargetIndicator", indicatorId);
        }

        public Task<IEnumerable<TargetIndicator>> GetTargetIndicators()
        {
            return _connection.InvokeAsync<IEnumerable<TargetIndicator>>("GetTargetIndicators");
        }

        public Task<Theme> GetTheme(int id)
        {
            return _connection.InvokeAsync<Theme>("GetTheme", id);
        }

        public Task<IEnumerable<Theme>> GetThemes()
        {
            return _connection.InvokeAsync<IEnumerable<Theme>>("GetThemes");
        }

        public Task<CapturedTicketCredential> GetTicketCredential(int credentialId)
        {
            return _connection.InvokeAsync<CapturedTicketCredential>("GetTicketCredential", credentialId);
        }

        public Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials()
        {
            return _connection.InvokeAsync<IEnumerable<CapturedTicketCredential>>("GetTicketCredentials");
        }

        public Task<IEnumerable<GruntTasking>> GetUninitializedGruntTaskingsForGrunt(int gruntId)
        {
            return _connection.InvokeAsync<IEnumerable<GruntTasking>>("GetUninitializedGruntTaskingsForGrunt", gruntId);
        }

        public Task<CovenantUser> GetUser(string userId)
        {
            return _connection.InvokeAsync<CovenantUser>("GetUser", userId);
        }

        public Task<CovenantUser> GetUserByUsername(string username)
        {
            return _connection.InvokeAsync<CovenantUser>("GetUserByUsername", username);
        }

        public Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId)
        {
            return _connection.InvokeAsync<IdentityUserRole<string>>("GetUserRole", userId, roleId);
        }

        public Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles()
        {
            return _connection.InvokeAsync<IEnumerable<IdentityUserRole<string>>>("GetUserRoles");
        }

        public Task<IEnumerable<IdentityUserRole<string>>> GetUserRolesForUser(string userId)
        {
            return _connection.InvokeAsync<IEnumerable<IdentityUserRole<string>>>("GetUserRolesForUser", userId);
        }

        public Task<IEnumerable<CovenantUser>> GetUsers()
        {
            return _connection.InvokeAsync<IEnumerable<CovenantUser>>("GetUsers");
        }

        public Task<WmicLauncher> GetWmicLauncher()
        {
            return _connection.InvokeAsync<WmicLauncher>("GetWmicLauncher");
        }

        public Task<WscriptLauncher> GetWscriptLauncher()
        {
            return _connection.InvokeAsync<WscriptLauncher>("GetWscriptLauncher");
        }

        public Task<GruntCommand> InteractGrunt(int GruntId, string UserId, string UserInput)
        {
            return _connection.InvokeAsync<GruntCommand>("InteractGrunt", GruntId, UserId, UserInput);
        }

        public Task<bool> IsGruntLost(Grunt g)
        {
            return _connection.InvokeAsync<bool>("IsGruntLost", g);
        }

        public Task<CovenantUserLoginResult> Login(CovenantUserLogin login)
        {
            return _connection.InvokeAsync<CovenantUserLoginResult>("Login", login);
        }

        public Task StartListener(int listenerId)
        {
            return _connection.InvokeAsync("StartListener", listenerId);
        }

        public Task<string> ParseParametersIntoTask(GruntTask task, List<ParsedParameter> parameters)
        {
            return _connection.InvokeAsync<string>("ParseParametersIntoTask", task, parameters);
        }

        public Task<GruntTaskAuthor> GetGruntTaskAuthor(int id)
        {
            return _connection.InvokeAsync<GruntTaskAuthor>("GetGruntTaskAuthor", id);
        }

        public Task<GruntTaskAuthor> GetGruntTaskAuthorByName(string Name)
        {
            return _connection.InvokeAsync<GruntTaskAuthor>("GetGruntTaskAuthorByName", Name);
        }

        public Task<IEnumerable<GruntTaskAuthor>> GetGruntTaskAuthors()
        {
            return _connection.InvokeAsync<IEnumerable<GruntTaskAuthor>>("GetGruntTaskAuthors");
        }

        public Task<GruntTaskAuthor> CreateGruntTaskAuthor(GruntTaskAuthor author)
        {
            return _connection.InvokeAsync<GruntTaskAuthor>("CreateGruntTaskAuthor", author);
        }

        public Task<GruntTaskAuthor> EditGruntTaskAuthor(GruntTaskAuthor author)
        {
            return _connection.InvokeAsync<GruntTaskAuthor>("EditGruntTaskAuthor", author);
        }
    }
}