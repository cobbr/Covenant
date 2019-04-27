using System;
using System.Net.Http;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

using Covenant.Core;
using Covenant.API;
using Covenant.API.Models;

namespace Covenant.Controllers
{
    [Authorize]
    public class ListenerController : Controller
    {
        private readonly CovenantAPI _client;

        public ListenerController(IConfiguration configuration)
        {
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
                new TokenCredentials(configuration["CovenantToken"]),
                clientHandler
            );
        }

        // GET: /listener/
        public async Task<IActionResult> Index()
        {
            ViewBag.ListenerTypes = await _client.ApiListenersTypesGetAsync();
            return View(await _client.ApiListenersGetAsync());
        }

        // GET: /listener/http
        public async Task<IActionResult> Http()
        {
            HttpListener listener = await _client.ApiListenersHttpPostAsync(new HttpListener());
            ViewBag.Profiles = await _client.ApiProfilesHttpGetAsync();
            ViewBag.ListenerType =  (await _client.ApiListenersTypesGetAsync()).FirstOrDefault(LT => LT.Name == "HTTP");
            return View(listener);
        }

        // POST: /listener/http
        [HttpPost]
        public async Task<IActionResult> Http(HttpListener listener)
        {
            try
            {
                listener = await _client.ApiListenersHttpPutAsync(listener);
                return RedirectToAction("Index");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Profiles = await _client.ApiProfilesHttpGetAsync();
                ViewBag.ListenerType = (await _client.ApiListenersTypesGetAsync()).FirstOrDefault(LT => LT.Name == "HTTP");
                return View(listener);
            }
        }

        // GET: /listener/interact/{id}
        public async Task<IActionResult> Interact(int id)
        {
            HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(id);
            ViewBag.Profile = await _client.ApiProfilesHttpByIdGetAsync(listener.ProfileId ?? default);
            ViewBag.ListenerType = await _client.ApiListenersTypesByIdGetAsync(listener.ListenerTypeId ?? default);
            return View(listener);
        }

        // POST: /listener/start/{id}
        [HttpPost]
        public async Task<IActionResult> Start(int id)
        {
            HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(id);
            return RedirectToAction("Index");
        }

        // POST: /listener/stop/{id}
        [HttpPost]
        public async Task<IActionResult> Stop(int id)
        {
            HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(id);
            return RedirectToAction("Index");
        }
    }
}
