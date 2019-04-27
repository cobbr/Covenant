using System;
using System.Net.Http;
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
    public class HomeController : Controller
    {
        private readonly CovenantAPI _client;

        public HomeController(IConfiguration configuration)
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

        // GET: /grunt
        public async Task<IActionResult> Index()
        {
            ViewBag.Grunts = await _client.ApiGruntsGetAsync();
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View();
        }
    }
}
