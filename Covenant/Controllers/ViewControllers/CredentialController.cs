using System;
using System.Collections.Generic;
using System.Linq;
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

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Covenant.Controllers
{
    [Authorize]
    public class CredentialController : Controller
    {
        private readonly CovenantAPI _client;

        public CredentialController(IConfiguration configuration)
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

        // GET: /credential/
        public async Task<IActionResult> Index()
        {
            ViewBag.PasswordCredentials = await _client.ApiCredentialsPasswordsGetAsync();
            ViewBag.HashCredentials = await _client.ApiCredentialsHashesGetAsync();
            ViewBag.TicketCredentials = await _client.ApiCredentialsTicketsGetAsync();
            return View(await _client.ApiCredentialsGetAsync());
        }
    }
}
