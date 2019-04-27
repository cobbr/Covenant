using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

using Covenant.Core;
using Covenant.API;
using Covenant.API.Models;

namespace Covenant.Controllers
{
    [Authorize]
    public class CovenantUserController : Controller
    {
        private readonly CovenantAPI _client;

        public CovenantUserController(IConfiguration configuration)
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

        // GET: /users/
        public async Task<IActionResult> Index()
        {
            return View(await _client.ApiUsersGetAsync());
        }
    }
}
