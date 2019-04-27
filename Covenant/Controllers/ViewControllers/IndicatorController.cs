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
    public class IndicatorController : Controller
    {
        private readonly CovenantAPI _client;

        public IndicatorController(IConfiguration configuration)
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

        // GET: /indicator/
        public async Task<IActionResult> Index()
        {
            ViewBag.TargetIndicators = await _client.ApiIndicatorsTargetsGetAsync();
            ViewBag.NetworkIndicators = await _client.ApiIndicatorsNetworksGetAsync();
            ViewBag.FileIndicators = await _client.ApiIndicatorsFilesGetAsync();
            return View(await _client.ApiIndicatorsGetAsync());
        }
    }
}
