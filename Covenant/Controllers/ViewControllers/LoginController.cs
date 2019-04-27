using System;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;


using Microsoft.Extensions.Configuration;

using Covenant.Core;
using Covenant.API;
using Covenant.API.Models;

namespace Covenant.Controllers.ViewControllers
{
    public class LoginController : Controller
    {
        private readonly CovenantAPI _client;
        private readonly SignInManager<Covenant.Models.Covenant.CovenantUser> _signInManager;

        public LoginController(SignInManager<Covenant.Models.Covenant.CovenantUser> signInManager, IConfiguration configuration)
        {
            _signInManager = signInManager;
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

        // GET: /login
        public IActionResult Index()
        {
            return View();
        }

        // POST: /login
        [HttpPost]
        public async Task<IActionResult> Index(CovenantUserLogin login)
        {
            try
            {
                var result = await _signInManager.PasswordSignInAsync(login.UserName, login.Password, true, lockoutOnFailure: false);
                if (result.Succeeded == true)
                {
                    Console.WriteLine("Logged in success");
                    return Redirect("/grunt");
                }
                ModelState.AddModelError(string.Empty, "Login Failed");
                return RedirectToAction(nameof(Index));

            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return View();
            }
        }

        // GET: /login/logout
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return RedirectToAction(nameof(Index));
        }
    }
}
