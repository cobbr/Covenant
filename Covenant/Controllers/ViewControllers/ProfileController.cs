using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly CovenantContext _context;

        public ProfileController(CovenantContext context)
        {
            _context = context;
        }

        // GET: /profile/
        public async Task<IActionResult> Index()
        {
            try
            {
                return View(await _context.GetProfiles());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        // GET: /profile/{id}
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                return View(await _context.GetHttpProfile(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        // POST: /profile/
        [HttpPost]
        public async Task<IActionResult> Edit(HttpProfile profile)
        {
            try
            {
                await _context.EditHttpProfile(profile);
                return RedirectToAction("Index", "Listener");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        // GET: /profile/create
        public IActionResult Create()
        {
            try
            {
                return View(new HttpProfile
                {
                    HttpUrls = new List<string> { "" },
                    HttpCookies = new List<string> { "" },
                    HttpRequestHeaders = new List<HttpProfileHeader> { new HttpProfileHeader { Name = "", Value = "" } },
                    HttpResponseHeaders = new List<HttpProfileHeader> { new HttpProfileHeader {  Name = "", Value = "" } }
                });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        // POST: /profile/
        [HttpPost]
        public async Task<IActionResult> Create(HttpProfile profile)
        {
            try
            {
                await _context.CreateHttpProfile(profile);
                return RedirectToAction("Index", "Listener");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }
    }
}
