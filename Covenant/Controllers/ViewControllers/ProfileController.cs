// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;

        public ProfileController(CovenantContext context, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [Authorize, HttpGet, Route("Profile"), Route("Profile/Index")]
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

        [Authorize, HttpGet, Route("Profile/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                return View(await _context.GetProfile(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        [Authorize, HttpPost, Route("Profile/EditHttp")]
        public async Task<IActionResult> EditHttp(HttpProfile profile)
        {
            try
            {
                await _context.EditHttpProfile(profile, await _userManager.GetUserAsync(HttpContext.User));
                return RedirectToAction("Index", "Listener");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        [Authorize, HttpPost, Route("Profile/EditBridge")]
        public async Task<IActionResult> EditBridge(BridgeProfile profile)
        {
            try
            {
                await _context.EditBridgeProfile(profile, await _userManager.GetUserAsync(HttpContext.User));
                return RedirectToAction("Index", "Listener");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        [Authorize, HttpGet, Route("Profile/Create")]
        public IActionResult Create()
        {
            try
            {
                return View();
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        [Authorize, HttpPost, Route("Profile/CreateHttp")]
        public async Task<IActionResult> CreateHttp(HttpProfile profile)
        {
            try
            {
                await _context.CreateHttpProfile(profile, await _userManager.GetUserAsync(HttpContext.User));
                return RedirectToAction("Index", "Listener");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }

        [Authorize, HttpPost, Route("Profile/CreateBridge")]
        public async Task<IActionResult> CreateBridge(BridgeProfile profile)
        {
            try
            {
                await _context.CreateBridgeProfile(profile, await _userManager.GetUserAsync(HttpContext.User));
                return RedirectToAction("Index", "Listener");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Listener");
            }
        }
    }
}
