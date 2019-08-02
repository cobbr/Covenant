using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers.ViewControllers
{
    [Authorize]
    public class DataController : Controller
    {
        private readonly CovenantContext _context;

        public DataController(CovenantContext context)
        {
            _context = context;
        }

        // GET: /data/
        public async Task<IActionResult> Index()
        {
            ViewBag.PasswordCredentials = await _context.GetPasswordCredentials();
            ViewBag.HashCredentials = await _context.GetHashCredentials();
            ViewBag.TicketCredentials = await _context.GetTicketCredentials();
            ViewBag.TargetIndicators = await _context.GetTargetIndicators();
            ViewBag.NetworkIndicators = await _context.GetNetworkIndicators();
            ViewBag.FileIndicators = await _context.GetFileIndicators();
            ViewBag.DownloadEvents = await _context.GetDownloadEvents();
            return View();
        }

        public async Task<IActionResult> Download(int id)
        {
            try
            {
                DownloadEvent ev = await _context.GetDownloadEvent(id);
                return File(Convert.FromBase64String(ev.FileContents), "plain/text", ev.FileName);
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }
    }
}
