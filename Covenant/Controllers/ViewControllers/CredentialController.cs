// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [Authorize]
    public class CredentialController : Controller
    {
        private readonly CovenantContext _context;

        public CredentialController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route("Credential"), Route("Credential/Index")]
        public async Task<IActionResult> Index()
        {
            ViewBag.PasswordCredentials = await _context.GetPasswordCredentials();
            ViewBag.HashCredentials = await _context.GetHashCredentials();
            ViewBag.TicketCredentials = await _context.GetTicketCredentials();
            return View(await _context.GetCredentials());
        }

        [Authorize, HttpGet, Route("Credential/Create")]
        public IActionResult Create()
        {
            return View(new CapturedCredential());
        }

        [Authorize, HttpPost, Route("Credential/CreatePasswordCredential")]
        public async Task<IActionResult> CreatePasswordCredential(CapturedPasswordCredential credential)
        {
            CapturedCredential createdCredential = await _context.CreatePasswordCredential(credential);
            return RedirectToAction("Index", "Data");
        }

        [Authorize, HttpPost, Route("Credential/CreateHashCredential")]
        public async Task<IActionResult> CreateHashCredential(CapturedHashCredential credential)
        {
            CapturedCredential createdCredential = await _context.CreateHashCredential(credential);
            return RedirectToAction("Index", "Data");
        }

        [Authorize, HttpPost, Route("Credential/CreateTicketCredential")]
        public async Task<IActionResult> CreateTicketCredential(CapturedTicketCredential credential)
        {
            CapturedCredential createdCredential = await _context.CreateTicketCredential(credential);
            return RedirectToAction("Index", "Data");
        }
    }
}
