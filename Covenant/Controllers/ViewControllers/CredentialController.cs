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

        // GET: /credential
        public async Task<IActionResult> Index()
        {
            ViewBag.PasswordCredentials = await _context.GetPasswordCredentials();
            ViewBag.HashCredentials = await _context.GetHashCredentials();
            ViewBag.TicketCredentials = await _context.GetTicketCredentials();
            return View(await _context.GetCredentials());
        }

        // GET: /credential/create
        public IActionResult Create()
        {
            return View(new CapturedCredential());
        }

        // POST: /credential/createpasswordcredential
        [HttpPost]
        public async Task<IActionResult> CreatePasswordCredential(CapturedPasswordCredential credential)
        {
            CapturedCredential createdCredential = await _context.CreatePasswordCredential(credential);
            return RedirectToAction("Index", "Data");
        }

        // POST: /credential/createhashcredential
        [HttpPost]
        public async Task<IActionResult> CreateHashCredential(CapturedHashCredential credential)
        {
            CapturedCredential createdCredential = await _context.CreateHashCredential(credential);
            return RedirectToAction("Index", "Data");
        }

        // POST: /credential/createticketcredential
        [HttpPost]
        public async Task<IActionResult> CreateTicketCredential(CapturedTicketCredential credential)
        {
            CapturedCredential createdCredential = await _context.CreateTicketCredential(credential);
            return RedirectToAction("Index", "Data");
        }
    }
}
