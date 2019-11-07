// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;

namespace Covenant.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly CovenantContext _context;

        public HomeController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route(""), Route("Home"), Route("Home/Index")]
        public async Task<IActionResult> Index()
        {
            ViewBag.Grunts = await _context.GetGrunts();
            ViewBag.Listeners = await _context.GetListeners();
            ViewBag.GruntTaskings = await _context.GetGruntTaskings();
            return View();
        }
    }
}
