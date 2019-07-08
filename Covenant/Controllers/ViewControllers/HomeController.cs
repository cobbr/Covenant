using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

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

        // GET: /
        public async Task<IActionResult> Index()
        {
            ViewBag.Grunts = await _context.GetGrunts();
            ViewBag.Listeners = await _context.GetListeners();
            ViewBag.GruntTaskings = await _context.GetGruntTaskings();
            return View();
        }
    }
}
