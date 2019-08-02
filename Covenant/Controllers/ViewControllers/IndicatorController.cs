using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.Indicators;

namespace Covenant.Controllers
{
    [Authorize]
    public class IndicatorController : Controller
    {
        private readonly CovenantContext _context;

        public IndicatorController(CovenantContext context)
        {
            _context = context;
        }

        // GET: /indicator/
        public async Task<IActionResult> Index()
        {
            ViewBag.TargetIndicators = await _context.GetTargetIndicators();
            ViewBag.NetworkIndicators = await _context.GetNetworkIndicators();
            ViewBag.FileIndicators = await _context.GetFileIndicators();
            return View(await _context.GetIndicators());
        }

        // GET: /indicator/create
        public IActionResult Create()
        {
            return View(new Indicator());
        }

        // POST: /indicator/createfileindicator
        [HttpPost]
        public async Task<IActionResult> CreateFileIndicator(FileIndicator indicator)
        {
            Indicator createdIndicator = await _context.CreateIndicator(indicator);
            return RedirectToAction("Index", "Data");
        }

        // POST: /indicator/createnetworkindicator
        [HttpPost]
        public async Task<IActionResult> CreateNetworkIndicator(NetworkIndicator indicator)
        {
            Indicator createdIndicator = await _context.CreateIndicator(indicator);
            return RedirectToAction("Index", "Data");
        }

        // POST: /indicator/createtargetindicator
        [HttpPost]
        public async Task<IActionResult> CreateTargetIndicator(TargetIndicator indicator)
        {
            Indicator createdIndicator = await _context.CreateIndicator(indicator);
            return RedirectToAction("Index", "Data");
        }
    }
}
