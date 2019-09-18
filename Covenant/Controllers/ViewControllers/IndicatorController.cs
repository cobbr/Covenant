// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

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

        [Authorize, HttpGet, Route("Indicator"), Route("Indicator/Index")]
        public async Task<IActionResult> Index()
        {
            ViewBag.TargetIndicators = await _context.GetTargetIndicators();
            ViewBag.NetworkIndicators = await _context.GetNetworkIndicators();
            ViewBag.FileIndicators = await _context.GetFileIndicators();
            return View(await _context.GetIndicators());
        }

        [Authorize, HttpGet, Route("Indicator/Create")]
        public IActionResult Create()
        {
            return View(new Indicator());
        }

        [Authorize, HttpPost, Route("Indicator/CreateFileIndicator")]
        public async Task<IActionResult> CreateFileIndicator(FileIndicator indicator)
        {
            Indicator createdIndicator = await _context.CreateIndicator(indicator);
            return RedirectToAction("Index", "Data");
        }

        [Authorize, HttpPost, Route("Indicator/CreateNetworkIndicator")]
        public async Task<IActionResult> CreateNetworkIndicator(NetworkIndicator indicator)
        {
            Indicator createdIndicator = await _context.CreateIndicator(indicator);
            return RedirectToAction("Index", "Data");
        }

        [Authorize, HttpPost, Route("Indicator/CreateTargetIndicator")]
        public async Task<IActionResult> CreateTargetIndicator(TargetIndicator indicator)
        {
            Indicator createdIndicator = await _context.CreateIndicator(indicator);
            return RedirectToAction("Index", "Data");
        }
    }
}
