using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

using Covenant.Hubs;
using Covenant.Models;
using Covenant.Models.Listeners;
using Covenant.Models.Covenant;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [Authorize]
    public class GraphController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;
        private readonly IHubContext<GruntHub> _grunthub;

        public GraphController(CovenantContext context, UserManager<CovenantUser> userManager, IHubContext<GruntHub> grunthub)
        {
            _context = context;
            _userManager = userManager;
            _grunthub = grunthub;
        }

        // GET: /graph
        public async Task<IActionResult> Index()
        {
            ViewBag.Listeners = await _context.GetHttpListeners();
            return View((await _context.GetGrunts()).Where(G => G.Status != GruntStatus.Uninitialized));
        }
    }
}
