using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

using Covenant.Hubs;
using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [Authorize]
    public class GruntController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;
        private readonly IHubContext<GruntHub> _grunthub;

        public GruntController(CovenantContext context, UserManager<CovenantUser> userManager, IHubContext<GruntHub> grunthub)
        {
            _context = context;
            _userManager = userManager;
            _grunthub = grunthub;
        }

        // GET: /grunt
        public async Task<IActionResult> Index()
        {
            return View(await _context.GetGrunts());
        }

        // GET: /grunt/interact/{id}
        public async Task<IActionResult> Interact(int id)
        {
            const int DISPLAY_LAST = 30;
            try
            {
                List<GruntCommand> allCommands = await _context.GruntCommands
                    .Where(GC => GC.GruntId == id)
                    .OrderBy(GC => GC.CommandTime)
                    .Include(GC => GC.User)
                    .ToListAsync();
                for (int i = 0; i < allCommands.Count() - DISPLAY_LAST; i++)
                {
                    allCommands[i].CommandOutput = await _context.CommandOutputs.FindAsync(allCommands[i].CommandOutputId);
                }
                ViewBag.GruntCommands = allCommands;
                ViewBag.GruntTaskings = (await _context.GetGruntTaskingsForGrunt(id)).OrderBy(GT => GT.TaskingTime);
                ViewBag.GruntTasks = (await _context.GetGruntTasks()).OrderBy(GT => GT.Name);
                return View(await _context.GetGrunt(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        // POST: /grunt/edit/{id}
        public async Task<IActionResult> Edit(Grunt grunt)
        {
            try
            {
                Grunt editedGrunt = await _context.EditGrunt(grunt, _userManager, HttpContext.User, _grunthub);
                return RedirectToAction(nameof(Interact), new { id = editedGrunt.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Interact), new { id = grunt.Id });
            }
        }
    }
}
