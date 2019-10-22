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
        private readonly IHubContext<EventHub> _eventhub;

        public GruntController(CovenantContext context, UserManager<CovenantUser> userManager, IHubContext<GruntHub> grunthub, IHubContext<EventHub> eventhub)
        {
            _context = context;
            _userManager = userManager;
            _grunthub = grunthub;
            _eventhub = eventhub;
        }

        // GET: /grunt
        public async Task<IActionResult> Index()
        {
            return View(await _context.GetGrunts());
        }

        // GET: /grunt/interact/{id}
        public async Task<IActionResult> Interact(int id)
        {
            const int DISPLAY_LAST = 0;
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
                Grunt original = await _context.GetGrunt(grunt.Id);
                grunt.GruntChallenge = original.GruntChallenge;
                grunt.GruntNegotiatedSessionKey = original.GruntNegotiatedSessionKey;
                grunt.GruntRSAPublicKey = original.GruntRSAPublicKey;
                grunt.GruntSharedSecretPassword = original.GruntSharedSecretPassword;
                grunt.PowerShellImport = original.PowerShellImport;
                grunt.ImplantTemplateId = original.ImplantTemplateId;
                grunt.ListenerId = original.ListenerId;

                Grunt editedGrunt = await _context.EditGrunt(grunt, _userManager, HttpContext.User, _grunthub, _eventhub);
                return RedirectToAction(nameof(Interact), new { id = editedGrunt.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Interact), new { id = grunt.Id });
            }
        }

        // GET: /grunt/hide/{id}
        public async Task<IActionResult> Hide(int id)
        {
            try
            {
                Grunt g = await _context.GetGrunt(id);
                _context.Entry(g).State = EntityState.Deleted;
                if (g.Status == GruntStatus.Hidden)
                {
                    g.Status = GruntStatus.Active;
                }
                else
                {
                    g.Status = GruntStatus.Hidden;
                }
                await _context.EditGrunt(g, _userManager, HttpContext.User, _grunthub, _eventhub);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }
    }
}
