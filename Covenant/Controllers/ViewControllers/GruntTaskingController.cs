// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Threading.Tasks;

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
    public class GruntTaskingController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;
        private readonly IHubContext<GruntHub> _grunthub;
        private readonly IHubContext<EventHub> _eventhub;

        public GruntTaskingController(CovenantContext context, UserManager<CovenantUser> userManager, IHubContext<GruntHub> grunthub, IHubContext<EventHub> eventhub)
        {
            _context = context;
            _userManager = userManager;
            _grunthub = grunthub;
            _eventhub = eventhub;
        }

        [Authorize, HttpGet, Route("GruntTasking"), Route("GruntTasking/Index")]
        public async Task<IActionResult> Index()
        {
            return View(await _context.GruntTaskings
                .Include(GT => GT.Grunt)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync());
        }

        [Authorize, HttpGet, Route("GruntTasking/Interact/{id}")]
        public async Task<IActionResult> Interact(int id)
        {
            try
            {
                GruntTasking tasking = await _context.GruntTaskings
                    .Include(GT => GT.Grunt)
                    .Include(GT => GT.GruntTask)
                        .ThenInclude(GT => GT.Options)
                    .Include(GT => GT.GruntCommand)
                        .ThenInclude(GC => GC.CommandOutput)
                    .Include(GT => GT.GruntCommand)
                        .ThenInclude(GC => GC.User)
                    .FirstOrDefaultAsync(GT => GT.Id == id);
                if (tasking == null)
                {
                    throw new ControllerNotFoundException($"NotFound - GruntTasking with id: {id}");
                }
                return View(tasking);
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        private static string GetCommand(GruntTasking tasking)
        {
            string command = tasking.GruntTask.Name;
            for (int i = 0; i < tasking.Parameters.Count; i++)
            {
                if (tasking.GruntTask.Options[i].DisplayInCommand)
                {
                    command += " /" + tasking.GruntTask.Options[i].Name.ToLower() + ":\"" + tasking.Parameters[i].Replace("\"", "\\\"") + "\"";
                }
            }
            return command;
        }

        [Authorize, HttpPost, Route("GruntTasking/Create")]
        public async Task<IActionResult> Create(GruntTasking tasking)
        {
            try
            {
                CovenantUser currentUser = await _context.GetCurrentUser(_userManager, HttpContext.User);
                tasking.Grunt = await _context.GetGrunt(tasking.GruntId);
                tasking.GruntTask = await _context.GetGruntTask(tasking.GruntTaskId);

                GruntCommand createdCommand = await _context.CreateGruntCommand(new GruntCommand
                {
                    Command = GetCommand(tasking),
                    CommandTime = DateTime.UtcNow,
                    CommandOutputId = 0,
                    CommandOutput = new CommandOutput(),
                    User = currentUser,
                    GruntId = tasking.Grunt.Id,
                    Grunt = tasking.Grunt
                }, _grunthub, _eventhub);
                tasking.GruntCommand = createdCommand;
                tasking.GruntCommandId = createdCommand.Id;

                GruntTasking created = await _context.CreateGruntTasking(tasking, _grunthub);
                return RedirectToAction(nameof(Interact), new { id = created.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }
    }
}
