using System;
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
    public class GruntTaskingController : Controller
    {
        private readonly CovenantContext _context;
        private readonly IHubContext<GruntHub> _grunthub;
        private readonly UserManager<CovenantUser> _userManager;

        public GruntTaskingController(CovenantContext context, IHubContext<GruntHub> grunthub, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _grunthub = grunthub;
            _userManager = userManager;
        }

        // GET: /grunttasking
        public async Task<IActionResult> Index()
        {
            return View(await _context.GruntTaskings
                .Include(GT => GT.Grunt)
                .Include(GT => GT.GruntTask)
                .Include(GT => GT.GruntCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync());
        }

        // GET: /grunttasking/interact/{id}
        public async Task<IActionResult> Interact(int id)
        {
            try
            {
                GruntTasking tasking = await _context.GruntTaskings
                    .Include(GT => GT.Grunt)
                    .Include(GT => GT.GruntTask)
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

        // POST: /grunttasking/create
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
                    User = currentUser,
                    GruntId = tasking.Grunt.Id,
                    Grunt = tasking.Grunt
                }, _grunthub);
                tasking.GruntCommand = createdCommand;
                tasking.GruntCommandId = createdCommand.Id;

                GruntTasking created = await _context.CreateGruntTasking(tasking);
                return RedirectToAction(nameof(Interact), new { id = created.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }
    }
}
