// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [Authorize]
    public class GruntTaskController : Controller
    {
        private readonly CovenantContext _context;

        public GruntTaskController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route("GruntTask"), Route("GruntTask/Index")]
        public async Task<IActionResult> Index()
        {
            ViewBag.ReferenceSourceLibraries = await _context.GetReferenceSourceLibraries();
            ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
            ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
            return View(await _context.GetGruntTasks());
        }

        [Authorize, HttpGet, Route("GruntTask/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                ViewBag.ReferenceSourceLibraries = await _context.GetReferenceSourceLibraries();
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(await _context.GetGruntTask(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        public class GruntTaskModel : GruntTask
        {
            public new List<int> ReferenceAssemblies { get; set; } = new List<int>();
            public new List<int> EmbeddedResources { get; set; } = new List<int>();
            public new List<int> ReferenceSourceLibraries { get; set; } = new List<int>();
        }

        [Authorize, HttpPost, Route("GruntTask/Edit")]
        public async Task<IActionResult> Edit(GruntTaskModel taskModel)
        {
            try
            {
                GruntTask task = new GruntTask
                {
                    Id = taskModel.Id,
                    Name = taskModel.Name,
                    Description = taskModel.Description,
                    Help = taskModel.Help,
                    Code = taskModel.Code,
                    UnsafeCompile = taskModel.UnsafeCompile,
                    TokenTask = taskModel.TokenTask,
                    Options = taskModel.Options
                };
                taskModel.ReferenceSourceLibraries.ForEach(async RSL => {
                    task.Add(await _context.GetReferenceSourceLibrary(RSL));
                });
                taskModel.ReferenceAssemblies.ForEach(async RA => {
                    task.Add(await _context.GetReferenceAssembly(RA));
                });
                taskModel.EmbeddedResources.ForEach(async ER => {
                    task.Add(await _context.GetEmbeddedResource(ER));
                });
                ViewBag.ReferenceSourceLibraries = await _context.GetReferenceSourceLibraries();
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(await _context.EditGruntTask(task));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Edit), new { Id = taskModel.Id });
            }
        }

        [Authorize, HttpGet, Route("GruntTask/Create")]
        public async Task<IActionResult> Create()
        {
            try
            {
                ViewBag.ReferenceSourceLibraries = await _context.GetReferenceSourceLibraries();
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(new GruntTask());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize, HttpPost, Route("GruntTask/Create")]
        public async Task<IActionResult> Create(GruntTaskModel taskModel)
        {
            try
            {
                GruntTask task = new GruntTask
                {
                    Name = taskModel.Name,
                    Description = taskModel.Description,
                    Help = taskModel.Help,
                    Code = taskModel.Code,
                    UnsafeCompile = taskModel.UnsafeCompile,
                    TokenTask = taskModel.TokenTask,
                    Options = taskModel.Options
                };
                taskModel.ReferenceSourceLibraries.ForEach(async RSL => {
                    task.Add(await _context.GetReferenceSourceLibrary(RSL));
                });
                taskModel.ReferenceAssemblies.ForEach(async RA => {
                    task.Add(await _context.GetReferenceAssembly(RA));
                });
                taskModel.EmbeddedResources.ForEach(async ER => {
                    task.Add(await _context.GetEmbeddedResource(ER));
                });
                ViewBag.ReferenceSourceLibraries = await _context.GetReferenceSourceLibraries();
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                GruntTask createdTask = await _context.CreateGruntTask(task);
                return RedirectToAction(nameof(Edit), new { Id = createdTask.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ViewBag.ReferenceSourceLibraries = await _context.GetReferenceSourceLibraries();
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(new GruntTask());
            }
        }
    }
}
