using System;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;

namespace Covenant.Controllers.ViewControllers
{
    [Authorize]
    public class ReferenceSourceLibraryController : Controller
    {
        private readonly CovenantContext _context;

        public ReferenceSourceLibraryController(CovenantContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(await _context.GetReferenceSourceLibrary(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "GruntTask");
            }
        }

        public class ReferenceSourceLibraryModel : ReferenceSourceLibrary
        {
            public new List<int> ReferenceAssemblies { get; set; } = new List<int>();
            public new List<int> EmbeddedResources { get; set; } = new List<int>();
        }

        // POST: /referencesourcelibrary/edit
        [HttpPost]
        public async Task<IActionResult> Edit(ReferenceSourceLibraryModel libraryModel)
        {
            try
            {
                ReferenceSourceLibrary library = new ReferenceSourceLibrary
                {
                    Id = libraryModel.Id,
                    Name = libraryModel.Name,
                    Description = libraryModel.Description,
                    Location = libraryModel.Location,
                    SupportedDotNetVersions = libraryModel.SupportedDotNetVersions
                };
                libraryModel.ReferenceAssemblies.ForEach(async RA => {
                    library.Add(await _context.GetReferenceAssembly(RA));
                });
                libraryModel.EmbeddedResources.ForEach(async ER => {
                    library.Add(await _context.GetEmbeddedResource(ER));
                });
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(await _context.EditReferenceSourceLibrary(library));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Edit), new { id = libraryModel.Id });
            }
        }

        // GET: /referencesourcelibrary/create
        public async Task<IActionResult> Create()
        {
            try
            {
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(new ReferenceSourceLibrary());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "GruntTask");
            }
        }

        // POST: /grunttask/create
        [HttpPost]
        public async Task<IActionResult> Create(ReferenceSourceLibraryModel libraryModel)
        {
            try
            {
                ReferenceSourceLibrary library = new ReferenceSourceLibrary
                {
                    Id = libraryModel.Id,
                    Name = libraryModel.Name,
                    Description = libraryModel.Description,
                    Location = libraryModel.Location,
                    SupportedDotNetVersions = libraryModel.SupportedDotNetVersions
                };
                libraryModel.ReferenceAssemblies.ForEach(async RA => {
                    library.Add(await _context.GetReferenceAssembly(RA));
                });
                libraryModel.EmbeddedResources.ForEach(async ER => {
                    library.Add(await _context.GetEmbeddedResource(ER));
                });
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                ReferenceSourceLibrary createdLibrary = await _context.CreateReferenceSourceLibrary(libraryModel);
                return RedirectToAction(nameof(Edit), new { Id = createdLibrary.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ViewBag.ReferenceAssemblies = await _context.GetReferenceAssemblies();
                ViewBag.EmbeddedResources = await _context.GetEmbeddedResources();
                return View(new ReferenceSourceLibrary());
            }
        }
    }
}
