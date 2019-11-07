// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;

namespace Covenant.Controllers.ViewControllers
{
    [Authorize]
    public class ReferenceAssemblyController : Controller
    {
        private readonly CovenantContext _context;

        public ReferenceAssemblyController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route("ReferenceAssembly/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                return View(await _context.GetReferenceAssembly(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "GruntTask");
            }
        }

        [Authorize, HttpPost, Route("ReferenceAssembly/Edit")]
        public async Task<IActionResult> Edit(ReferenceAssembly assembly)
        {
            try
            {
                return View(await _context.EditReferenceAssembly(assembly));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Edit), new { id = assembly.Id });
            }
        }

        [Authorize, HttpGet, Route("ReferenceAssembly/Create")]
        public IActionResult Create()
        {
            try
            {
                return View(new ReferenceAssembly());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "GruntTask");
            }
        }

        [Authorize, HttpPost, Route("ReferenceAssembly/Create")]
        public async Task<IActionResult> Create(ReferenceAssembly assembly)
        {
            try
            {
                ReferenceAssembly createdAssembly = await _context.CreateReferenceAssembly(assembly);
                return RedirectToAction(nameof(Edit), new { Id = createdAssembly.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return View(new ReferenceAssembly());
            }
        }
    }
}
