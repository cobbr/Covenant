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
    public class EmbeddedResourceController : Controller
    {
        private readonly CovenantContext _context;

        public EmbeddedResourceController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route("EmbeddedResource/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            return View(await _context.GetEmbeddedResource(id));
        }

        [Authorize, HttpPost, Route("EmbeddedResource/Edit")]
        public async Task<IActionResult> Edit(EmbeddedResource resource)
        {
            try
            {
                return View(await _context.EditEmbeddedResource(resource));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Edit), new { id = resource.Id });
            }
        }

        [Authorize, HttpGet, Route("EmbeddedResource/Create")]
        public IActionResult Create()
        {
            try
            {
                return View(new EmbeddedResource());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "GruntTask");
            }
        }

        [Authorize, HttpPost, Route("EmbeddedResource/Create")]
        public async Task<IActionResult> Create(EmbeddedResource resource)
        {
            try
            {
                EmbeddedResource createdResource = await _context.CreateEmbeddedResource(resource);
                return RedirectToAction(nameof(Edit), new { Id = createdResource.Id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return View(new EmbeddedResource());
            }
        }
    }
}
