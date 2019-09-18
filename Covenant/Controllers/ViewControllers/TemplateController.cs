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

namespace Covenant.Controllers
{
    [Authorize]
    public class TemplateController : Controller
    {
        private readonly CovenantContext _context;

        public TemplateController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route("Template"), Route("Template/Index")]
        public async Task<IActionResult> Index()
        {
            try
            {
                return View(await _context.GetImplantTemplates());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction("Index", "Home");
            }
        }

        [Authorize, HttpGet, Route("Template/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                ViewBag.ListenerTypes = await _context.GetListenerTypes();
                return View(await _context.GetImplantTemplate(id));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize, HttpPost, Route("Template/Edit")]
        public async Task<IActionResult> Edit(ImplantTemplate template)
        {
            try
            {
                await _context.EditImplantTemplate(template);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize, HttpGet, Route("Template/Create")]
        public async Task<IActionResult> Create()
        {
            try
            {
                ViewBag.ListenerTypes = await _context.GetListenerTypes();
                return View(new ImplantTemplate());
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize, HttpPost, Route("Template/Create")]
        public async Task<IActionResult> Create(ImplantTemplate template)
        {
            try
            {
                await _context.CreateImplantTemplate(template);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }
    }
}
