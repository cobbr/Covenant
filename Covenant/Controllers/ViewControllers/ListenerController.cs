using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR;

using Covenant.Core;
using Covenant.Hubs;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [Authorize]
    public class ListenerController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens;
        private readonly IHubContext<EventHub> _eventhub;

        public ListenerController(CovenantContext context, UserManager<CovenantUser> userManager, IConfiguration configuration, ConcurrentDictionary<int, CancellationTokenSource> ListenerCancellationTokens, IHubContext<EventHub> eventhub)
        {
            _context = context;
            _userManager = userManager;
            _configuration = configuration;
            _ListenerCancellationTokens = ListenerCancellationTokens;
            _eventhub = eventhub;
        }

        // GET: /listener/
        public async Task<IActionResult> Index()
        {
            ViewBag.ListenerTypes = await _context.GetListenerTypes();
            ViewBag.Profiles = await _context.GetProfiles();
            return View(await _context.GetListeners());
        }

        // GET: /listener/create
        public async Task<IActionResult> Create()
        {
            try
            {
                ViewBag.Profiles = await _context.GetProfiles();
                ViewBag.ListenerTypes = await _context.GetListenerTypes();
                return View();
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        // POST: /listener/createhttp
        [HttpPost]
        public async Task<IActionResult> CreateHttp(HttpListener listener)
        {
            try
            {
                listener = await _context.CreateHttpListener(_userManager, _configuration, listener, _ListenerCancellationTokens, _eventhub);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Profiles = await _context.GetHttpProfiles();
                ViewBag.ListenerTypes = await _context.GetListenerTypes();
                return RedirectToAction(nameof(Create));
            }
        }

        // POST: /listener/createbridge
        [HttpPost]
        public async Task<IActionResult> CreateBridge(BridgeListener listener)
        {
            try
            {
                listener = await _context.CreateBridgeListener(_userManager, _configuration, listener, _ListenerCancellationTokens, _eventhub);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Profiles = await _context.GetHttpProfiles();
                ViewBag.ListenerTypes = await _context.GetListenerTypes();
                return RedirectToAction(nameof(Create));
            }
        }

        // GET: /listener/interact/{id}
        public async Task<IActionResult> Interact(int id)
        {
            try
            {
                Listener listener = await _context.GetListener(id);
                ViewBag.Profiles = await _context.GetHttpProfiles();
                ViewBag.HostedFiles = await _context.GetHostedFiles(listener.Id);
                ViewBag.ListenerType = await _context.GetListenerType(listener.ListenerTypeId);
                return View(listener);
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        // GET: /listener/start/{id}
        public async Task<IActionResult> Start(int id)
        {
            Console.WriteLine("Start: " + id);
            try
            {
                Listener listener = await _context.GetListener(id);
                if (listener.Status == ListenerStatus.Active)
                {
                    return RedirectToAction(nameof(Index));
                }
                _context.Entry(listener).State = EntityState.Detached;
                listener.Status = ListenerStatus.Active;
                Console.WriteLine("EditListener");
                await _context.EditListener(listener, _ListenerCancellationTokens, _eventhub);
                return RedirectToAction(nameof(Interact), new { id = id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        // GET: /listener/stop/{id}
        public async Task<IActionResult> Stop(int id)
        {
            try
            {
                Listener listener = await _context.GetListener(id);
                if (listener.Status == ListenerStatus.Stopped)
                {
                    return RedirectToAction(nameof(Index));
                }
                _context.Entry(listener).State = EntityState.Detached;
                listener.Status = ListenerStatus.Stopped;
                await _context.EditListener(listener, _ListenerCancellationTokens, _eventhub);
                return RedirectToAction(nameof(Interact), new { id = id });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        // GET: /listener/delete/{id}
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                Listener listener = await _context.GetListener(id);
                await _context.DeleteListener(listener.Id, _ListenerCancellationTokens);
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
