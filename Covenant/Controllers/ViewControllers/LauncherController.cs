// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;
using Covenant.Models.Launchers;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [Authorize]
    public class LauncherController : Controller
    {
        private readonly CovenantContext _context;

        public LauncherController(CovenantContext context)
        {
            _context = context;
        }

        [Authorize, HttpGet, Route("Launcher"), Route("Launcher/Index")]
        public async Task<IActionResult> Index()
        {
            return View(await _context.GetLaunchers());
        }

        [Authorize, HttpGet, Route("Launcher/Create/{id}")]
        public async Task<IActionResult> Create(string id)
        {
            try
            {
                IEnumerable<Listener> Listeners = await _context.GetListeners();
                IEnumerable<ImplantTemplate> ImplantTemplates = await _context.GetImplantTemplates();
                IEnumerable<Listener> ActiveListeners = Listeners.Where(L => L.Status == ListenerStatus.Active);
                ViewBag.Listeners = ActiveListeners;
                IEnumerable<ImplantTemplate> CompatibleTemplates = ImplantTemplates.Where(IT => IT.CompatibleListenerTypes.Select(CLT => ActiveListeners.Select(AL => AL.ListenerTypeId).Contains(CLT.Id)).Any(B => B == true));
                ViewBag.ImplantTemplates = CompatibleTemplates;
                switch (id.ToLower())
                {
                    case "binary":
                        return View(await _context.GetBinaryLauncher());
                    case "powershell":
                        return View(await _context.GetPowerShellLauncher());
                    case "installutil":
                        return View(await _context.GetInstallUtilLauncher());
                    case "msbuild":
                        return View(await _context.GetMSBuildLauncher());
                    case "regsvr32":
                        return View(await _context.GetRegsvr32Launcher());
                    case "mshta":
                        return View(await _context.GetMshtaLauncher());
                    case "wmic":
                        return View(await _context.GetWmicLauncher());
                    case "cscript":
                        return View(await _context.GetCscriptLauncher());
                    case "wscript":
                        return View(await _context.GetWscriptLauncher());
                    default:
                        return RedirectToAction(nameof(Index));
                }
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize, HttpPost, Route("Launcher/Binary")]
        public async Task<IActionResult> Binary(BinaryLauncher launcher)
        {
            try
            {
                launcher = await _context.EditBinaryLauncher(launcher);
                launcher = await _context.GenerateBinaryLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostBinary")]
        public async Task<IActionResult> HostBinary(HostedFile file)
        {
            try
            {
                BinaryLauncher launcher = await _context.GenerateBinaryLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateBinaryHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Binary" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/BinaryDownload")]
        public async Task<IActionResult> BinaryDownload()
        {
            try
            {
                BinaryLauncher binaryLauncher = await _context.GetBinaryLauncher();
                return File(Convert.FromBase64String(binaryLauncher.Base64ILByteString), MediaTypeNames.Application.Octet, "GruntStager.exe");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Binary" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/PowerShell")]
        public async Task<IActionResult> PowerShell(PowerShellLauncher launcher)
        {
            try
            {
                launcher = await _context.EditPowerShellLauncher(launcher);
                launcher = await _context.GeneratePowerShellLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostPowerShell")]
        public async Task<IActionResult> HostPowerShell(HostedFile file)
        {
            try
            {
                PowerShellLauncher launcher = await _context.GeneratePowerShellLauncher();
                file = await _context.CreateHostedFile(file.ListenerId, file);
                launcher = await _context.GeneratePowerShellHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "PowerShell" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/PowerShellDownload")]
        public async Task<IActionResult> PowerShellDownload()
        {
            try
            {
                PowerShellLauncher powershellLauncher = await _context.GetPowerShellLauncher();
                return File(Common.CovenantEncoding.GetBytes(powershellLauncher.PowerShellCode), MediaTypeNames.Text.Plain, "GruntStager.ps1");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "PowerShell" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/InstallUtil")]
        public async Task<IActionResult> InstallUtil(InstallUtilLauncher launcher)
        {
            try
            {
                launcher = await _context.EditInstallUtilLauncher(launcher);
                launcher = await _context.GenerateInstallUtilLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostInstallUtil")]
        public async Task<IActionResult> HostInstallUtil(HostedFile file)
        {
            try
            {
                InstallUtilLauncher launcher = await _context.GenerateInstallUtilLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateInstallUtilHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "InstallUtil" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/InstallUtilDownload")]
        public async Task<IActionResult> InstallUtilDownload()
        {
            try
            {
                InstallUtilLauncher installUtilLauncher = await _context.GetInstallUtilLauncher();
                return File(Common.CovenantEncoding.GetBytes(installUtilLauncher.DiskCode), MediaTypeNames.Text.Xml, "GruntStager.xml");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "InstallUtil" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/MSBuild")]
        public async Task<IActionResult> MSBuild(MSBuildLauncher launcher)
        {
            try
            {
                launcher = await _context.EditMSBuildLauncher(launcher);
                launcher = await _context.GenerateMSBuildLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostMSBuild")]
        public async Task<IActionResult> HostMSBuild(HostedFile file)
        {
            try
            {
                MSBuildLauncher launcher = await _context.GenerateMSBuildLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateMSBuildHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "MSBuild" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/MSBuildDownload")]
        public async Task<IActionResult> MSBuildDownload()
        {
            try
            {
                MSBuildLauncher msbuildLauncher = await _context.GetMSBuildLauncher();
                return File(Common.CovenantEncoding.GetBytes(msbuildLauncher.DiskCode), MediaTypeNames.Text.Xml, "GruntStager.xml");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "MSBuild" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/Regsvr32")]
        public async Task<IActionResult> Regsvr32(Regsvr32Launcher launcher)
        {
            try
            {
                launcher = await _context.EditRegsvr32Launcher(launcher);
                launcher = await _context.GenerateRegsvr32Launcher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostRegsvr32")]
        public async Task<IActionResult> HostRegsvr32(HostedFile file)
        {
            try
            {
                Regsvr32Launcher launcher = await _context.GenerateRegsvr32Launcher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateRegsvr32HostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Regsvr32" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/Regsvr32Download")]
        public async Task<IActionResult> Regsvr32Download()
        {
            try
            {
                Regsvr32Launcher regsvr32Launcher = await _context.GetRegsvr32Launcher();
                return File(Common.CovenantEncoding.GetBytes(regsvr32Launcher.DiskCode), MediaTypeNames.Text.Plain, "GruntStager.sct");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Regsvr32" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/Mshta")]
        public async Task<IActionResult> Mshta(MshtaLauncher launcher)
        {
            try
            {
                launcher = await _context.EditMshtaLauncher(launcher);
                launcher = await _context.GenerateMshtaLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostMshta")]
        public async Task<IActionResult> HostMshta(HostedFile file)
        {
            try
            {
                MshtaLauncher launcher = await _context.GenerateMshtaLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateMshtaHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Mshta" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/MshtaDownload")]
        public async Task<IActionResult> MshtaDownload()
        {
            try
            {
                MshtaLauncher mshtaLauncher = await _context.GetMshtaLauncher();
                return File(Common.CovenantEncoding.GetBytes(mshtaLauncher.DiskCode), MediaTypeNames.Text.Plain, "GruntStager.hta");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Mshta" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/Wmic")]
        public async Task<IActionResult> Wmic(WmicLauncher launcher)
        {
            try
            {
                launcher = await _context.EditWmicLauncher(launcher);
                launcher = await _context.GenerateWmicLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostWmic")]
        public async Task<IActionResult> HostWmic(HostedFile file)
        {
            try
            {
                WmicLauncher launcher = await _context.GenerateWmicLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateWmicHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Wmic" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/WmicDownload")]
        public async Task<IActionResult> WmicDownload()
        {
            try
            {
                WmicLauncher wmicLauncher = await _context.GetWmicLauncher();
                return File(Common.CovenantEncoding.GetBytes(wmicLauncher.DiskCode), MediaTypeNames.Text.Plain, "GruntStager.xsl");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Wmic" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/Cscript")]
        public async Task<IActionResult> Cscript(CscriptLauncher launcher)
        {
            try
            {
                launcher = await _context.EditCscriptLauncher(launcher);
                launcher = await _context.GenerateCscriptLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostCscript")]
        public async Task<IActionResult> HostCscript(HostedFile file)
        {
            try
            {
                CscriptLauncher launcher = await _context.GenerateCscriptLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateCscriptHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Cscript" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/CscriptDownload")]
        public async Task<IActionResult> CscriptDownload()
        {
            try
            {
                CscriptLauncher cscriptLauncher = await _context.GetCscriptLauncher();
                return File(Common.CovenantEncoding.GetBytes(cscriptLauncher.DiskCode), MediaTypeNames.Text.Plain, "GruntStager.js");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Cscript" });
            }
        }

        [Authorize, HttpPost, Route("Launcher/Wscript")]
        public async Task<IActionResult> Wscript(WscriptLauncher launcher)
        {
            try
            {
                launcher = await _context.EditWscriptLauncher(launcher);
                launcher = await _context.GenerateWscriptLauncher();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _context.GetListeners();
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
        }

        [Authorize, HttpPost, Route("Launcher/HostWscript")]
        public async Task<IActionResult> HostWscript(HostedFile file)
        {
            try
            {
                WscriptLauncher launcher = await _context.GenerateWscriptLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(listener.Id, file);
                launcher = await _context.GenerateWscriptHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Wscript" });
            }
        }

        [Authorize, HttpGet, Route("Launcher/WscriptDownload")]
        public async Task<IActionResult> WscriptDownload()
        {
            try
            {
                WscriptLauncher wscriptLauncher = await _context.GetWscriptLauncher();
                return File(Common.CovenantEncoding.GetBytes(wscriptLauncher.DiskCode), MediaTypeNames.Text.Plain, "GruntStager.js");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Wscript" });
            }
        }
    }
}
