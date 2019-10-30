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

        // GET: /launcher/
        public async Task<IActionResult> Index()
        {
            return View(await _context.GetLaunchers());
        }

        // GET: /launcher/create/{name}
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

        // POST: /launcher/binary
        [HttpPost]
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

        // POST: /launcher/hostbinary
        public async Task<IActionResult> HostBinary(HostedFile file)
        {
            try
            {
                BinaryLauncher launcher = await _context.GenerateBinaryLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateBinaryHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Binary" });
            }
        }

        // GET: /launcher/binarydownload
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

        // POST: /launcher/powershell
        [HttpPost]
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

        // POST: /launcher/hostpowershell
        public async Task<IActionResult> HostPowerShell(HostedFile file)
        {
            try
            {
                PowerShellLauncher launcher = await _context.GeneratePowerShellLauncher();
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GeneratePowerShellHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "PowerShell" });
            }
        }

        // GET: /launcher/powershelldownload
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

        // POST: /launcher/installutil
        [HttpPost]
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

        // POST: /launcher/hostinstallutil
        public async Task<IActionResult> HostInstallUtil(HostedFile file)
        {
            try
            {
                InstallUtilLauncher launcher = await _context.GenerateInstallUtilLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateInstallUtilHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "InstallUtil" });
            }
        }

        // GET: /launcher/installutildownload
        public async Task<IActionResult> InstallUtilDownload()
        {
            try
            {
                InstallUtilLauncher installUtilLauncher = await _context.GetInstallUtilLauncher();
                return File(Convert.FromBase64String(installUtilLauncher.DiskCode), MediaTypeNames.Application.Octet, "GruntStager.dll");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "InstallUtil" });
            }
        }

        // POST: /launcher/msbuild
        [HttpPost]
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

        // POST: /launcher/hostmsbuild
        public async Task<IActionResult> HostMSBuild(HostedFile file)
        {
            try
            {
                MSBuildLauncher launcher = await _context.GenerateMSBuildLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateMSBuildHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "MSBuild" });
            }
        }

        // GET: /launcher/msbuilddownload
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

        // POST: /launcher/regsvr32
        [HttpPost]
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

        // POST: /launcher/hostregsvr32
        public async Task<IActionResult> HostRegsvr32(HostedFile file)
        {
            try
            {
                Regsvr32Launcher launcher = await _context.GenerateRegsvr32Launcher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateRegsvr32HostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Regsvr32" });
            }
        }

        // GET: /launcher/regsvr32download
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

        // POST: /launcher/mshta
        [HttpPost]
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

        // POST: /launcher/hostmshta
        public async Task<IActionResult> HostMshta(HostedFile file)
        {
            try
            {
                MshtaLauncher launcher = await _context.GenerateMshtaLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateMshtaHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Mshta" });
            }
        }

        // GET: /launcher/mshtadownload
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

        // POST: /launcher/wmic
        [HttpPost]
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

        // POST: /launcher/hostwmic
        public async Task<IActionResult> HostWmic(HostedFile file)
        {
            try
            {
                WmicLauncher launcher = await _context.GenerateWmicLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateWmicHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Wmic" });
            }
        }

        // GET: /launcher/wmicdownload
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

        // POST: /launcher/cscript
        [HttpPost]
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

        // POST: /launcher/hostcscript
        public async Task<IActionResult> HostCscript(HostedFile file)
        {
            try
            {
                CscriptLauncher launcher = await _context.GenerateCscriptLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateCscriptHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Cscript" });
            }
        }

        // GET: /launcher/cscriptdownload
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

        // POST: /launcher/wscript
        [HttpPost]
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

        // POST: /launcher/hostwscript
        public async Task<IActionResult> HostWscript(HostedFile file)
        {
            try
            {
                WscriptLauncher launcher = await _context.GenerateWscriptLauncher();
                HttpListener listener = await _context.GetHttpListener(file.ListenerId);
                file = await _context.CreateHostedFile(file);
                launcher = await _context.GenerateWscriptHostedLauncher(file);
                return RedirectToAction(nameof(Create), new { id = launcher.Name });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Create), new { id = "Wscript" });
            }
        }

        // GET: /launcher/wscriptdownload
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
