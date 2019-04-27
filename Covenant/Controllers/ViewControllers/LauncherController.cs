using System;
using System.Net.Http;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

using Covenant.Core;
using Covenant.API;
using Covenant.API.Models;

namespace Covenant.Controllers
{
    [Authorize]
    public class LauncherController : Controller
    {
        private readonly CovenantAPI _client;

        public LauncherController(IConfiguration configuration)
        {
            X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == covenantCert.GetCertHashString();
                }
            };
            _client = new CovenantAPI(
                new Uri("https://localhost:7443"),
                new TokenCredentials(configuration["CovenantToken"]),
                clientHandler
            );
        }

        // GET: /launcher/
        public async Task<IActionResult> Index()
        {
            return View(await _client.ApiLaunchersGetAsync());
        }

        // GET: /launcher/powershell
        public async Task<IActionResult> PowerShell()
        {
            PowerShellLauncher launcher = await _client.ApiLaunchersPowershellGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/powershell
        [HttpPost]
        public async Task<IActionResult> PowerShell(PowerShellLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersPowershellPutAsync(launcher);
                launcher = await _client.ApiLaunchersPowershellPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/powershell/host
        [HttpPost("powershell/host", Name = "HostPowerShell")]
        public async Task<IActionResult> HostPowerShell(HostedFile file)
        {
            try
            {
                PowerShellLauncher launcher = await _client.ApiLaunchersPowershellPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersPowershellHostedPostAsync(file);
                return RedirectToAction("PowerShell");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("PowerShell");
            }
        }

        // GET: /launcher/binary
        public async Task<IActionResult> Binary()
        {
            BinaryLauncher launcher = await _client.ApiLaunchersBinaryGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/binary
        [HttpPost]
        public async Task<IActionResult> Binary(BinaryLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersBinaryPutAsync(launcher);
                launcher = await _client.ApiLaunchersBinaryPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/binary/host
        [HttpPost("binary/host", Name = "HostBinary")]
        public async Task<IActionResult> HostBinary(HostedFile file)
        {
            try
            {
                BinaryLauncher launcher = await _client.ApiLaunchersBinaryPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersBinaryHostedPostAsync(file);
                return RedirectToAction("Binary");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("Binary");
            }
        }

        // GET: /launcher/installutil
        public async Task<IActionResult> InstallUtil()
        {
            InstallUtilLauncher launcher = await _client.ApiLaunchersInstallutilGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/installutil
        [HttpPost]
        public async Task<IActionResult> InstallUtil(InstallUtilLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersInstallutilPutAsync(launcher);
                launcher = await _client.ApiLaunchersInstallutilPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/installutil/host
        [HttpPost("installutil/host", Name = "HostInstallUtil")]
        public async Task<IActionResult> HostInstallUtil(HostedFile file)
        {
            try
            {
                InstallUtilLauncher launcher = await _client.ApiLaunchersInstallutilPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersInstallutilHostedPostAsync(file);
                return RedirectToAction("InstallUtil");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("InstallUtil");
            }
        }

        // GET: /launcher/msbuild
        public async Task<IActionResult> MSBuild()
        {
            MSBuildLauncher launcher = await _client.ApiLaunchersMsbuildGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/msbuild
        [HttpPost]
        public async Task<IActionResult> MSBuild(MSBuildLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersMsbuildPutAsync(launcher);
                launcher = await _client.ApiLaunchersMsbuildPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/msbuild/host
        [HttpPost("msbuild/host", Name = "HostMSBuild")]
        public async Task<IActionResult> HostMSBuild(HostedFile file)
        {
            try
            {
                MSBuildLauncher launcher = await _client.ApiLaunchersMsbuildPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersMsbuildHostedPostAsync(file);
                return RedirectToAction("MSBuild");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("MSBuild");
            }
        }

        // GET: /launcher/regsvr32
        public async Task<IActionResult> Regsvr32()
        {
            Regsvr32Launcher launcher = await _client.ApiLaunchersRegsvr32GetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/regsvr32
        [HttpPost]
        public async Task<IActionResult> Regsvr32(Regsvr32Launcher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersRegsvr32PutAsync(launcher);
                launcher = await _client.ApiLaunchersRegsvr32PostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/regsvr32/host
        [HttpPost("regsvr32/host", Name = "HostRegsvr32")]
        public async Task<IActionResult> HostRegsvr32(HostedFile file)
        {
            try
            {
                Regsvr32Launcher launcher = await _client.ApiLaunchersRegsvr32PostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersRegsvr32HostedPostAsync(file);
                return RedirectToAction("Regsvr32");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("Regsvr32");
            }
        }

        // GET: /launcher/mshta
        public async Task<IActionResult> Mshta()
        {
            MshtaLauncher launcher = await _client.ApiLaunchersMshtaGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/mshta
        [HttpPost]
        public async Task<IActionResult> Mshta(MshtaLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersMshtaPutAsync(launcher);
                launcher = await _client.ApiLaunchersMshtaPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/mshta/host
        [HttpPost("mshta/host", Name = "HostMshta")]
        public async Task<IActionResult> HostMshta(HostedFile file)
        {
            try
            {
                MshtaLauncher launcher = await _client.ApiLaunchersMshtaPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersMshtaHostedPostAsync(file);
                return RedirectToAction("Mshta");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("Mshta");
            }
        }

        // GET: /launcher/wmic
        public async Task<IActionResult> Wmic()
        {
            WmicLauncher launcher = await _client.ApiLaunchersWmicGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/wmic
        [HttpPost]
        public async Task<IActionResult> Wmic(WmicLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersWmicPutAsync(launcher);
                launcher = await _client.ApiLaunchersWmicPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/wmic/host
        [HttpPost("wmic/host", Name = "HostWmic")]
        public async Task<IActionResult> HostWmic(HostedFile file)
        {
            try
            {
                WmicLauncher launcher = await _client.ApiLaunchersWmicPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersWmicHostedPostAsync(file);
                return RedirectToAction("Wmic");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("Wmic");
            }
        }

        // GET: /launcher/cscript
        public async Task<IActionResult> Cscript()
        {
            CscriptLauncher launcher = await _client.ApiLaunchersCscriptGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/cscript
        [HttpPost]
        public async Task<IActionResult> Cscript(CscriptLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersCscriptPutAsync(launcher);
                launcher = await _client.ApiLaunchersCscriptPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/cscript/host
        [HttpPost("cscript/host", Name = "HostCscript")]
        public async Task<IActionResult> HostCscript(HostedFile file)
        {
            try
            {
                CscriptLauncher launcher = await _client.ApiLaunchersCscriptPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersCscriptHostedPostAsync(file);
                return RedirectToAction("Cscript");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("Cscript");
            }
        }

        // GET: /launcher/wscript
        public async Task<IActionResult> Wscript()
        {
            WscriptLauncher launcher = await _client.ApiLaunchersWscriptGetAsync();
            ViewBag.Launcher = launcher;
            ViewBag.Listeners = await _client.ApiListenersGetAsync();
            return View(launcher);
        }

        // POST: /launcher/wscript
        [HttpPost]
        public async Task<IActionResult> Wscript(WscriptLauncher launcher)
        {
            try
            {
                launcher = await _client.ApiLaunchersWscriptPutAsync(launcher);
                launcher = await _client.ApiLaunchersWscriptPostAsync();
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                ViewBag.Launcher = launcher;
                ViewBag.Listeners = await _client.ApiListenersGetAsync();
                return View(launcher);
            }
        }

        // POST: /launcher/wscript/host
        [HttpPost("wscript/host", Name = "HostWscript")]
        public async Task<IActionResult> HostWscript(HostedFile file)
        {
            try
            {
                WscriptLauncher launcher = await _client.ApiLaunchersWscriptPostAsync();
                HttpListener listener = await _client.ApiListenersHttpByIdGetAsync(file.ListenerId ?? default);
                file = await _client.ApiListenersByIdHostedfilesPostAsync(listener.Id ?? default, file);
                launcher = await _client.ApiLaunchersWscriptHostedPostAsync(file);
                return RedirectToAction("Wscript");
            }
            catch (HttpOperationException e)
            {
                ModelState.AddModelError(string.Empty, e.Response.Content);
                return RedirectToAction("Wscript");
            }
        }
    }
}
