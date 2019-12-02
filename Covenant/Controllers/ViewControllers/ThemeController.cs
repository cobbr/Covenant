using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Settings;

namespace Covenant.Controllers.ViewControllers
{
    public class ThemeController : Controller
    {
        private readonly CovenantContext _context;
        private readonly SignInManager<CovenantUser> _signInManager;
        private readonly UserManager<CovenantUser> _userManager;

        public ThemeController(CovenantContext context, SignInManager<CovenantUser> signInManager, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            IEnumerable<Setting> settings = await _context.GetSettings(new List<string> { Common.Settings.Themes.Standard, Common.Settings.Themes.Dark });
            IEnumerable<Theme> themes = await _context.GetThemes();
            return View(Tuple.Create(settings, themes));
        }

        // GET: /theme/create
        [Authorize(Policy = "RequireAdministratorRole")]
        public IActionResult Create()
        {
            return View(new Theme());
        }

        // POST: /theme/create
        [HttpPost]
        public async Task<IActionResult> Create(Theme theme)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        // GET: /theme/{id}
        [Authorize(Policy = "RequireAdministratorRole")]
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                Theme theme = await _context.GetTheme(id);
                ThemeOptionsViewModel themeOptions = new ThemeOptionsViewModel(theme.Options);
                return View(Tuple.Create(theme, themeOptions));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost]
        public async Task<IActionResult> Edit(Theme theme)
        {
            try
            {
                //CovenantUser user = await _context.GetUserByUsername(login.UserName);
                //await _context.EditUser(_userManager, user, login);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
                //return View(new CovenantUserLogin { Id = login.Id, UserName = login.UserName, Password = "12345678" });
            }
        }

        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost]
        public async Task<IActionResult> EditThemeSettings(SettingsTheme settings)
        {
            try
            {
                await _context.ChangeSettingValue(Common.Settings.Themes.Standard, settings.StandardThemeId);
                await _context.ChangeSettingValue(Common.Settings.Themes.Dark, settings.DarkThemeId);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize(Policy = "RequireAdministratorRole")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                // verify this isn't a selected theme.
                IEnumerable<Setting> settings = await _context.GetSettings(new List<string> { Common.Settings.Themes.Standard, Common.Settings.Themes.Dark });
                if (settings.Where(s => s.Key == Common.Settings.Themes.Standard || s.Key == Common.Settings.Themes.Dark).Any(s => s.Value == id.ToString())) {
                    ModelState.AddModelError(string.Empty, "Unable to delete. This theme is currently being used.");
                    Theme theme = await _context.GetTheme(id);
                    return View(nameof(Edit), theme);
                }
                //await _context.DeleteTheme(id);
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