using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<CovenantUser> _signInManager;
        private readonly UserManager<CovenantUser> _userManager;

        public LoginModel(SignInManager<CovenantUser> signInManager, UserManager<CovenantUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public CovenantUserRegister CovenantUserRegister { get; set; }
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                if (!_userManager.Users.ToList().Where(U => _userManager.IsInRoleAsync(U, "Administrator").WaitResult()).Any())
                {
                    if (CovenantUserRegister.Password != CovenantUserRegister.ConfirmPassword)
                    {
                        return BadRequest($"BadRequest - Password does not match ConfirmPassword.");
                    }

                    CovenantUser user = new CovenantUser { UserName = CovenantUserRegister.UserName };
                    IdentityResult userResult = await _userManager.CreateAsync(user, CovenantUserRegister.Password);
                    await _userManager.AddToRoleAsync(user, "User");
                    await _userManager.AddToRoleAsync(user, "Administrator");
                    await _signInManager.PasswordSignInAsync(CovenantUserRegister.UserName, CovenantUserRegister.Password, true, lockoutOnFailure: false);
                    // return RedirectToAction(nameof(Index));
                    return LocalRedirect("/home/index");
                }
                else
                {
                    var result = await _signInManager.PasswordSignInAsync(CovenantUserRegister.UserName, CovenantUserRegister.Password, true, lockoutOnFailure: false);
                    if (!result.Succeeded == true)
                    {
                        ModelState.AddModelError(string.Empty, "Incorrect username or password");
                        return Page();
                    }
                    // if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    // {
                    //     return LocalRedirect(returnUrl);
                    // }
                    // return RedirectToAction("Index", "Home");
                    return LocalRedirect("/home/index");
                }
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return Page();
            }
        }
    }
}
