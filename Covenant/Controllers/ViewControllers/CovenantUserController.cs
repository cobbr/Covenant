using System;

using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    public class CovenantUserController : Controller
    {
        private readonly CovenantContext _context;
        private readonly SignInManager<CovenantUser> _signInManager;
        private readonly UserManager<CovenantUser> _userManager;

        public CovenantUserController(CovenantContext context, SignInManager<CovenantUser> signInManager, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        // GET: /covenantuser/login
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        // POST: /covenantuser/login
        [HttpPost]
        public async Task<IActionResult> Login(CovenantUserLogin login, string returnUrl = "")
        {
            try
            {
                var result = await _signInManager.PasswordSignInAsync(login.UserName, login.Password, true, lockoutOnFailure: false);
                if (!result.Succeeded == true)
                {
                    ModelState.AddModelError(string.Empty, "Incorrect username or password");
                    return View();
                }
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return LocalRedirect(returnUrl);
                }
                return RedirectToAction("Index", "Home");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return View();
            }
        }

        // GET: /covenantuser/logout
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction(nameof(Index));
            }
        }

        // GET: /users/
        [Authorize]
        public async Task<IActionResult> Index()
        {
            IEnumerable<CovenantUser> users = await _context.GetUsers();
            IEnumerable<IdentityUserRole<string>> userRoles = await _context.GetUserRoles();
            Dictionary<string, string> userRoleDict = new Dictionary<string, string>();
            foreach (CovenantUser user in users)
            {
                try
                {
                    string roles = String.Join(", ",
                    userRoles.Where(UR => UR.UserId == user.Id)
                    .Select(UR =>
                    {
                        var t = _context.GetRole(UR.RoleId);
                        t.Wait();
                        return t.Result.Name;
                    }).ToList());
                    userRoleDict[user.UserName] = roles;
                }
                catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
                {
                    continue;
                }
            }
            ViewBag.UserRoleDict = userRoleDict;
            return View(users);
        }

        // GET: /covenantuser/create
        [Authorize(Policy = "RequireAdministratorRole")]
        public IActionResult Create()
        {
            return View(new CovenantUserRegister());
        }

        // POST: /covenantuser/create
        [HttpPost]
        public async Task<IActionResult> Create(CovenantUserRegister register)
        {
            try
            {
                if (register.Password != register.ConfirmPassword)
                {
                    return BadRequest($"BadRequest - Password does not match ConfirmPassword.");
                }

                if (!_userManager.Users.Any())
                {
                    CovenantUser user = new CovenantUser { UserName = register.UserName };
                    IdentityResult userResult = await _userManager.CreateAsync(user, register.Password);
                    await _userManager.AddToRoleAsync(user, "User");
                    await _userManager.AddToRoleAsync(user, "Administrator");
                    await _signInManager.PasswordSignInAsync(register.UserName, register.Password, true, lockoutOnFailure: false);
                }
                else if (_signInManager.IsSignedIn(HttpContext.User) && HttpContext.User.IsInRole("Administrator"))
                {
                    CovenantUser user = new CovenantUser { UserName = register.UserName };
                    IdentityResult userResult = await _userManager.CreateAsync(user, register.Password);
                    await _userManager.AddToRoleAsync(user, "User");
                }
                else
                {
                    return new UnauthorizedResult();
                }
                return RedirectToAction("Index", "Home");
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return RedirectToAction("Index", "Home");
            }
        }

        [Authorize]
        public async Task<IActionResult> Edit(string id)
        {
            try
            {
                CovenantUser user = await _context.GetUser(id);
                List<string> rolesSelected = (await _context.GetUserRoles(user.Id)).Select(UR =>
                {
                    Task<IdentityRole> t = _context.GetRole(UR.RoleId);
                    t.Wait();
                    return t.Result.Name;
                }).ToList();
                ViewBag.RolesSelected = rolesSelected;
                ViewBag.RolesNotSelected = (await _context.GetRoles()).Where(R => !rolesSelected.Contains(R.Name)).Select(R => R.Name);
                return View(new CovenantUserLogin { UserName = user.UserName, Password = "12345678" });
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }

        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost]
        public async Task<IActionResult> Edit(CovenantUserLogin login)
        {
            try
            {
                CovenantUser user = await _context.GetUserByUsername(login.UserName);
                await _context.EditUser(_userManager, user, login);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return View(new CovenantUserLogin { UserName = login.UserName, Password = "12345678" });
            }
        }

        public class EditRolesModel
        {
            public string UserName { get; set; }
            public List<string> Rolenames { get; set; }
        }

        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost]
        public async Task<IActionResult> EditRoles(EditRolesModel roleadd)
        {
            try
            {
                CovenantUser user = await _context.GetUserByUsername(roleadd.UserName);
                IEnumerable<string> userRoles = (await _context.GetUserRoles(user.Id)).Select(UR =>
                {
                    Task<IdentityRole> t = _context.GetRole(UR.RoleId);
                    t.Wait();
                    return t.Result.Name;
                });

                IEnumerable<string> userRolesRemain = userRoles.Where(UR => roleadd.Rolenames.Contains(UR));
                foreach (string rolename in roleadd.Rolenames)
                {
                    // Selected role that has not been added, must add
                    if (!userRolesRemain.Contains(rolename))
                    {
                        IdentityRole role = await _context.GetRoleByName(rolename);
                        await _context.CreateUserRole(_userManager, user.Id, role.Id);
                    }
                }

                IEnumerable<string> userRolesNotRemain = userRoles.Where(UR => !roleadd.Rolenames.Contains(UR));
                foreach (string rolename in userRolesNotRemain)
                {
                    // Did not select role that is already added, must remove
                    IdentityRole role = await _context.GetRoleByName(rolename);
                    await _context.DeleteUserRole(_userManager, user.Id, role.Id);
                }
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                return RedirectToAction(nameof(Index));
            }
        }
    }
}