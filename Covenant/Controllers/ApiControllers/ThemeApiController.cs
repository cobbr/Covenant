// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;
using System;

namespace Covenant.Controllers.ApiControllers
{
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/themes")]
    public class ThemeApiController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;

        public ThemeApiController(CovenantContext context, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [HttpGet("style.css")]
        public async Task<IActionResult> GetThemeCss()
        {
            try
            {
                string standardThemeCss = await _context.GetThemeCss(ThemeType.Standard);
                string darkThemeCss = await _context.GetThemeCss(ThemeType.Dark);
                string css = standardThemeCss + "\n\n\n" + darkThemeCss;
                return Content(css, "text/css");
            }
            catch (Exception ex)
            {
                return Content(string.Empty, "text/css");
            }            
        }
    }
}