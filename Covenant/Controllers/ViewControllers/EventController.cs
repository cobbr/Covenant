// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace Covenant.Controllers
{
    [Authorize]
    public class EventController : Controller
    {
        [Authorize, HttpGet, Route("Event"), Route("Event/Index")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
