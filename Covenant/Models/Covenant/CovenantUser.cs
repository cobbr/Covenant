// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace Covenant.Models.Covenant
{
    public class CovenantUser : IdentityUser
    {
        
    }

    public class CovenantUserLogin
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    public class CovenantUserLoginResult
    {
        public bool success { get; set; } = true;
        public string token { get; set; } = default;
    }
}
