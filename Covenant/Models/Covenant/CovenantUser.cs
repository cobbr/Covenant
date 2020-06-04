// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Identity;

namespace Covenant.Models.Covenant
{
    public class CovenantUser : IdentityUser
    {

    }

    public class CovenantUserLogin
    {
        public string Id { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }

    public class CovenantUserRegister : CovenantUserLogin
    {
        [Required]
        public string ConfirmPassword { get; set; }
    }

    public class CovenantUserLoginResult
    {
        public bool Success { get; set; } = true;
        public string CovenantToken { get; set; } = default;
    }
}
