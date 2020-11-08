// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Covenant.Core;
using Microsoft.AspNetCore.Identity;
using NLog;

namespace Covenant.Models.Covenant
{
    public class CovenantUser : IdentityUser, ILoggable
    {
        public CovenantUser() : base()
        {
            this.Email = "";
            this.NormalizedEmail = "";
            this.PhoneNumber = "";
            this.LockoutEnd = DateTime.UnixEpoch;
            this.ThemeId = 1;
        }

        public int ThemeId { get; set; }
        public Theme Theme { get; set; }

        public async Task ToLog(LogAction action, LogLevel level)
        {
            // CovenantUser|Action|ID|UserName
            await Task.Run(() => Common.logger.Log(level, $"CovenantUser|{action}|{this.Id}|{this.NormalizedUserName}"));
        }
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
