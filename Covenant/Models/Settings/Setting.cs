// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

using Covenant.Core;

namespace Covenant.Models.Settings
{
    public class Setting
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Key { get; set; }
        [Required]
        public string Title { get; set; }
        [Required]
        public string Value { get; set; }
        public string DefaultValue { get; set; }
        public string Description { get; set; }
    }

    public class SettingsTheme
    {
        [Required]
        public string StandardThemeId { get; set; }
        [Required]
        public string DarkThemeId { get; set; }
    }
}
