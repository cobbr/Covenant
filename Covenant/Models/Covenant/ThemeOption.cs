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

namespace Covenant.Models.Covenant
{
    public class ThemeOption
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; }
        [Required]
        public string Value { get; set; }
        public string DefaultValue { get; set; }
        public string Description { get; set; }

        [Required]
        public int ThemeId { get; set; }
        public Theme Theme { get; set; }
    }

    public static class ThemeOptionExtension
    {
        public static string GetValueByName(this IEnumerable<ThemeOption> themeOptions, string name)
        {
            return themeOptions.SingleOrDefault(to => to.Name == name)?.Value;
        }
    }
}
