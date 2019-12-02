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
    public enum ThemeType
    {
        Standard,
        Dark
    }

    public class Theme
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; }
        public string Description { get; set; }

        public IEnumerable<ThemeOption> Options { get; set; }

        public Theme()
        {

        }
    }

    public class ThemeOptionsViewModel
    {
        private IEnumerable<ThemeOption> Options { get; set; }

        public int Id { get; set; }
        public string BackgroundColor { get; set; }
        public string BackgroundColorPlaceholder { get; set; }

        public ThemeOptionsViewModel(IEnumerable<ThemeOption> options)
        {
            MapOptionsToFields(options);
        }

        public void MapOptionsToFields(IEnumerable<ThemeOption> options)
        {
            BackgroundColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.BackgroundColor)?.Value;
            BackgroundColorPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.BackgroundColor)?.DefaultValue;
        }        
    }
}
