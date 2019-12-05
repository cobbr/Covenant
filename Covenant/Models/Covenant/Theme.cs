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

        [Required]
        public int ThemeId { get; set; }
        [Required]
        public string BackgroundColor { get; set; }
        public string BackgroundColorPlaceholder { get; set; }
        [Required]
        public string SidebarColor { get; set; }
        public string SidebarColorPlaceholder { get; set; }
        [Required]
        public string TextColor { get; set; }
        public string TextColorPlaceHolder { get; set; }
        [Required]
        public string TextHeaderColor { get; set; }
        public string TextHeaderColorPlaceHolder { get; set; }
        [Required]
        public string TextLinksColor { get; set; }
        public string TextLinksColorPlaceholder { get; set; }
        [Required]
        public string TextLinksHoverColor { get; set; }
        public string TextLinksHoverColorPlaceholder { get; set; }        
        [Required]
        public string NavLinksColor { get; set; }
        public string NavLinksColorPlaceholder { get; set; }
        [Required]
        public string NavLinksColorSelected { get; set; }
        public string NavLinksColorSelectedPlaceholder { get; set; }
        [Required]
        public string NavLinksColorHover { get; set; }
        public string NavLinksColorHoverPlaceholder { get; set; }
        public string CustomCss { get; set; }

        public ThemeOptionsViewModel()
        {
            Options = new List<ThemeOption>();
        }

        public ThemeOptionsViewModel(int themeId, IEnumerable<ThemeOption> options)
        {
            ThemeId = themeId;
            MapOptionsToFields(options);
        }

        public void MapOptionsToFields(IEnumerable<ThemeOption> options)
        {
            BackgroundColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.BackgroundColor)?.Value;
            BackgroundColorPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.BackgroundColor)?.DefaultValue;
            SidebarColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.SidebarColor)?.Value;
            SidebarColorPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.SidebarColor)?.DefaultValue;
            TextColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextColor)?.Value;
            TextColorPlaceHolder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextColor)?.DefaultValue;
            TextHeaderColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextHeaderColor)?.Value;
            TextHeaderColorPlaceHolder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextHeaderColor)?.DefaultValue;
            TextLinksColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextLinksColor)?.Value;
            TextLinksColorPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextLinksColor)?.DefaultValue;
            TextLinksHoverColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextLinksHoverColor)?.Value;
            TextLinksHoverColorPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextLinksHoverColor)?.DefaultValue;
            NavLinksColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColor)?.Value;
            NavLinksColorPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColor)?.DefaultValue;
            NavLinksColorSelected = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColorSelected)?.Value;
            NavLinksColorSelectedPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColorSelected)?.DefaultValue;
            NavLinksColorHover = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColorHover)?.Value;
            NavLinksColorHoverPlaceholder = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColorHover)?.DefaultValue;
            CustomCss = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.CustomCss)?.Value;
        }   
        
        public IEnumerable<ThemeOption> MapFieldsToOptions()
        {
            return Options;
        }
    }
}
