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
            Options = new List<ThemeOption>();
        }
    }

    public class ThemeOption
    {
        [Key]
        [Required]
        public int ThemeId { get; set; }
        [Key]
        [Required]
        public string Name { get; set; }
        public string Value { get; set; }
        public string Description { get; set; }
        public Theme Theme { get; set; }
    }

    public class ThemeViewModel
    {
        public Theme Theme { get; set; }
        public ThemeOptionsViewModel ThemeOptions { get; set; }

        public ThemeViewModel()
        {
            Theme = new Theme();
            ThemeOptions = new ThemeOptionsViewModel();
        }

        public ThemeViewModel(Theme theme, ThemeOptionsViewModel themeOptions)
        {
            Theme = theme;
            ThemeOptions = themeOptions;
        }
    }

    public class ThemeOptionsViewModel
    {
        [Required]        
        public int ThemeId { get; set; }
        [Required]
        public string BackgroundColor { get; set; }
        [Required]
        public string SidebarColor { get; set; }
        [Required]
        public string TextColor { get; set; }
        [Required]
        public string TextHeaderColor { get; set; }
        [Required]
        public string TextLinksColor { get; set; }
        [Required]
        public string TextLinksHoverColor { get; set; }
        [Required]
        public string NavLinksColor { get; set; }
        [Required]
        public string NavLinksColorSelected { get; set; }
        [Required]
        public string NavLinksColorHover { get; set; }
        public string CustomCss { get; set; }

        public ThemeOptionsViewModel()
        {

        }

        public ThemeOptionsViewModel(int themeId, IEnumerable<ThemeOption> options)
        {
            ThemeId = themeId;
            MapOptionsToFields(options);
        }

        public void MapOptionsToFields(IEnumerable<ThemeOption> options)
        {
            BackgroundColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.BackgroundColor)?.Value;
            SidebarColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.SidebarColor)?.Value;
            TextColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextColor)?.Value;
            TextHeaderColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextHeaderColor)?.Value;
            TextLinksColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextLinksColor)?.Value;
            TextLinksHoverColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.TextLinksHoverColor)?.Value;
            NavLinksColor = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColor)?.Value;
            NavLinksColorSelected = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColorSelected)?.Value;
            NavLinksColorHover = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.NavLinksColorHover)?.Value;
            CustomCss = options.SingleOrDefault(o => o.Name == Common.Settings.Themes.Options.CustomCss)?.Value;
        }   
        
        public IEnumerable<ThemeOption> GetThemeOptionsList()
        {
            List<ThemeOption> options = new List<ThemeOption>();
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.BackgroundColor, Value = BackgroundColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.SidebarColor, Value = SidebarColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.TextColor, Value = TextColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.TextHeaderColor, Value = TextHeaderColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.TextLinksColor, Value = TextLinksColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.TextLinksHoverColor, Value = TextLinksHoverColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.NavLinksColor, Value = NavLinksColor });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.NavLinksColorSelected, Value = NavLinksColorSelected });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.NavLinksColorHover, Value = NavLinksColorHover });
            options.Add(new ThemeOption() { ThemeId = ThemeId, Name = Common.Settings.Themes.Options.CustomCss, Value = CustomCss });
            return options;
        }
    }

    public static class ThemeOptionExtension
    {
        public static string GetValueByName(this IEnumerable<ThemeOption> themeOptions, string name)
        {
            return themeOptions.SingleOrDefault(to => to.Name == name)?.Value;
        }
    }
}
