// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Covenant.Models.Covenant
{
    public enum CodeMirrorTheme
    {
        @default,
        night
    }

    public class Theme
    {
        private const string ColorRegExp = "^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$";

        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";

        [RegularExpression(ColorRegExp)]
        public string BackgroundColor { get; set; } = "#ffffff";
        [RegularExpression(ColorRegExp)]
        public string BackgroundTextColor { get; set; } = "#212529";

        [RegularExpression(ColorRegExp)]
        public string PrimaryColor { get; set; } = "#007bff";
        [RegularExpression(ColorRegExp)]
        public string PrimaryTextColor { get; set; } = "#ffffff";
        [RegularExpression(ColorRegExp)]
        public string PrimaryHighlightColor { get; set; } = "#0069d9";

        [RegularExpression(ColorRegExp)]
        public string SecondaryColor { get; set; } = "#6c757d";
        [RegularExpression(ColorRegExp)]
        public string SecondaryTextColor { get; set; } = "#ffffff";
        [RegularExpression(ColorRegExp)]
        public string SecondaryHighlightColor { get; set; } = "#545b62";

        [RegularExpression(ColorRegExp)]
        public string TerminalColor { get; set; } = "#062549";
        [RegularExpression(ColorRegExp)]
        public string TerminalTextColor { get; set; } = "#ffffff";
        [RegularExpression(ColorRegExp)]
        public string TerminalHighlightColor { get; set; } = "#17a2b8";
        [RegularExpression(ColorRegExp)]
        public string TerminalBorderColor { get; set; } = "#17a2b8";

        [RegularExpression(ColorRegExp)]
        public string NavbarColor { get; set; } = "#343a40";
        [RegularExpression(ColorRegExp)]
        public string SidebarColor { get; set; } = "#f8f9fa";

        [RegularExpression(ColorRegExp)]
        public string InputColor { get; set; } = "#ffffff";
        [RegularExpression(ColorRegExp)]
        public string InputDisabledColor { get; set; } = "#e9ecef";
        [RegularExpression(ColorRegExp)]
        public string InputTextColor { get; set; } = "#212529";
        [RegularExpression(ColorRegExp)]
        public string InputHighlightColor { get; set; } = "#0069d9";

        [RegularExpression(ColorRegExp)]
        public string TextLinksColor { get; set; } = "#007bff";

        public CodeMirrorTheme CodeMirrorTheme { get; set; } = CodeMirrorTheme.@default;
    }
}