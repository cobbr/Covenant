using System;

namespace Covenant.Core
{
    public static class ConsoleWriter
    {
        private static readonly ConsoleColor InfoColor = ConsoleColor.Gray;
        private static readonly ConsoleColor HighlightColor = ConsoleColor.Cyan;
        private static readonly ConsoleColor WarningColor = ConsoleColor.Yellow;
        private static readonly ConsoleColor ErrorColor = ConsoleColor.Red;

        private static readonly string InfoLabel = "[+]";
        private static readonly string HighlightLabel = "[*]";
        private static readonly string WarningLabel = "[-]";
        private static readonly string ErrorLabel = "[!]";
        private static readonly object _ConsoleLock = new object();

        public static void SetForegroundColor(ConsoleColor color)
        {
            lock (_ConsoleLock)
            {
                Console.ForegroundColor = color;
            }
        }

        private static string PrintColor(string ToPrint = "", ConsoleColor color = ConsoleColor.DarkGray)
        {
            string toReturn;
            SetForegroundColor(color);
            lock (_ConsoleLock)
            {
                toReturn = ToPrint;
                Console.ResetColor();
            }
            return toReturn;
        }

        private static string PrintColorLine(string ToPrint = "", ConsoleColor color = ConsoleColor.DarkGray)
        {
            string toReturn;
            lock (_ConsoleLock)
            {
                Console.ForegroundColor = color;
                toReturn = ToPrint + Environment.NewLine;
                Console.ResetColor();
            }
            return toReturn;
        }

        public static string PrintInfo(string ToPrint = "")
        {
            return PrintColor(ToPrint, ConsoleWriter.InfoColor);
        }

        public static string PrintInfoLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, ConsoleWriter.InfoColor);
        }

        public static string PrintFormattedInfo(string ToPrint = "")
        {
            return PrintColor(ConsoleWriter.InfoLabel + " " + ToPrint, ConsoleWriter.InfoColor);
        }

        public static string PrintFormattedInfoLine(string ToPrint = "")
        {
            return PrintColorLine(ConsoleWriter.InfoLabel + " " + ToPrint, ConsoleWriter.InfoColor);
        }

        public static string PrintHighlight(string ToPrint = "")
        {
            return PrintColor(ToPrint, ConsoleWriter.HighlightColor);
        }

        public static string PrintHighlightLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, ConsoleWriter.HighlightColor);
        }

        public static string PrintFormattedHighlight(string ToPrint = "")
        {
            return PrintColor(ConsoleWriter.HighlightLabel + " " + ToPrint, ConsoleWriter.HighlightColor);
        }

        public static string PrintFormattedHighlightLine(string ToPrint = "")
        {
            return PrintColorLine(ConsoleWriter.HighlightLabel + " " + ToPrint, ConsoleWriter.HighlightColor);
        }

        public static string PrintWarning(string ToPrint = "")
        {
            return PrintColor(ToPrint, ConsoleWriter.WarningColor);
        }

        public static string PrintWarningLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, ConsoleWriter.WarningColor);
        }

        public static string PrintFormattedWarning(string ToPrint = "")
        {
            return PrintColor(ConsoleWriter.WarningLabel + " " + ToPrint, ConsoleWriter.WarningColor);
        }

        public static string PrintFormattedWarningLine(string ToPrint = "")
        {
            return PrintColorLine(ConsoleWriter.WarningLabel + " " + ToPrint, ConsoleWriter.WarningColor);
        }

        public static string PrintError(string ToPrint = "")
        {
            return PrintColor(ToPrint, ConsoleWriter.ErrorColor);
        }

        public static string PrintErrorLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, ConsoleWriter.ErrorColor);
        }

        public static string PrintFormattedError(string ToPrint = "")
        {
            return PrintColorLine(ConsoleWriter.ErrorLabel + " " + ToPrint, ConsoleWriter.ErrorColor);
        }

        public static string PrintFormattedErrorLine(string ToPrint = "")
        {
            return PrintColorLine(ConsoleWriter.ErrorLabel + " " + ToPrint, ConsoleWriter.ErrorColor);
        }
    }
}
