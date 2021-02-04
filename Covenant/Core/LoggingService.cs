using System;
using System.IO;
using System.Threading.Tasks;

using NLog;

using Covenant.Models;
using Covenant.Models.Grunts;
using Covenant.Models.Covenant;

namespace Covenant.Core
{
    public class LoggingService
    {
        private static readonly Logger CovenantLogger = LogManager.GetCurrentClassLogger();

        public static async Task Log(LogAction action, LogLevel level, ILoggable loggable)
        {
            await Task.Run(() => CovenantLogger.Log(level, loggable.ToLog(action)));
        }

        // Not working yet, not sure how to deal with streaming output
        public static async Task LogOutput(Grunt grunt, CovenantUser user, GruntCommand command, CommandOutput output)
        {
            await Task.Run(() =>
            {
                File.AppendAllText(
                    $"{Common.CovenantLogDirectory}grunt_{grunt.Name}", // Log file
                    $"[{command.CommandTime}]{Environment.NewLine}({user.UserName}) > {command.Command}{Environment.NewLine}{output.Output}" // Append output
                );
            });
        }
    }
}
