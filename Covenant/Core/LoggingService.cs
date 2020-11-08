using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR;

using Covenant;
using Covenant.Hubs;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;
using Covenant.Models.Launchers;
using Covenant.Models.Grunts;
using Covenant.Models.Indicators;
using NLog;

namespace Covenant.Core
{
    public interface ILoggable
    {
        public Task ToLog(LogAction action, LogLevel level);
    }
    public enum LogAction
    {
        Create,
        Delete,
        Update
    }

    public class LoggingService
    {
        public static async Task Log(LogAction action, LogLevel level, ILoggable CovenantEvent)
        {
            await Task.Run(() => CovenantEvent.ToLog(action, level));
       }
    }
}
