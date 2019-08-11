// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;

using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Hubs
{
    public static class EventHubProxy
    {
        public async static Task SendEvent(IHubContext<EventHub> context, Event theEvent)
        {
            await context.Clients.Group(theEvent.Context).SendAsync("ReceiveEvent", theEvent);
        }
    }

    [Authorize]
    public class EventHub : Hub
    {
        private readonly CovenantContext _context;

        public EventHub(CovenantContext context)
        {
            _context = context;
        }

        public async Task JoinGroup(string context)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, context);
        }
    }
}
