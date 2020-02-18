// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;

using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;

namespace Covenant.Hubs
{
    [Authorize]
    public class GruntCommandHub : Hub
    {
        public async Task JoinGroup(string context)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, context);
        }
    }
}
