using System.Threading.Tasks;

using Microsoft.AspNetCore.SignalR;

namespace Covenant.Hubs
{
    public class TestHub : Hub
    {
        public async Task Send(string one, string two)
        {
            await Clients.All.SendAsync("ReceiveMessage", one, two);
        }
    }
}
