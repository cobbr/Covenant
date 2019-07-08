using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Microsoft.Rest;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

namespace Covenant.Hubs
{
    public static class HubProxy
    {
        public async static Task SendEvent(IHubContext<GruntHub> context, Event anEvent)
        {
            await context.Clients.Group(anEvent.Context).SendAsync("ReceiveEvent", EliteConsole.PrintFormattedHighlight(anEvent.MessageHeader), anEvent.MessageBody);
        }

        public async static Task SendCommandEvent(IHubContext<GruntHub> context, Event taskingEvent, GruntCommand command)
        {
            await context.Clients.Group(taskingEvent.Context)
                .SendAsync("ReceiveCommandEvent", command.Id, EliteConsole.PrintFormattedHighlight(taskingEvent.MessageHeader),
                           command.User.UserName, command.Command, command.CommandOutput.Output);
        }
    }

    [Authorize]
    public class GruntHub : Hub
    {
        private readonly CovenantContext _context;
        private readonly Interaction interact;

        public GruntHub(CovenantContext context, IHubContext<GruntHub> grunthub)
        {
            _context = context;
            interact = new Interaction(_context, grunthub);
        }

        public async Task JoinGroup(string gruntName)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, gruntName);
        }

        public async Task GetGrunts()
        {
            List<Grunt> grunts = (await _context.GetGrunts()).Where(G => G.Status != GruntStatus.Uninitialized).ToList();
            foreach (Grunt g in grunts)
            {
                await this.Clients.Caller.SendAsync("ReceiveGrunt", g.Id, g.Name);
            }
        }

        public async Task GetListeners()
        {
            List<Listener> listeners = (await _context.GetListeners()).Where(L => L.Status == ListenerStatus.Active).ToList();
            foreach (Listener l in listeners)
            {
                await this.Clients.Caller.SendAsync("ReceiveListener", l.Id, l.Name);
            }
        }

        public async Task GetGruntLinks()
        {
            List<Grunt> grunts = (await _context.GetGrunts()).Where(G => G.Status != GruntStatus.Uninitialized && G.Children.Any()).ToList();
            foreach (Grunt g in grunts)
            {
                foreach (string child in g.Children)
                {
                    Grunt childGrunt = await _context.GetGruntByGUID(child);
                    await this.Clients.Caller.SendAsync("ReceiveGruntLink", g.Id, childGrunt.Id);
                }
            }
        }

        public async Task GetGruntListenerLinks()
        {
            IEnumerable<Grunt> allGrunts = await _context.GetGrunts();
            List<Grunt> grunts = (await _context.GetGrunts())
                .Where(G => G.Status != GruntStatus.Uninitialized)
                .Where(G => !allGrunts.Any(AG => AG.Children.Contains(G.GUID)))
                .ToList();
            foreach (Grunt g in grunts)
            {
                await this.Clients.Caller.SendAsync("ReceiveGruntListenerLink", g.ListenerId, g.Id);
            }
        }

        public async Task GetInteract(string gruntName, string input)
        {
            CovenantUser user = await _context.GetUserByUsername(this.Context.User.Identity.Name);
            Grunt grunt = await _context.GetGruntByName(gruntName);
            GruntCommand command = await interact.Input(user, grunt, input);
        }

        public async Task GetCommandOutput(int id)
        {
            GruntCommand command = await _context.GetGruntCommand(id);
            CommandOutput output = await _context.GetCommandOutput(command.CommandOutputId);
            if (!string.IsNullOrWhiteSpace(output.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", output.Output);
            }
        }

        public async Task GetSuggestions(string gruntName)
        {
            CovenantUser user = await _context.GetUserByUsername(this.Context.User.Identity.Name);
            List<string> suggestions = await interact.GetSuggestions(gruntName);
            await this.Clients.Caller.SendAsync("ReceiveSuggestions", suggestions);
        }
    }
}
