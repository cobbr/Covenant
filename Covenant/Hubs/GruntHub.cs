// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

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
    public static class GruntHubProxy
    {
        public async static Task SendCommandEvent(IHubContext<GruntHub> context, Event taskingEvent, GruntCommand command)
        {
            await context.Clients.Group(taskingEvent.Context).SendAsync("ReceiveCommandEvent", command, taskingEvent);
            if (taskingEvent.Context != "*")
            {
                await context.Clients.Group("*").SendAsync("ReceiveCommandEvent", command, taskingEvent);
            }
        }

        public async static Task NotifyListener(IHubContext<GruntHub> context, Grunt egressGrunt)
        {
            await context.Clients.Group(egressGrunt.Listener.GUID).SendAsync("NotifyListener", egressGrunt.GUID);
        }
    }

    [Authorize]
    public class GruntHub : Hub
    {
        private readonly CovenantContext _context;
        private readonly Interaction interact;

        public GruntHub(CovenantContext context, IHubContext<GruntHub> grunthub, IHubContext<EventHub> eventhub)
        {
            _context = context;
            interact = new Interaction(_context, grunthub, eventhub);
        }

        public async Task JoinGroup(string groupname)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupname);
        }

        public async Task GetGrunts()
        {
            List<Grunt> grunts = (await _context.GetGrunts()).Where(G => G.Status != GruntStatus.Uninitialized).ToList();
            foreach (Grunt g in grunts)
            {
                await this.Clients.Caller.SendAsync("ReceiveGrunt", g.GUID, g.Name);
            }
        }

        public async Task GetListeners()
        {
            List<Listener> listeners = (await _context.GetListeners()).Where(L => L.Status == ListenerStatus.Active).ToList();
            foreach (Listener l in listeners)
            {
                await this.Clients.Caller.SendAsync("ReceiveListener", l.GUID, l.Name);
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
                    await this.Clients.Caller.SendAsync("ReceiveGruntLink", g.GUID, childGrunt.GUID);
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
                Listener l = await _context.GetListener(g.ListenerId);
                await this.Clients.Caller.SendAsync("ReceiveGruntListenerLink", l.GUID, g.GUID);
            }
        }

        public async Task GetInteract(string gruntName, string input)
        {
            CovenantUser user = await _context.GetUser(this.Context.UserIdentifier);
            Grunt grunt = await _context.GetGruntByName(gruntName);
            GruntCommand command = await interact.Input(user, grunt, input);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetCommandOutput(int id)
        {
            GruntCommand command = await _context.GruntCommands
                .Where(GC => GC.Id == id)
                .Include(GC => GC.User)
                .Include(GC => GC.CommandOutput)
                .Include(GC => GC.GruntTasking)
                    .ThenInclude(GC => GC.GruntTask)
                .FirstOrDefaultAsync();
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
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
