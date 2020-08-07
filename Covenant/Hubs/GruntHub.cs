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
    [Authorize]
    public class GruntHub : Hub
    {
        private readonly ICovenantService _service;

        public GruntHub(ICovenantService service)
        {
            _service = service;
        }

        public async Task JoinGroup(string groupname)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupname);
        }

        public async Task GetGrunts()
        {
            List<Grunt> grunts = (await _service.GetGrunts()).Where(G => G.Status != GruntStatus.Uninitialized).ToList();
            foreach (Grunt g in grunts)
            {
                await this.Clients.Caller.SendAsync("ReceiveGrunt", g.GUID, g.Name);
            }
        }

        public async Task GetListeners()
        {
            List<Listener> listeners = (await _service.GetListeners()).Where(L => L.Status == ListenerStatus.Active).ToList();
            foreach (Listener l in listeners)
            {
                await this.Clients.Caller.SendAsync("ReceiveListener", l.GUID, l.Name);
            }
        }

        public async Task GetGruntLinks()
        {
            List<Grunt> grunts = (await _service.GetGrunts()).Where(G => G.Status != GruntStatus.Uninitialized && G.Children.Any()).ToList();
            foreach (Grunt g in grunts)
            {
                foreach (string child in g.Children)
                {
                    Grunt childGrunt = await _service.GetGruntByGUID(child);
                    await this.Clients.Caller.SendAsync("ReceiveGruntLink", g.GUID, childGrunt.GUID);
                }
            }
        }

        public async Task GetGruntListenerLinks()
        {
            IEnumerable<Grunt> allGrunts = await _service.GetGrunts();
            List<Grunt> grunts = (await _service.GetGrunts())
                .Where(G => G.Status != GruntStatus.Uninitialized)
                .Where(G => !allGrunts.Any(AG => AG.Children.Contains(G.GUID)))
                .ToList();
            foreach (Grunt g in grunts)
            {
                Listener l = await _service.GetListener(g.ListenerId);
                await this.Clients.Caller.SendAsync("ReceiveGruntListenerLink", l.GUID, g.GUID);
            }
        }

        public async Task GetInteract(string gruntName, string input)
        {
            CovenantUser user = await _service.GetUser(this.Context.UserIdentifier);
            Grunt grunt = await _service.GetGruntByName(gruntName);
            GruntCommand command = await _service.InteractGrunt(grunt.Id, user.Id, input);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetCommandOutput(int id)
        {
            GruntCommand command = await _service.GetGruntCommand(id);
            command.CommandOutput ??= await _service.GetCommandOutput(command.CommandOutputId);
            command.User ??= await _service.GetUser(command.UserId);
            command.GruntTasking ??= await _service.GetGruntTasking(command.GruntTaskingId ?? default);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetSuggestions(string gruntName)
        {
            Grunt grunt = await _service.GetGruntByName(gruntName);
            List<string> suggestions = await _service.GetCommandSuggestionsForGrunt(grunt);
            await this.Clients.Caller.SendAsync("ReceiveSuggestions", suggestions);
        }
    }
}
