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
        public IEnumerable<GruntTasking> GetAllGruntTaskings()
        {
            return _context.GruntTaskings.ToList();
        }

        // GET: api/grunts/{id}/taskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet("grunts/{id}/taskings", Name = "GetGruntTaskings")]
        public IEnumerable<GruntTasking> GetGruntTaskings(int id)
        {
            return _context.GruntTaskings.Where(GT => GT.GruntId == id).ToList();
        }

        // GET: api/grunts/{id}/taskings/search
        // <summary>
        // Get GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search", Name = "GetSearchGruntTaskings")]
        public IEnumerable<GruntTasking> GetSearchGruntTaskings(int id)
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
        public IEnumerable<GruntTasking> GetUninitializedGruntTaskings(int id)
        {
            return _context.GruntTaskings
                .Where(GT => GT.GruntId == id && GT.status == GruntTasking.GruntTaskingStatus.Uninitialized)
                .ToList();
        }

        // GET: api/grunts/{id}/taskings/search/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search/uninitialized", Name = "GetSearchUninitializedGruntTaskings")]
        public IEnumerable<GruntTasking> GetSearchUninitializedGruntTaskings(int id)
        {
            List<GruntTasking> uninitializedTasks = _context.GruntTaskings.Where(GT => GT.status == GruntTasking.GruntTaskingStatus.Uninitialized).ToList();
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
            GruntTasking gruntTasking = _context.GruntTaskings.FirstOrDefault(GT => GT.GruntId == id && GT.Name == taskname);
            if (gruntTasking == null)
            {
                return NotFound();
            }
            return Ok(gruntTasking);
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
            CovenantUser taskingUser = this.GetCurrentUser();
            if (grunt == null || taskingUser == null)
            {
                return NotFound();
            }
            gruntTasking.TaskingUser = taskingUser.UserName;
            gruntTasking.TaskingTime = DateTime.UtcNow;
            if (gruntTasking.type == GruntTasking.GruntTaskingType.Assembly)
            {
                GruntTask task = _context.GruntTasks.FirstOrDefault(T => T.Id == gruntTasking.TaskId);
                if (task == null)
                {
                    return NotFound();
                }
                task.Options = _context.GruntTaskOptions.Where(O => O.TaskId == task.Id).ToList();
                List<string> parameters = task.Options.OrderBy(O => O.OptionId).Select(O => O.Value).ToList();
                if (task.Name.ToLower() == "wmigrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[1].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound();
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
                        return NotFound();
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
                        return NotFound();
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
                    gruntTasking.Compile(
                        task.Code, parameters,
                        task.GetReferenceAssemblies(),
                        task.GetReferenceSourceLibraries(),
                        task.GetEmbeddedResources(),
                        grunt.DotNetFrameworkVersion
                    );
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Task Compilation failed: " + e.Message + e.StackTrace);
                    return BadRequest("Task returned compilation errors:" + e.Message + e.StackTrace);
                }
            }
            else if (gruntTasking.type == GruntTasking.GruntTaskingType.Connect)
            {
                string hostname = gruntTasking.TaskingMessage.message.Split(",")[0];
                string pipename = gruntTasking.TaskingMessage.message.Split(",")[1];
                if (hostname == "localhost" || hostname == "127.0.0.1")
                {
                    hostname = grunt.Hostname;
                }
                gruntTasking.Value = hostname + "," + pipename;
            }
            _context.GruntTaskings.Add(gruntTasking);
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
            GruntTasking updatingGruntTasking = _context.GruntTaskings.FirstOrDefault(GT => id == GT.GruntId && taskname == GT.Name);
            Grunt grunt = _context.Grunts.FirstOrDefault(G => G.Id == gruntTasking.GruntId);
            GruntTask gruntTask = _context.GruntTasks.FirstOrDefault(G => G.Id == gruntTasking.TaskId);
            GruntTask DownloadTask = _context.GruntTasks.FirstOrDefault(GT => GT.Name == "Download");
            if (updatingGruntTasking == null || grunt == null || gruntTask == null || DownloadTask == null)
            {
                return NotFound();
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
            GruntTasking.GruntTaskingStatus newStatus = gruntTasking.status;
            GruntTasking.GruntTaskingStatus originalStatus = updatingGruntTasking.status;
            if ((originalStatus == GruntTasking.GruntTaskingStatus.Tasked || originalStatus == GruntTasking.GruntTaskingStatus.Progressed) &&
                newStatus == GruntTasking.GruntTaskingStatus.Completed)
            {
                if (gruntTasking.type == GruntTasking.GruntTaskingType.Kill)
                {
                    grunt.Status = Grunt.GruntStatus.Killed;
                }
                else if (gruntTasking.type == GruntTasking.GruntTaskingType.Connect)
                {
                    if (originalStatus == GruntTasking.GruntTaskingStatus.Tasked)
                    {
                        // Check if this Grunt was already connected
                        string hostname = gruntTasking.TaskingMessage.message.Split(",")[0];
                        string pipename = gruntTasking.TaskingMessage.message.Split(",")[1];
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
                                    if (g.GetChildren().Contains(previouslyConnectedGrunt.GUID))
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
                            newStatus = GruntTasking.GruntTaskingStatus.Progressed;
                        }
                    }
                    else if (originalStatus == GruntTasking.GruntTaskingStatus.Progressed)
                    {
                        // Connecting Grunt has staged, add as Child
                        string hostname = gruntTasking.TaskingMessage.message.Split(",")[0];
                        string pipename = gruntTasking.TaskingMessage.message.Split(",")[1];
                        Grunt stagingGrunt = _context.Grunts.FirstOrDefault(G =>
                            G.CommType == Grunt.CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename &&
                            G.Status == Grunt.GruntStatus.Stage0
                        );
                        if (stagingGrunt == null)
                        {
                            return NotFound();
                        }
                        grunt.AddChild(stagingGrunt);
                    }
                }
                else if (gruntTasking.type == GruntTasking.GruntTaskingType.Disconnect)
                {
                    Grunt disconnectFromGrunt = _context.Grunts.FirstOrDefault(G => G.GUID == gruntTasking.TaskingMessage.message);
                    if (disconnectFromGrunt == null)
                    {
                        return NotFound();
                    }

                    disconnectFromGrunt.Status = Grunt.GruntStatus.Disconnected;
                    _context.Grunts.Update(disconnectFromGrunt);
                    grunt.RemoveChild(disconnectFromGrunt);
                }
            }

            if ((newStatus == GruntTasking.GruntTaskingStatus.Completed || newStatus == GruntTasking.GruntTaskingStatus.Progressed) && originalStatus != newStatus)
            {
                if (newStatus == GruntTasking.GruntTaskingStatus.Completed)
                {
                    updatingGruntTasking.CompletionTime = DateTime.UtcNow;
                }
                string verb = newStatus == GruntTasking.GruntTaskingStatus.Completed ? "completed" : "progressed";
                if (gruntTasking.TaskId == DownloadTask.Id)
                {
                    _context.Events.Add(new Event
                    {
                        Time = updatingGruntTasking.CompletionTime,
                        MessageHeader = "[" + updatingGruntTasking.CompletionTime + " UTC] Grunt: " + grunt.Name + " has " + verb + " GruntTasking: " + gruntTasking.Name,
                        Level = Event.EventLevel.Highlight,
                        Context = grunt.Name
                    });
                    string FileName = Common.CovenantEncoding.GetString(Convert.FromBase64String(gruntTasking.GruntTaskingAssembly.Split(",")[1]));
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

            updatingGruntTasking.status = newStatus;
            updatingGruntTasking.GruntTaskOutput = gruntTasking.GruntTaskOutput;
            _context.GruntTaskings.Update(updatingGruntTasking);
            _context.Grunts.Update(grunt);
            _context.SaveChanges();

            return Ok(updatingGruntTasking);
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
                return NotFound();
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
            if (parentGrunt.GetChildren().Contains(childGrunt.GUID))
            {
                return true;
            }
            foreach (string child in parentGrunt.GetChildren())
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
